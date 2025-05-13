"""
Production-ready frontend module for Threat Intelligence Platform.
Handles web interface, dashboard views, and real-time data display.
Public-facing interface only - no admin controls.
"""

import os
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from typing import Dict, List, Any, Optional

from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask import flash, abort, g, current_app, Response

# Import config module for centralized configuration
from config import Config, ServiceManager, ServiceStatus

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.3")
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')

# Cache settings
CACHE_TIMEOUT = 300  # 5 minutes
LONG_CACHE_TIMEOUT = 1800  # 30 minutes
API_CACHE = {}
API_CACHE_TIMESTAMP = {}

# Configure logging
logger = logging.getLogger('frontend')

# Create Blueprint
frontend_app = Blueprint('frontend', __name__, template_folder='templates', static_folder='static')

# ====== Event Handlers ======

def invalidate_cache_on_ingestion(data):
    """Invalidate cache when new data is ingested."""
    logger.info("Invalidating cache due to data ingestion")
    clear_api_cache('feeds')
    clear_api_cache('iocs')
    clear_api_cache('stats')
    clear_api_cache('threat_summary')

def invalidate_cache_on_analysis(data):
    """Invalidate cache when analysis completes."""
    logger.info("Invalidating cache due to analysis completion")
    clear_api_cache('ai')
    clear_api_cache('threat_summary')
    clear_api_cache('analyses')

# Register event handlers when blueprint is recorded
@frontend_app.record
def register_event_handlers(state):
    """Register event handlers when blueprint is registered."""
    app = state.app
    if hasattr(app, 'event_bus'):
        logger.info("Registering frontend event handlers")
        app.event_bus.subscribe('data_ingested', invalidate_cache_on_ingestion)
        app.event_bus.subscribe('analysis_completed', invalidate_cache_on_analysis)
        app.event_bus.subscribe('ingestion_completed', invalidate_cache_on_ingestion)
        
        # Update service status
        service_manager = Config.get_service_manager()
        service_manager.update_status('frontend', ServiceStatus.READY)

# ====== Helper Functions ======

def safe_report_exception(e=None):
    """Safely report exception using config module."""
    try:
        from config import report_error
        report_error(e or Exception("Frontend error"))
    except Exception as err:
        logger.warning(f"Failed to report exception: {err}")

def cache_key(func_name: str, **params) -> str:
    """Generate cache key excluding sensitive parameters."""
    param_str = "&".join(f"{k}={str(v)}" for k, v in sorted(params.items()) 
                        if k not in ['api_key', 'token', 'password'] and v is not None)
    return f"{func_name}:{param_str}"

def cache_valid(key: str, timeout: int = CACHE_TIMEOUT) -> bool:
    """Check if cached value is still valid."""
    return (key in API_CACHE and key in API_CACHE_TIMESTAMP and 
            (time.time() - API_CACHE_TIMESTAMP[key]) < timeout)

def api_cache(timeout: int = CACHE_TIMEOUT):
    """Cache decorator for API results."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = cache_key(func.__name__, **kwargs)
            if cache_valid(key, timeout):
                return API_CACHE[key]
            
            result = func(*args, **kwargs)
            if result and 'error' not in result:  # Only cache successful responses
                API_CACHE[key] = result
                API_CACHE_TIMESTAMP[key] = time.time()
            return result
        return wrapper
    return decorator

def clear_api_cache(prefix: str = None):
    """Clear API cache entries with optional prefix filter."""
    global API_CACHE, API_CACHE_TIMESTAMP
    
    if prefix:
        keys = [k for k in API_CACHE if k.startswith(prefix)]
        for k in keys:
            API_CACHE.pop(k, None)
            API_CACHE_TIMESTAMP.pop(k, None)
        logger.debug(f"Cleared {len(keys)} cache entries with prefix '{prefix}'")
    else:
        API_CACHE = {}
        API_CACHE_TIMESTAMP = {}
        logger.debug("Cleared all API cache entries")

# ====== API Interaction Functions ======

def get_api_key() -> str:
    """Get API key from config."""
    if hasattr(Config, 'API_KEY') and Config.API_KEY:
        api_key = Config.API_KEY.strip()
        if api_key != 'default-api-key':
            return api_key
    
    # Use default key for public view
    return 'default-api-key'

@api_cache(timeout=CACHE_TIMEOUT)
def api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make internal API request with service status check."""
    
    # Check service status first
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    # Allow requests during initialization
    if status['overall'] == ServiceStatus.ERROR.value:
        return {"error": "Services unavailable", "status": "error"}
    
    try:
        import requests
        
        # Construct URL
        base_url = request.url_root.rstrip('/')
        url = f"{base_url}/api/{endpoint.lstrip('/')}"
        
        # Prepare headers
        headers = {"Content-Type": "application/json"}
        api_key = get_api_key()
        
        # Always include API key for consistent behavior
        headers["X-API-Key"] = api_key
        
        logger.debug(f"API request to {endpoint}")
        
        # Make request with retries
        max_retries = 3
        start_time = time.time()
        response = None
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                
                # Break on success or non-retriable failure
                if response.status_code < 500 or response.status_code == 401:
                    break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning(f"Request attempt {attempt + 1} failed: {str(e)}")
                
            # Exponential backoff
            if attempt < max_retries - 1:
                time.sleep(0.5 * (2 ** attempt))
        
        # Report slow requests
        request_time = time.time() - start_time
        if request_time > 1.0:
            logger.info(f"Slow API request ({request_time:.2f}s): {method} {url}")
        
        # Handle response
        if not response:
            logger.error(f"No response received for API request: {method} {url}")
            return {"error": "No response from API"}
        
        if response.status_code != 200:
            logger.warning(f"API request failed: {response.status_code}")
            return {
                "error": f"API request failed with status {response.status_code}",
                "status_code": response.status_code,
                "message": response.text[:200]
            }
        
        # Parse JSON response
        try:
            return response.json() if response.text else {}
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from {endpoint}")
            return {"error": "Invalid JSON response"}
    
    except Exception as e:
        logger.error(f"API request error ({endpoint}): {str(e)}")
        safe_report_exception(e)
        return {"error": f"API error: {str(e)}"}

# ====== Data Processing Functions ======

def prepare_dashboard_context(current_view: str, days: int) -> Dict[str, Any]:
    """Prepare common dashboard context data."""
    # Check service status
    service_manager = Config.get_service_manager()
    service_status = service_manager.get_status()
    
    # Initialize base context
    context = {
        'current_view': current_view,
        'days': days,
        'service_status': service_status,
        'public_view': True,
        'threat_score': 50,
        'feed_trend': 0,
        'ioc_trend': 0,
        'analysis_trend': 0,
        'activity_dates': [],
        'activity_counts': [],
        'ioc_type_labels': [],
        'ioc_type_values': [],
        'top_iocs': [],
        'geo_stats': [],
        'ai_summary': None,
        'threat_summary': {'overall_score': 50},
        'stats': {
            'feeds': {'total_sources': 0},
            'iocs': {'total': 0, 'types': []},
            'analyses': {'total_analyses': 0},
            'timestamp': datetime.utcnow().isoformat()
        }
    }
    
    # Set page metadata
    page_metadata = {
        'feeds': {
            'title': 'Threat Feeds',
            'subtitle': 'Intelligence sources and data collection',
            'icon': 'rss'
        },
        'iocs': {
            'title': 'Indicators of Compromise',
            'subtitle': 'Observed indicators and threat artifacts',
            'icon': 'fingerprint'
        },
        'ai-analysis': {
            'title': 'AI-Powered Analysis',
            'subtitle': 'Machine learning threat intelligence analysis',
            'icon': 'brain'
        },
        'dashboard': {
            'title': 'Threat Intelligence Dashboard',
            'subtitle': 'Platform overview and threat summary',
            'icon': 'tachometer-alt'
        }
    }
    
    metadata = page_metadata.get(current_view, page_metadata['dashboard'])
    context.update({
        'page_title': metadata['title'],
        'page_subtitle': metadata['subtitle'],
        'page_icon': metadata['icon']
    })
    
    return context

def load_dashboard_stats(context: Dict[str, Any], days: int):
    """Load statistics for dashboard."""
    stats_response = api_request('stats', params={"days": days})
    if not stats_response or 'error' in stats_response:
        logger.warning(f"Failed to load stats: {stats_response}")
        return
    
    context['stats'] = {
        'feeds': stats_response.get('feeds', {'total_sources': 0}),
        'iocs': stats_response.get('iocs', {'total': 0, 'types': []}),
        'analyses': stats_response.get('analyses', {'total_analyses': 0}),
        'timestamp': stats_response.get('timestamp', datetime.utcnow().isoformat())
    }
    
    # Calculate trends
    context['feed_trend'] = stats_response.get('feeds', {}).get('growth_rate', 0) or 0
    context['ioc_trend'] = stats_response.get('iocs', {}).get('growth_rate', 0) or 0
    context['analysis_trend'] = stats_response.get('analyses', {}).get('growth_rate', 0) or 0
    
    # IOC type data
    ioc_types = stats_response.get('iocs', {}).get('types', [])
    context['ioc_type_labels'] = [item.get('type', '') for item in ioc_types if isinstance(item, dict)]
    context['ioc_type_values'] = [item.get('count', 0) for item in ioc_types if isinstance(item, dict)]
    
    # Process visualization data
    if 'visualization_data' in stats_response:
        viz_data = stats_response['visualization_data']
        if 'daily_counts' in viz_data:
            # Create date range
            today = datetime.now().date()
            date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
            context['activity_dates'] = date_range
            
            # Map counts to dates
            daily_counts = viz_data['daily_counts']
            counts = [0] * len(date_range)
            date_to_index = {date: idx for idx, date in enumerate(date_range)}
            
            for entry in daily_counts:
                if isinstance(entry, dict) and 'date' in entry and 'count' in entry:
                    date_str = entry['date']
                    if date_str in date_to_index:
                        counts[date_to_index[date_str]] = entry['count']
            
            context['activity_counts'] = counts

def load_view_specific_data(context: Dict[str, Any], current_view: str, days: int):
    """Load view-specific data."""
    if current_view == 'feeds':
        feeds_response = api_request('feeds')
        if not feeds_response or 'error' in feeds_response:
            context['feed_items'] = []
        else:
            context['feed_items'] = feeds_response.get('feed_details', feeds_response.get('feeds', []))
        
    elif current_view == 'iocs':
        iocs_response = api_request('iocs', params={"days": days, "limit": 100})
        if not iocs_response or 'error' in iocs_response:
            context['ioc_items'] = []
        else:
            context['ioc_items'] = iocs_response.get('records', [])
        
    elif current_view == 'ai-analysis':
        ai_response = api_request('ai/analyses', params={"days": days})
        if not ai_response or 'error' in ai_response:
            context['ai_analyses'] = {}
            context['last_ai_analysis'] = None
        else:
            context['ai_analyses'] = ai_response
            context['last_ai_analysis'] = ai_response.get('last_run_time')
        
    else:
        # Dashboard view - load additional data
        # Get recent IOCs
        iocs_response = api_request('iocs', params={"days": days, "limit": 10})
        if iocs_response and 'error' not in iocs_response:
            context['top_iocs'] = iocs_response.get('records', [])
        
        # Get threat summary
        threat_summary = api_request('threat_summary', params={"days": days})
        if threat_summary and 'error' not in threat_summary:
            context['threat_summary'] = threat_summary
            context['threat_score'] = threat_summary.get('overall_score', 50)
        
        # Get AI summary
        ai_summary = api_request('ai/summary')
        if ai_summary and 'error' not in ai_summary:
            context['ai_summary'] = ai_summary
        
        # Get geo stats
        geo_stats = api_request('iocs/geo', params={"days": days})
        if geo_stats and 'error' not in geo_stats:
            context['geo_stats'] = geo_stats.get('countries', [])

# ====== Route Handlers ======

@frontend_app.route('/')
def index():
    """Root redirects to dashboard."""
    return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/dashboard')
@frontend_app.route('/dashboard/<view>')
def dashboard(view=None):
    """Dashboard view with dynamic content loading."""
    try:
        # Get view parameters
        current_view = view or request.args.get('view', 'dashboard')
        days = int(request.args.get('days', '30'))
        
        # Prepare base context
        context = prepare_dashboard_context(current_view, days)
        
        # Load statistics
        load_dashboard_stats(context, days)
        
        # Load view-specific data
        load_view_specific_data(context, current_view, days)
        
        return render_template('dashboard.html', **context, now=datetime.now())
    
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        safe_report_exception(e)
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('frontend.index'))

@frontend_app.route('/<content_type>/<path:identifier>')
def dynamic_content_detail(content_type, identifier):
    """Display detailed view for any content type."""
    try:
        # Sanitize inputs
        allowed_types = ['ioc', 'feed', 'analysis', 'threat_actor', 'campaign']
        if content_type not in allowed_types:
            abort(404)
        
        # Initialize context
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'data': {},
            'related_items': [],
            'icon': 'info-circle',
            'view_type': content_type + 's'
        }
        
        # Set icon based on content type
        icons = {
            'ioc': 'fingerprint',
            'feed': 'rss',
            'analysis': 'brain',
            'threat_actor': 'user-secret',
            'campaign': 'bullhorn'
        }
        context['icon'] = icons.get(content_type, 'info-circle')
        
        # Handle different content types
        if content_type == 'ioc':
            # Parse IOC identifier (format: type/value)
            parts = identifier.split('/', 1)
            if len(parts) == 2:
                ioc_type, ioc_value = parts
                # Get IOC data by type and value
                iocs_response = api_request('iocs', params={'type': ioc_type, 'value': ioc_value, 'limit': 1})
                if iocs_response and 'records' in iocs_response and len(iocs_response['records']) > 0:
                    context['data'] = iocs_response['records'][0]
                else:
                    flash('IOC not found', 'warning')
                    return redirect(url_for('frontend.dashboard', view='iocs'))
            else:
                flash('Invalid IOC identifier', 'warning')
                return redirect(url_for('frontend.dashboard', view='iocs'))
                
        elif content_type == 'feed':
            # Get feed data by ID
            feeds_response = api_request('feeds')
            if feeds_response and 'feed_details' in feeds_response:
                for feed in feeds_response['feed_details']:
                    if feed.get('id') == identifier:
                        context['data'] = feed
                        break
                else:
                    flash('Feed not found', 'warning')
                    return redirect(url_for('frontend.dashboard', view='feeds'))
                    
        elif content_type == 'analysis':
            # Get analysis data by ID
            analysis_response = api_request(f'analysis/{identifier}')
            if analysis_response and 'error' not in analysis_response:
                context['data'] = analysis_response
            else:
                flash('Analysis not found', 'warning')
                return redirect(url_for('frontend.dashboard', view='ai-analysis'))
        
        return render_template('detail.html', **context)
        
    except Exception as e:
        logger.error(f"Error in dynamic_content_detail: {str(e)}")
        flash('Error loading content details', 'danger')
        return redirect(url_for('frontend.dashboard'))

# ====== Error Handlers ======

@frontend_app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.info(f"Page not found: {request.path}")
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page Not Found",
                         error_description="The page you're looking for doesn't exist or has been moved.",
                         error_icon="search-location"), 404

@frontend_app.errorhandler(403)  
def forbidden(e):
    """Handle 403 errors."""
    logger.warning(f"Forbidden access: {request.path}")
    return render_template('error.html',
                         error_code=403,
                         error_message="Access Forbidden", 
                         error_description="You don't have permission to access this resource.",
                         error_icon="ban"), 403

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {str(e)}")
    safe_report_exception(e)
    return render_template('error.html',
                         error_code=500,
                         error_message="Internal Server Error",
                         error_description="An unexpected error occurred. Please try again later.",
                         error_icon="exclamation-triangle"), 500

# ====== Context Processors ======

@frontend_app.context_processor
def inject_global_data():
    """Inject global data into templates."""
    return {
        'now': datetime.now(),
        'environment': ENVIRONMENT,
        'version': VERSION,
        'project_id': getattr(Config, 'GCP_PROJECT', None),
        'debug_mode': DEBUG_MODE,
    }

# ====== Cache Management ======

def periodic_cache_cleanup():
    """Periodically clean up expired cache entries."""
    while True:
        try:
            current_time = time.time()
            expired_keys = []
            
            for key, timestamp in API_CACHE_TIMESTAMP.items():
                if current_time - timestamp > LONG_CACHE_TIMEOUT:
                    expired_keys.append(key)
            
            for key in expired_keys:
                API_CACHE.pop(key, None)
                API_CACHE_TIMESTAMP.pop(key, None)
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
            
            time.sleep(600)  # Sleep for 10 minutes
        except Exception as e:
            logger.error(f"Error in cache cleanup: {str(e)}")
            time.sleep(60)

# Start cache cleanup thread
if __name__ != "__main__":
    cleanup_thread = threading.Thread(target=periodic_cache_cleanup, daemon=True)
    cleanup_thread.start()
    logger.info("Frontend module initialized successfully")
