"""
Optimized frontend module for Threat Intelligence Platform.
Handles web interface, dashboard views, and AI-powered analysis.
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
from flask import flash, abort, g, current_app, send_file, Response, session

# Import config module for centralized configuration
from config import Config, ServiceManager, ServiceStatus

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.3")
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')

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
    
    # Invalidate specific IOC if provided
    if data and 'indicator_id' in data:
        cache_key = f"iocs_{data['indicator_id']}"
        API_CACHE.pop(cache_key, None)
        API_CACHE_TIMESTAMP.pop(cache_key, None)

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
            if not result or 'error' not in result:  # Only cache successful responses
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
    # Get from Config class
    if hasattr(Config, 'API_KEY') and Config.API_KEY:
        return Config.API_KEY.strip()
    
    # Fallback to environment
    api_key = os.environ.get('API_KEY', 'default-api-key')
    return api_key.strip()

@api_cache(timeout=CACHE_TIMEOUT)
def api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make internal API request with service status check."""
    
    # Check service status first
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
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
        
        if api_key and api_key != 'default-api-key':
            headers["X-API-Key"] = api_key
        
        logger.debug(f"API request to {endpoint} with API key: {api_key[:4]}...")
        
        # Make request with optimized retries
        max_retries = 3
        start_time = time.time()
        response = None
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, params=params, timeout=30)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
                
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
            logger.warning(f"API request failed: {response.status_code} - {response.text[:100]}")
            return {
                "error": f"API request failed with status {response.status_code}",
                "status_code": response.status_code,
                "message": response.text[:200]
            }
        
        # Parse JSON response
        try:
            return response.json() if response.text else {}
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from {endpoint}: {response.text[:100]}")
            return {"error": "Invalid JSON response"}
    
    except Exception as e:
        logger.error(f"API request error ({endpoint}): {str(e)}")
        safe_report_exception(e)
        return {"error": f"API error: {str(e)}"}

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
        # Check service status
        service_manager = Config.get_service_manager()
        service_status = service_manager.get_status()
        
        # Get view parameters
        current_view = view or request.args.get('view', 'dashboard')
        days = int(request.args.get('days', '30'))
        
        # Initialize context
        context = {
            'current_view': current_view,
            'days': days,
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
            },
            'service_status': service_status
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
        
        # Load statistics
        stats_response = api_request('stats', params={"days": days})
        if not stats_response or 'error' in stats_response:
            logger.warning(f"Failed to load stats: {stats_response}")
            if stats_response and 'error' in stats_response:
                flash(f"Error loading statistics: {stats_response['error']}", 'warning')
        else:
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
        
        # Load view-specific data
        if current_view == 'feeds':
            feeds_response = api_request('feeds')
            if not feeds_response or 'error' in feeds_response:
                context['feed_items'] = []
                if feeds_response and 'error' in feeds_response:
                    flash(f"Error loading feeds: {feeds_response['error']}", 'warning')
            else:
                context['feed_items'] = feeds_response.get('feed_details', [])
            
        elif current_view == 'iocs':
            iocs_response = api_request('iocs', params={"days": days, "limit": 100})
            if not iocs_response or 'error' in iocs_response:
                context['ioc_items'] = []
                if iocs_response and 'error' in iocs_response:
                    flash(f"Error loading IOCs: {iocs_response['error']}", 'warning')
            else:
                context['ioc_items'] = iocs_response.get('records', [])
            
        elif current_view == 'ai-analysis':
            ai_response = api_request('ai/analyses', params={"days": days})
            if not ai_response or 'error' in ai_response:
                context['ai_analyses'] = {}
                context['last_ai_analysis'] = None
                if ai_response and 'error' in ai_response:
                    flash(f"Error loading AI analysis: {ai_response['error']}", 'warning')
            else:
                context['ai_analyses'] = ai_response
                context['last_ai_analysis'] = ai_response.get('last_run_time')
            
        else:
            # Dashboard view
            # Date range for activity chart
            today = datetime.now().date()
            date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
            context['activity_dates'] = date_range
            
            # Activity data
            if stats_response and 'visualization_data' in stats_response:
                daily_counts = stats_response['visualization_data'].get('daily_counts', [])
                counts = [0] * len(date_range)
                date_to_index = {date: idx for idx, date in enumerate(date_range)}
                
                for entry in daily_counts:
                    if isinstance(entry, dict) and 'date' in entry:
                        date_str = entry.get('date')
                        if date_str in date_to_index:
                            counts[date_to_index[date_str]] = entry.get('count', 0)
                
                context['activity_counts'] = counts
            else:
                context['activity_counts'] = [20 + i * 2 for i in range(days)]
            
            # Load additional dashboard data
            iocs_response = api_request('iocs', params={"days": days, "limit": 10})
            if iocs_response and 'error' not in iocs_response:
                context['top_iocs'] = iocs_response.get('records', [])
            
            threat_summary = api_request('threat_summary', params={"days": days})
            if threat_summary and 'error' not in threat_summary:
                context['threat_summary'] = threat_summary
                context['threat_score'] = threat_summary.get('overall_score', 50)
            
            ai_summary = api_request('ai/summary')
            if ai_summary and 'error' not in ai_summary:
                context['ai_summary'] = ai_summary
            
            geo_stats = api_request('iocs/geo', params={"days": days})
            if geo_stats and 'error' not in geo_stats:
                context['geo_stats'] = geo_stats.get('countries', [])
        
        return render_template('dashboard.html', **context, now=datetime.now())
    
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        safe_report_exception(e)
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('frontend.index'))

# Additional routes that were missing

@frontend_app.route('/feeds')
def feeds():
    """Redirect to dashboard feeds view."""
    return redirect(url_for('frontend.dashboard', view='feeds'))

@frontend_app.route('/iocs')
def iocs():
    """Redirect to dashboard IOCs view."""
    return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/ioc/<ioc_id>/analyze', methods=['GET', 'POST'])
def analyze_ioc(ioc_id):
    """Trigger AI analysis for a specific IOC."""
    try:
        if request.method == 'POST':
            result = api_request('admin/analyze', method='POST', data={
                'indicator_ids': [ioc_id],
                'force_reanalysis': True
            })
            
            if result.get('error'):
                flash(f'Error triggering IOC analysis: {result["error"]}', 'danger')
            else:
                flash('AI analysis triggered successfully for IOC', 'success')
                clear_api_cache('ai')
            
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        # For GET, trigger analysis and redirect
        result = api_request('admin/analyze', method='POST', data={
            'indicator_ids': [ioc_id],
            'force_reanalysis': True
        })
        
        if result.get('error'):
            flash(f'Error triggering IOC analysis: {result["error"]}', 'danger')
        else:
            flash('AI analysis triggered successfully for IOC', 'success')
        
        return redirect(url_for('frontend.dashboard', view='iocs'))
        
    except Exception as e:
        logger.error(f"Error in analyze_ioc: {str(e)}")
        safe_report_exception(e)
        flash('Error triggering IOC analysis', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/export/iocs')
def export_iocs():
    """Export IOCs in various formats."""
    try:
        format_type = request.args.get('format', 'json')
        days = int(request.args.get('days', 30))
        ioc_type = request.args.get('type', '')
        
        # Get IOCs from API
        params = {"days": days, "limit": 10000}
        if ioc_type:
            params['type'] = ioc_type
            
        iocs_response = api_request('iocs/export', params=params)
        
        if not iocs_response or 'error' in iocs_response:
            flash('Error exporting IOCs', 'danger')
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        iocs = iocs_response.get('records', [])
        
        # Format based on requested type
        if format_type == 'json':
            return Response(
                json.dumps(iocs, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=iocs.json'}
            )
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if iocs:
                writer = csv.DictWriter(output, fieldnames=iocs[0].keys())
                writer.writeheader()
                writer.writerows(iocs)
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=iocs.csv'}
            )
        elif format_type == 'txt':
            lines = []
            for ioc in iocs:
                lines.append(f"{ioc.get('type', 'unknown')}: {ioc.get('value', '')}")
            
            return Response(
                '\n'.join(lines),
                mimetype='text/plain',
                headers={'Content-Disposition': 'attachment; filename=iocs.txt'}
            )
        else:
            flash('Unsupported export format', 'warning')
            return redirect(url_for('frontend.dashboard', view='iocs'))
            
    except Exception as e:
        logger.error(f"Error exporting IOCs: {str(e)}")
        safe_report_exception(e)
        flash('Error exporting IOCs', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/<content_type>/<path:identifier>')
def dynamic_content_detail(content_type, identifier):
    """Dynamic content detail view."""
    try:
        # Map content type to view
        content_map = {
            'ioc': 'ioc_detail',
            'feed': 'feed_detail',
            'analysis': 'analysis_detail',
            'campaign': 'campaign_detail',
            'threat_actor': 'threat_actor_detail'
        }
        
        if content_type not in content_map:
            abort(404)
        
        # Get data from API
        endpoint = f"{content_type}s/{identifier}"
        data = api_request(endpoint)
        
        if not data or 'error' in data:
            flash(f'Error loading {content_type} details', 'danger')
            return redirect(url_for('frontend.dashboard'))
        
        # Get related items if applicable
        related_items = []
        if content_type == 'ioc':
            related_response = api_request(f"{endpoint}/related")
            if related_response and 'error' not in related_response:
                related_items = related_response.get('items', [])
        
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'data': data,
            'related_items': related_items,
            'view_type': content_type + 's',
            'icon': {
                'ioc': 'fingerprint',
                'feed': 'rss',
                'analysis': 'brain',
                'campaign': 'bullhorn',
                'threat_actor': 'user-secret'
            }.get(content_type, 'info-circle')
        }
        
        return render_template('detail.html', **context)
    
    except Exception as e:
        logger.error(f"Error in dynamic_content_detail: {str(e)}")
        safe_report_exception(e)
        flash(f'Error loading {content_type} details', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/ingest_threat_data', methods=['GET', 'POST'])
def ingest_threat_data():
    """Trigger threat data ingestion."""
    try:
        if request.method == 'POST':
            result = api_request('admin/ingest', method='POST', data={'process_all': True})
            
            if result.get('error'):
                flash(f'Error triggering ingestion: {result["error"]}', 'danger')
            else:
                flash('Threat data ingestion triggered successfully', 'success')
                clear_api_cache()  # Clear cache to show fresh data
            
            return redirect(url_for('frontend.dashboard'))
        
        # For GET, render loading page
        return render_template('base.html', 
                              title="Triggering Data Ingestion", 
                              content="""
                              <div class="text-center py-8">
                                <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-t-2 border-accent mb-4"></div>
                                <h1 class="text-2xl font-bold mb-4">Triggering Threat Data Ingestion</h1>
                                <p class="mb-6">Please wait while we process your request...</p>
                                <form id="ingestForm" method="post">
                                </form>
                                <script>
                                  document.addEventListener('DOMContentLoaded', function() {
                                    document.getElementById('ingestForm').submit();
                                  });
                                </script>
                              </div>
                              """)
    except Exception as e:
        logger.error(f"Error in ingest_threat_data: {str(e)}")
        safe_report_exception(e)
        flash('Error triggering ingestion', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/run_ai_analysis', methods=['GET', 'POST'])
def run_ai_analysis():
    """Trigger AI analysis on threat data."""
    try:
        if request.method == 'POST':
            result = api_request('admin/analyze', method='POST', data={
                'analyze_all': True,
                'force_reanalysis': request.form.get('force', False)
            })
            
            if result.get('error'):
                flash(f'Error triggering AI analysis: {result["error"]}', 'danger')
            else:
                flash('AI analysis triggered successfully. This may take a few minutes.', 'success')
                clear_api_cache('ai')  # Clear AI-related cache
            
            return redirect(url_for('frontend.dashboard', view='ai-analysis'))
        
        # For GET, render loading page
        return render_template('base.html', 
                              title="Triggering AI Analysis", 
                              content="""
                              <div class="text-center py-8">
                                <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-t-2 border-purple-600 mb-4"></div>
                                <h1 class="text-2xl font-bold mb-4">Running AI Analysis</h1>
                                <p class="mb-6">AI is analyzing your threat intelligence data...</p>
                                <form id="analysisForm" method="post">
                                </form>
                                <script>
                                  document.addEventListener('DOMContentLoaded', function() {
                                    document.getElementById('analysisForm').submit();
                                  });
                                </script>
                              </div>
                              """)
    except Exception as e:
        logger.error(f"Error in run_ai_analysis: {str(e)}")
        safe_report_exception(e)
        flash('Error triggering AI analysis', 'danger')
        return redirect(url_for('frontend.dashboard'))

# Template filters and context processors
def format_datetime(value):
    """Format a datetime string for display."""
    if not value:
        return 'N/A'
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        else:
            dt = value
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(value)

# Error handlers
@frontend_app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.info(f"Page not found: {request.path}")
    return render_template('500.html', error_code=404, error_message="Page Not Found"), 404

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {str(e)}")
    safe_report_exception(e)
    return render_template('500.html'), 500

# Context processors
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

# Cache management
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
    cleanup_thread = threading.Thread(target=periodic_cache_cleanup)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    logger.info("Frontend module initialized successfully")
