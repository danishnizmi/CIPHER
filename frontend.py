"""
Production-ready frontend module for threat intelligence platform.
Handles web interface, dashboard views, and real-time data display.
Public-facing interface only - no admin controls.
"""

import os
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import re  # For simplified domain validation without tldextract

from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask import flash, abort, g, current_app, Response, make_response
import requests

# Import config module for centralized configuration
from config import Config, ServiceStatus, Utils, CacheManager, shared_cache, report_error

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.3")
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')

# Configure logging
logger = logging.getLogger('frontend')

# Create Blueprint
frontend_app = Blueprint('frontend', __name__, template_folder='templates', static_folder='static')

# Domain extraction without tldextract
def extract_domain_from_url(url):
    """Extract domain from URL without tldextract dependency."""
    if not url:
        return None
    
    # Strip protocol
    domain = url.lower()
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    
    # Strip path
    if '/' in domain:
        domain = domain.split('/', 1)[0]
    
    # Strip port
    if ':' in domain:
        domain = domain.split(':', 1)[0]
    
    return domain

# ====== Event Handlers ======

def invalidate_cache_on_ingestion(data):
    """Invalidate cache when new data is ingested."""
    try:
        logger.info("Invalidating cache due to data ingestion")
        shared_cache.clear('feeds')
        shared_cache.clear('iocs')
        shared_cache.clear('stats')
        shared_cache.clear('threat_summary')
    except Exception as e:
        logger.error(f"Error invalidating cache: {e}")

def invalidate_cache_on_analysis(data):
    """Invalidate cache when analysis completes."""
    try:
        logger.info("Invalidating cache due to analysis completion")
        shared_cache.clear('ai')
        shared_cache.clear('threat_summary')
        shared_cache.clear('analyses')
    except Exception as e:
        logger.error(f"Error invalidating cache: {e}")

# Register event handlers when blueprint is recorded
@frontend_app.record
def register_event_handlers(state):
    """Register event handlers when blueprint is registered."""
    try:
        app = state.app
        if hasattr(app, 'event_bus'):
            logger.info("Registering frontend event handlers")
            app.event_bus.subscribe('data_ingested', invalidate_cache_on_ingestion)
            app.event_bus.subscribe('analysis_completed', invalidate_cache_on_analysis)
            app.event_bus.subscribe('ingestion_completed', invalidate_cache_on_ingestion)
            
            # Update service status
            service_manager = Config.get_service_manager()
            service_manager.update_status('frontend', ServiceStatus.READY)
    except Exception as e:
        logger.error(f"Error registering event handlers: {e}")

# ====== API Interaction Functions ======

def get_api_key() -> str:
    """Get API key from config."""
    try:
        if hasattr(Config, 'API_KEY') and Config.API_KEY:
            api_key = Config.API_KEY.strip()
            if api_key != 'default-api-key':
                return api_key
    except Exception as e:
        logger.error(f"Error getting API key: {e}")
    
    # Use default key for public view
    return 'default-api-key'

def api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make internal API request with proper context handling."""
    
    # Check service status first
    try:
        service_manager = Config.get_service_manager()
        status = service_manager.get_status()
        
        # Allow requests during initialization
        if status['overall'] == ServiceStatus.ERROR.value:
            return {"error": "Services unavailable", "status": "error"}
    except Exception as e:
        logger.error(f"Error checking service status: {e}")
        return {"error": "Error checking service status", "status": "error"}
    
    # Create cache key for caching
    try:
        cache_key = f"api:{endpoint}:{method}:{json.dumps(params or {})}:{json.dumps(data or {})}"
        cached_result = shared_cache.get(cache_key)
        if cached_result:
            return cached_result
    except Exception as e:
        logger.error(f"Error with cache: {e}")
        # Continue with the request even if caching fails
    
    try:
        # For internal requests, we'll use the HTTP approach for consistency
        # Get the current app's URL for internal requests
        try:
            if request:
                base_url = request.url_root.rstrip('/')
            else:
                # Fallback to constructing URL from environment
                scheme = 'https' if os.environ.get('HTTPS', '').lower() == 'true' else 'http'
                host = os.environ.get('HOST', '0.0.0.0')
                port = os.environ.get('PORT', '8080')
                
                # For Cloud Run, use the service URL if available
                cloud_run_url = os.environ.get('CLOUD_RUN_URL')
                if cloud_run_url:
                    base_url = cloud_run_url.rstrip('/')
                else:
                    base_url = f"{scheme}://{host}:{port}"
        except RuntimeError:
            # Outside of request context
            base_url = f"http://localhost:{os.environ.get('PORT', '8080')}"
        
        # Construct URL
        url = f"{base_url}/api/{endpoint.lstrip('/')}"
        
        # Prepare headers
        headers = {"Content-Type": "application/json"}
        api_key = get_api_key()
        headers["X-API-Key"] = api_key
        
        logger.debug(f"Making API request to {endpoint}")
        
        # Make request with retries but shorter timeout
        max_retries = 2
        start_time = time.time()
        response = None
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, params=params, timeout=5)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=5)
                
                # Break on success or non-retriable failure
                if response.status_code < 500 or response.status_code == 401:
                    break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning(f"Request attempt {attempt + 1} failed: {str(e)}")
                
            # Shorter backoff for internal requests
            if attempt < max_retries - 1:
                time.sleep(0.2 * (2 ** attempt))
        
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
            result = response.json() if response.text else {}
            # Cache successful responses
            try:
                if 'error' not in result:
                    shared_cache.set(cache_key, result, ttl=300)
            except Exception as cache_e:
                logger.warning(f"Failed to cache response: {cache_e}")
            return result
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from {endpoint}")
            return {"error": "Invalid JSON response"}
    
    except Exception as e:
        logger.error(f"API request error ({endpoint}): {str(e)}")
        report_error(e)
        return {"error": f"API error: {str(e)}"}

# ====== Data Processing Functions ======

def prepare_dashboard_context(current_view: str, days: int) -> Dict[str, Any]:
    """Prepare common dashboard context data."""
    try:
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
    except Exception as e:
        logger.error(f"Error preparing dashboard context: {e}")
        # Return minimal context to avoid template errors
        return {
            'current_view': current_view,
            'days': days,
            'service_status': {'overall': 'error', 'services': {}},
            'stats': {
                'feeds': {'total_sources': 0},
                'iocs': {'total': 0, 'types': []},
                'analyses': {'total_analyses': 0},
                'timestamp': datetime.utcnow().isoformat()
            },
            'page_title': page_metadata.get(current_view, page_metadata['dashboard'])['title'],
            'page_subtitle': page_metadata.get(current_view, page_metadata['dashboard'])['subtitle'],
            'page_icon': page_metadata.get(current_view, page_metadata['dashboard'])['icon']
        }

def load_dashboard_stats(context: Dict[str, Any], days: int):
    """Load statistics for dashboard."""
    try:
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
    except Exception as e:
        logger.error(f"Error loading dashboard stats: {e}")

def load_view_specific_data(context: Dict[str, Any], current_view: str, days: int):
    """Load view-specific data."""
    try:
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
                # Transform the response for the template
                if isinstance(ai_response, dict):
                    context['ai_analyses'] = ai_response
                    context['overall_threat_level'] = ai_response.get('overall_threat_level', 'Medium')
                    context['total_feeds_analyzed'] = ai_response.get('total_feeds_analyzed', 0)
                    context['batch_analyses'] = ai_response.get('batch_analyses', [])
                    context['threat_distribution'] = ai_response.get('threat_level_distribution', [])
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
    except Exception as e:
        logger.error(f"Error loading view-specific data: {e}")

# ====== Route Handlers ======

@frontend_app.route('/')
def index():
    """Root redirects to dashboard."""
    try:
        return redirect(url_for('frontend.dashboard'))
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return render_template('error.html',
                             error_code=500,
                             error_message="Internal Server Error",
                             error_description="An error occurred while loading the dashboard.",
                             error_icon="exclamation-triangle"), 500

# Handle direct URL patterns like /dashboard/ai-analysis
@frontend_app.route('/dashboard/ai-analysis')
def ai_analysis_direct_route():
    """Handle direct access to AI analysis dashboard"""
    try:
        days = request.args.get('days', '30')
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 30
        return dashboard('ai-analysis', days=days)
    except Exception as e:
        logger.error(f"Error in AI analysis direct route: {e}")
        flash('An error occurred while loading the AI analysis dashboard', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/dashboard/feeds')
def feeds_direct_route():
    """Handle direct access to feeds dashboard"""
    try:
        days = request.args.get('days', '30')
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 30
        return dashboard('feeds', days=days)
    except Exception as e:
        logger.error(f"Error in feeds direct route: {e}")
        flash('An error occurred while loading the feeds dashboard', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/dashboard/iocs')
def iocs_direct_route():
    """Handle direct access to IOCs dashboard"""
    try:
        days = request.args.get('days', '30')
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 30
        return dashboard('iocs', days=days)
    except Exception as e:
        logger.error(f"Error in IOCs direct route: {e}")
        flash('An error occurred while loading the IOCs dashboard', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/dashboard')
@frontend_app.route('/dashboard/<view>')
def dashboard(view=None, days=None):
    """Dashboard view with dynamic content loading."""
    try:
        # Get view parameters
        current_view = view or request.args.get('view', 'dashboard')
        days_param = days or request.args.get('days', '30')
        
        # Ensure days is an integer
        try:
            days = int(days_param)
        except (ValueError, TypeError):
            days = 30
        
        # Prepare base context
        context = prepare_dashboard_context(current_view, days)
        
        # Load statistics
        load_dashboard_stats(context, days)
        
        # Load view-specific data
        load_view_specific_data(context, current_view, days)
        
        # Render the template
        response = make_response(render_template('dashboard.html', **context, now=datetime.now()))
        
        # Add cache headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        report_error(e)
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('frontend.index'))

@frontend_app.route('/export/iocs')
def export_iocs():
    """Export IOCs in various formats."""
    try:
        format_type = request.args.get('format', 'json').lower()
        days = int(request.args.get('days', '30'))
        ioc_type = request.args.get('type', '')
        
        # Get IOCs data
        params = {'days': days, 'limit': 10000}
        if ioc_type:
            params['type'] = ioc_type
        
        iocs_response = api_request('iocs', params=params)
        
        if not iocs_response or 'error' in iocs_response:
            flash('Error retrieving IOCs for export', 'danger')
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        records = iocs_response.get('records', [])
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"threat_iocs_{timestamp}.{format_type}"
        
        if format_type == 'json':
            response = make_response(json.dumps(records, indent=2))
            response.headers['Content-Type'] = 'application/json'
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if records:
                writer = csv.DictWriter(output, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
        elif format_type == 'txt':
            # Simple text format
            lines = []
            for record in records:
                line = f"{record.get('type', 'unknown')}: {record.get('value', '')}"
                if record.get('source'):
                    line += f" (source: {record['source']})"
                lines.append(line)
            
            response = make_response('\n'.join(lines))
            response.headers['Content-Type'] = 'text/plain'
        else:
            flash('Invalid export format', 'danger')
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        flash('Error during export', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

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
            # Get analysis data by ID - for now just return to AI analysis view
            flash('Analysis details coming soon', 'info')
            return redirect(url_for('frontend.dashboard', view='ai-analysis'))
        
        return render_template('detail.html', **context)
        
    except Exception as e:
        logger.error(f"Error in dynamic_content_detail: {str(e)}", exc_info=True)
        flash('Error loading content details', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/analyze/ioc/<ioc_id>', methods=['GET', 'POST'])
def analyze_ioc(ioc_id):
    """Trigger AI analysis for a specific IOC."""
    try:
        # This is just a stub to prevent errors if referred to in templates
        flash('AI analysis functionality coming soon', 'info')
        return redirect(url_for('frontend.dashboard', view='iocs'))
    except Exception as e:
        logger.error(f"Error in analyze_ioc: {e}")
        flash('Error analyzing IOC', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

# ====== Error Handlers ======

@frontend_app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    try:
        logger.info(f"Page not found: {request.path}")
        return render_template('error.html', 
                            error_code=404, 
                            error_message="Page Not Found",
                            error_description="The page you're looking for doesn't exist or has been moved.",
                            error_icon="search-location"), 404
    except Exception as render_error:
        logger.error(f"Error rendering 404 template: {render_error}")
        return jsonify({
            "error": "Page not found",
            "status": 404,
            "message": "The page you're looking for doesn't exist or has been moved."
        }), 404

@frontend_app.errorhandler(403)  
def forbidden(e):
    """Handle 403 errors."""
    try:
        logger.warning(f"Forbidden access: {request.path}")
        return render_template('error.html',
                            error_code=403,
                            error_message="Access Forbidden", 
                            error_description="You don't have permission to access this resource.",
                            error_icon="ban"), 403
    except Exception as render_error:
        logger.error(f"Error rendering 403 template: {render_error}")
        return jsonify({
            "error": "Access forbidden",
            "status": 403,
            "message": "You don't have permission to access this resource."
        }), 403

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    try:
        logger.error(f"Server error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        report_error(e)
        return render_template('error.html',
                            error_code=500,
                            error_message="Internal Server Error",
                            error_description="An unexpected error occurred. Please try again later.",
                            error_icon="exclamation-triangle"), 500
    except Exception as render_error:
        logger.error(f"Error rendering 500 template: {render_error}")
        return jsonify({
            "error": "Internal server error",
            "status": 500,
            "message": "An unexpected error occurred. Please try again later."
        }), 500

# Fallback handler for any unhandled exceptions
@frontend_app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())
    report_error(e)
    return render_template('error.html',
                         error_code=500,
                         error_message="Unexpected Error",
                         error_description="An unexpected error occurred. Please try again later.",
                         error_icon="exclamation-triangle"), 500

# ====== Context Processors ======

@frontend_app.context_processor
def inject_global_data():
    """Inject global data into templates."""
    try:
        return {
            'now': datetime.now(),
            'environment': ENVIRONMENT,
            'version': VERSION,
            'project_id': getattr(Config, 'GCP_PROJECT', None),
            'debug_mode': DEBUG_MODE,
        }
    except Exception as e:
        logger.error(f"Error injecting global data: {e}")
        return {
            'now': datetime.now(),
            'environment': 'production',
            'version': '1.0.3',
            'project_id': None,
            'debug_mode': False,
        }

# Initialize module
logger.info("Frontend module initialized successfully")
