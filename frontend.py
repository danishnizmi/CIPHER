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
from flask import flash, abort, g, current_app, send_file, Response

# Import config module for centralized configuration
import config
from config import Config

# Environment settings with defaults
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

# Create Blueprint for the frontend module
frontend_app = Blueprint('frontend', __name__, template_folder='templates', static_folder='static')

# ====== Helper Functions ======

def safe_report_exception(e=None):
    """Safely report exception using config module."""
    try:
        config.report_error(e or Exception("Frontend error"))
    except Exception as err:
        logger.warning(f"Failed to report exception: {err}")

def cache_key(func_name: str, **params) -> str:
    """Generate cache key excluding sensitive parameters."""
    param_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()) 
                        if k not in ['api_key', 'token', 'password'])
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
    """Get API key from config with simplified logic."""
    # 1. Check environment variable
    api_key = os.environ.get('API_KEY')
    if api_key and api_key != 'default-api-key':
        logger.debug(f"Using API key from environment: {api_key[:4]}...")
        return api_key
    
    # 2. Check Config class
    if hasattr(Config, 'API_KEY') and Config.API_KEY and Config.API_KEY != 'default-api-key':
        logger.debug(f"Using API key from Config: {Config.API_KEY[:4]}...")
        return Config.API_KEY
    
    # 3. Return default
    default_key = 'default-api-key'
    logger.debug(f"Using default API key: {default_key}")
    return default_key

@api_cache(timeout=CACHE_TIMEOUT)
def api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make internal API request with caching and optimized error handling."""
    try:
        import requests
        
        # Construct URL
        base_url = request.url_root.rstrip('/')
        url = f"{base_url}/api/{endpoint.lstrip('/')}"
        
        # Add API key 
        headers = {"Content-Type": "application/json"}
        api_key = get_api_key()
        
        logger.debug(f"API request to {endpoint} using API key: {api_key[:4]}...")
        
        if api_key and api_key != 'default-api-key':
            headers["X-API-Key"] = api_key
        
        # Make request with optimized retries
        max_retries = 3
        start_time = time.time()
        response = None
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                
                # Break on success or specific failure
                if response.status_code < 500:
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
        # Get view parameters
        current_view = view or request.args.get('view', 'dashboard')
        days = int(request.args.get('days', '30'))
        
        # Initialize context with all required default values
        context = {
            'current_view': current_view,
            'days': days,
            'threat_score': 50,  # Default threat score
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
            'threat_summary': {'overall_score': 50},  # Default threat summary
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
        
        # Load statistics with error handling
        stats_response = api_request('stats', params={"days": days})
        if not stats_response or 'error' in stats_response:
            logger.warning(f"Failed to load stats: {stats_response}")
            # Leave default stats in place
        else:
            # Update stats in context
            context['stats'] = {
                'feeds': stats_response.get('feeds', {'total_sources': 0}),
                'iocs': stats_response.get('iocs', {'total': 0, 'types': []}),
                'analyses': stats_response.get('analyses', {'total_analyses': 0}),
                'timestamp': stats_response.get('timestamp', datetime.utcnow().isoformat())
            }
            
            # Calculate trends safely
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
            iocs_response = api_request('iocs', params={"days": days})
            if not iocs_response or 'error' in iocs_response:
                context['ioc_items'] = []
                if iocs_response and 'error' in iocs_response:
                    flash(f"Error loading IOCs: {iocs_response['error']}", 'warning')
            else:
                context['ioc_items'] = iocs_response.get('records', [])
            
        elif current_view == 'ai-analysis':
            # Load AI analysis data
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
            # Dashboard view - ensure all required data is present
            # Date range for activity chart
            today = datetime.now().date()
            date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
            context['activity_dates'] = date_range
            
            # Activity data
            if stats_response and 'visualization_data' in stats_response and 'daily_counts' in stats_response['visualization_data']:
                counts = [0] * len(date_range)
                date_to_index = {date: idx for idx, date in enumerate(date_range)}
                
                for entry in stats_response['visualization_data']['daily_counts']:
                    if isinstance(entry, dict) and 'date' in entry and entry.get('date') in date_to_index:
                        counts[date_to_index[entry['date']]] = entry.get('count', 0)
                
                context['activity_counts'] = counts
            else:
                # Default activity data
                context['activity_counts'] = [20 + i * 2 for i in range(days)]
            
            # Load additional dashboard data
            iocs_response = api_request('iocs', params={"days": days, "limit": 10})
            if iocs_response and 'error' not in iocs_response:
                context['top_iocs'] = iocs_response.get('records', [])
            
            threat_summary = api_request('threat_summary', params={"days": days})
            if threat_summary and 'error' not in threat_summary:
                context['threat_summary'] = threat_summary
                context['threat_score'] = threat_summary.get('overall_score', 50)
            
            # AI summary for dashboard
            ai_summary = api_request('ai/summary')
            if ai_summary and 'error' not in ai_summary:
                context['ai_summary'] = ai_summary
            
            # Geographic statistics
            geo_stats = api_request('iocs/geo', params={"days": days})
            if geo_stats and 'error' not in geo_stats:
                context['geo_stats'] = geo_stats.get('countries', [])
        
        return render_template('dashboard.html', **context, now=datetime.now())
    
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        safe_report_exception(e)
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('frontend.index'))

@frontend_app.route('/detail/<content_type>/<path:identifier>')
def dynamic_content_detail(content_type, identifier):
    """Generic detail page for different content types."""
    try:
        # Prepare context
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'title': f"{content_type.title()} Detail"
        }
        
        # Map content types to API endpoints
        api_endpoints = {
            'ioc': f'iocs/{identifier}',
            'feed': f'feeds/{identifier}',
            'analysis': f'ai/analyses/{identifier}'
        }
        
        endpoint = api_endpoints.get(content_type)
        if not endpoint:
            flash('Invalid content type', 'danger')
            return redirect(url_for('frontend.dashboard'))
        
        # Get detailed data
        data = api_request(endpoint)
        if not data or data.get('error'):
            flash(f'Error loading {content_type}: {data.get("error", "Unknown error")}', 'danger')
            return redirect(url_for('frontend.dashboard'))
        
        context['data'] = data
        
        # Get related items if applicable
        if content_type == 'ioc':
            related = api_request(f'iocs/{identifier}/related')
            if related and 'error' not in related:
                context['related_items'] = related.get('items', [])
            else:
                context['related_items'] = []
            context['view_type'] = 'iocs'
            context['icon'] = 'fingerprint'
        elif content_type == 'feed':
            context['view_type'] = 'feeds'
            context['icon'] = 'rss'
        elif content_type == 'analysis':
            context['view_type'] = 'ai-analysis'
            context['icon'] = 'brain'
        
        return render_template('detail.html', **context, now=datetime.now())
    
    except Exception as e:
        logger.error(f"Error loading detail page: {str(e)}")
        safe_report_exception(e)
        flash(f'Error loading {content_type} detail', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/ingest_threat_data', methods=['GET', 'POST'])
def ingest_threat_data():
    """Trigger threat data ingestion."""
    try:
        if request.method == 'POST':
            # Trigger ingestion
            result = api_request('admin/ingest', method='POST', data={'process_all': True})
            
            if result.get('error'):
                flash(f'Error triggering ingestion: {result["error"]}', 'danger')
            else:
                flash('Threat data ingestion triggered successfully', 'success')
                clear_api_cache()  # Clear cache to show fresh data
            
            return redirect(url_for('frontend.dashboard'))
        
        # For GET, render loading page with auto-submit form
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
            # Trigger AI analysis
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

@frontend_app.route('/analyze_ioc/<ioc_id>')
def analyze_ioc(ioc_id):
    """Run AI analysis on a specific IOC."""
    try:
        # Trigger analysis for specific IOC
        result = api_request('admin/analyze', method='POST', data={
            'indicator_ids': [ioc_id],
            'force_reanalysis': True
        })
        
        if result.get('error'):
            flash(f'Error analyzing IOC: {result["error"]}', 'danger')
        else:
            flash('IOC analysis started. Results will be available shortly.', 'success')
        
        return redirect(url_for('frontend.dynamic_content_detail', content_type='ioc', identifier=ioc_id))
    
    except Exception as e:
        logger.error(f"Error analyzing IOC: {str(e)}")
        safe_report_exception(e)
        flash('Error analyzing IOC', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/export_iocs')
def export_iocs():
    """Export IOCs in various formats."""
    try:
        # Get parameters
        format_type = request.args.get('format', 'json')
        days = int(request.args.get('days', 30))
        ioc_type = request.args.get('type', '')
        
        # Get IOCs from API
        params = {
            'days': days,
            'type': ioc_type,
            'limit': 10000  # Maximum export size
        }
        
        iocs_response = api_request('iocs/export', params=params)
        
        if iocs_response.get('error'):
            flash(f'Error exporting IOCs: {iocs_response["error"]}', 'danger')
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        # Prepare data for export
        iocs = iocs_response.get('records', [])
        
        # Generate file based on format
        if format_type == 'json':
            data = json.dumps(iocs, indent=2)
            mimetype = 'application/json'
            filename = f'iocs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        elif format_type == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            if iocs:
                fieldnames = iocs[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(iocs)
            
            data = output.getvalue()
            mimetype = 'text/csv'
            filename = f'iocs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        elif format_type == 'txt':
            # Simple text format - one IOC per line
            lines = []
            for ioc in iocs:
                lines.append(f"{ioc.get('type', 'unknown')}:{ioc.get('value', '')}")
            
            data = '\n'.join(lines)
            mimetype = 'text/plain'
            filename = f'iocs_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        
        elif format_type == 'stix':
            # STIX 2.1 format
            stix_bundle = {
                "type": "bundle",
                "id": f"bundle--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "objects": []
            }
            
            for ioc in iocs:
                stix_obj = {
                    "type": "indicator",
                    "id": f"indicator--{ioc.get('id', '')}",
                    "created": ioc.get('created_at', datetime.now().isoformat()),
                    "modified": ioc.get('updated_at', datetime.now().isoformat()),
                    "pattern": f"[{ioc.get('type', 'file')}:value = '{ioc.get('value', '')}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.get('first_seen', ioc.get('created_at', datetime.now().isoformat()))
                }
                stix_bundle["objects"].append(stix_obj)
            
            data = json.dumps(stix_bundle, indent=2)
            mimetype = 'application/json'
            filename = f'iocs_stix_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        else:
            flash('Invalid export format', 'danger')
            return redirect(url_for('frontend.dashboard', view='iocs'))
        
        # Return file download
        return Response(
            data,
            mimetype=mimetype,
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Length': len(data)
            }
        )
    
    except Exception as e:
        logger.error(f"Error exporting IOCs: {str(e)}")
        safe_report_exception(e)
        flash('Error exporting IOCs', 'danger')
        return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/export_analysis')
def export_analysis():
    """Export AI analysis reports."""
    try:
        # Get parameters
        report_type = request.args.get('report_type', 'summary')
        format_type = request.args.get('format', 'pdf')
        period = request.args.get('period', 'monthly')
        
        # Request analysis report from API
        params = {
            'report_type': report_type,
            'period': period
        }
        
        report_response = api_request('ai/generate_report', method='POST', data=params)
        
        if report_response.get('error'):
            flash(f'Error generating report: {report_response["error"]}', 'danger')
            return redirect(url_for('frontend.dashboard', view='ai-analysis'))
        
        # Get report content
        report_data = report_response.get('report', {})
        
        # Generate file based on format
        if format_type == 'pdf':
            # PDF generation would require additional libraries like ReportLab
            flash('PDF export is not yet implemented', 'warning')
            return redirect(url_for('frontend.dashboard', view='ai-analysis'))
        
        elif format_type == 'html':
            # Generate HTML report
            html_content = render_template('report.html', report=report_data, now=datetime.now())
            filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
            
            return Response(
                html_content,
                mimetype='text/html',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}',
                    'Content-Length': len(html_content)
                }
            )
        
        elif format_type == 'json':
            data = json.dumps(report_data, indent=2)
            filename = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            
            return Response(
                data,
                mimetype='application/json',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}',
                    'Content-Length': len(data)
                }
            )
        
        else:
            flash('Invalid export format', 'danger')
            return redirect(url_for('frontend.dashboard', view='ai-analysis'))
    
    except Exception as e:
        logger.error(f"Error exporting analysis: {str(e)}")
        safe_report_exception(e)
        flash('Error exporting analysis report', 'danger')
        return redirect(url_for('frontend.dashboard', view='ai-analysis'))

@frontend_app.route('/search')
def search():
    """Search across all threat intelligence data."""
    try:
        query = request.args.get('q', '')
        if not query:
            return redirect(url_for('frontend.dashboard'))
        
        # Search via API
        search_results = api_request('search', params={'query': query})
        
        if search_results.get('error'):
            flash(f'Search error: {search_results["error"]}', 'danger')
            return redirect(url_for('frontend.dashboard'))
        
        context = {
            'page_type': 'search',
            'query': query,
            'results': search_results.get('results', [])
        }
        
        return render_template('content.html', **context, now=datetime.now())
    
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        safe_report_exception(e)
        flash('Error performing search', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/export')
def export_page():
    """Export data page."""
    return render_template('content.html', page_type='export', now=datetime.now())

# Shortcut routes
@frontend_app.route('/feeds')
def feeds():
    """Redirect to dashboard feeds view."""
    return redirect(url_for('frontend.dashboard', view='feeds'))

@frontend_app.route('/iocs')
def iocs():
    """Redirect to dashboard IOCs view."""
    return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/ai-analysis')
def ai_analysis():
    """Redirect to dashboard AI analysis view."""
    return redirect(url_for('frontend.dashboard', view='ai-analysis'))

# ====== Template Filters and Context ======

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

# ====== Error Handlers ======

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

@frontend_app.context_processor
def utility_processor():
    """Add utility functions to template context."""
    def format_number(value):
        """Format numbers with commas."""
        try:
            return "{:,}".format(int(value)) if value else "0"
        except:
            return str(value)
    
    def get_severity_class(severity):
        """Get CSS class for severity levels."""
        severity_map = {
            'critical': 'bg-red-600 text-white',
            'high': 'bg-orange-500 text-white',
            'medium': 'bg-amber-400 text-gray-800',
            'low': 'bg-teal-500 text-white'
        }
        return severity_map.get(str(severity).lower(), 'bg-gray-300 text-gray-800')
    
    def get_confidence_width(value):
        """Get width percentage for confidence bar."""
        try:
            return min(100, max(0, int(value))) if isinstance(value, (int, float)) else 40
        except:
            return 40
    
    return {
        'format_number': format_number,
        'get_severity_class': get_severity_class,
        'get_confidence_width': get_confidence_width,
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
            
            # Sleep for 10 minutes
            time.sleep(600)
        except Exception as e:
            logger.error(f"Error in cache cleanup: {str(e)}")
            time.sleep(60)

# Start cache cleanup thread (only when module is imported, not running main)
if __name__ != "__main__":
    cleanup_thread = threading.Thread(target=periodic_cache_cleanup)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    logger.info("Frontend module initialized successfully")

# Module testing functionality
if __name__ == "__main__":
    logger.info("Frontend module running in test mode")
    # Add any test functionality here
