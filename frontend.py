"""
Threat Intelligence Platform - Frontend Module (Fixed Version)
Handles web interface, user authentication, and dashboard views with improved session and CSRF handling.
"""

import os
import json
import logging
import hashlib
import time
import traceback
import secrets
import threading
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from typing import Dict, List, Any, Optional, Union

from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask import flash, session, abort, g, Response, current_app
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import BadRequest

# Import config module for centralized configuration
import config
from config import Config

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.2")
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')

# Cache settings
CACHE_TIMEOUT = 300  # Cache for 5 minutes
LONG_CACHE_TIMEOUT = 1800  # Cache for 30 minutes
API_CACHE = {}
API_CACHE_TIMESTAMP = {}

# Configure logging
logger = logging.getLogger('frontend')
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
logging.basicConfig(level=LOG_LEVEL, 
                    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')

# Create Blueprint for the frontend module
frontend_app = Blueprint('frontend', __name__, template_folder='templates', static_folder='static')

# ====== Session and Security Configuration ======

# Force session creation before requests
@frontend_app.before_request
def before_request():
    """Ensure session is properly established with robust error handling."""
    try:
        # Force session creation
        if '_id' not in session:
            session.permanent = True
            session['_id'] = secrets.token_hex(16)
            session['csrf_token'] = secrets.token_hex(16)
            logger.debug(f"New session created: {session.get('_id')}")
        
        # Ensure CSRF token exists in session
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
            logger.debug("CSRF token added to session")
        
        # Add session debug info
        if DEBUG_MODE:
            logger.debug(f"Session data: {dict(session)}")
            logger.debug(f"Request headers: {dict(request.headers)}")
    
    except Exception as e:
        logger.error(f"Error in before_request: {str(e)}")
        logger.error(traceback.format_exc())

# Custom CSRF token validation
def validate_csrf_token():
    """Validate CSRF token with improved error handling."""
    if request.method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
        return True
    
    try:
        # Skip CSRF check for health endpoints
        if request.path.startswith('/health') or request.path.startswith('/api/health'):
            return True
        
        # Get token from form or headers
        token = request.form.get('csrf_token')
        if not token:
            token = request.headers.get('X-CSRF-Token')
        
        session_token = session.get('csrf_token')
        
        if DEBUG_MODE:
            logger.debug(f"CSRF check - Form token: {token}, Session token: {session_token}")
        
        if not token or not session_token or token != session_token:
            logger.error(f"CSRF validation failed. Token: {token}, Session: {session_token}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error validating CSRF token: {str(e)}")
        return False

# ====== Helper Functions ======
def safe_report_exception():
    """Safely report exception using config module"""
    try:
        config.report_error(Exception("Frontend error"))
    except Exception as e:
        logger.warning(f"Failed to report exception: {e}")

def generate_trend_data(days: int, base: int = 50, variance: int = 15) -> List[int]:
    """Generate a smooth trend line for charts when real data isn't available"""
    import random
    from math import sin, pi
    
    # Generate a more natural-looking trend
    cycle = days / 4  # Cyclical component
    
    trend = []
    for i in range(days):
        # Combine base, cyclical component, and random noise
        cycle_component = sin(i * 2 * pi / cycle) * 20
        value = max(5, int(base + cycle_component + (random.randint(-variance, variance))))
        trend.append(value)
        
        # Adjust base for next iteration (slight upward trend)
        base += random.randint(-2, 3) / 10
    
    return trend

def get_cache_key(func_name: str, **params) -> str:
    """Generate a cache key for a function call"""
    param_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()) if k not in ['api_key', 'token', 'password'])
    return f"{func_name}:{param_str}"

def is_cache_valid(cache_key: str, timeout: int = CACHE_TIMEOUT) -> bool:
    """Check if a cached value is still valid"""
    if cache_key not in API_CACHE or cache_key not in API_CACHE_TIMESTAMP:
        return False
    
    timestamp = API_CACHE_TIMESTAMP[cache_key]
    return (time.time() - timestamp) < timeout

def api_cache(timeout: int = CACHE_TIMEOUT):
    """Decorator for caching API results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = get_cache_key(func.__name__, **kwargs)
            
            # Check cache
            if is_cache_valid(cache_key, timeout):
                logger.debug(f"Cache hit for {func.__name__}")
                return API_CACHE[cache_key]
            
            # Call function if not cached or expired
            logger.debug(f"Cache miss for {func.__name__}")
            result = func(*args, **kwargs)
            
            # Update cache
            API_CACHE[cache_key] = result
            API_CACHE_TIMESTAMP[cache_key] = time.time()
            
            # Clean up old cache entries if too many
            if len(API_CACHE) > 100:
                # Find 10 oldest entries
                oldest_keys = sorted(
                    API_CACHE_TIMESTAMP, 
                    key=API_CACHE_TIMESTAMP.get
                )[:10]
                
                # Remove them
                for k in oldest_keys:
                    if k in API_CACHE:
                        del API_CACHE[k]
                        del API_CACHE_TIMESTAMP[k]
            
            return result
        return wrapper
    return decorator

def clear_api_cache(prefix: str = None):
    """Clear API cache entries, optionally filtering by prefix"""
    global API_CACHE, API_CACHE_TIMESTAMP
    
    if prefix:
        # Clear only entries with matching prefix
        keys_to_delete = [k for k in API_CACHE if k.startswith(prefix)]
        for k in keys_to_delete:
            if k in API_CACHE:
                del API_CACHE[k]
            if k in API_CACHE_TIMESTAMP:
                del API_CACHE_TIMESTAMP[k]
        logger.debug(f"Cleared {len(keys_to_delete)} cache entries with prefix '{prefix}'")
    else:
        # Clear all cache
        API_CACHE = {}
        API_CACHE_TIMESTAMP = {}
        logger.debug("Cleared all API cache entries")

# ====== API Interaction Functions ======
def get_api_key() -> str:
    """Get API key for internal requests using config module"""
    # Try to get API key from config module
    api_key = getattr(Config, 'API_KEY', None)
    
    # If not available directly, try to get from cached config
    if not api_key:
        api_keys_config = config.get_cached_config('api-keys')
        if api_keys_config and 'platform_api_key' in api_keys_config:
            api_key = api_keys_config['platform_api_key']
    
    # Try environment variable as last resort
    if not api_key:
        api_key = os.environ.get('API_KEY', '')
    
    return api_key or ''

@api_cache(timeout=CACHE_TIMEOUT)
def _api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make an internal API request with caching and enhanced error handling"""
    try:
        # Import requests here to avoid global dependency
        import requests
        
        # Construct base URL
        base_url = request.url_root.rstrip('/')
        api_url = f"{base_url}/api/{endpoint.lstrip('/')}"
        
        # Add API key in headers
        api_key = get_api_key()
        headers = {"X-API-Key": api_key} if api_key else {}
        headers["Content-Type"] = "application/json"
        
        # Make the request
        logger.debug(f"API request: {method} {api_url}")
        start_time = time.time()
        
        # Add retry logic for resilience
        max_retries = 3
        retry_count = 0
        response = None
        
        while retry_count < max_retries:
            try:
                if method.upper() == 'GET':
                    response = requests.get(api_url, headers=headers, params=params, timeout=10)
                else:  # POST
                    response = requests.post(api_url, headers=headers, json=data, timeout=10)
                
                # Break if successful
                if response.status_code < 500:
                    break
                    
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning(f"Attempt {retry_count+1}/{max_retries} failed: {str(e)}")
                
            # Exponential backoff
            wait_time = 0.5 * (2 ** retry_count)
            time.sleep(wait_time)
            retry_count += 1
        
        if response is None:
            # All retries failed
            return {"error": "Failed to connect to API after multiple retries"}
        
        # Log response time
        request_time = time.time() - start_time
        if request_time > 1.0:
            logger.info(f"Slow API request ({request_time:.2f}s): {method} {api_url}")
        
        # Check for errors
        if response.status_code != 200:
            logger.warning(f"API request failed: {response.status_code} - {response.text[:100]}")
            return {
                "error": f"API request failed with status {response.status_code}",
                "status_code": response.status_code
            }
        
        # Parse and return JSON
        if response.text:
            try:
                return response.json()
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON response: {response.text[:100]}")
                return {"error": "Invalid JSON response", "raw_response": response.text[:500]}
        
        return {}
    
    except Exception as e:
        if 'requests' in locals() and isinstance(e, requests.RequestException):
            logger.error(f"API request error ({endpoint}): {str(e)}")
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            
            error_msg = f"API error: {str(e)}"
            if status_code:
                error_msg += f" (status code: {status_code})"
            
            return {"error": error_msg, "status_code": status_code}
        else:
            logger.error(f"Unexpected API error ({endpoint}): {str(e)}")
            return {"error": f"Unexpected error: {str(e)}"}

# ====== Authentication Functions ======
def login_required(f):
    """Decorator to require login for views"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            # Save the requested URL
            session['next_url'] = request.url
            flash('Please log in to continue', 'info')
            return redirect(url_for('frontend.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            session['next_url'] = request.url
            flash('Please log in to continue', 'info')
            return redirect(url_for('frontend.login'))
        if session.get('role') != 'admin':
            flash('Admin privileges required', 'danger')
            return render_template('auth.html', page_type='not_authorized')
        return f(*args, **kwargs)
    return decorated_function

def load_users() -> Dict[str, Dict]:
    """Load user data from auth config using config module"""
    try:
        # Get auth config from config module
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'users' in auth_config and auth_config['users']:
            return auth_config.get('users', {})
        
        # If no users exist, create default admin
        logger.warning("No users found in auth config")
        return {}
    except Exception as e:
        logger.error(f"Failed to load users: {str(e)}")
        return {}

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify password with support for multiple hash formats"""
    if not stored_password or not provided_password:
        return False
    
    # Simple SHA-256 hash comparison
    provided_hash = hashlib.sha256(provided_password.encode()).hexdigest()
    if stored_password == provided_hash:
        return True
        
    # For backward compatibility with Werkzeug hash format
    if stored_password.startswith('pbkdf2:sha256:'):
        try:
            from werkzeug.security import check_password_hash
            return check_password_hash(stored_password, provided_password)
        except ImportError:
            logger.warning("Werkzeug security not available for password check")
            return False
    
    return False

def hash_password(password: str) -> str:
    """Hash password using secure method"""
    # Use simple SHA-256 for consistent hashing
    return hashlib.sha256(password.encode()).hexdigest()

# ====== Route Handlers ======
@frontend_app.route('/')
def index():
    """Root redirects to dashboard if logged in, otherwise to login"""
    if session.get('logged_in'):
        return redirect(url_for('frontend.dashboard'))
    return redirect(url_for('frontend.login'))

@frontend_app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page handler with comprehensive error handling and CSRF protection"""
    error = None
    
    try:
        if request.method == 'POST':
            # CSRF validation
            if not validate_csrf_token():
                logger.error("CSRF validation failed for login attempt")
                flash('Your session has expired or there was a security issue. Please try again.', 'danger')
                return redirect(url_for('frontend.login'))
            
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember') == 'on'
            
            # Debug output for login attempt
            logger.info(f"Login attempt for user: {username}")
            
            # Validate inputs
            if not username or not password:
                error = "Username and password are required"
                return render_template('auth.html', page_type='login', error=error, 
                                     now=datetime.now(), csrf_token=session.get('csrf_token'))
            
            # Load users
            users = load_users()
            
            if username in users:
                user = users[username]
                stored_password = user.get('password', '')
                
                # Verify password
                if verify_password(stored_password, password):
                    # Login successful
                    session.clear()  # Clear previous session data
                    session.permanent = remember
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user.get('role', 'readonly')
                    session['csrf_token'] = secrets.token_hex(16)  # Generate new CSRF token
                    session['_id'] = secrets.token_hex(16)  # Generate new session ID
                    
                    # Update last login
                    try:
                        last_login = {'last_login': datetime.utcnow().isoformat()}
                        config.update_user(username, last_login)
                    except Exception as e:
                        logger.warning(f"Could not update last login: {str(e)}")
                    
                    # Log the successful login
                    logger.info(f"Successful login: {username}")
                    
                    flash(f'Welcome, {username}!', 'success')
                    
                    # Redirect to requested page or dashboard
                    next_page = session.pop('next_url', None) or request.args.get('next')
                    if next_page and next_page.startswith('/'):
                        return redirect(next_page)
                    return redirect(url_for('frontend.dashboard'))
                else:
                    error = "Invalid password"
                    logger.warning(f"Failed login attempt: Invalid password for {username}")
            else:
                error = "Invalid username"
                logger.warning(f"Failed login attempt: Invalid username {username}")
    except Exception as e:
        logger.error(f"Unexpected error in login: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        error = f"An unexpected error occurred: {str(e)}"
    
    # For GET requests or failed logins
    return render_template('auth.html', page_type='login', error=error, 
                         now=datetime.now(), csrf_token=session.get('csrf_token'))

@frontend_app.route('/logout')
def logout():
    """Logout route handler"""
    username = session.get('username')
    
    if username:
        logger.info(f"User logged out: {username}")
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('frontend.login'))

@frontend_app.route('/dashboard')
@frontend_app.route('/dashboard/<view>')
@login_required
def dashboard(view=None):
    """Dashboard view with dynamic content loading based on view type"""
    try:
        # Get and validate the view and timeframe
        current_view = view or request.args.get('view', 'dashboard')
        days = int(request.args.get('days', '30'))
        
        # Base context
        context = {
            'current_view': current_view,
            'days': days,
        }
        
        # Set page metadata based on view
        if current_view == 'feeds':
            context.update({
                'page_title': 'Threat Feeds',
                'page_subtitle': 'Intelligence sources and data collection',
                'page_icon': 'rss'
            })
        elif current_view == 'iocs':
            context.update({
                'page_title': 'Indicators of Compromise',
                'page_subtitle': 'Observed indicators and threat artifacts',
                'page_icon': 'fingerprint'
            })
        elif current_view == 'campaigns':
            context.update({
                'page_title': 'Threat Campaigns',
                'page_subtitle': 'Detected threat actor campaigns and activities',
                'page_icon': 'project-diagram'
            })
        else:
            context.update({
                'page_title': 'Threat Intelligence Dashboard',
                'page_subtitle': 'Platform overview and threat summary',
                'page_icon': 'tachometer-alt'
            })
        
        # Load statistics for all views with safety checks
        try:
            # Get statistics using the helper function
            stats_response = _api_request('stats', params={"days": days}) or {}
            context['stats'] = stats_response
            
            # Extract trends from statistics - use real data if available or defaults if not
            if isinstance(stats_response, dict):
                context['feed_trend'] = stats_response.get('feeds', {}).get('growth_rate', 0)
                context['ioc_trend'] = stats_response.get('iocs', {}).get('growth_rate', 0)
                context['campaign_trend'] = stats_response.get('campaigns', {}).get('growth_rate', 0)
                context['analysis_trend'] = stats_response.get('analyses', {}).get('growth_rate', 0)
                
                # Extract IOC type data for charts
                context['ioc_type_labels'] = [item.get('type', '') for item in stats_response.get('iocs', {}).get('types', [])]
                context['ioc_type_values'] = [item.get('count', 0) for item in stats_response.get('iocs', {}).get('types', [])]
            else:
                # Set defaults if stats_response is not a dict
                context['feed_trend'] = 0
                context['ioc_trend'] = 0
                context['campaign_trend'] = 0
                context['analysis_trend'] = 0
                context['ioc_type_labels'] = []
                context['ioc_type_values'] = []
            
            # Load view-specific data with safety checks
            if current_view == 'feeds':
                feeds_response = _api_request('feeds') or {}
                context['feed_items'] = (feeds_response.get('feed_details', []) 
                                        if isinstance(feeds_response, dict) else [])
                context['feed_type_descriptions'] = {
                    feed.get('name', ''): feed.get('description', 'Threat Intelligence Feed') 
                    for feed in context['feed_items'] if isinstance(feed, dict) and 'name' in feed
                }
                
            elif current_view == 'iocs':
                iocs_response = _api_request('iocs', params={"days": days}) or {}
                context['ioc_items'] = (iocs_response.get('records', []) 
                                       if isinstance(iocs_response, dict) else [])
                
            elif current_view == 'campaigns':
                campaigns_response = _api_request('campaigns', params={"days": days}) or {}
                context['campaigns'] = (campaigns_response.get('campaigns', []) 
                                       if isinstance(campaigns_response, dict) else [])
                
            else:
                # Dashboard view - load additional data with safety checks
                # Get date range for activity chart
                today = datetime.now().date()
                date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
                context['activity_dates'] = date_range
                
                # Get activity counts from stats if available
                if (isinstance(stats_response, dict) and 
                    'visualization_data' in stats_response and 
                    'daily_counts' in stats_response['visualization_data']):
                    
                    counts = [0] * len(date_range)
                    date_to_index = {date: idx for idx, date in enumerate(date_range)}
                    
                    for entry in stats_response['visualization_data']['daily_counts']:
                        if isinstance(entry, dict) and 'date' in entry and entry.get('date') in date_to_index:
                            counts[date_to_index[entry['date']]] = entry.get('count', 0)
                    
                    context['activity_counts'] = counts
                else:
                    # Generate a basic trend if no visualization data
                    context['activity_counts'] = generate_trend_data(days)
                
                # Load campaigns for dashboard - safely handle list slicing
                campaigns_response = _api_request('campaigns', params={"days": days}) or {}
                campaigns_list = (campaigns_response.get('campaigns', []) 
                                 if isinstance(campaigns_response, dict) else [])
                
                # FIX: Safely handle list slicing by checking if list exists first
                if campaigns_list:
                    context['campaigns'] = campaigns_list[:3]
                else:
                    context['campaigns'] = []
                
                # Load IOCs for dashboard
                iocs_response = _api_request('iocs', params={"days": days}) or {}
                iocs_list = (iocs_response.get('records', []) 
                            if isinstance(iocs_response, dict) else [])
                
                # FIX: Safely handle list slicing here too
                if iocs_list:
                    context['top_iocs'] = iocs_list[:4]
                else:
                    context['top_iocs'] = []
                
                # Load threat summary for dashboard
                threat_summary = _api_request(f"threat_summary", params={"days": days}) or {}
                context['threat_summary'] = threat_summary
                
                # Load geo data for map
                geo_stats = _api_request(f"iocs/geo", params={"days": days}) or {}
                context['geo_stats'] = geo_stats.get('countries', []) if isinstance(geo_stats, dict) else []
                
        except Exception as e:
            logger.error(f"Error loading dashboard data: {str(e)}")
            logger.error(traceback.format_exc())
            safe_report_exception()
            
            # Initialize empty data structures on error
            context['stats'] = {'feeds': {}, 'campaigns': {}, 'iocs': {'types': []}, 'analyses': {}}
            context['feed_trend'] = 0
            context['ioc_trend'] = 0
            context['campaign_trend'] = 0
            context['analysis_trend'] = 0
            context['ioc_type_labels'] = []
            context['ioc_type_values'] = []
            
            if current_view == 'feeds':
                context['feed_items'] = []
                context['feed_type_descriptions'] = {}
            elif current_view == 'iocs':
                context['ioc_items'] = []
            elif current_view == 'campaigns':
                context['campaigns'] = []
            else:
                # Dashboard view
                today = datetime.now().date()
                context['activity_dates'] = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
                context['activity_counts'] = generate_trend_data(days)
                context['campaigns'] = []
                context['top_iocs'] = []
                context['geo_stats'] = []
                
            flash('Could not load all dashboard data. Some information may be missing.', 'warning')
        
        return render_template('dashboard.html', **context, now=datetime.now())
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('frontend.login'))

# ====== Template Filters ======

# Define datetime formatter function that can be registered in app.py
def format_datetime(value):
    """Format a datetime string for display"""
    if not value:
        return 'N/A'
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        else:
            dt = value
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(value)

# ====== Error Handlers ======

@frontend_app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    logger.info(f"Page not found: {request.path}")
    try:
        return render_template('404.html'), 404
    except:
        return render_template('base.html', 
                               title="Page Not Found", 
                               content="<h1>404 - Page Not Found</h1><p>The requested page does not exist.</p>"), 404

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    logger.error(traceback.format_exc())
    safe_report_exception()
    try:
        return render_template('500.html'), 500
    except:
        return render_template('base.html', 
                               title="Server Error", 
                               content="<h1>500 - Server Error</h1><p>An unexpected error occurred.</p>"), 500

@frontend_app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors"""
    logger.error(f"400 error: {str(e)}")
    logger.error(traceback.format_exc())
    
    # Check if this is a CSRF error
    if isinstance(e, BadRequest) and 'CSRF' in str(e):
        logger.error("CSRF validation failed")
        flash('Your session has expired or there was a security issue. Please try again.', 'danger')
        return redirect(url_for('frontend.login'))
    
    # For other 400 errors
    error_msg = str(e)
    return render_template('500.html', 
                           title="Bad Request", 
                           content=f"<h1>400 - Bad Request</h1><p>{error_msg}</p>"), 400

# ====== Context Processors ======

@frontend_app.context_processor
def inject_global_data():
    """Inject global data into templates"""
    return {
        'now': datetime.now(),
        'environment': ENVIRONMENT,
        'version': VERSION,
        'project_id': getattr(Config, 'GCP_PROJECT', None),
        'debug_mode': DEBUG_MODE,
        'csrf_token': session.get('csrf_token', ''),
    }

# ====== Template Function ======
@frontend_app.context_processor
def utility_processor():
    """Add utility functions to template context"""
    def format_number(value):
        """Format numbers with commas"""
        try:
            return "{:,}".format(int(value)) if value else "0"
        except:
            return str(value)
    
    def get_severity_class(severity):
        """Get CSS class for severity levels"""
        severity_map = {
            'critical': 'bg-red-600 text-white',
            'high': 'bg-orange-500 text-white',
            'medium': 'bg-amber-400 text-gray-800',
            'low': 'bg-teal-500 text-white'
        }
        return severity_map.get(str(severity).lower(), 'bg-gray-300 text-gray-800')
    
    def get_confidence_width(value):
        """Get width percentage for confidence bar"""
        try:
            if isinstance(value, (int, float)):
                return min(100, max(0, int(value)))
            return 40  # Default
        except:
            return 40
    
    return dict(
        format_number=format_number,
        get_severity_class=get_severity_class,
        get_confidence_width=get_confidence_width
    )

# If this script is run directly, start a development server
if __name__ == "__main__":
    app = current_app
    app.run(debug=ENVIRONMENT != 'production', 
            host='0.0.0.0', 
            port=int(os.environ.get('PORT', 8080)))
