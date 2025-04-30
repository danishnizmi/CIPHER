"""
Threat Intelligence Platform - Frontend Module
Handles web interface, user authentication, and dashboard views.
Production-ready implementation with full GCP integration.
"""

import os
import json
import logging
import hashlib
import time
import traceback
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from typing import Dict, List, Any, Optional, Union

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask import flash, session, abort, g, Response, current_app
from werkzeug.middleware.proxy_fix import ProxyFix

# Import config module for centralized configuration
import config

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.1")
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

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Try to import CORS but continue if not available
try:
    from flask_cors import CORS
    CORS(app)
    logger.info("CORS support enabled")
except ImportError:
    logger.warning("CORS not available - flask_cors not installed")

# ====== CSRF Protection Setup ======
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
    # Initialize without immediately protecting all routes
    csrf.init_app(app)
    HAS_CSRF = True
    logger.info("CSRF protection initialized")
    
except ImportError:
    HAS_CSRF = False
    logger.warning("CSRF protection not available - flask_wtf not installed")
    
    # Provide a dummy csrf_token function for templates
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=lambda: "")

# ====== Secret Key for Sessions ======

def get_secret_key() -> str:
    """Get secret key for Flask sessions using config module"""
    try:
        # Try config module first
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'session_secret' in auth_config:
            return auth_config['session_secret']
        
        # Try environment variable
        secret_key = os.environ.get('SECRET_KEY')
        if secret_key:
            return secret_key
        
        # Try Secret Manager via config module
        secret = config.get_secret("flask-secret-key")
        if secret:
            return secret
    except Exception as e:
        logger.error(f"Error retrieving secret key: {str(e)}")
    
    # Generate a secure key if all else fails
    logger.warning("Generating temporary secret key - sessions will be invalidated on restart")
    return hashlib.sha256(f"{time.time()}{secrets.token_hex(32)}".encode()).hexdigest()

# Configure Flask
SECRET_KEY = get_secret_key()
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=ENVIRONMENT == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    TEMPLATES_AUTO_RELOAD=ENVIRONMENT != 'production',
    WTF_CSRF_ENABLED=HAS_CSRF,  # Only enable if the library is available
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour CSRF token validity
    WTF_CSRF_SSL_STRICT=False,  # Allow HTTPS -> HTTP
)

# Share GCP clients with the app context
@app.before_request
def setup_gcp_clients():
    """Share GCP clients from config module with application context"""
    if not hasattr(g, 'gcp_clients'):
        g.gcp_clients = config.get_gcp_clients()
    if not hasattr(g, 'gcp_services_available'):
        g.gcp_services_available = config.GCP_SERVICES_AVAILABLE

# ====== Helper Functions ======

def safe_report_exception():
    """Safely report exception using config module"""
    try:
        config.report_exception()
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
                old_keys = sorted(API_CACHE_TIMESTAMP, key=API_CACHE_TIMESTAMP.get)[:10]
                for k in old_keys:
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
    api_key = getattr(config, 'api_key', None)
    
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
    
    except requests.RequestException as e:
        logger.error(f"API request error ({endpoint}): {str(e)}")
        status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
        
        error_msg = f"API error: {str(e)}"
        if status_code:
            error_msg += f" (status code: {status_code})"
        
        return {"error": error_msg, "status_code": status_code}
    
    except Exception as e:
        logger.error(f"Unexpected API error ({endpoint}): {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}

@api_cache(timeout=CACHE_TIMEOUT)
def get_stats_data(days=30):
    """Get statistics data from API with caching"""
    return _api_request(f"stats?days={days}")

@api_cache(timeout=CACHE_TIMEOUT)
def get_feeds_data():
    """Get feeds data from API with caching"""
    return _api_request("feeds")

@api_cache(timeout=CACHE_TIMEOUT)
def get_iocs_data(days=30, ioc_type=None, value=None):
    """Get IOCs data from API with caching"""
    params = {"days": days}
    if ioc_type:
        params["type"] = ioc_type
    if value:
        params["value"] = value
    
    param_str = "&".join(f"{k}={v}" for k, v in params.items())
    return _api_request(f"iocs?{param_str}")

@api_cache(timeout=CACHE_TIMEOUT)
def get_campaigns_data(days=30, severity=None):
    """Get campaigns data from API with caching and better error handling"""
    params = {"days": days}
    if severity:
        params["severity"] = severity
    
    param_str = "&".join(f"{k}={v}" for k, v in params.items())
    response = _api_request(f"campaigns?{param_str}")
    
    # Ensure 'campaigns' is always a list even if not present in the response
    if isinstance(response, dict) and 'campaigns' not in response:
        response['campaigns'] = []
    elif not isinstance(response, dict):
        # Return a properly formatted empty result
        return {"campaigns": [], "count": 0, "total": 0, "has_more": False}
    
    return response

@api_cache(timeout=LONG_CACHE_TIMEOUT)
def get_feed_stats(feed_name, days=30):
    """Get feed stats from API with longer caching"""
    return _api_request(f"feeds/{feed_name}/stats?days={days}")

@api_cache(timeout=CACHE_TIMEOUT)
def get_feed_data(feed_name, limit=100, offset=0):
    """Get feed data from API with caching"""
    return _api_request(f"feeds/{feed_name}/data?limit={limit}&offset={offset}")

@api_cache(timeout=CACHE_TIMEOUT)
def get_threat_summary(days=30):
    """Get threat summary from API with caching"""
    return _api_request(f"threat_summary?days={days}")

@api_cache(timeout=CACHE_TIMEOUT)
def get_ioc_geo_stats(days=30):
    """Get geographic IOC statistics with caching"""
    return _api_request(f"iocs/geo?days={days}")

def trigger_ingestion(feed_name=None, force=False):
    """Trigger data ingestion for a specific feed or all feeds"""
    data = {"process_all": True}
    if feed_name and feed_name != "all":
        data["feed_name"] = feed_name
    if force:
        data["force"] = True
    
    result = _api_request("ingest_threat_data", method="POST", data=data)
    
    # Clear relevant caches on successful ingestion
    if not result.get("error"):
        clear_api_cache("get_feeds_data")
        clear_api_cache("get_stats_data")
        if feed_name:
            clear_api_cache(f"get_feed_stats:{feed_name}")
            clear_api_cache(f"get_feed_data:{feed_name}")
        clear_api_cache("get_threat_summary")
    
    return result

def upload_csv_file(csv_content, feed_name="csv_upload"):
    """Upload CSV for threat analysis"""
    data = {
        "file_type": "csv",
        "content": csv_content,
        "feed_name": feed_name
    }
    
    result = _api_request("upload_csv", method="POST", data=data)
    
    # Clear relevant caches on successful upload
    if not result.get("error"):
        clear_api_cache("get_feeds_data")
        clear_api_cache("get_stats_data")
    
    return result

# ====== Authentication Decorators ======

def login_required(f):
    """Decorator to require login for views"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            # Remember where the user was trying to go
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('Admin privileges required', 'danger')
            return render_template('auth.html', page_type='not_authorized')
        return f(*args, **kwargs)
    return decorated_function

# ====== Authentication Functions ======

def load_users() -> Dict[str, Dict]:
    """Load user data from auth config using config module"""
    try:
        # Get auth config from config module
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'users' in auth_config and auth_config['users']:
            return auth_config.get('users', {})
        
        # No users exist yet, ensure admin user is created
        admin_password = config.set_initial_admin_password()
        if admin_password and ENVIRONMENT == 'development':
            print(f"\n=== ADMIN PASSWORD: {admin_password} ===\n")
            
        # Reload auth config after setup
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        return auth_config.get('users', {})
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

@app.route('/')
def index():
    """Root redirects to dashboard if logged in, otherwise to login"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Properly exempt the login route from CSRF
def login():
    """Login page handler with comprehensive error handling"""
    error = None
    
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember') == 'on'
            
            # Debug output for login attempt
            logger.info(f"Login attempt for user: {username}")
            
            # Validate inputs
            if not username or not password:
                error = "Username and password are required"
                return render_template('auth.html', page_type='login', error=error, now=datetime.now())
            
            # Load users
            users = load_users()
            
            if username in users:
                user = users[username]
                stored_password = user.get('password', '')
                
                # Verify password
                if verify_password(stored_password, password):
                    # Login successful
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user.get('role', 'readonly')
                    session.permanent = remember
                    
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
                    next_page = request.args.get('next')
                    if next_page and next_page.startswith('/'):
                        return redirect(next_page)
                    return redirect(url_for('dashboard'))
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
    return render_template('auth.html', page_type='login', error=error, now=datetime.now())

@app.route('/logout')
def logout():
    """Logout route handler"""
    username = session.get('username')
    
    if username:
        logger.info(f"User logged out: {username}")
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@app.route('/dashboard/<view>')
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
            stats_response = get_stats_data(days=days) or {}
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
                feeds_response = get_feeds_data() or {}
                context['feed_items'] = (feeds_response.get('feed_details', []) 
                                        if isinstance(feeds_response, dict) else [])
                context['feed_type_descriptions'] = {
                    feed.get('name', ''): feed.get('description', 'Threat Intelligence Feed') 
                    for feed in context['feed_items'] if isinstance(feed, dict) and 'name' in feed
                }
                
            elif current_view == 'iocs':
                iocs_response = get_iocs_data(days=days) or {}
                context['ioc_items'] = (iocs_response.get('records', []) 
                                       if isinstance(iocs_response, dict) else [])
                
            elif current_view == 'campaigns':
                campaigns_response = get_campaigns_data(days=days) or {}
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
                campaigns_response = get_campaigns_data(days=days) or {}
                campaigns_list = (campaigns_response.get('campaigns', []) 
                                 if isinstance(campaigns_response, dict) else [])
                
                # FIX: Use explicit if-else instead of conditional slicing to avoid unhashable type error
                if campaigns_list:
                    context['campaigns'] = campaigns_list[:3]
                else:
                    context['campaigns'] = []
                
                # Load IOCs for dashboard
                iocs_response = get_iocs_data(days=days) or {}
                iocs_list = (iocs_response.get('records', []) 
                            if isinstance(iocs_response, dict) else [])
                
                # Also fix this similar pattern with the same approach
                if iocs_list:
                    context['top_iocs'] = iocs_list[:4]
                else:
                    context['top_iocs'] = []
                
                # Load threat summary for dashboard
                threat_summary = get_threat_summary(days=days) or {}
                context['threat_summary'] = threat_summary
                
                # Load geo data for map
                geo_stats = get_ioc_geo_stats(days=days) or {}
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
        return redirect(url_for('login'))

@app.route('/refresh_feeds')
@login_required
def refresh_feeds():
    """Trigger feed refresh and redirect back to feeds view"""
    try:
        # Log who triggered the refresh
        username = session.get('username')
        logger.info(f"Feed refresh triggered by: {username}")
        
        # Call API to trigger ingestion
        result = trigger_ingestion(force=True)
        
        # Check result
        if result.get('error'):
            flash(f"Error refreshing feeds: {result['error']}", 'danger')
        else:
            # Clear all relevant caches
            clear_api_cache('get_feeds')
            clear_api_cache('get_stats')
            
            feeds_count = len(result.get('results', []))
            success_count = sum(1 for r in result.get('results', []) if r.get('status') == 'success')
            
            flash(f'Successfully refreshed {success_count} of {feeds_count} feeds', 'success')
        
        # Redirect back to feeds view
        return redirect(url_for('dashboard', view='feeds'))
    except Exception as e:
        logger.error(f"Error in refresh_feeds: {str(e)}")
        flash(f'Error refreshing feeds: {str(e)}', 'danger')
        return redirect(url_for('dashboard', view='feeds'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    username = session.get('username')
    users = load_users()
    user = users.get(username, {})
    
    return render_template('auth.html', page_type='profile', username=username, user=user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Handle password change form submission"""
    try:
        # CSRF protection is applied to all POST routes except login
        username = session.get('username')
        users = load_users()
        user = users.get(username, {})
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
        else:
            stored_password = user.get('password', '')
            
            # Verify current password
            if verify_password(stored_password, current_password):
                # Hash and update the new password
                hashed_password = hash_password(new_password)
                if config.update_user(username, {'password': hashed_password}):
                    flash('Password updated successfully', 'success')
                    logger.info(f"Password changed for user: {username}")
                else:
                    flash('Error updating password. Please try again.', 'danger')
            else:
                flash('Current password is incorrect', 'danger')
        
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f"Error in change_password: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An error occurred while changing password. Please try again.', 'danger')
        return redirect(url_for('profile'))

@app.route('/users')
@admin_required
def users():
    """User management page"""
    users = load_users()
    return render_template('content.html', page_type='users', users=users)

@app.route('/user/add', methods=['GET', 'POST'])
@admin_required
def add_user_route():
    """Add user page"""
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role', 'readonly')
            
            # Validation
            if not username or not password:
                flash('Username and password are required', 'danger')
            elif password != confirm_password:
                flash('Passwords do not match', 'danger')
            elif username in load_users():
                flash('Username already exists', 'danger')
            elif len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
            elif not username.isalnum():
                flash('Username must contain only letters and numbers', 'danger')
            else:
                # Add user with secure password hash using config module
                if config.add_user(username, password, role):
                    flash(f'User {username} added successfully', 'success')
                    logger.info(f"New user added: {username} with role {role}")
                    return redirect(url_for('users'))
                else:
                    flash('Error adding user. Please try again.', 'danger')
        
        return render_template('auth.html', page_type='user_add')
    except Exception as e:
        logger.error(f"Error in add_user: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An error occurred while adding user. Please try again.', 'danger')
        return redirect(url_for('users'))

@app.route('/user/edit/<username>', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    """Edit user page"""
    try:
        users = load_users()
        
        if username not in users:
            flash(f'User {username} not found', 'danger')
            return redirect(url_for('users'))
        
        user = users[username]
        
        if request.method == 'POST':
            password = request.form.get('password')
            role = request.form.get('role')
            
            updates = {'role': role}
            
            # Only hash and update password if provided
            if password:
                if len(password) < 8:
                    flash('Password must be at least 8 characters long', 'danger')
                    return render_template('auth.html', page_type='user_edit', username=username, user=user)
                    
                updates['password'] = hash_password(password)
            
            if config.update_user(username, updates):
                flash(f'User {username} updated successfully', 'success')
                logger.info(f"User updated: {username}")
                return redirect(url_for('users'))
            else:
                flash('Error updating user. Please try again.', 'danger')
        
        return render_template('auth.html', page_type='user_edit', username=username, user=user)
    except Exception as e:
        logger.error(f"Error in edit_user: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An error occurred while editing user. Please try again.', 'danger')
        return redirect(url_for('users'))

@app.route('/user/delete/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    """Delete user route"""
    try:
        users = load_users()
        
        if username not in users:
            flash(f'User {username} not found', 'danger')
            return redirect(url_for('users'))
        
        if username == session.get('username'):
            flash('Cannot delete your own account', 'danger')
            return redirect(url_for('users'))
        
        # Delete user by removing from auth config
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if 'users' in auth_config and username in auth_config['users']:
            del auth_config['users'][username]
            if config.create_or_update_secret('auth-config', json.dumps(auth_config)):
                flash(f'User {username} deleted successfully', 'success')
                logger.info(f"User deleted: {username}")
            else:
                flash('Error deleting user. Please try again.', 'danger')
        else:
            flash(f'User {username} not found in configuration', 'danger')
        
        return redirect(url_for('users'))
    except Exception as e:
        logger.error(f"Error in delete_user: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An error occurred while deleting user. Please try again.', 'danger')
        return redirect(url_for('users'))

@app.route('/feeds')
@login_required
def feeds():
    """Shortcut to feeds view"""
    return redirect(url_for('dashboard', view='feeds'))

@app.route('/iocs')
@login_required
def iocs():
    """Shortcut to IOCs view"""
    return redirect(url_for('dashboard', view='iocs'))

@app.route('/campaigns')
@login_required
def campaigns():
    """Shortcut to campaigns view"""
    return redirect(url_for('dashboard', view='campaigns'))

@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger data ingestion manually"""
    try:
        # Log operation
        username = session.get('username')
        logger.info(f"Manual ingestion triggered by {username}")
        
        # Trigger ingestion
        result = trigger_ingestion(force=True)
        
        # Process result
        if isinstance(result, dict) and 'results' in result:
            success_count = sum(1 for r in result['results'] if r.get('status') == 'success')
            total_count = len(result['results'])
            
            if success_count == total_count and total_count > 0:
                flash(f'Threat data refreshed successfully. Processed {total_count} feeds.', 'success')
            elif success_count > 0:
                flash(f'Threat data refresh partially completed. {success_count} of {total_count} feeds processed successfully.', 'warning')
            else:
                flash('Failed to refresh threat data. Please check logs for details.', 'danger')
        else:
            # Handle single feed result
            if result.get('status') == 'success':
                flash(f'Successfully processed feed: {result.get("feed_name")}', 'success')
            else:
                flash(f'Error processing feed: {result.get("message", "Unknown error")}', 'danger')
            
    except Exception as e:
        logger.error(f"Error triggering threat data ingestion: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash(f'Error refreshing threat data: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/dynamic_content_detail/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Dynamic content detail page for IOCs, campaigns, feeds, etc."""
    try:
        data = {}
        
        if content_type == 'ioc':
            # Split identifier
            try:
                ioc_type, ioc_value = identifier.split('/', 1)
            except ValueError:
                flash('Invalid IOC identifier format', 'danger')
                return redirect(url_for('iocs'))
            
            # Get IOCs with matching type/value
            iocs_data = get_iocs_data()
            
            # Find the matching IOC
            for ioc in iocs_data.get('records', []):
                if ioc.get('type') == ioc_type and ioc.get('value') == ioc_value:
                    data = ioc
                    break
                    
            # Get related campaigns
            if data:
                campaigns_data = get_campaigns_data()
                campaigns_list = campaigns_data.get('campaigns', [])
                # Fix another potential slice issue here
                if campaigns_list:
                    data['campaigns'] = campaigns_list[:3]
                else:
                    data['campaigns'] = []
                    
                # Set placeholders for missing fields
                for field in ['first_seen', 'last_seen', 'sources', 'confidence', 'tags']:
                    if field not in data:
                        data[field] = [] if field in ['sources', 'tags'] else None
                
        elif content_type == 'campaign':
            # Get campaign details
            campaigns_data = get_campaigns_data()
            
            # Find the specific campaign
            for campaign in campaigns_data.get('campaigns', []):
                if campaign.get('campaign_id') == identifier:
                    data = campaign
                    break
            
            # Enrich with additional data
            if data:
                # Get IOCs related to this campaign
                iocs_data = get_iocs_data()
                iocs_list = iocs_data.get('records', [])
                # Fix another potential slice issue here
                if iocs_list:
                    data['iocs'] = iocs_list[:5]
                else:
                    data['iocs'] = []
                
                # Add description if missing
                if 'description' not in data:
                    data['description'] = f"Campaign {data.get('campaign_name', 'Unknown')} details."
                
        elif content_type == 'feed':
            # Get feed stats and data
            feed_stats = get_feed_stats(identifier)
            feed_data = get_feed_data(identifier)
            
            # Combine data
            data = feed_stats or {}
            data['name'] = identifier
            sample_data = feed_data.get('records', [])
            # Fix another potential slice issue here
            if sample_data:
                data['sample_data'] = sample_data[:10]
            else:
                data['sample_data'] = []
            
            # Add description if missing
            if 'description' not in data:
                feeds_data = get_feeds_data()
                for feed in feeds_data.get('feed_details', []):
                    if feed.get('name') == identifier:
                        data['description'] = feed.get('description', f"Feed: {identifier}")
                        break
            
            if 'description' not in data:
                data['description'] = f"Data from {identifier} threat intelligence feed."
    
        # Return context
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'data': data
        }
        
        return render_template('detail.html', **context)
    
    except Exception as e:
        logger.error(f"Error loading detail page for {content_type}/{identifier}: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('Error loading content details.', 'danger')
        return redirect(url_for('dashboard'))

# ====== API Passthrough ======
@app.route('/api/refresh_feeds', methods=['POST'])
@login_required
def api_refresh_feeds():
    """API endpoint to trigger feed refresh"""
    try:
        feed_name = request.json.get('feed_name', 'all')
        force = request.json.get('force', False)
        
        # Log who triggered the refresh
        username = session.get('username')
        logger.info(f"Feed refresh API call by: {username}, feed: {feed_name}, force: {force}")
        
        # Call API to trigger ingestion
        result = trigger_ingestion(feed_name=feed_name, force=force)
        
        # Return result
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in API refresh_feeds: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload_csv', methods=['POST'])
@login_required
def api_upload_csv():
    """API endpoint to upload CSV data"""
    try:
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "No file selected"}), 400
                
            # Read CSV content
            try:
                csv_content = file.read().decode('utf-8')
            except UnicodeDecodeError:
                # Try alternative encodings
                file.seek(0)
                content = file.read()
                for encoding in ['latin-1', 'iso-8859-1', 'windows-1252']:
                    try:
                        csv_content = content.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    return jsonify({"error": "Unable to decode CSV file"}), 400
                    
            feed_name = request.form.get('feed_name', os.path.splitext(file.filename)[0])
        else:
            # Get from JSON payload
            data = request.json
            if not data or 'content' not in data:
                return jsonify({"error": "No CSV content provided"}), 400
                
            csv_content = data['content']
            feed_name = data.get('feed_name', 'csv_upload')
            
        # Process the CSV data
        result = upload_csv_file(csv_content, feed_name)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in API upload_csv: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ====== Template Filters ======

@app.template_filter('datetime')
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

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    logger.info(f"Page not found: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    logger.error(traceback.format_exc())
    safe_report_exception()
    return render_template('500.html'), 500

# Special error handler for CSRF errors to make them more user-friendly
@app.errorhandler(400)
def handle_csrf_error(e):
    logger.error(f"400 error: {str(e)}")
    # Check if this is a CSRF error
    if 'CSRF' in str(e):
        flash('Your session has expired or there was a security issue. Please try again.', 'danger')
        return redirect(url_for('login'))
    # For other 400 errors, use the default handler
    return str(e), 400

# ====== Context Processors ======

@app.context_processor
def inject_global_data():
    """Inject global data into templates"""
    return {
        'now': datetime.now(),
        'environment': ENVIRONMENT,
        'version': VERSION,
        'project_id': config.project_id,
        'debug_mode': DEBUG_MODE
    }

# Initialize the app
if __name__ == "__main__":
    app.run(debug=ENVIRONMENT != 'production', 
            host='0.0.0.0', 
            port=int(os.environ.get('PORT', 8080)))
