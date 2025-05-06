"""
Threat Intelligence Platform - Frontend Module
Handles web interface, user authentication, and dashboard views.
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
VERSION = os.environ.get("VERSION", "1.0.3")
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

@frontend_app.before_request
def before_request():
    """Ensure session is properly established with cloud-based session."""
    try:
        # Force session creation if needed
        if '_id' not in session:
            session.permanent = True
            session['_id'] = secrets.token_hex(16)
            logger.debug(f"New session created: {session.get('_id')}")
        
        # Add session debug info in development
        if DEBUG_MODE:
            logger.debug(f"Session data: {dict(session)}")
            logger.debug(f"Request path: {request.path}")
            logger.debug(f"Request method: {request.method}")
    
    except Exception as e:
        logger.error(f"Error in before_request: {str(e)}")
        logger.error(traceback.format_exc())

# ====== Helper Functions ======
def safe_report_exception(e=None):
    """Safely report exception using config module"""
    try:
        if e:
            config.report_error(e)
        else:
            config.report_error(Exception("Frontend error"))
    except Exception as err:
        logger.warning(f"Failed to report exception: {err}")

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
            # Skip cache for authenticated users for real-time data
            if session.get('logged_in'):
                return func(*args, **kwargs)
            
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
        
        # Always include API key for internal requests
        headers = {"Content-Type": "application/json"}
        api_key = get_api_key()
        if api_key:
            headers["X-API-Key"] = api_key
        else:
            logger.warning("No API key available for internal request")
        
        # Add CSRF token if available
        csrf_token = session.get('csrf_token')
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        
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
            return {
                "error": "Failed to connect to API after multiple retries",
                # Add default structure to prevent template errors
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }
        
        # Log response time
        request_time = time.time() - start_time
        if request_time > 1.0:
            logger.info(f"Slow API request ({request_time:.2f}s): {method} {api_url}")
        
        # Check for errors
        if response.status_code != 200:
            logger.warning(f"API request failed: {response.status_code} - {response.text[:100]}")
            return {
                "error": f"API request failed with status {response.status_code}",
                "status_code": response.status_code,
                # Add default structure to prevent template errors
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }
        
        # Parse and return JSON
        if response.text:
            try:
                return response.json()
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON response: {response.text[:100]}")
                return {
                    "error": "Invalid JSON response", 
                    "raw_response": response.text[:500],
                    # Add default structure to prevent template errors
                    "feeds": {"total_sources": 0},
                    "iocs": {"total": 0, "types": []},
                    "campaigns": {"total_campaigns": 0},
                    "analyses": {"total_analyses": 0}
                }
        
        return {}
    
    except Exception as e:
        if 'requests' in locals() and isinstance(e, requests.RequestException):
            logger.error(f"API request error ({endpoint}): {str(e)}")
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            
            error_msg = f"API error: {str(e)}"
            if status_code:
                error_msg += f" (status code: {status_code})"
            
            return {
                "error": error_msg, 
                "status_code": status_code,
                # Add default structure to prevent template errors
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }
        else:
            logger.error(f"Unexpected API error ({endpoint}): {str(e)}")
            safe_report_exception(e)
            return {
                "error": f"Unexpected error: {str(e)}",
                # Add default structure to prevent template errors
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }

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
        
        # If no users found in config, check for default admin user in environment
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if admin_password:
            default_admin = {
                'admin': {
                    'password': hash_password(admin_password),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            return default_admin
            
        # As a last resort, try hardcoded admin (for development only)
        if ENVIRONMENT != 'production':
            logger.warning("No users found in auth config, using default admin")
            return {
                'admin': {
                    'password': hash_password('admin'),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        
        # For production, look for admin password in config
        if hasattr(Config, 'ADMIN_PASSWORD') and Config.ADMIN_PASSWORD:
            logger.info("Using admin password from Config")
            return {
                'admin': {
                    'password': hash_password(Config.ADMIN_PASSWORD),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            
        logger.error("No user accounts found or configured")
        return {}
    except Exception as e:
        logger.error(f"Failed to load users: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception(e)
        
        # In development, provide a fallback admin account
        if ENVIRONMENT != 'production':
            return {
                'admin': {
                    'password': hash_password('admin'),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
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
    logger.debug("Accessed root route")
    if session.get('logged_in'):
        return redirect(url_for('frontend.dashboard'))
    return redirect(url_for('frontend.login'))

@frontend_app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page handler with Flask-WTF CSRF protection"""
    error = None
    logger.debug("Accessed login route")
    
    try:
        if request.method == 'POST':
            # Flask-WTF automatically handles CSRF validation
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
                    session.clear()  # Clear previous session data
                    session.permanent = remember
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user.get('role', 'readonly')
                    session['_id'] = secrets.token_hex(16)  # Generate new session ID
                    
                    # Update last login time
                    try:
                        auth_config = config.get_cached_config('auth-config', force_refresh=True)
                        if auth_config and 'users' in auth_config and username in auth_config['users']:
                            auth_config['users'][username]['last_login'] = datetime.utcnow().isoformat()
                            config.create_or_update_secret('auth-config', json.dumps(auth_config))
                    except Exception as e:
                        logger.warning(f"Could not update last login time: {str(e)}")
                    
                    # Log the successful login
                    logger.info(f"Successful login: {username}")
                    
                    flash(f'Welcome, {username}!', 'success')
                    
                    # Clear cache for this user
                    clear_api_cache()
                    
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
        safe_report_exception(e)
        error = f"An unexpected error occurred: {str(e)}"
    
    # For GET requests or failed logins
    return render_template('auth.html', page_type='login', error=error, now=datetime.now())

@frontend_app.route('/profile')
@login_required
def profile():
    """User profile page handler"""
    try:
        users = load_users()
        user = users.get(session.get('username'))
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('frontend.dashboard'))
        
        return render_template('auth.html', 
                             page_type='profile', 
                             username=session.get('username'),
                             user=user)
    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}")
        logger.error(traceback.format_exc())
        flash('Error loading profile page', 'error')
        safe_report_exception(e)
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Handle password change requests"""
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        users = load_users()
        user = users.get(session.get('username'))
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('frontend.profile'))
        
        # Verify current password
        if not verify_password(user.get('password', ''), current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('frontend.profile'))
        
        # Update password
        user['password'] = hash_password(new_password)
        
        # Update in Secret Manager if possible
        try:
            auth_config = config.get_cached_config('auth-config')
            if auth_config and 'users' in auth_config:
                auth_config['users'][session.get('username')]['password'] = hash_password(new_password)
                # Save back to Secret Manager
                config.create_or_update_secret('auth-config', json.dumps(auth_config))
        except Exception as e:
            logger.warning(f"Failed to update password in Secret Manager: {str(e)}")
            # Continue anyway as we've updated the in-memory version
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('frontend.profile'))
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        safe_report_exception(e)
        flash('Error changing password', 'danger')
        return redirect(url_for('frontend.profile'))

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
        logger.debug(f"Accessing dashboard with view: {view}")
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
        
        # Load statistics for all views
        try:
            # Get statistics using the helper function
            stats_response = _api_request('stats', params={"days": days}) or {}
            
            # Ensure stats has the expected structure even if API fails
            context['stats'] = {
                'feeds': stats_response.get('feeds', {'total_sources': 0}),
                'iocs': stats_response.get('iocs', {'total': 0, 'types': []}),
                'campaigns': stats_response.get('campaigns', {'total_campaigns': 0}),
                'analyses': stats_response.get('analyses', {'total_analyses': 0}),
                'timestamp': stats_response.get('timestamp', datetime.utcnow().isoformat())
            }
            
            # Extract trends from statistics - use real data
            if isinstance(stats_response, dict) and 'feeds' in stats_response:
                context['feed_trend'] = stats_response.get('feeds', {}).get('growth_rate', 0)
                context['ioc_trend'] = stats_response.get('iocs', {}).get('growth_rate', 0)
                context['campaign_trend'] = stats_response.get('campaigns', {}).get('growth_rate', 0)
                context['analysis_trend'] = stats_response.get('analyses', {}).get('growth_rate', 0)
                
                # Extract IOC type data for charts
                context['ioc_type_labels'] = [item.get('type', '') for item in stats_response.get('iocs', {}).get('types', [])]
                context['ioc_type_values'] = [item.get('count', 0) for item in stats_response.get('iocs', {}).get('types', [])]
            
            # Load view-specific data
            if current_view == 'feeds':
                feeds_response = _api_request('feeds') or {}
                context['feed_items'] = feeds_response.get('feed_details', [])
                context['feed_type_descriptions'] = {
                    feed.get('name', ''): feed.get('description', 'Threat Intelligence Feed') 
                    for feed in context['feed_items'] if isinstance(feed, dict) and 'name' in feed
                }
                
            elif current_view == 'iocs':
                iocs_response = _api_request('iocs', params={"days": days}) or {}
                context['ioc_items'] = iocs_response.get('records', [])
                
            elif current_view == 'campaigns':
                campaigns_response = _api_request('campaigns', params={"days": days}) or {}
                context['campaigns'] = campaigns_response.get('campaigns', [])
                
            else:
                # Dashboard view - load additional data
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
                    context['activity_counts'] = [20 + i * 2 for i in range(days)]
                
                # Load campaigns for dashboard
                campaigns_response = _api_request('campaigns', params={"days": days}) or {}
                campaigns_list = campaigns_response.get('campaigns', [])
                
                if campaigns_list:
                    context['campaigns'] = campaigns_list[:3]
                else:
                    context['campaigns'] = []
                
                # Load IOCs for dashboard
                iocs_response = _api_request('iocs', params={"days": days}) or {}
                iocs_list = iocs_response.get('records', [])
                
                if iocs_list:
                    context['top_iocs'] = iocs_list[:4]
                else:
                    context['top_iocs'] = []
                
                # Load threat summary for dashboard
                threat_summary = _api_request(f"threat_summary", params={"days": days}) or {}
                context['threat_summary'] = threat_summary
                
                # Load geo data for map
                geo_stats = _api_request(f"iocs/geo", params={"days": days}) or {}
                context['geo_stats'] = geo_stats.get('countries', [])
                
        except Exception as e:
            logger.error(f"Error loading dashboard data: {str(e)}")
            logger.error(traceback.format_exc())
            safe_report_exception(e)
            
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
                context['activity_counts'] = [20 + i * 2 for i in range(days)]
                context['campaigns'] = []
                context['top_iocs'] = []
                context['geo_stats'] = []
                
            flash('Could not load all dashboard data. Some information may be missing.', 'warning')
        
        return render_template('dashboard.html', **context, now=datetime.now())
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception(e)
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('frontend.login'))

# User Management Routes
@frontend_app.route('/users')
@login_required
@admin_required
def users():
    """User management page"""
    try:
        users = load_users()
        return render_template('content.html', page_type='users', users=users)
    except Exception as e:
        logger.error(f"Error loading users page: {str(e)}")
        safe_report_exception(e)
        flash('Error loading users page', 'danger')
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/user/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user_route():
    """Add new user"""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role', 'readonly')
            
            users = load_users()
            if username in users:
                flash('Username already exists', 'danger')
                return redirect(url_for('frontend.add_user_route'))
            
            # Create new user
            users[username] = {
                'password': hash_password(password),
                'role': role,
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Save to Secret Manager if possible
            try:
                auth_config = config.get_cached_config('auth-config')
                if auth_config and 'users' in auth_config:
                    auth_config['users'][username] = users[username]
                    # Save back to Secret Manager
                    config.create_or_update_secret('auth-config', json.dumps(auth_config))
            except Exception as e:
                logger.warning(f"Failed to save new user to Secret Manager: {str(e)}")
                # Continue anyway as we've updated the in-memory version
            
            flash(f'User {username} created successfully', 'success')
            return redirect(url_for('frontend.users'))
            
        except Exception as e:
            logger.error(f"Error adding user: {str(e)}")
            safe_report_exception(e)
            flash('Error creating user', 'danger')
    
    return render_template('auth.html', page_type='user_add')

@frontend_app.route('/user/edit/<username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(username):
    """Edit user"""
    users = load_users()
    if username not in users:
        flash('User not found', 'danger')
        return redirect(url_for('frontend.users'))
    
    if request.method == 'POST':
        try:
            password = request.form.get('password')
            role = request.form.get('role')
            
            if password:
                users[username]['password'] = hash_password(password)
            if role:
                users[username]['role'] = role
            
            # Save to Secret Manager if possible
            try:
                auth_config = config.get_cached_config('auth-config')
                if auth_config and 'users' in auth_config:
                    if password:
                        auth_config['users'][username]['password'] = hash_password(password)
                    if role:
                        auth_config['users'][username]['role'] = role
                    # Save back to Secret Manager
                    config.create_or_update_secret('auth-config', json.dumps(auth_config))
            except Exception as e:
                logger.warning(f"Failed to update user in Secret Manager: {str(e)}")
                # Continue anyway as we've updated the in-memory version
            
            flash(f'User {username} updated successfully', 'success')
            return redirect(url_for('frontend.users'))
            
        except Exception as e:
            logger.error(f"Error editing user: {str(e)}")
            safe_report_exception(e)
            flash('Error updating user', 'danger')
    
    return render_template('auth.html', page_type='user_edit', username=username, user=users[username])

@frontend_app.route('/user/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    """Delete user"""
    try:
        users = load_users()
        if username in users:
            del users[username]
            
            # Delete from Secret Manager if possible
            try:
                auth_config = config.get_cached_config('auth-config')
                if auth_config and 'users' in auth_config and username in auth_config['users']:
                    del auth_config['users'][username]
                    # Save back to Secret Manager
                    config.create_or_update_secret('auth-config', json.dumps(auth_config))
            except Exception as e:
                logger.warning(f"Failed to delete user from Secret Manager: {str(e)}")
                # Continue anyway as we've updated the in-memory version
            
            flash(f'User {username} deleted successfully', 'success')
        else:
            flash('User not found', 'warning')
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        safe_report_exception(e)
        flash('Error deleting user', 'danger')
    
    return redirect(url_for('frontend.users'))

# Admin Routes
@frontend_app.route('/ingest_threat_data', methods=['GET', 'POST'])
@login_required
@admin_required
def ingest_threat_data():
    """Trigger threat data ingestion"""
    try:
        if request.method == 'POST':
            # Trigger ingestion through API
            result = _api_request('admin/ingest', method='POST', data={'process_all': True})
            
            if result.get('error'):
                flash(f'Error triggering ingestion: {result["error"]}', 'danger')
            else:
                flash('Threat data ingestion triggered successfully', 'success')
            
            return redirect(url_for('frontend.dashboard'))
        
        # For GET requests, trigger POST to the same endpoint using autosubmit form
        return render_template('base.html', 
                              title="Triggering Data Ingestion", 
                              content="""
                              <div class="text-center py-8">
                                <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-t-2 border-accent mb-4"></div>
                                <h1 class="text-2xl font-bold mb-4">Triggering Threat Data Ingestion</h1>
                                <p class="mb-6">Please wait while we process your request...</p>
                                <form id="ingestForm" method="post">
                                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
        flash('An error occurred while triggering ingestion', 'danger')
        return redirect(url_for('frontend.dashboard'))

# Additional Routes for Dashboard Links
@frontend_app.route('/feeds')
@login_required
def feeds():
    """Redirect to dashboard feeds view"""
    return redirect(url_for('frontend.dashboard', view='feeds'))

@frontend_app.route('/iocs')
@login_required
def iocs():
    """Redirect to dashboard IOCs view"""
    return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/campaigns')
@login_required
def campaigns():
    """Redirect to dashboard campaigns view"""
    return redirect(url_for('frontend.dashboard', view='campaigns'))

@frontend_app.route('/detail/<content_type>/<path:identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Generic detail page for different content types"""
    try:
        # This is a placeholder for detailed views
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'title': f"{content_type.title()} Detail"
        }
        return render_template('detail.html', **context)
    except Exception as e:
        logger.error(f"Error loading detail page: {str(e)}")
        safe_report_exception(e)
        flash(f'Error loading {content_type} detail', 'danger')
        return redirect(url_for('frontend.dashboard'))

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
        return render_template('500.html', error_code=404, error_message="Page Not Found"), 404
    except Exception as render_error:
        logger.error(f"Error rendering 404 page: {str(render_error)}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Page Not Found</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; }
                h1 { color: #d63031; }
            </style>
        </head>
        <body>
            <h1>404 - Page Not Found</h1>
            <p>The requested page does not exist.</p>
            <p><a href="/">Return to Home</a></p>
        </body>
        </html>
        """, 404

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    logger.error(traceback.format_exc())
    safe_report_exception(e)
    try:
        return render_template('500.html'), 500
    except Exception as render_error:
        logger.error(f"Error rendering 500 page: {str(render_error)}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Server Error</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; }
                h1 { color: #d63031; }
            </style>
        </head>
        <body>
            <h1>500 - Server Error</h1>
            <p>An unexpected error occurred.</p>
            <p><a href="/">Return to Home</a></p>
        </body>
        </html>
        """, 500

@frontend_app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors"""
    logger.error(f"400 error: {str(e)}")
    
    # Check if this is a CSRF error
    if isinstance(e, BadRequest) and 'CSRF' in str(e):
        logger.error("CSRF validation failed")
        flash('Your session has expired or there was a security issue. Please try again.', 'danger')
        return redirect(url_for('frontend.login'))
    
    # For other 400 errors
    try:
        return render_template('500.html', 
                            error_code=400,
                            error_message=f"Bad Request: {str(e)}"), 400
    except Exception as render_error:
        logger.error(f"Error rendering 400 page: {str(render_error)}")
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bad Request</title>
            <style>
                body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
                h1 {{ color: #d63031; }}
            </style>
        </head>
        <body>
            <h1>400 - Bad Request</h1>
            <p>{str(e)}</p>
            <p><a href="/">Return to Home</a></p>
        </body>
        </html>
        """, 400

# ====== Context Processors ======

@frontend_app.context_processor
def inject_global_data():
    """Inject global data into templates"""
    # Flask-WTF handles CSRF token automatically
    return {
        'now': datetime.now(),
        'environment': ENVIRONMENT,
        'version': VERSION,
        'project_id': getattr(Config, 'GCP_PROJECT', None),
        'debug_mode': DEBUG_MODE,
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
        get_confidence_width=get_confidence_width,
    )

# Initialize module
logger.info("Frontend module initialized successfully")
