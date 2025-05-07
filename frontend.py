"""
Optimized frontend module for Threat Intelligence Platform.
Handles web interface, user authentication, and dashboard views.
"""

import os
import json
import logging
import hashlib
import time
import secrets
import threading
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from typing import Dict, List, Any, Optional

from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask import flash, session, abort, g, current_app
from werkzeug.exceptions import BadRequest

# Import config module for centralized configuration
import config
from config import Config, SecretManager

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
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
logging.basicConfig(level=LOG_LEVEL, 
                    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')

# Create Blueprint for the frontend module
frontend_app = Blueprint('frontend', __name__, template_folder='templates', static_folder='static')

# ====== Session and Security Functions ======

@frontend_app.before_request
def before_request():
    """Ensure session is properly established."""
    if '_id' not in session:
        session.permanent = True
        session['_id'] = secrets.token_hex(16)
        if DEBUG_MODE:
            logger.debug(f"New session created: {session.get('_id')}")

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
            # Skip cache for authenticated users
            if session.get('logged_in'):
                return func(*args, **kwargs)
            
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

@lru_cache(maxsize=1)
def get_api_key() -> str:
    """Get API key from config with optimized caching."""
    # Try config module attributes
    api_key = getattr(Config, 'API_KEY', None)
    
    # Try cached config
    if not api_key:
        api_keys_config = config.get_cached_config('api-keys') if hasattr(config, 'get_cached_config') else None
        if api_keys_config and 'platform_api_key' in api_keys_config:
            api_key = api_keys_config['platform_api_key']
    
    # Fall back to environment variable
    return api_key or os.environ.get('API_KEY', '')

@api_cache(timeout=CACHE_TIMEOUT)
def api_request(endpoint: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Dict:
    """Make internal API request with caching and optimized error handling."""
    try:
        import requests
        
        # Construct URL
        base_url = request.url_root.rstrip('/')
        url = f"{base_url}/api/{endpoint.lstrip('/')}"
        
        # Add API key and CSRF token
        headers = {"Content-Type": "application/json"}
        api_key = get_api_key()
        if api_key:
            headers["X-API-Key"] = api_key
        
        csrf_token = session.get('csrf_token')
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        
        # Make request with optimized retries
        max_retries = 3
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                
                # Break on success or specific failure
                if response.status_code < 500:
                    break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                pass
                
            # Exponential backoff
            if attempt < max_retries - 1:
                time.sleep(0.5 * (2 ** attempt))
        
        # Report slow requests
        request_time = time.time() - start_time
        if request_time > 1.0:
            logger.info(f"Slow API request ({request_time:.2f}s): {method} {url}")
        
        # Handle response
        if not response or response.status_code != 200:
            logger.warning(f"API request failed: {getattr(response, 'status_code', 'No response')} - {getattr(response, 'text', '')[:100]}")
            return {
                "error": f"API request failed with status {getattr(response, 'status_code', 'unknown')}",
                "status_code": getattr(response, 'status_code', 500),
                # Default structure for templates
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }
        
        # Parse JSON response
        try:
            return response.json() if response.text else {}
        except json.JSONDecodeError:
            return {
                "error": "Invalid JSON response",
                # Default structure for templates
                "feeds": {"total_sources": 0},
                "iocs": {"total": 0, "types": []},
                "campaigns": {"total_campaigns": 0},
                "analyses": {"total_analyses": 0}
            }
    
    except Exception as e:
        logger.error(f"API request error ({endpoint}): {str(e)}")
        safe_report_exception(e)
        return {
            "error": f"API error: {str(e)}",
            # Default structure for templates
            "feeds": {"total_sources": 0},
            "iocs": {"total": 0, "types": []},
            "campaigns": {"total_campaigns": 0},
            "analyses": {"total_analyses": 0}
        }

# ====== Authentication Functions ======

def login_required(func):
    """Decorator requiring login for views."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            session['next_url'] = request.url
            flash('Please log in to continue', 'info')
            return redirect(url_for('frontend.login'))
        return func(*args, **kwargs)
    return decorated_function

def admin_required(func):
    """Decorator requiring admin role."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            session['next_url'] = request.url
            flash('Please log in to continue', 'info')
            return redirect(url_for('frontend.login'))
        if session.get('role') != 'admin':
            flash('Admin privileges required', 'danger')
            return render_template('auth.html', page_type='not_authorized')
        return func(*args, **kwargs)
    return decorated_function

def load_users() -> Dict[str, Dict]:
    """Load user data with optimized config access."""
    try:
        # Try to ensure admin password sync first (critical fix)
        if hasattr(SecretManager, 'ensure_password_sync'):
            SecretManager.ensure_password_sync()
        
        # Try config module first
        auth_config = None
        if hasattr(config, 'get_cached_config'):
            auth_config = config.get_cached_config('auth-config', force_refresh=True)
        
        if auth_config and 'users' in auth_config and auth_config['users']:
            logger.info(f"Loaded {len(auth_config['users'])} users from auth config")
            return auth_config.get('users', {})
        
        # Check environment variables
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if admin_password:
            logger.info("Loaded admin password from environment variables")
            return {
                'admin': {
                    'password': hash_password(admin_password),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            
        # Development fallback
        if ENVIRONMENT != 'production':
            logger.warning("Using default admin account for development")
            return {
                'admin': {
                    'password': hash_password('admin'),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        
        # Config module fallback
        if hasattr(Config, 'ADMIN_PASSWORD') and Config.ADMIN_PASSWORD:
            logger.info("Using admin password from Config class")
            return {
                'admin': {
                    'password': hash_password(Config.ADMIN_PASSWORD),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            
        logger.error("No user accounts found")
        return {}
        
    except Exception as e:
        logger.error(f"Error loading users: {str(e)}")
        safe_report_exception(e)
        
        # Development fallback
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
    """Verify password with support for multiple hash formats."""
    if not stored_password or not provided_password:
        return False
    
    # Simple hash comparison
    provided_hash = hash_password(provided_password)
    if stored_password == provided_hash:
        return True
    
    # Direct string comparison in dev mode (dangerous in production)
    if ENVIRONMENT != 'production' and stored_password == provided_password:
        logger.warning("Dev-mode direct password comparison used")
        return True
        
    # Werkzeug compatibility for legacy hashes
    if stored_password.startswith('pbkdf2:sha256:'):
        try:
            from werkzeug.security import check_password_hash
            return check_password_hash(stored_password, provided_password)
        except ImportError:
            pass
    
    # Always log failures to help debug authentication issues
    logger.warning(f"Password verification failed. Stored hash: {stored_password[:10]}... Provided hash: {provided_hash[:10]}...")
    
    return False

def hash_password(password: str) -> str:
    """Hash password using secure method."""
    if not password:
        return ""
    return hashlib.sha256(password.encode()).hexdigest()

# ====== Route Handlers ======

@frontend_app.route('/')
def index():
    """Root redirects to dashboard or login."""
    if session.get('logged_in'):
        return redirect(url_for('frontend.dashboard'))
    return redirect(url_for('frontend.login'))

@frontend_app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page handler."""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        if not username or not password:
            error = "Username and password are required"
            return render_template('auth.html', page_type='login', error=error, now=datetime.now())
        
        # Load users from config - force refresh to ensure we have the latest data
        users = load_users()
        
        if username in users:
            user = users[username]
            
            # Additional logging for transparency
            logger.info(f"Login attempt for {username}")
            
            # Verify password - improved with better error handling
            if verify_password(user.get('password', ''), password):
                # Set up session
                session.clear()
                session.permanent = remember
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user.get('role', 'readonly')
                session['_id'] = secrets.token_hex(16)
                
                # Update last login time
                try:
                    auth_config = config.get_cached_config('auth-config', force_refresh=True)
                    if auth_config and 'users' in auth_config and username in auth_config['users']:
                        auth_config['users'][username]['last_login'] = datetime.utcnow().isoformat()
                        config.create_or_update_secret('auth-config', auth_config)
                except Exception as e:
                    logger.warning(f"Failed to update last login time: {str(e)}")
                
                logger.info(f"Successful login: {username}")
                flash(f'Welcome, {username}!', 'success')
                
                # Clear cache and redirect
                clear_api_cache()
                next_page = session.pop('next_url', None) or request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('frontend.dashboard'))
            else:
                error = "Invalid password"
                logger.warning(f"Failed login: Invalid password for {username}")
                
                # Debug logging to help diagnose authentication issues
                if DEBUG_MODE:
                    stored_hash = user.get('password', '')
                    provided_hash = hash_password(password)
                    logger.debug(f"Auth debug - Stored hash: {stored_hash[:10]}... Provided hash: {provided_hash[:10]}...")
        else:
            error = "Invalid username"
            logger.warning(f"Failed login: Invalid username {username}")
    
    return render_template('auth.html', page_type='login', error=error, now=datetime.now())

@frontend_app.route('/profile')
@login_required
def profile():
    """User profile page."""
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
        flash('Error loading profile', 'error')
        safe_report_exception(e)
        return redirect(url_for('frontend.dashboard'))

@frontend_app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Handle password change requests."""
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        users = load_users()
        user = users.get(session.get('username'))
        
        if not user or not verify_password(user.get('password', ''), current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('frontend.profile'))
        
        # Create updated password hash
        password_hash = hash_password(new_password)
        
        # Update in Secret Manager if possible
        try:
            auth_config = config.get_cached_config('auth-config')
            if auth_config and 'users' in auth_config:
                auth_config['users'][session.get('username')]['password'] = password_hash
                config.create_or_update_secret('auth-config', auth_config)
                flash('Password changed successfully', 'success')
                
                # Special handling for admin user
                if session.get('username') == 'admin':
                    # Also update admin-initial-password if it exists
                    config.create_or_update_secret('admin-initial-password', new_password)
                    logger.info("Updated admin-initial-password after password change")
            else:
                flash('Could not update password in configuration', 'warning')
        except Exception as e:
            logger.warning(f"Error updating password: {str(e)}")
            flash('Password updated in memory only', 'warning')
        
        return redirect(url_for('frontend.profile'))
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        safe_report_exception(e)
        flash('Error changing password', 'danger')
        return redirect(url_for('frontend.profile'))

@frontend_app.route('/logout')
def logout():
    """Logout handler."""
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
    """Dashboard view with dynamic content loading."""
    try:
        # Get view parameters
        current_view = view or request.args.get('view', 'dashboard')
        days = int(request.args.get('days', '30'))
        
        # Base context
        context = {
            'current_view': current_view,
            'days': days,
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
            'campaigns': {
                'title': 'Threat Campaigns',
                'subtitle': 'Detected threat actor campaigns and activities',
                'icon': 'project-diagram'
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
        try:
            stats_response = api_request('stats', params={"days": days}) or {}
            
            # Ensure stats structure
            context['stats'] = {
                'feeds': stats_response.get('feeds', {'total_sources': 0}),
                'iocs': stats_response.get('iocs', {'total': 0, 'types': []}),
                'campaigns': stats_response.get('campaigns', {'total_campaigns': 0}),
                'analyses': stats_response.get('analyses', {'total_analyses': 0}),
                'timestamp': stats_response.get('timestamp', datetime.utcnow().isoformat())
            }
            
            # Extract trends
            if isinstance(stats_response, dict) and 'feeds' in stats_response:
                context['feed_trend'] = stats_response.get('feeds', {}).get('growth_rate', 0)
                context['ioc_trend'] = stats_response.get('iocs', {}).get('growth_rate', 0)
                context['campaign_trend'] = stats_response.get('campaigns', {}).get('growth_rate', 0)
                context['analysis_trend'] = stats_response.get('analyses', {}).get('growth_rate', 0)
                
                # IOC type data
                context['ioc_type_labels'] = [item.get('type', '') for item in stats_response.get('iocs', {}).get('types', [])]
                context['ioc_type_values'] = [item.get('count', 0) for item in stats_response.get('iocs', {}).get('types', [])]
            
            # Load view-specific data
            if current_view == 'feeds':
                feeds_response = api_request('feeds') or {}
                context['feed_items'] = feeds_response.get('feed_details', [])
                context['feed_type_descriptions'] = {
                    feed.get('name', ''): feed.get('description', 'Threat Intelligence Feed') 
                    for feed in context['feed_items'] if isinstance(feed, dict) and 'name' in feed
                }
                
            elif current_view == 'iocs':
                iocs_response = api_request('iocs', params={"days": days}) or {}
                context['ioc_items'] = iocs_response.get('records', [])
                
            elif current_view == 'campaigns':
                campaigns_response = api_request('campaigns', params={"days": days}) or {}
                context['campaigns'] = campaigns_response.get('campaigns', [])
                
            else:
                # Dashboard view extras
                today = datetime.now().date()
                date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
                context['activity_dates'] = date_range
                
                # Activity data
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
                    context['activity_counts'] = [20 + i * 2 for i in range(days)]
                
                # Load additional dashboard data
                campaigns_response = api_request('campaigns', params={"days": days}) or {}
                context['campaigns'] = campaigns_response.get('campaigns', [])[:3]
                
                iocs_response = api_request('iocs', params={"days": days}) or {}
                context['top_iocs'] = iocs_response.get('records', [])[:4]
                
                threat_summary = api_request(f"threat_summary", params={"days": days}) or {}
                context['threat_summary'] = threat_summary
                
                geo_stats = api_request(f"iocs/geo", params={"days": days}) or {}
                context['geo_stats'] = geo_stats.get('countries', [])
                
        except Exception as e:
            logger.error(f"Error loading dashboard data: {str(e)}")
            safe_report_exception(e)
            
            # Initialize empty data structures
            context.update({
                'stats': {'feeds': {}, 'campaigns': {}, 'iocs': {'types': []}, 'analyses': {}},
                'feed_trend': 0,
                'ioc_trend': 0,
                'campaign_trend': 0,
                'analysis_trend': 0,
                'ioc_type_labels': [],
                'ioc_type_values': []
            })
            
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
        logger.error(f"Unexpected dashboard error: {str(e)}")
        safe_report_exception(e)
        flash('An unexpected error occurred', 'danger')
        return redirect(url_for('frontend.login'))

# User Management Routes
@frontend_app.route('/users')
@login_required
@admin_required
def users():
    """User management page."""
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
    """Add new user."""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role', 'readonly')
            
            # Load existing users
            auth_config = config.get_cached_config('auth-config')
            if not auth_config:
                auth_config = {"users": {}}
            elif "users" not in auth_config:
                auth_config["users"] = {}
                
            # Check if user exists
            if username in auth_config["users"]:
                flash('Username already exists', 'danger')
                return redirect(url_for('frontend.add_user_route'))
            
            # Create new user
            auth_config["users"][username] = {
                'password': hash_password(password),
                'role': role,
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Save to Secret Manager
            if config.create_or_update_secret('auth-config', auth_config):
                flash(f'User {username} created successfully', 'success')
            else:
                flash(f'User created but not saved to configuration', 'warning')
                
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
    """Edit user."""
    users = load_users()
    if username not in users:
        flash('User not found', 'danger')
        return redirect(url_for('frontend.users'))
    
    if request.method == 'POST':
        try:
            password = request.form.get('password')
            role = request.form.get('role')
            
            # Get auth config
            auth_config = config.get_cached_config('auth-config')
            if not auth_config or "users" not in auth_config or username not in auth_config["users"]:
                flash('User configuration not found', 'danger')
                return redirect(url_for('frontend.users'))
            
            # Update user
            if password:
                auth_config["users"][username]['password'] = hash_password(password)
                
                # Special handling for admin user
                if username == 'admin':
                    # Also update admin-initial-password
                    config.create_or_update_secret('admin-initial-password', password)
                    logger.info("Updated admin-initial-password during user edit")
                    
            if role:
                auth_config["users"][username]['role'] = role
            
            # Save to configuration
            if config.create_or_update_secret('auth-config', auth_config):
                flash(f'User {username} updated successfully', 'success')
                
                # Re-sync passwords if admin
                if username == 'admin' and hasattr(SecretManager, 'ensure_password_sync'):
                    SecretManager.ensure_password_sync()
                    logger.info("Re-synchronized admin password after edit")
            else:
                flash(f'Changes not saved to configuration', 'warning')
                
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
    """Delete user."""
    try:
        # Prevent deleting admin user
        if username == 'admin':
            flash('Cannot delete admin user', 'danger')
            return redirect(url_for('frontend.users'))
            
        # Get auth config
        auth_config = config.get_cached_config('auth-config')
        if not auth_config or "users" not in auth_config:
            flash('User configuration not found', 'danger')
            return redirect(url_for('frontend.users'))
        
        # Delete user
        if username in auth_config["users"]:
            del auth_config["users"][username]
            
            # Save changes
            if config.create_or_update_secret('auth-config', auth_config):
                flash(f'User {username} deleted successfully', 'success')
            else:
                flash(f'User deleted but changes not saved to configuration', 'warning')
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
    """Trigger threat data ingestion."""
    try:
        if request.method == 'POST':
            # Trigger ingestion
            result = api_request('admin/ingest', method='POST', data={'process_all': True})
            
            if result.get('error'):
                flash(f'Error triggering ingestion: {result["error"]}', 'danger')
            else:
                flash('Threat data ingestion triggered successfully', 'success')
            
            return redirect(url_for('frontend.dashboard'))
        
        # For GET, render autosubmit form
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
        flash('Error triggering ingestion', 'danger')
        return redirect(url_for('frontend.dashboard'))

# Shortcut routes
@frontend_app.route('/feeds')
@login_required
def feeds():
    """Redirect to dashboard feeds view."""
    return redirect(url_for('frontend.dashboard', view='feeds'))

@frontend_app.route('/iocs')
@login_required
def iocs():
    """Redirect to dashboard IOCs view."""
    return redirect(url_for('frontend.dashboard', view='iocs'))

@frontend_app.route('/campaigns')
@login_required
def campaigns():
    """Redirect to dashboard campaigns view."""
    return redirect(url_for('frontend.dashboard', view='campaigns'))

@frontend_app.route('/detail/<content_type>/<path:identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Generic detail page for different content types."""
    try:
        return render_template('detail.html', 
                              content_type=content_type,
                              identifier=identifier,
                              title=f"{content_type.title()} Detail")
    except Exception as e:
        logger.error(f"Error loading detail page: {str(e)}")
        safe_report_exception(e)
        flash(f'Error loading {content_type} detail', 'danger')
        return redirect(url_for('frontend.dashboard'))

# ====== Template Filters and Context ======

# Define datetime formatter function
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
    try:
        return render_template('500.html', error_code=404, error_message="Page Not Found"), 404
    except Exception:
        return """
        <html><body><h1>404 - Page Not Found</h1><p>The requested page does not exist.</p>
        <p><a href="/">Return to Home</a></p></body></html>
        """, 404

@frontend_app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {str(e)}")
    safe_report_exception(e)
    try:
        return render_template('500.html'), 500
    except Exception:
        return """
        <html><body><h1>500 - Server Error</h1><p>An unexpected error occurred.</p>
        <p><a href="/">Return to Home</a></p></body></html>
        """, 500

@frontend_app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors."""
    logger.error(f"400 error: {str(e)}")
    
    # Handle CSRF errors
    if isinstance(e, BadRequest) and 'CSRF' in str(e):
        flash('Your session has expired or there was a security issue. Please try again.', 'danger')
        return redirect(url_for('frontend.login'))
    
    # Handle other 400 errors
    try:
        return render_template('500.html', error_code=400, error_message=f"Bad Request: {str(e)}"), 400
    except Exception:
        return f"""
        <html><body><h1>400 - Bad Request</h1><p>{str(e)}</p>
        <p><a href="/">Return to Home</a></p></body></html>
        """, 400

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

# Initialize module
logger.info("Frontend module initialized successfully")
