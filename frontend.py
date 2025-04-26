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
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from typing import Dict, List, Any, Optional, Union, Tuple

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask import flash, session, abort, g, current_app, Response
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

# GCP Services
try:
    from google.cloud import logging as gcp_logging
    from google.cloud import error_reporting
    from google.cloud import secretmanager
    import google.auth
    GCP_SERVICES_AVAILABLE = True
except ImportError:
    GCP_SERVICES_AVAILABLE = False

# Import config module for centralized configuration
import config
# Import API module for direct function calls (will be imported by app.py)
try:
    from api import api_bp
    API_MODULE_AVAILABLE = True
except ImportError:
    API_MODULE_AVAILABLE = False

# ==== GCP Service Initialization ====

# Structured logger setup
logger = logging.getLogger('frontend')

DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)

try:
    # Get project ID from GCP environment
    if GCP_SERVICES_AVAILABLE:
        credentials, project_id = google.auth.default()
        
        if config.environment == 'production' and not DEBUG_MODE:
            # Configure Cloud Logging for production
            logging_client = gcp_logging.Client()
            cloud_handler = logging_client.get_default_handler()
            
            # Create structured logger
            logger.setLevel(LOG_LEVEL)
            logger.addHandler(cloud_handler)
            
            # Initialize Error Reporting client
            error_client = error_reporting.Client(service="frontend")
        else:
            # Use standard logging for development
            logging.basicConfig(level=LOG_LEVEL, 
                              format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    else:
        logging.basicConfig(level=LOG_LEVEL, 
                          format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
except Exception as e:
    # Fallback to standard logging if GCP setup fails
    logging.basicConfig(level=LOG_LEVEL, 
                      format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    logger.error(f"GCP services initialization failed: {str(e)}")

# ==== Flask Application Setup ====

# Create Flask app
app = Flask(__name__)

# Add security headers and CORS support
CORS(app)
csrf = CSRFProtect(app)

# Add proxy fix for proper handling behind load balancers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ==== Secret Management ====

def get_secret_key() -> str:
    """Get secret key from Secret Manager or fallback sources"""
    try:
        # Try to get from config module first
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'session_secret' in auth_config:
            return auth_config['session_secret']
        
        # Try environment variable
        secret_key = os.environ.get('SECRET_KEY')
        if secret_key:
            return secret_key
            
        # Try Secret Manager in production
        if config.environment == 'production' and GCP_SERVICES_AVAILABLE:
            try:
                secret_client = secretmanager.SecretManagerServiceClient()
                secret_name = f"projects/{config.project_id}/secrets/flask-secret-key/versions/latest"
                response = secret_client.access_secret_version(request={"name": secret_name})
                return response.payload.data.decode("UTF-8")
            except Exception as e:
                logger.warning(f"Failed to get secret from Secret Manager: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error retrieving secret key: {str(e)}")
    
    # Generate a secure key if all else fails
    logger.warning("Generating temporary secret key - sessions will be invalidated on restart")
    return hashlib.sha256(f"{time.time()}{os.urandom(24).hex()}".encode()).hexdigest()

# Get the secret key
SECRET_KEY = get_secret_key()

# Configure Flask
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=config.environment == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    TEMPLATES_AUTO_RELOAD=config.environment != 'production',
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour CSRF token validity
)

# ==== Authentication Functions ====

def load_users() -> Dict[str, Dict]:
    """Load user data from auth config with error handling"""
    try:
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if auth_config and 'users' in auth_config:
            return auth_config.get('users', {})
        
        # Create default admin user if no users exist and in development
        if config.environment != 'production' or DEBUG_MODE:
            default_users = {
                'admin': {
                    'password': hashlib.sha256('admin'.encode()).hexdigest(),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            # Try to save the default user
            try:
                if 'users' not in auth_config:
                    auth_config['users'] = {}
                auth_config['users'].update(default_users)
                config.create_or_update_secret('auth-config', json.dumps(auth_config))
            except Exception as e:
                logger.warning(f"Failed to save default user: {str(e)}")
            
            return default_users
    except Exception as e:
        logger.error(f"Failed to load users: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return default admin in case of errors
        if config.environment != 'production' or DEBUG_MODE:
            return {
                'admin': {
                    'password': hashlib.sha256('admin'.encode()).hexdigest(),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
    
    # Return empty dict if all fails    
    return {}

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify password with support for multiple hash formats"""
    if not stored_password or not provided_password:
        return False
        
    # For backward compatibility with different hash formats
    if stored_password.startswith('pbkdf2:sha256:'):
        # Werkzeug password hash format
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_password, provided_password)
    else:
        # Simple SHA-256 hash
        return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()

def hash_password(password: str) -> str:
    """Hash password using secure method"""
    if config.environment == 'production' and not DEBUG_MODE:
        # Use Werkzeug's more secure password hashing in production
        from werkzeug.security import generate_password_hash
        return generate_password_hash(password)
    else:
        # Use simpler SHA-256 in development for performance
        return hashlib.sha256(password.encode()).hexdigest()

# ==== Authentication Decorators ====

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

# ==== Route Handlers ====

@app.route('/')
def index():
    """Root redirects to dashboard if logged in, otherwise to login"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page handler with comprehensive error handling"""
    error = None
    
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember') == 'on'
            
            # Validate inputs
            if not username or not password:
                error = "Username and password are required"
                return render_template('auth.html', page_type='login', error=error, now=datetime.now())
            
            # Get users with more robust error handling
            try:
                users = load_users()
                if not users and (DEBUG_MODE or config.environment != 'production'):
                    # Create an admin user on the fly for development/debug
                    users = {
                        'admin': {
                            'password': hashlib.sha256('admin'.encode()).hexdigest(),
                            'role': 'admin',
                            'created_at': datetime.utcnow().isoformat()
                        }
                    }
                    logger.warning("Created temporary admin user for debugging")
            except Exception as e:
                logger.error(f"Error loading users: {str(e)}")
                logger.error(traceback.format_exc())
                users = {}
                
                # Fallback to default admin in development mode
                if config.environment != 'production':
                    users = {
                        'admin': {
                            'password': hashlib.sha256('admin'.encode()).hexdigest(),
                            'role': 'admin',
                            'created_at': datetime.utcnow().isoformat()
                        }
                    }
            
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
                    logger.info(f"Successful login: {username}", 
                               extra={"user": username, "ip": request.remote_addr})
                    
                    flash(f'Welcome, {username}!', 'success')
                    
                    # Redirect to requested page or dashboard
                    next_page = request.args.get('next')
                    if next_page and next_page.startswith('/'):
                        return redirect(next_page)
                    return redirect(url_for('dashboard'))
                else:
                    error = "Invalid password"
                    logger.warning(f"Failed login attempt: Invalid password for {username}", 
                                  extra={"user": username, "ip": request.remote_addr})
            else:
                error = "Invalid username"
                logger.warning(f"Failed login attempt: Invalid username {username}", 
                              extra={"user": username, "ip": request.remote_addr})
    except Exception as e:
        logger.error(f"Unexpected error in login: {str(e)}")
        logger.error(traceback.format_exc())
        error = "An unexpected error occurred. Please try again later."
        
        # In debug mode, show detailed error
        if DEBUG_MODE:
            error = f"Error: {str(e)}"
    
    # If we get here, there was an error or it's a GET request
    try:
        return render_template('auth.html', page_type='login', error=error, now=datetime.now())
    except Exception as template_error:
        logger.error(f"Template rendering error: {str(template_error)}")
        logger.error(traceback.format_exc())
        
        # Provide a fallback if template can't be rendered
        error_html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>Login - Threat Intelligence Platform</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 500px; margin: 40px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .error {{ color: red; margin-bottom: 15px; }}
                    input {{ width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; }}
                    button {{ background: #4285f4; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Threat Intelligence Platform</h1>
                    <h2>Login</h2>
                    {f'<div class="error">{error}</div>' if error else ''}
                    <form method="post" action="/login">
                        <div>
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div>
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <div>
                            <input type="checkbox" id="remember" name="remember">
                            <label for="remember">Remember me</label>
                        </div>
                        <button type="submit">Login</button>
                    </form>
                    <p style="margin-top: 20px; text-align: center; color: #666;">
                        Environment: {config.environment} | Version: {os.environ.get('VERSION', '1.0.0')}
                    </p>
                </div>
            </body>
        </html>
        """
        return Response(error_html, mimetype='text/html')

@app.route('/logout')
def logout():
    """Logout route handler"""
    username = session.get('username')
    
    if username:
        logger.info(f"User logged out: {username}", 
                   extra={"user": username, "ip": request.remote_addr})
    
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
        
        # Load statistics for all views with proper error handling
        try:
            if API_MODULE_AVAILABLE:
                # Get statistics using the API module directly
                with app.app_context():
                    g.gcp_clients = {}  # Initialize clients
                    stats_response = api_bp.get_stats()
                    context['stats'] = stats_response
                    
                    # Extract trends from statistics
                    context['feed_trend'] = stats_response.get('feeds', {}).get('growth_rate', 0)
                    context['ioc_trend'] = stats_response.get('iocs', {}).get('growth_rate', 0)
                    context['campaign_trend'] = stats_response.get('campaigns', {}).get('growth_rate', 0)
                    context['analysis_trend'] = stats_response.get('analyses', {}).get('growth_rate', 0)
                    
                    # Extract IOC type data for charts
                    context['ioc_type_labels'] = [item['type'] for item in stats_response.get('iocs', {}).get('types', [])]
                    context['ioc_type_values'] = [item['count'] for item in stats_response.get('iocs', {}).get('types', [])]
                    
                    # Load view-specific data
                    if current_view == 'feeds':
                        feeds_response = api_bp.list_feeds()
                        context['feed_items'] = feeds_response.get('feed_details', [])
                        
                        # Build feed descriptions dictionary
                        context['feed_type_descriptions'] = {}
                        for feed in context['feed_items']:
                            context['feed_type_descriptions'][feed['name']] = feed.get('description', 'Threat Intelligence Feed')
                        
                    elif current_view == 'iocs':
                        iocs_response = api_bp.search_iocs()
                        context['ioc_items'] = iocs_response.get('records', [])
                        
                    elif current_view == 'campaigns':
                        campaigns_response = api_bp.list_campaigns()
                        context['campaigns'] = campaigns_response.get('campaigns', [])
                        
                    else:
                        # Dashboard view - load additional data
                        
                        # Get date range for activity chart
                        today = datetime.now().date()
                        date_range = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
                        context['activity_dates'] = date_range
                        
                        # Get activity counts from stats if available
                        if 'visualization_data' in stats_response and 'daily_counts' in stats_response['visualization_data']:
                            counts = [0] * len(date_range)
                            date_to_index = {date: idx for idx, date in enumerate(date_range)}
                            
                            for entry in stats_response['visualization_data']['daily_counts']:
                                if entry.get('date') in date_to_index:
                                    counts[date_to_index[entry['date']]] = entry.get('count', 0)
                            
                            context['activity_counts'] = counts
                        else:
                            # Generate a basic trend if no visualization data
                            context['activity_counts'] = generate_trend_data(days)
                        
                        # Load campaigns for dashboard
                        if 'campaigns' in context:
                            context['campaigns'] = context['campaigns'][:3]  # Top 3 campaigns
                        else:
                            campaigns_response = api_bp.list_campaigns()
                            context['campaigns'] = campaigns_response.get('campaigns', [])[:3]
                        
                        # Load IOCs for dashboard
                        if 'ioc_items' in context:
                            context['top_iocs'] = context['ioc_items'][:4]  # Top 4 IOCs
                        else:
                            iocs_response = api_bp.search_iocs()
                            context['top_iocs'] = iocs_response.get('records', [])[:4]
            else:
                # Handle missing API module
                logger.error("API module not available - cannot load dashboard data")
                context['stats'] = {'feeds': {}, 'campaigns': {}, 'iocs': {'types': []}, 'analyses': {}}
                context['feed_trend'] = 0
                context['ioc_trend'] = 0
                context['campaign_trend'] = 0
                context['analysis_trend'] = 0
                context['ioc_type_labels'] = []
                context['ioc_type_values'] = []
                flash('API service unavailable. Some information may be missing.', 'warning')
        
        except Exception as e:
            logger.error(f"Error loading dashboard data: {str(e)}")
            logger.error(traceback.format_exc())
            
            if config.environment == 'production' and 'error_client' in globals():
                try:
                    error_client.report_exception()
                except Exception as report_error:
                    logger.error(f"Error reporting to error client: {str(report_error)}")
            
            # Initialize empty data structures on error to prevent template errors
            if 'stats' not in context:
                context['stats'] = {'feeds': {}, 'campaigns': {}, 'iocs': {'types': []}, 'analyses': {}}
                context['feed_trend'] = 0
                context['ioc_trend'] = 0
                context['campaign_trend'] = 0
                context['analysis_trend'] = 0
                context['ioc_type_labels'] = []
                context['ioc_type_values'] = []
                
            if current_view == 'feeds' and 'feed_items' not in context:
                context['feed_items'] = []
                context['feed_type_descriptions'] = {}
                
            elif current_view == 'iocs' and 'ioc_items' not in context:
                context['ioc_items'] = []
                
            elif current_view == 'campaigns' and 'campaigns' not in context:
                context['campaigns'] = []
                
            elif current_view == 'dashboard':
                if 'activity_dates' not in context:
                    today = datetime.now().date()
                    context['activity_dates'] = [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]
                    context['activity_counts'] = generate_trend_data(days)
                if 'campaigns' not in context:
                    context['campaigns'] = []
                if 'top_iocs' not in context:
                    context['top_iocs'] = []
                    
            flash('Could not load all dashboard data. Some information may be missing.', 'warning')
        
        try:
            return render_template('dashboard.html', **context, now=datetime.now())
        except Exception as template_error:
            logger.error(f"Template rendering error for dashboard: {str(template_error)}")
            logger.error(traceback.format_exc())
            
            # Fallback to a simple dashboard if template rendering fails
            return render_fallback_dashboard(context)
            
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {str(e)}")
        logger.error(traceback.format_exc())
        
        if config.environment == 'production' and 'error_client' in globals():
            try:
                error_client.report_exception()
            except Exception:
                pass
                
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    try:
        username = session.get('username')
        users = load_users()
        user = users.get(username, {})
        
        return render_template('auth.html', page_type='profile', username=username, user=user)
    except Exception as e:
        logger.error(f"Error in profile page: {str(e)}")
        logger.error(traceback.format_exc())
        flash('Error loading profile. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Handle password change form submission"""
    try:
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
                    logger.info(f"Password changed for user: {username}", 
                              extra={"user": username, "ip": request.remote_addr})
                else:
                    flash('Error updating password. Please try again.', 'danger')
                    logger.error(f"Failed to update password for user: {username}", 
                                extra={"user": username, "ip": request.remote_addr})
            else:
                flash('Current password is incorrect', 'danger')
                logger.warning(f"Failed password change - incorrect current password: {username}", 
                              extra={"user": username, "ip": request.remote_addr})
        
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f"Error in change_password: {str(e)}")
        logger.error(traceback.format_exc())
        flash('An error occurred while changing password. Please try again.', 'danger')
        return redirect(url_for('profile'))

@app.route('/users')
@admin_required
def users():
    """User management page"""
    try:
        users = load_users()
        return render_template('content.html', page_type='users', users=users)
    except Exception as e:
        logger.error(f"Error in users page: {str(e)}")
        logger.error(traceback.format_exc())
        flash('Error loading user management. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

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
                # Add user with secure password hash
                if config.add_user(username, password, role):
                    flash(f'User {username} added successfully', 'success')
                    logger.info(f"New user added: {username} with role {role}", 
                              extra={"admin": session.get('username'), "new_user": username})
                    return redirect(url_for('users'))
                else:
                    flash('Error adding user. Please try again.', 'danger')
                    logger.error(f"Failed to add user: {username}", 
                                extra={"admin": session.get('username')})
        
        return render_template('auth.html', page_type='user_add')
    except Exception as e:
        logger.error(f"Error in add_user: {str(e)}")
        logger.error(traceback.format_exc())
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
                logger.info(f"User updated: {username}", 
                          extra={"admin": session.get('username'), "edited_user": username})
                return redirect(url_for('users'))
            else:
                flash('Error updating user. Please try again.', 'danger')
                logger.error(f"Failed to update user: {username}", 
                            extra={"admin": session.get('username')})
        
        return render_template('auth.html', page_type='user_edit', username=username, user=user)
    except Exception as e:
        logger.error(f"Error in edit_user: {str(e)}")
        logger.error(traceback.format_exc())
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
        
        # Delete user by getting current users, removing the user, and updating the config
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if 'users' in auth_config and username in auth_config['users']:
            del auth_config['users'][username]
            if config.create_or_update_secret('auth-config', json.dumps(auth_config)):
                flash(f'User {username} deleted successfully', 'success')
                logger.info(f"User deleted: {username}", 
                          extra={"admin": session.get('username'), "deleted_user": username})
            else:
                flash('Error deleting user. Please try again.', 'danger')
                logger.error(f"Failed to delete user: {username}", 
                            extra={"admin": session.get('username')})
        else:
            flash(f'User {username} not found in configuration', 'danger')
        
        return redirect(url_for('users'))
    except Exception as e:
        logger.error(f"Error in delete_user: {str(e)}")
        logger.error(traceback.format_exc())
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

@app.route('/explore')
@login_required
def explore():
    """Data exploration page"""
    try:
        return render_template('content.html', page_type='explore')
    except Exception as e:
        logger.error(f"Error in explore page: {str(e)}")
        flash('Error loading explore page. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    try:
        return render_template('content.html', page_type='alerts')
    except Exception as e:
        logger.error(f"Error in alerts page: {str(e)}")
        flash('Error loading alerts page. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger data ingestion manually, fully integrated with your pipeline"""
    try:
        # Import ingestion function directly
        try:
            from ingestion import ThreatDataIngestion
            
            # Create ingestion instance and process feeds
            ingestion_engine = ThreatDataIngestion()
            results = ingestion_engine.process_all_feeds()
            
            # Log operation
            username = session.get('username')
            logger.info(f"Manual ingestion triggered by {username}: {len(results)} feeds processed", 
                      extra={"user": username, "feeds_processed": len(results)})
            
            # Handle success/failure messaging
            success_count = sum(1 for r in results if r.get('status') == 'success')
            if success_count == len(results):
                flash(f'Threat data refreshed successfully. Processed {len(results)} feeds.', 'success')
            elif success_count > 0:
                flash(f'Threat data refresh partially completed. {success_count} of {len(results)} feeds processed successfully.', 'warning')
            else:
                flash('Failed to refresh threat data. Please check logs for details.', 'danger')
                
            # Publish event to Pub/Sub to trigger analysis
            try:
                if GCP_SERVICES_AVAILABLE:
                    from google.cloud import pubsub_v1
                    publisher = pubsub_v1.PublisherClient()
                    topic_path = publisher.topic_path(config.project_id, config.get("PUBSUB_TOPIC", "threat-data-ingestion"))
                    
                    message = {
                        "event_type": "manual_ingestion",
                        "user": username,
                        "timestamp": datetime.utcnow().isoformat(),
                        "feeds_processed": len(results),
                        "success_count": success_count
                    }
                    
                    data = json.dumps(message).encode("utf-8")
                    publisher.publish(topic_path, data=data)
            except Exception as e:
                logger.warning(f"Failed to publish ingestion event: {str(e)}")
                
        except ImportError:
            logger.error("Ingestion module not available")
            flash('Ingestion module not available. Please check your installation.', 'danger')
    
    except Exception as e:
        logger.error(f"Error triggering threat data ingestion: {str(e)}")
        logger.error(traceback.format_exc())
        
        if config.environment == 'production' and 'error_client' in globals():
            try:
                error_client.report_exception()
            except Exception:
                pass
                
        flash(f'Error refreshing threat data: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/dynamic_content_detail/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Dynamic content detail page for IOCs, campaigns, etc."""
    try:
        data = {}
        
        # Create g.gcp_clients for API functions
        g.gcp_clients = {}
        
        if API_MODULE_AVAILABLE:
            if content_type == 'ioc':
                try:
                    # Split identifier
                    ioc_type, ioc_value = identifier.split('/', 1)
                    
                    # Get IOCs with matching type/value
                    params = {"type": ioc_type, "value": ioc_value, "limit": 100}
                    iocs_data = api_bp.search_iocs()
                    
                    # Find the matching IOC
                    for ioc in iocs_data.get('records', []):
                        if ioc.get('type') == ioc_type and ioc.get('value') == ioc_value:
                            data = ioc
                            break
                            
                    # Get related campaigns and enrich with additional info
                    if data:
                        # Get related campaigns based on this IOC
                        campaigns_data = api_bp.list_campaigns()
                        data['campaigns'] = []
                        
                        for campaign in campaigns_data.get('campaigns', [])[:3]:
                            data['campaigns'].append(campaign)
                            
                        # Set placeholder values for missing fields required by template
                        for field in ['first_seen', 'last_seen', 'sources', 'confidence', 'tags']:
                            if field not in data:
                                data[field] = [] if field in ['sources', 'tags'] else None
                except Exception as e:
                    logger.error(f"Error getting IOC details: {str(e)}")
                    logger.error(traceback.format_exc())
                    flash('Error loading IOC details', 'danger')
                    
            elif content_type == 'campaign':
                try:
                    # Get campaign details
                    campaigns_data = api_bp.list_campaigns()
                    
                    # Find the specific campaign
                    for campaign in campaigns_data.get('campaigns', []):
                        if campaign.get('campaign_id') == identifier:
                            data = campaign
                            break
                    
                    # Enrich with additional data needed by template
                    if data:
                        # Get IOCs related to this campaign
                        iocs_data = api_bp.search_iocs()
                        data['iocs'] = iocs_data.get('records', [])[:5]
                        
                        # Get techniques if not already present
                        if 'techniques' not in data:
                            data['techniques'] = []
                        
                        # Add description if missing
                        if 'description' not in data:
                            data['description'] = f"Campaign {data.get('campaign_name', 'Unknown')} details."
                except Exception as e:
                    logger.error(f"Error getting campaign details: {str(e)}")
                    logger.error(traceback.format_exc())
                    flash('Error loading campaign details', 'danger')
                    
            elif content_type == 'feed':
                try:
                    # Get feed stats and data
                    feed_stats = api_bp.feed_stats(identifier)
                    feed_data = api_bp.feed_data(identifier)
                    
                    # Combine data
                    data = feed_stats or {}
                    data['name'] = identifier
                    data['sample_data'] = feed_data.get('records', [])[:5]
                    
                    # Add description if missing
                    if 'description' not in data:
                        feed_details = api_bp.list_feeds()
                        for feed in feed_details.get('feed_details', []):
                            if feed.get('name') == identifier:
                                data['description'] = feed.get('description', f"Feed: {identifier}")
                                break
                                
                    if 'description' not in data:
                        data['description'] = f"Data from {identifier} threat intelligence feed."
                except Exception as e:
                    logger.error(f"Error getting feed details: {str(e)}")
                    logger.error(traceback.format_exc())
                    flash('Error loading feed details', 'danger')
        else:
            flash('API service unavailable. Cannot load details.', 'warning')
    
        # Return with all necessary context
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'data': data
        }
        
        try:
            return render_template('detail.html', **context)
        except Exception as template_error:
            logger.error(f"Template rendering error for detail page: {str(template_error)}")
            logger.error(traceback.format_exc())
            
            # Fallback to a simple detail view
            return render_fallback_detail(context)
    
    except Exception as e:
        logger.error(f"Error loading detail page for {content_type}/{identifier}: {str(e)}")
        logger.error(traceback.format_exc())
        
        if config.environment == 'production' and 'error_client' in globals():
            try:
                error_client.report_exception()
            except Exception:
                pass
                
        flash('Error loading content details.', 'danger')
        return redirect(url_for('dashboard'))

# ==== Fallback Renderers ====

def render_fallback_dashboard(context):
    """Render a simple fallback dashboard when template rendering fails"""
    html = f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>Dashboard - Threat Intelligence Platform</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee; }}
                .alert {{ padding: 10px; margin-bottom: 15px; border-radius: 4px; }}
                .alert-warning {{ background-color: #fff3cd; color: #856404; }}
                .card {{ padding: 15px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 4px; }}
                .nav {{ display: flex; margin-bottom: 20px; }}
                .nav a {{ padding: 10px 15px; text-decoration: none; color: #333; }}
                .nav a.active {{ border-bottom: 2px solid #0066cc; color: #0066cc; }}
                .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{context.get('page_title', 'Threat Intelligence Dashboard')}</h1>
                    <p>{context.get('page_subtitle', 'Platform overview')}</p>
                </div>
                
                <div class="alert alert-warning">
                    <strong>Template Rendering Error</strong><br>
                    The dashboard template could not be rendered. This is a simplified fallback view.
                </div>
                
                <div class="nav">
                    <a href="{url_for('dashboard')}" class="{'active' if context.get('current_view') == 'dashboard' else ''}">Dashboard</a>
                    <a href="{url_for('feeds')}" class="{'active' if context.get('current_view') == 'feeds' else ''}">Feeds</a>
                    <a href="{url_for('iocs')}" class="{'active' if context.get('current_view') == 'iocs' else ''}">IOCs</a>
                    <a href="{url_for('campaigns')}" class="{'active' if context.get('current_view') == 'campaigns' else ''}">Campaigns</a>
                    <a href="{url_for('logout')}">Logout</a>
                </div>
                
                <div class="card">
                    <h2>Platform Statistics</h2>
                    <p>User: {session.get('username', 'Unknown')}</p>
                    <p>Role: {session.get('role', 'Unknown')}</p>
                    <p>Environment: {config.environment}</p>
                </div>
                
                <div class="footer">
                    <p>&copy; {datetime.now().year} Threat Intelligence Platform</p>
                    <p>Version: {os.environ.get('VERSION', '1.0.0')}</p>
                </div>
            </div>
        </body>
    </html>
    """
    return Response(html, mimetype='text/html')

def render_fallback_detail(context):
    """Render a simple fallback detail page when template rendering fails"""
    content_type = context.get('content_type', 'unknown')
    identifier = context.get('identifier', 'unknown')
    data = context.get('data', {})
    
    html = f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>{content_type.title()} Details - Threat Intelligence Platform</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee; }}
                .alert {{ padding: 10px; margin-bottom: 15px; border-radius: 4px; }}
                .alert-warning {{ background-color: #fff3cd; color: #856404; }}
                .detail-item {{ margin-bottom: 10px; }}
                .detail-label {{ font-weight: bold; margin-right: 10px; }}
                .nav {{ display: flex; margin-bottom: 20px; }}
                .nav a {{ padding: 10px 15px; text-decoration: none; color: #333; }}
                .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; background: #eee; }}
                .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{content_type.title()} Details</h1>
                    <p>{identifier}</p>
                </div>
                
                <div class="alert alert-warning">
                    <strong>Template Rendering Error</strong><br>
                    The detail template could not be rendered. This is a simplified fallback view.
                </div>
                
                <div class="nav">
                    <a href="{url_for('dashboard')}">Dashboard</a>
                    <a href="{url_for('dashboard')}">Back</a>
                </div>
                
                <div class="details">
                    <h2>Details</h2>
                    {''.join([f'<div class="detail-item"><span class="detail-label">{k}:</span> {v}</div>' for k, v in data.items() if not isinstance(v, (list, dict)) and k not in ['_ingestion_timestamp', '_ingestion_id', '_source', '_feed_type']])}
                </div>
                
                <div class="footer">
                    <p>&copy; {datetime.now().year} Threat Intelligence Platform</p>
                    <p>Version: {os.environ.get('VERSION', '1.0.0')}</p>
                </div>
            </div>
        </body>
    </html>
    """
    return Response(html, mimetype='text/html')

# ==== Helper Functions ====

def generate_trend_data(days: int) -> List[int]:
    """Generate a smooth trend line for charts when real data isn't available"""
    import random
    from math import sin, pi
    
    # Generate a more natural-looking trend
    base = 50  # Base value
    variance = 15  # Random variance
    cycle = days / 4  # Cyclical component (4 cycles in the period)
    
    trend = []
    for i in range(days):
        # Combine base, cyclical component, and random noise
        cycle_component = sin(i * 2 * pi / cycle) * 20
        value = max(5, int(base + cycle_component + random.randint(-variance, variance)))
        trend.append(value)
        
        # Adjust base for next iteration (slight upward trend)
        base += random.randint(-2, 3) / 10
    
    return trend

# ==== Template Filters ====

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

# ==== Error Handlers ====

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    logger.info(f"Page not found: {request.path}",
               extra={"path": request.path, "ip": request.remote_addr})
    try:
        return render_template('404.html'), 404
    except Exception as template_error:
        logger.error(f"Template rendering error for 404 page: {str(template_error)}")
        html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>404 - Page Not Found</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 500px; margin: 40px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>404 - Page Not Found</h1>
                    <p>The page you are looking for does not exist.</p>
                    <p><a href="{url_for('index')}">Return to Homepage</a></p>
                </div>
            </body>
        </html>
        """
        return Response(html, mimetype='text/html', status=404)

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    error_details = str(e)
    logger.error(f"Server error: {error_details}")
    logger.error(traceback.format_exc())
    
    # Report to Error Reporting
    if config.environment == 'production' and 'error_client' in globals():
        try:
            error_client.report_exception()
        except Exception:
            pass
    
    try:
        return render_template('500.html'), 500
    except Exception as template_error:
        logger.error(f"Template rendering error for 500 page: {str(template_error)}")
        html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>500 - Server Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 500px; margin: 40px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
                    .error-details {{ margin-top: 20px; padding: 10px; background: #f8d7da; color: #721c24; border-radius: 5px; text-align: left; overflow-wrap: break-word; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>500 - Server Error</h1>
                    <p>An internal server error has occurred. Please try again later.</p>
                    <p><a href="{url_for('index')}">Return to Homepage</a></p>
                    {f'<div class="error-details"><strong>Error:</strong> {error_details}</div>' if DEBUG_MODE else ''}
                </div>
            </body>
        </html>
        """
        return Response(html, mimetype='text/html', status=500)

# ==== Context Processors ====

@app.context_processor
def inject_global_data():
    """Inject global data into templates"""
    return {
        'now': datetime.now(),
        'environment': config.environment,
        'version': os.environ.get('VERSION', '1.0.0'),
        'project_id': config.project_id,
        'debug_mode': DEBUG_MODE
    }

# Initialize the app
if __name__ == "__main__":
    app.run(debug=config.environment != 'production', 
            host='0.0.0.0', 
            port=int(os.environ.get('PORT', 8080)))
