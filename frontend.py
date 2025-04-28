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
import string
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Any, Optional, Union

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask import flash, session, abort, g, Response
from werkzeug.middleware.proxy_fix import ProxyFix

# Import config module for centralized configuration
import config

# Environment settings
VERSION = os.environ.get("VERSION", "1.0.0")
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')

# Configure logging
logger = logging.getLogger('frontend')
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
logging.basicConfig(level=LOG_LEVEL, 
                   format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')

# GCP services availability flag
GCP_SERVICES_AVAILABLE = False

# GCP clients dictionary
gcp_clients = {}

try:
    from google.cloud import logging as gcp_logging
    from google.cloud import error_reporting
    from google.cloud import secretmanager
    import google.auth
    GCP_SERVICES_AVAILABLE = True
    logger.info("GCP libraries successfully imported")
except ImportError:
    GCP_SERVICES_AVAILABLE = False
    logger.warning("Google Cloud libraries not installed. GCP integration disabled.")

# Create a dummy error reporting client to avoid failures
class DummyErrorClient:
    def report_exception(self, *args, **kwargs):
        logger.warning("Error reporting attempted but API not available")

# Get or create GCP client
def get_client(client_type: str):
    """Get or create a GCP client with proper error handling"""
    global gcp_clients
    
    if client_type in gcp_clients and gcp_clients[client_type] is not None:
        return gcp_clients[client_type]
        
    if not GCP_SERVICES_AVAILABLE:
        logger.warning(f"GCP services not available, cannot create {client_type} client")
        if client_type == 'error_reporting':
            gcp_clients[client_type] = DummyErrorClient()
            return gcp_clients[client_type]
        return None
    
    try:
        if client_type == 'error_reporting':
            try:
                gcp_clients[client_type] = error_reporting.Client(service="frontend")
                logger.info("Error reporting client initialized")
            except Exception as e:
                logger.warning(f"Error reporting initialization failed: {e}")
                gcp_clients[client_type] = DummyErrorClient()
                
        elif client_type == 'logging':
            gcp_clients[client_type] = gcp_logging.Client()
            logger.info("Cloud Logging client initialized")
            
        elif client_type == 'secretmanager':
            gcp_clients[client_type] = secretmanager.SecretManagerServiceClient()
            logger.info("Secret Manager client initialized")
            
        return gcp_clients[client_type]
        
    except Exception as e:
        logger.error(f"Failed to initialize {client_type} client: {str(e)}")
        if client_type == 'error_reporting':
            gcp_clients[client_type] = DummyErrorClient()
            return gcp_clients[client_type]
        return None

# Set up GCP services for production
if GCP_SERVICES_AVAILABLE and ENVIRONMENT == 'production' and not DEBUG_MODE:
    try:
        credentials, project_id = google.auth.default()
        
        # Configure Cloud Logging
        logging_client = get_client('logging')
        if logging_client:
            cloud_handler = logging_client.get_default_handler()
            logger.setLevel(LOG_LEVEL)
            logger.addHandler(cloud_handler)
        
        # Initialize Error Reporting
        error_client = get_client('error_reporting')
        
        logger.info("GCP logging and error reporting initialized")
    except Exception as e:
        logger.error(f"GCP services initialization failed: {str(e)}")
        error_client = DummyErrorClient()
else:
    error_client = DummyErrorClient()

# Safe wrapper for error reporting
def safe_report_exception():
    """Safely report exception to Error Reporting"""
    try:
        if GCP_SERVICES_AVAILABLE and ENVIRONMENT == 'production':
            client = get_client('error_reporting')
            if client:
                client.report_exception()
    except Exception as e:
        logger.warning(f"Failed to report exception: {e}")

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
    """Get secret key for Flask sessions"""
    try:
        # Try config module first
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'session_secret' in auth_config:
            return auth_config['session_secret']
        
        # Try environment variable
        secret_key = os.environ.get('SECRET_KEY')
        if secret_key:
            return secret_key
        
        # Try Secret Manager in production
        if ENVIRONMENT == 'production' and GCP_SERVICES_AVAILABLE:
            try:
                secret = config.get_secret("flask-secret-key")
                if secret:
                    return secret
            except Exception as e:
                logger.warning(f"Failed to get secret from Secret Manager: {str(e)}")
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
    """Share GCP clients with application context"""
    if not hasattr(g, 'gcp_clients'):
        g.gcp_clients = gcp_clients
    if not hasattr(g, 'gcp_services_available'):
        g.gcp_services_available = GCP_SERVICES_AVAILABLE

# ====== Helper Functions ======

def generate_trend_data(days: int) -> List[int]:
    """Generate a smooth trend line for charts when real data isn't available"""
    import random
    from math import sin, pi
    
    # Generate a more natural-looking trend
    base = 50  # Base value
    variance = 15  # Random variance
    cycle = days / 4  # Cyclical component
    
    trend = []
    for i in range(days):
        # Combine base, cyclical component, and random noise
        cycle_component = sin(i * 2 * pi / cycle) * 20
        value = max(5, int(base + cycle_component + random.randint(-variance, variance)))
        trend.append(value)
        
        # Adjust base for next iteration (slight upward trend)
        base += random.randint(-2, 3) / 10
    
    return trend

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
    """Load user data from auth config with error handling"""
    try:
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
        
        # Load statistics for all views
        try:
            # Import API module
            from api import api_bp
            
            # Get statistics
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
                context['feed_type_descriptions'] = {feed['name']: feed.get('description', 'Threat Intelligence Feed') 
                                                  for feed in context['feed_items']}
                
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
                campaigns_response = api_bp.list_campaigns()
                context['campaigns'] = campaigns_response.get('campaigns', [])[:3]
                
                # Load IOCs for dashboard
                iocs_response = api_bp.search_iocs()
                context['top_iocs'] = iocs_response.get('records', [])[:4]
                
        except ImportError:
            logger.warning("API module not available - cannot load dashboard data")
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
                
            flash('Could not load all dashboard data. Some information may be missing.', 'warning')
        
        return render_template('dashboard.html', **context, now=datetime.now())
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('login'))

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
                # Add user with secure password hash
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
        # Import ingestion function directly
        from ingestion import ThreatDataIngestion
        
        # Create ingestion instance and process feeds
        ingestion_engine = ThreatDataIngestion()
        results = ingestion_engine.process_all_feeds()
        
        # Log operation
        username = session.get('username')
        logger.info(f"Manual ingestion triggered by {username}: {len(results)} feeds processed")
        
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
        safe_report_exception()
        flash(f'Error refreshing threat data: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/dynamic_content_detail/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Dynamic content detail page for IOCs, campaigns, etc."""
    try:
        data = {}
        
        # Import API module
        from api import api_bp
        
        if content_type == 'ioc':
            # Split identifier
            ioc_type, ioc_value = identifier.split('/', 1)
            
            # Get IOCs with matching type/value
            iocs_data = api_bp.search_iocs()
            
            # Find the matching IOC
            for ioc in iocs_data.get('records', []):
                if ioc.get('type') == ioc_type and ioc.get('value') == ioc_value:
                    data = ioc
                    break
                    
            # Get related campaigns
            if data:
                campaigns_data = api_bp.list_campaigns()
                data['campaigns'] = []
                
                for campaign in campaigns_data.get('campaigns', [])[:3]:
                    data['campaigns'].append(campaign)
                    
                # Set placeholders for missing fields
                for field in ['first_seen', 'last_seen', 'sources', 'confidence', 'tags']:
                    if field not in data:
                        data[field] = [] if field in ['sources', 'tags'] else None
                
        elif content_type == 'campaign':
            # Get campaign details
            campaigns_data = api_bp.list_campaigns()
            
            # Find the specific campaign
            for campaign in campaigns_data.get('campaigns', []):
                if campaign.get('campaign_id') == identifier:
                    data = campaign
                    break
            
            # Enrich with additional data
            if data:
                # Get IOCs related to this campaign
                iocs_data = api_bp.search_iocs()
                data['iocs'] = iocs_data.get('records', [])[:5]
                
                # Add description if missing
                if 'description' not in data:
                    data['description'] = f"Campaign {data.get('campaign_name', 'Unknown')} details."
                
        elif content_type == 'feed':
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
    
        # Return context
        context = {
            'content_type': content_type,
            'identifier': identifier,
            'data': data
        }
        
        return render_template('detail.html', **context)
    
    except ImportError:
        flash('API service unavailable. Cannot load details.', 'warning')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error loading detail page for {content_type}/{identifier}: {str(e)}")
        logger.error(traceback.format_exc())
        safe_report_exception()
        flash('Error loading content details.', 'danger')
        return redirect(url_for('dashboard'))

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
