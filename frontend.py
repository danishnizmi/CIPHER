"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform with improved security and performance.
"""

import os
import json
import logging
import hashlib
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort
import requests
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import secretmanager

# Import config module
import config

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
                   handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = config.project_id
REGION = config.region
API_URL = config.api_url

# Get API key with fallbacks
API_KEY = os.environ.get("API_KEY", "") or config.api_key or ""
if not API_KEY and hasattr(config, 'get_cached_config'):
    api_keys_config = config.get_cached_config('api-keys')
    API_KEY = api_keys_config.get('platform_api_key', "") if api_keys_config else ""

# Secret Manager client
_secret_client = None

def get_secret_client():
    """Get or initialize Secret Manager client"""
    global _secret_client
    if _secret_client is None:
        try:
            _secret_client = secretmanager.SecretManagerServiceClient()
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {e}")
    return _secret_client

def get_or_create_secret(secret_id, secret_value):
    """Get secret or create if it doesn't exist"""
    client = get_secret_client()
    if not client:
        return None
        
    try:
        # Check if secret exists
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}"
        try:
            client.get_secret(request={"name": name})
            # Secret exists - get latest version
            latest = client.access_secret_version(request={"name": f"{name}/versions/latest"})
            return latest.payload.data.decode("UTF-8")
        except Exception:
            # Secret doesn't exist or access error - create it
            parent = f"projects/{PROJECT_ID}"
            
            try:
                # Create secret
                client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
                
                # Add version with value
                client.add_secret_version(
                    request={
                        "parent": f"{parent}/secrets/{secret_id}",
                        "payload": {"data": secret_value.encode("UTF-8")},
                    }
                )
                
                logger.info(f"Created secret {secret_id}")
                return secret_value
            except Exception as e:
                logger.error(f"Error creating secret {secret_id}: {e}")
                return None
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {e}")
        return None

# Get or generate persistent Flask secret key
def get_flask_secret_key():
    """Get or create a persistent Flask secret key"""
    # Try environment variable first
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key
        
    # Try config
    config_key = config.get("FLASK_SECRET_KEY")
    if config_key:
        return config_key
        
    # Try Secret Manager
    secret_key = get_or_create_secret("flask-secret-key", os.urandom(32).hex())
    if secret_key:
        return secret_key
        
    # Fallback to random (but log warning)
    logger.warning("Using temporary random Flask secret key - sessions will not persist across restarts")
    return os.urandom(32).hex()

# Initialize Flask app with persistent secret key
app = Flask(__name__, template_folder='templates')
app.secret_key = get_flask_secret_key()
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
CORS(app)

# Authentication settings
REQUIRE_AUTH = config.get("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "true").lower() == "true")
SESSION_TIMEOUT = int(config.get("SESSION_TIMEOUT", "28800"))  # 8 hours in seconds

# Admin credentials - securely retrieved and initialized
ADMIN_USERNAME = 'admin'
ADMIN_HASH = None

def get_admin_credentials():
    """Get admin credentials from Secret Manager or create a secure fallback"""
    global ADMIN_HASH

    # Try to get credentials from Secret Manager
    try:
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if auth_config and 'users' in auth_config and 'admin' in auth_config['users']:
            admin_user = auth_config['users']['admin']
            ADMIN_HASH = admin_user.get('password')
            logger.info("Admin credentials loaded from Secret Manager")
            return {'username': 'admin', 'password_hash': ADMIN_HASH, 'role': admin_user.get('role', 'admin')}
    except Exception as e:
        logger.warning(f"Failed to retrieve admin credentials: {e}")
    
    # Check for admin password in secrets
    try:
        admin_password_secret = get_or_create_secret("admin-initial-password", None)
        if admin_password_secret:
            ADMIN_HASH = hashlib.sha256(admin_password_secret.encode()).hexdigest()
            logger.info("Admin credentials loaded from admin-initial-password secret")
            return {'username': 'admin', 'password_hash': ADMIN_HASH, 'role': 'admin'}
    except Exception as e:
        logger.warning(f"Failed to retrieve admin password from secret: {e}")
    
    # Generate a secure random password as last resort
    secure_password = os.urandom(8).hex()
    ADMIN_HASH = hashlib.sha256(secure_password.encode()).hexdigest()
    
    # Store in Secret Manager for persistence
    try:
        # Save password in a dedicated secret for recovery
        get_or_create_secret("admin-initial-password", secure_password)
        
        # Also save in auth-config
        if hasattr(config, 'add_user'):
            config.add_user('admin', secure_password, 'admin')
        
        logger.warning(f"IMPORTANT: Generated admin password: {secure_password}")
        logger.warning("Password saved to Secret Manager as 'admin-initial-password'")
    except Exception as e:
        logger.error(f"Failed to store admin credentials: {e}")
    
    return {
        'username': 'admin',
        'password_hash': ADMIN_HASH,
        'role': 'admin',
        'generated_password': secure_password
    }

# Initialize admin credentials
admin_creds = get_admin_credentials()

# Utility Functions
def hash_password(password): 
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password): 
    return stored_hash == hash_password(password)

def is_session_valid():
    """Check if the session is valid and not expired"""
    if not session.get('logged_in'):
        return False
    
    last_activity = session.get('last_activity')
    if not last_activity:
        return False
    
    # Check if session has expired
    now = time.time()
    if now - last_activity > SESSION_TIMEOUT:
        return False
    
    # Update last activity time
    session['last_activity'] = now
    return True

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH:
            if not is_session_valid():
                # Clear any existing session data
                session.clear()
                return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_session_valid() or session.get('role') != 'admin':
            flash("Administrator access required", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# API Helper with caching
api_cache = {}
api_cache_timestamp = {}

def api_request(endpoint: str, params: Dict = None, cache_time: int = 60) -> Dict:
    """Make a request to the API service with caching"""
    # Generate cache key
    cache_key = f"{endpoint}:{json.dumps(params or {})}"
    
    # Check cache
    now = time.time()
    if cache_key in api_cache and cache_key in api_cache_timestamp:
        if now - api_cache_timestamp[cache_key] < cache_time:
            return api_cache[cache_key]
    
    # Default response structure for error cases
    default_response = {
        "error": "API request failed",
        "feeds": {"total_sources": 0},
        "campaigns": {"total_campaigns": 0},
        "iocs": {"total": 0, "types": []},
        "analyses": {"total_analyses": 0}
    }
    
    # Try direct API call first
    try:
        import api
        if hasattr(api, endpoint) and callable(getattr(api, endpoint)):
            direct_function = getattr(api, endpoint)
            result = direct_function(params)
            if result: 
                # Cache successful result
                api_cache[cache_key] = result
                api_cache_timestamp[cache_key] = now
                
                # Manage cache size (max 100 items)
                if len(api_cache) > 100:
                    oldest_key = min(api_cache_timestamp, key=api_cache_timestamp.get)
                    if oldest_key in api_cache:
                        del api_cache[oldest_key]
                    if oldest_key in api_cache_timestamp:
                        del api_cache_timestamp[oldest_key]
                
                return result
    except (ImportError, AttributeError) as e:
        logger.debug(f"Direct API call failed, falling back to HTTP: {e}")
    
    # Build URL
    if API_URL:
        base_url = API_URL.rstrip('/')
        url = f"{base_url}/api/{endpoint}"
    else:
        url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/{endpoint}"
    
    headers = {"X-API-Key": API_KEY} if API_KEY else {}
    
    try:
        logger.debug(f"Making API request to: {url}")
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        # Cache successful result
        api_cache[cache_key] = result
        api_cache_timestamp[cache_key] = now
        
        # Manage cache size
        if len(api_cache) > 100:
            oldest_key = min(api_cache_timestamp, key=api_cache_timestamp.get)
            if oldest_key in api_cache:
                del api_cache[oldest_key]
            if oldest_key in api_cache_timestamp:
                del api_cache_timestamp[oldest_key]
        
        return result
    except Exception as e:
        logger.error(f"API request error: {str(e)}")
        return default_response

def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
    """Format datetime objects or ISO strings for display"""
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime(format)
        except (ValueError, TypeError):
            return value
    elif isinstance(value, datetime):
        return value.strftime(format)
    return value if value else "N/A"

# Register template filters
app.jinja_env.filters['datetime'] = format_datetime

# Context processors
@app.context_processor
def inject_common_data():
    """Inject common data into templates"""
    return {
        'now': datetime.now(),
        'environment': config.environment,
        'project_id': config.project_id,
        'current_endpoint': request.endpoint
    }

# ======== Route Handlers ========

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for user: {username}")
        
        # First check if username exists in auth config
        user_data = None
        try:
            auth_config = config.get_cached_config('auth-config')
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                user_data = auth_config['users'][username]
        except Exception as e:
            logger.warning(f"Error accessing auth config: {e}")
        
        # Check credentials - either config stored or admin fallback
        is_valid = False
        user_role = 'readonly'
        
        if user_data and 'password' in user_data:
            is_valid = user_data['password'] == hash_password(password)
            user_role = user_data.get('role', 'readonly')
        elif username == ADMIN_USERNAME and verify_password(ADMIN_HASH, password):
            is_valid = True
            user_role = 'admin'
        
        if is_valid:
            # Update last login time
            try:
                if hasattr(config, 'update_user'):
                    config.update_user(username, {'last_login': datetime.utcnow().isoformat()})
            except Exception as e:
                logger.warning(f"Failed to update last login time: {e}")
                
            # Set session data
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user_role
            session['last_activity'] = time.time()
            session.permanent = True
            
            logger.info(f"User {username} logged in successfully with role {user_role}")
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
            logger.warning(f"Failed login attempt for user: {username}")
    
    return render_template('auth.html', page_type='login', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username')
    session.clear()
    if username:
        logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    """User Profile page"""
    username = session.get('username')
    user_data = {}
    
    try:
        # Get actual user data from auth config
        auth_config = config.get_cached_config('auth-config')
        if auth_config and 'users' in auth_config and username in auth_config['users']:
            user_data = auth_config['users'][username]
    except Exception as e:
        logger.warning(f"Error retrieving user data: {e}")
    
    return render_template('auth.html', 
                          page_type='profile', 
                          username=username,
                          user={"role": user_data.get('role', session.get('role', 'user')), 
                                "last_login": user_data.get('last_login', datetime.now().isoformat())})

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    global ADMIN_HASH
    
    username = session.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash("All fields are required", "danger")
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for('profile'))
    
    # Check password complexity
    if len(new_password) < 8:
        flash("Password must be at least 8 characters long", "danger")
        return redirect(url_for('profile'))
    
    # Verify current password
    is_valid = False
    
    # Check if admin user
    if username == ADMIN_USERNAME:
        # Update admin in Secret Manager
        if verify_password(ADMIN_HASH, current_password):
            is_valid = True
            ADMIN_HASH = hash_password(new_password)
            
            # Update in Secret Manager if available
            try:
                if hasattr(config, 'update_user'):
                    config.update_user(username, {
                        'password': ADMIN_HASH,
                        'password_changed': datetime.utcnow().isoformat()
                    })
                    logger.info("Admin password updated in Secret Manager")
            except Exception as e:
                logger.warning(f"Failed to update admin in Secret Manager: {e}")
    else:
        # Regular user password update
        try:
            auth_config = config.get_cached_config('auth-config', force_refresh=True)
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                user_data = auth_config['users'][username]
                if user_data.get('password') == hash_password(current_password):
                    is_valid = True
                    # Update in Secret Manager
                    if hasattr(config, 'update_user'):
                        config.update_user(username, {
                            'password': hash_password(new_password),
                            'password_changed': datetime.utcnow().isoformat()
                        })
                        logger.info(f"Password updated for user {username}")
        except Exception as e:
            logger.error(f"Error updating password: {e}")
    
    if is_valid:
        flash("Password changed successfully", "success")
    else:
        flash("Current password is incorrect", "danger")
    
    return redirect(url_for('profile'))

# Main Routes
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page with tabs"""
    days = request.args.get('days', '30')
    view_type = request.args.get('view', 'dashboard')
    
    # Get platform stats for all view types - cache for 5 minutes
    stats = api_request('stats', {'days': days}, cache_time=300)
    
    # Ensure stats has required structure
    if not isinstance(stats, dict):
        stats = {}
    if "feeds" not in stats:
        stats["feeds"] = {"total_sources": 0}
    if "campaigns" not in stats:
        stats["campaigns"] = {"total_campaigns": 0}
    if "iocs" not in stats:
        stats["iocs"] = {"total": 0, "types": []}
    if "analyses" not in stats:
        stats["analyses"] = {"total_analyses": 0}
    
    # Common data for all views
    common_data = {
        'days': days,
        'current_view': view_type,
        'stats': stats,
        'campaigns': [],
        'top_iocs': [],
        'page_title': 'Threat Intelligence Dashboard',
        'page_subtitle': 'Real-time overview of threat intelligence with actionable insights',
    }
    
    # Dashboard view (default)
    if view_type == 'dashboard':
        # Get real data for dashboard
        campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
        iocs_data = api_request('iocs', {'days': days, 'limit': 5})
        gcp_metrics = get_gcp_metrics()
        
        # Get chart data
        ioc_type_labels = []
        ioc_type_values = []
        
        # Use real data for IOC type distribution
        if 'iocs' in stats and 'types' in stats['iocs'] and stats['iocs']['types']:
            types_data = stats['iocs']['types']
            if isinstance(types_data, list) and len(types_data) > 0:
                for item in types_data:
                    if isinstance(item, dict):
                        ioc_type_labels.append(item.get('type', 'unknown'))
                        ioc_type_values.append(item.get('count', 0))
        
        # Activity data
        activity_dates = []
        activity_counts = []
        
        # Try to use real activity data if available
        if 'daily_activity' in stats:
            daily_activity = stats.get('daily_activity', [])
            for item in daily_activity:
                if isinstance(item, dict):
                    activity_dates.append(item.get('date'))
                    activity_counts.append(item.get('count', 0))
        
        # Calculate trends based on real data if available
        feed_trend = stats.get('feeds', {}).get('growth_rate', 0)
        ioc_trend = stats.get('iocs', {}).get('growth_rate', 0) 
        campaign_trend = stats.get('campaigns', {}).get('growth_rate', 0)
        analysis_trend = stats.get('analyses', {}).get('growth_rate', 0)
        
        # Update data for dashboard view
        common_data.update({
            'campaigns': campaigns_data.get('campaigns', []),
            'top_iocs': iocs_data.get('records', []),
            'gcp_metrics': gcp_metrics,
            'ioc_type_labels': json.dumps(ioc_type_labels),
            'ioc_type_values': json.dumps(ioc_type_values),
            'activity_dates': json.dumps(activity_dates),
            'activity_counts': json.dumps(activity_counts),
            'feed_trend': feed_trend,
            'ioc_trend': ioc_trend,
            'campaign_trend': campaign_trend,
            'analysis_trend': analysis_trend
        })
    
    # Feeds view
    elif view_type == 'feeds':
        feeds_data = api_request('feeds')
        common_data.update({
            'page_title': 'Threat Intelligence Feeds',
            'page_icon': 'rss',
            'page_subtitle': 'Collection of threat data from various sources',
            'feed_items': feeds_data.get('feed_details', [])
        })
    
    # IOCs view
    elif view_type == 'iocs':
        iocs_data = api_request('iocs', {'days': days})
        ioc_items = []
        for record in iocs_data.get('records', []):
            ioc_items.extend(record.get('iocs', []))
        
        common_data.update({
            'page_title': 'Indicators of Compromise',
            'page_icon': 'fingerprint',
            'page_subtitle': 'Collected IOCs from all sources',
            'ioc_items': ioc_items,
            'top_iocs': iocs_data.get('records', [])
        })
    
    return render_template('dashboard.html', **common_data)

# Route aliases
@app.route('/feeds')
@login_required
def feeds():
    """Feeds view - redirects to dashboard with view parameter"""
    days = request.args.get('days', '30')
    return redirect(url_for('dashboard', view='feeds', days=days))

@app.route('/iocs')
@login_required
def iocs():
    """IOCs view - redirects to dashboard with view parameter"""
    days = request.args.get('days', '30')
    return redirect(url_for('dashboard', view='iocs', days=days))

@app.route('/campaigns')
@login_required
def campaigns():
    """Campaigns view - redirects to dashboard with view parameter"""
    days = request.args.get('days', '30')
    return redirect(url_for('dashboard', view='campaigns', days=days))

@app.route('/explore')
@login_required
def explore():
    """Data exploration view - redirects to dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/alerts')
@login_required
def alerts():
    """Alerts view - redirects to dashboard"""
    return redirect(url_for('dashboard'))

# Dynamic content detail
@app.route('/content/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Generic handler for content details"""
    # Get actual content data from API
    content_data = {}
    try:
        if content_type == 'feed':
            feed_data = api_request(f'feeds/{identifier}/stats')
            content_data = feed_data
        elif content_type == 'campaign':
            campaign_data = api_request(f'campaigns/{identifier}')
            content_data = campaign_data
        elif content_type == 'ioc':
            ioc_parts = identifier.split('/')
            if len(ioc_parts) >= 2:
                ioc_type = ioc_parts[0]
                ioc_value = '/'.join(ioc_parts[1:])  # Handle URLs with slashes
                ioc_data = api_request(f'iocs/detail', {'type': ioc_type, 'value': ioc_value})
                content_data = ioc_data
    except Exception as e:
        logger.warning(f"Error retrieving content data for {content_type}/{identifier}: {e}")
    
    # Fallback to basic info if API request failed
    if not content_data:
        content_data = {"type": content_type, "id": identifier}
    
    return render_template('detail.html', 
                          content_type=content_type, 
                          identifier=identifier,
                          title=f"{content_type.title()} Details: {identifier}",
                          content=content_data)

# Ingest data route
@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger the ingestion process"""
    try:
        # Try local module first
        try:
            import ingestion
            if hasattr(ingestion, 'ingest_threat_data'):
                result = ingestion.ingest_threat_data(request)
                flash("Ingestion process started successfully", "success")
                return redirect(url_for('dashboard', view='feeds'))
        except ImportError:
            logger.debug("Local ingestion module not available, using API")
        
        # Fall back to API
        response = requests.post(
            f"{request.url_root.rstrip('/')}/api/ingest_threat_data",
            json={"process_all": True},
            headers={"X-API-Key": API_KEY} if API_KEY else {},
            timeout=30
        )
        
        if response.status_code == 200:
            flash("Ingestion process started successfully", "success")
        else:
            flash(f"Error starting ingestion: {response.text}", "danger")
    except Exception as e:
        logger.error(f"Error starting ingestion: {str(e)}")
        flash(f"Error starting ingestion: {str(e)}", "danger")
    
    return redirect(url_for('dashboard', view='feeds'))

# API health check for Cloud Run
@app.route('/api/health', methods=['GET'])
def api_health():
    """API health check endpoint"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": os.environ.get("VERSION", "1.0.0"),
        "environment": config.environment,
        "project": PROJECT_ID
    })

# Root health check
@app.route('/health', methods=['GET'])
def health():
    """Root health check endpoint"""
    return api_health()

# ======== Admin Routes ========
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard - redirects to user management for now"""
    return redirect(url_for('users'))

@app.route('/admin/users')
@login_required
@admin_required
def users():
    """User management page"""
    # Get user list from auth config
    users = []
    try:
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if auth_config and 'users' in auth_config:
            for username, user_data in auth_config['users'].items():
                users.append({
                    'username': username,
                    'role': user_data.get('role', 'readonly'),
                    'created_at': user_data.get('created_at'),
                    'last_login': user_data.get('last_login', 'Never')
                })
    except Exception as e:
        logger.error(f"Error getting user list: {e}")
        flash(f"Error loading users: {str(e)}", "danger")
    
    return render_template('content.html', 
                          page_title="User Management",
                          content_type="users",
                          users=users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user_route():
    """Add new user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'readonly')
        
        # Validate inputs
        if not username or not password or not confirm_password:
            flash("All fields are required", "danger")
            return render_template('auth.html', page_type='user_add', error="All fields are required")
        
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template('auth.html', page_type='user_add', error="Passwords do not match")
        
        # Check password complexity
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return render_template('auth.html', page_type='user_add', error="Password must be at least 8 characters")
        
        # Check if user already exists
        try:
            auth_config = config.get_cached_config('auth-config', force_refresh=True)
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                flash(f"User {username} already exists", "danger")
                return render_template('auth.html', page_type='user_add', error=f"User {username} already exists")
        except Exception as e:
            logger.error(f"Error checking existing user: {e}")
        
        # Create the user
        try:
            success = False
            if hasattr(config, 'add_user'):
                success = config.add_user(username, password, role)
            
            if success:
                flash(f"User {username} created successfully", "success")
                return redirect(url_for('users'))
            else:
                flash("Failed to create user", "danger")
                return render_template('auth.html', page_type='user_add', error="Failed to create user")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            flash(f"Error creating user: {str(e)}", "danger")
            return render_template('auth.html', page_type='user_add', error=f"Error: {str(e)}")
    
    return render_template('auth.html', page_type='user_add')

@app.route('/admin/users/edit/<username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(username):
    """Edit user"""
    # Get user data
    user_data = None
    try:
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if auth_config and 'users' in auth_config and username in auth_config['users']:
            user_data = auth_config['users'][username]
    except Exception as e:
        logger.error(f"Error getting user data: {e}")
        flash(f"Error loading user data: {str(e)}", "danger")
        return redirect(url_for('users'))
    
    if not user_data:
        flash(f"User {username} not found", "danger")
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        role = request.form.get('role', 'readonly')
        
        # Update user
        updates = {'role': role}
        if password:
            updates['password'] = hash_password(password)
        
        try:
            success = False
            if hasattr(config, 'update_user'):
                success = config.update_user(username, updates)
            
            if success:
                flash(f"User {username} updated successfully", "success")
                return redirect(url_for('users'))
            else:
                flash("Failed to update user", "danger")
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            flash(f"Error updating user: {str(e)}", "danger")
    
    return render_template('auth.html', 
                          page_type='user_edit', 
                          username=username,
                          user=user_data)

@app.route('/admin/users/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    """Delete user"""
    if username == ADMIN_USERNAME or username == session.get('username'):
        flash("Cannot delete admin user or yourself", "danger")
        return redirect(url_for('users'))
    
    # Delete the user
    try:
        success = False
        if hasattr(config, 'delete_user'):
            success = config.delete_user(username)
        elif hasattr(config, 'update_user'):
            # Alternative approach - mark as inactive
            success = config.update_user(username, {'active': False})
        
        if success:
            flash(f"User {username} deleted successfully", "success")
        else:
            flash("Failed to delete user", "danger")
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        flash(f"Error deleting user: {str(e)}", "danger")
    
    return redirect(url_for('users'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({
            "error": "Resource not found",
            "path": request.path,
            "timestamp": datetime.utcnow().isoformat()
        }), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({
            "error": "Internal server error",
            "path": request.path,
            "timestamp": datetime.utcnow().isoformat()
        }), 500
    return render_template('500.html'), 500

# Utility Functions
def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services with better error handling and caching"""
    cache_key = "gcp_metrics"
    cache_ttl = 300  # 5 minutes
    
    # Check cache
    now = time.time()
    if cache_key in api_cache and cache_key in api_cache_timestamp:
        if now - api_cache_timestamp[cache_key] < cache_ttl:
            return api_cache[cache_key]
    
    metrics = {"table_count": 0, "storage_objects": 0, "storage_size": 0.0}
    
    try:
        # Get BigQuery table counts
        bq_client = bigquery.Client(project=PROJECT_ID)
        query = f"""
        SELECT COUNT(*) as table_count 
        FROM `{PROJECT_ID}.{config.bigquery_dataset}.__TABLES__`
        """
        
        query_job = bq_client.query(query)
        query_job.result()
        for row in query_job:
            metrics["table_count"] = row.table_count
        
        # Get Storage bucket info
        try:
            storage_client = storage.Client(project=PROJECT_ID)
            bucket = storage_client.get_bucket(config.gcs_bucket)
            # Use pagination to avoid memory issues with large buckets
            blobs = list(bucket.list_blobs(max_results=1000))
            metrics["storage_objects"] = len(blobs)
            metrics["storage_size"] = sum(blob.size for blob in blobs if hasattr(blob, 'size')) / (1024 * 1024)  # MB
        except Exception as e:
            logger.warning(f"Error getting storage metrics: {str(e)}")
    except Exception as e:
        logger.warning(f"Error getting GCP metrics: {str(e)}")
    
    # Cache results
    api_cache[cache_key] = metrics
    api_cache_timestamp[cache_key] = now
    
    return metrics

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug_mode = config.environment != "production"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
