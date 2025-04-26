"""
Threat Intelligence Platform - Frontend Module
Provides web interface with improved security and performance.
"""

import os
import json
import logging
import hashlib
import sys
import time
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort
import requests
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import secretmanager
from google.api_core.exceptions import AlreadyExists, NotFound, PermissionDenied

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

# API key with fallbacks
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
            logger.info("Secret Manager client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {e}")
    return _secret_client

def access_secret(secret_id, version="latest"):
    """Access a secret by ID and version"""
    client = get_secret_client()
    if not client:
        logger.error("No Secret Manager client available")
        return None
        
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/{version}"
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")
        logger.info(f"Successfully accessed secret: {secret_id}")
        return payload
    except NotFound:
        logger.info(f"Secret not found: {secret_id}")
        return None
    except PermissionDenied:
        logger.error(f"Permission denied accessing secret: {secret_id}")
        return None
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {str(e)}")
        return None

def create_secret_if_not_exists(secret_id, secret_value):
    """Create a secret if it doesn't already exist"""
    client = get_secret_client()
    if not client:
        logger.error("No Secret Manager client available")
        return False
        
    try:
        # First try to access the secret to see if it exists
        existing_value = access_secret(secret_id)
        if existing_value:
            logger.info(f"Secret {secret_id} already exists")
            return existing_value
    
        # Secret doesn't exist, create it
        parent = f"projects/{PROJECT_ID}"
        
        try:
            # Create secret resource
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
            logger.info(f"Created secret resource: {secret_id}")
        except AlreadyExists:
            logger.info(f"Secret {secret_id} already exists")
        except Exception as e:
            logger.error(f"Error creating secret resource {secret_id}: {str(e)}")
            return False
            
        # Add version with value
        try:
            secret_parent = f"{parent}/secrets/{secret_id}"
            client.add_secret_version(
                request={
                    "parent": secret_parent,
                    "payload": {"data": secret_value.encode("UTF-8")},
                }
            )
            logger.info(f"Added version to secret: {secret_id}")
            return secret_value
        except Exception as e:
            logger.error(f"Error adding version to secret {secret_id}: {str(e)}")
            return False
    except Exception as e:
        logger.error(f"Unexpected error with secret {secret_id}: {str(e)}")
        return False

# Get or create Flask secret key
def setup_flask_secret_key():
    """Get or create a persistent Flask secret key"""
    # Try environment variable first
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        logger.info("Using Flask secret key from environment variable")
        return env_key
    
    # Try to get from Secret Manager
    logger.info("Attempting to get Flask secret key from Secret Manager")
    secret_key = access_secret("flask-secret-key")
    
    # If found, use it
    if secret_key:
        logger.info("Using existing Flask secret key from Secret Manager")
        return secret_key
        
    # Create a new one
    logger.info("Creating new Flask secret key")
    new_key = secrets.token_hex(32)
    result = create_secret_if_not_exists("flask-secret-key", new_key)
    
    if result:
        logger.info("Created and stored new Flask secret key")
        return new_key
    else:
        # Fallback
        logger.warning("Using temporary Flask secret key - sessions will not persist")
        return secrets.token_hex(32)

# Initialize Flask app
flask_secret_key = setup_flask_secret_key()
app = Flask(__name__, template_folder='templates')
app.secret_key = flask_secret_key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
CORS(app)

# Authentication settings
REQUIRE_AUTH = config.get("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "true").lower() == "true")
SESSION_TIMEOUT = int(config.get("SESSION_TIMEOUT", "28800"))  # 8 hours in seconds

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = None
ADMIN_HASH = None

def setup_admin_credentials():
    """Set up admin credentials"""
    global ADMIN_HASH, ADMIN_PASSWORD
    
    # Try to get from auth-config in Secret Manager first
    logger.info("Looking for admin credentials in auth-config secret")
    admin_from_config = None
    try:
        auth_config_json = access_secret("auth-config")
        if auth_config_json:
            auth_config = json.loads(auth_config_json)
            if 'users' in auth_config and 'admin' in auth_config['users']:
                admin_user = auth_config['users']['admin']
                if 'password' in admin_user:
                    ADMIN_HASH = admin_user['password']
                    logger.info("Admin credentials found in auth-config")
                    return None
    except Exception as e:
        logger.warning(f"Could not retrieve admin from auth-config: {e}")
    
    # Try to get dedicated admin password secret
    logger.info("Looking for admin-initial-password secret")
    admin_password_secret = access_secret("admin-initial-password")
    if admin_password_secret:
        ADMIN_PASSWORD = admin_password_secret
        ADMIN_HASH = hashlib.sha256(admin_password_secret.encode()).hexdigest()
        logger.info("Admin password loaded from admin-initial-password secret")
        return None
    
    # Generate a new secure password
    logger.info("Generating new admin password")
    new_password = secrets.token_urlsafe(12)[:12]  # 12 character readable password
    ADMIN_PASSWORD = new_password
    ADMIN_HASH = hashlib.sha256(new_password.encode()).hexdigest()
    
    # Store in dedicated secret
    logger.info("Storing new admin password in Secret Manager")
    if create_secret_if_not_exists("admin-initial-password", new_password):
        logger.info("Successfully stored admin password in Secret Manager")
    else:
        logger.error("Failed to store admin password in Secret Manager")
    
    # Also try to add to auth-config
    logger.info("Attempting to add admin user to auth-config")
    try:
        if hasattr(config, 'add_user'):
            config.add_user('admin', new_password, 'admin')
            logger.info("Added admin user to auth-config")
    except Exception as e:
        logger.error(f"Failed to add admin user to auth-config: {e}")
    
    return new_password

# Set up admin credentials and display if newly created
new_admin_password = setup_admin_credentials()
if new_admin_password:
    logger.warning("")
    logger.warning("="*80)
    logger.warning("IMPORTANT: NEW ADMIN PASSWORD GENERATED")
    logger.warning(f"USERNAME: admin")
    logger.warning(f"PASSWORD: {new_admin_password}")
    logger.warning("="*80)
    logger.warning("")

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
    if cache_key in api_cache and now - api_cache_timestamp.get(cache_key, 0) < cache_time:
        return api_cache[cache_key]
    
    # Default response
    default_response = {
        "error": "API request failed",
        "feeds": {"total_sources": 0},
        "campaigns": {"total_campaigns": 0},
        "iocs": {"total": 0, "types": []},
        "analyses": {"total_analyses": 0}
    }
    
    # Try direct API call
    try:
        import api
        if hasattr(api, endpoint) and callable(getattr(api, endpoint)):
            result = getattr(api, endpoint)(params)
            if result:
                api_cache[cache_key] = result
                api_cache_timestamp[cache_key] = now
                return result
    except (ImportError, AttributeError):
        pass
    
    # Build URL for HTTP call
    url = f"{API_URL.rstrip('/')}/api/{endpoint}" if API_URL else f"http://localhost:{os.environ.get('PORT', '8080')}/api/{endpoint}"
    headers = {"X-API-Key": API_KEY} if API_KEY else {}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        api_cache[cache_key] = result
        api_cache_timestamp[cache_key] = now
        
        # Manage cache size
        if len(api_cache) > 100:
            oldest_key = min(api_cache_timestamp, key=api_cache_timestamp.get)
            if oldest_key in api_cache:
                del api_cache[oldest_key]
                del api_cache_timestamp[oldest_key]
        
        return result
    except Exception as e:
        logger.error(f"API request error: {str(e)}")
        return default_response

# Template helpers
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

# Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for user: {username}")
        
        # Check credentials
        is_valid = False
        user_role = 'readonly'
        
        # Try auth config first
        try:
            auth_config = config.get_cached_config('auth-config')
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                user_data = auth_config['users'][username]
                is_valid = user_data.get('password') == hash_password(password)
                user_role = user_data.get('role', 'readonly')
                logger.info(f"Auth config validation: {is_valid}")
        except Exception as e:
            logger.warning(f"Error accessing auth config: {e}")
            
        # Try admin fallback
        if not is_valid and username == ADMIN_USERNAME:
            is_valid = verify_password(ADMIN_HASH, password)
            user_role = 'admin'
            logger.info(f"Admin fallback validation: {is_valid}")
        
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
    if not current_password or not new_password or new_password != confirm_password or len(new_password) < 8:
        flash("Password validation failed", "danger")
        return redirect(url_for('profile'))
    
    # Verify current password and update
    is_valid = False
    
    if username == ADMIN_USERNAME and verify_password(ADMIN_HASH, current_password):
        is_valid = True
        ADMIN_HASH = hash_password(new_password)
        
        # Update in Secret Manager
        if hasattr(config, 'update_user'):
            config.update_user(username, {'password': ADMIN_HASH})
    else:
        try:
            auth_config = config.get_cached_config('auth-config', force_refresh=True)
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                user_data = auth_config['users'][username]
                if user_data.get('password') == hash_password(current_password):
                    is_valid = True
                    if hasattr(config, 'update_user'):
                        config.update_user(username, {'password': hash_password(new_password)})
        except Exception as e:
            logger.error(f"Error updating password: {e}")
    
    flash("Password changed successfully" if is_valid else "Current password is incorrect", 
          "success" if is_valid else "danger")
    return redirect(url_for('profile'))

# Main Routes
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page with tabs"""
    days = request.args.get('days', '30')
    view_type = request.args.get('view', 'dashboard')
    
    # Get platform stats
    stats = api_request('stats', {'days': days}, cache_time=300)
    
    # Ensure stats has required structure
    if not isinstance(stats, dict):
        stats = {}
    for key in ['feeds', 'campaigns', 'iocs', 'analyses']:
        if key not in stats:
            stats[key] = {"total_sources" if key == "feeds" else "total": 0}
    
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
        # Get dashboard data
        campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
        iocs_data = api_request('iocs', {'days': days, 'limit': 5})
        gcp_metrics = get_gcp_metrics()
        
        # Process chart data
        ioc_type_labels = []
        ioc_type_values = []
        if 'types' in stats.get('iocs', {}) and stats['iocs']['types']:
            for item in stats['iocs']['types']:
                if isinstance(item, dict):
                    ioc_type_labels.append(item.get('type', 'unknown'))
                    ioc_type_values.append(item.get('count', 0))
        
        # Activity data
        activity_dates = []
        activity_counts = []
        for item in stats.get('daily_activity', []):
            if isinstance(item, dict):
                activity_dates.append(item.get('date'))
                activity_counts.append(item.get('count', 0))
        
        # Calculate trends
        common_data.update({
            'campaigns': campaigns_data.get('campaigns', []),
            'top_iocs': iocs_data.get('records', []),
            'gcp_metrics': gcp_metrics,
            'ioc_type_labels': json.dumps(ioc_type_labels),
            'ioc_type_values': json.dumps(ioc_type_values),
            'activity_dates': json.dumps(activity_dates),
            'activity_counts': json.dumps(activity_counts),
            'feed_trend': stats.get('feeds', {}).get('growth_rate', 0),
            'ioc_trend': stats.get('iocs', {}).get('growth_rate', 0),
            'campaign_trend': stats.get('campaigns', {}).get('growth_rate', 0),
            'analysis_trend': stats.get('analyses', {}).get('growth_rate', 0)
        })
    # Feeds view
    elif view_type == 'feeds':
        common_data.update({
            'page_title': 'Threat Intelligence Feeds',
            'page_icon': 'rss',
            'page_subtitle': 'Collection of threat data from various sources',
            'feed_items': api_request('feeds').get('feed_details', [])
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
    return redirect(url_for('dashboard', view='feeds', days=request.args.get('days', '30')))

@app.route('/iocs')
@login_required
def iocs():
    return redirect(url_for('dashboard', view='iocs', days=request.args.get('days', '30')))

@app.route('/campaigns')
@login_required
def campaigns():
    return redirect(url_for('dashboard', view='campaigns', days=request.args.get('days', '30')))

@app.route('/explore')
@login_required
def explore():
    return redirect(url_for('dashboard'))

@app.route('/alerts')
@login_required
def alerts():
    return redirect(url_for('dashboard'))

# Content detail
@app.route('/content/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Generic handler for content details"""
    content_data = {}
    
    try:
        if content_type == 'feed':
            content_data = api_request(f'feeds/{identifier}/stats')
        elif content_type == 'campaign':
            content_data = api_request(f'campaigns/{identifier}')
        elif content_type == 'ioc':
            ioc_parts = identifier.split('/')
            if len(ioc_parts) >= 2:
                ioc_type = ioc_parts[0]
                ioc_value = '/'.join(ioc_parts[1:])  # Handle URLs with slashes
                content_data = api_request(f'iocs/detail', {'type': ioc_type, 'value': ioc_value})
    except Exception as e:
        logger.warning(f"Error retrieving content data for {content_type}/{identifier}: {e}")
    
    if not content_data:
        content_data = {"type": content_type, "id": identifier}
    
    return render_template('detail.html', 
                          content_type=content_type, 
                          identifier=identifier,
                          title=f"{content_type.title()} Details: {identifier}",
                          content=content_data)

# Ingest data
@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger the ingestion process"""
    try:
        # Try local module first
        try:
            import ingestion
            if hasattr(ingestion, 'ingest_threat_data'):
                ingestion.ingest_threat_data(request)
                flash("Ingestion process started successfully", "success")
                return redirect(url_for('dashboard', view='feeds'))
        except ImportError:
            pass
        
        # Fall back to API
        response = requests.post(
            f"{request.url_root.rstrip('/')}/api/ingest_threat_data",
            json={"process_all": True},
            headers={"X-API-Key": API_KEY} if API_KEY else {},
            timeout=30
        )
        
        flash("Ingestion process started successfully" if response.status_code == 200 
              else f"Error starting ingestion: {response.text}", 
              "success" if response.status_code == 200 else "danger")
    except Exception as e:
        flash(f"Error starting ingestion: {str(e)}", "danger")
    
    return redirect(url_for('dashboard', view='feeds'))

# Health checks
@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": os.environ.get("VERSION", "1.0.0"),
        "environment": config.environment,
        "project": PROJECT_ID
    })

@app.route('/health', methods=['GET'])
def health():
    return api_health()

# ======== Admin Routes ========
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return redirect(url_for('users'))

@app.route('/admin/users')
@login_required
@admin_required
def users():
    """User management page"""
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
        
        # Validate
        if not username or not password or password != confirm_password:
            flash("Validation failed", "danger")
            return render_template('auth.html', page_type='user_add')
        
        if len(password) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('auth.html', page_type='user_add')
        
        # Check if user exists
        try:
            auth_config = config.get_cached_config('auth-config', force_refresh=True)
            if auth_config and 'users' in auth_config and username in auth_config['users']:
                flash(f"User {username} already exists", "danger")
                return render_template('auth.html', page_type='user_add')
        except Exception:
            pass
        
        # Create user
        try:
            if hasattr(config, 'add_user') and config.add_user(username, password, role):
                flash(f"User {username} created successfully", "success")
                return redirect(url_for('users'))
            else:
                flash("Failed to create user", "danger")
        except Exception as e:
            flash(f"Error creating user: {str(e)}", "danger")
    
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
            if hasattr(config, 'update_user') and config.update_user(username, updates):
                flash(f"User {username} updated successfully", "success")
                return redirect(url_for('users'))
            else:
                flash("Failed to update user", "danger")
        except Exception as e:
            flash(f"Error updating user: {str(e)}", "danger")
    
    return render_template('auth.html', page_type='user_edit', username=username, user=user_data)

@app.route('/admin/users/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    """Delete user"""
    if username == ADMIN_USERNAME or username == session.get('username'):
        flash("Cannot delete admin user or yourself", "danger")
        return redirect(url_for('users'))
    
    try:
        success = False
        if hasattr(config, 'delete_user'):
            success = config.delete_user(username)
        elif hasattr(config, 'update_user'):
            success = config.update_user(username, {'active': False})
        
        flash(f"User {username} deleted successfully" if success else "Failed to delete user",
              "success" if success else "danger")
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "danger")
    
    return redirect(url_for('users'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({"error": "Resource not found", "path": request.path}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({"error": "Internal server error", "path": request.path}), 500
    return render_template('500.html'), 500

# Utility Functions
def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    cache_key = "gcp_metrics"
    
    # Check cache
    now = time.time()
    if cache_key in api_cache and now - api_cache_timestamp.get(cache_key, 0) < 300:
        return api_cache[cache_key]
    
    metrics = {"table_count": 0, "storage_objects": 0, "storage_size": 0.0}
    
    try:
        # Get BigQuery table counts
        bq_client = bigquery.Client(project=PROJECT_ID)
        query = f"SELECT COUNT(*) as table_count FROM `{PROJECT_ID}.{config.bigquery_dataset}.__TABLES__`"
        for row in bq_client.query(query).result():
            metrics["table_count"] = row.table_count
        
        # Get Storage bucket info
        try:
            storage_client = storage.Client(project=PROJECT_ID)
            bucket = storage_client.get_bucket(config.gcs_bucket)
            blobs = list(bucket.list_blobs(max_results=1000))
            metrics["storage_objects"] = len(blobs)
            metrics["storage_size"] = sum(blob.size for blob in blobs if hasattr(blob, 'size')) / (1024 * 1024)
        except Exception as e:
            logger.warning(f"Error getting storage metrics: {str(e)}")
    except Exception as e:
        logger.warning(f"Error getting GCP metrics: {str(e)}")
    
    # Cache results
    api_cache[cache_key] = metrics
    api_cache_timestamp[cache_key] = now
    
    return metrics

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug_mode = config.environment != "production"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
