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
import base64
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

def get_secret(secret_id, version_id="latest"):
    """Get secret from Secret Manager"""
    client = get_secret_client()
    if not client:
        return None
        
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.debug(f"Secret {secret_id} not found: {e}")
        return None

def create_secret(secret_id, secret_value):
    """Create a new secret"""
    client = get_secret_client()
    if not client:
        return False
        
    try:
        parent = f"projects/{PROJECT_ID}"
        
        # Create the secret
        client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )
        
        # Add the secret version
        client.add_secret_version(
            request={
                "parent": f"{parent}/secrets/{secret_id}",
                "payload": {"data": secret_value.encode("UTF-8")},
            }
        )
        return True
    except Exception as e:
        logger.error(f"Error creating secret {secret_id}: {e}")
        return False

def get_or_create_secret(secret_id, default_value_func=None):
    """Get secret or create it if it doesn't exist"""
    # Try to get existing secret
    value = get_secret(secret_id)
    if value:
        return value
        
    # Generate default value if not exists
    if default_value_func:
        new_value = default_value_func()
        if create_secret(secret_id, new_value):
            return new_value
    
    return None

# Initialize Flask app
# Get Flask secret key from Secret Manager or create a persistent one
flask_secret_key = get_or_create_secret("flask-secret-key", lambda: os.urandom(24).hex())
if not flask_secret_key:
    flask_secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
    logger.warning("Using temporary Flask secret key - sessions will not persist across restarts")

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
    """Set up admin credentials - returns the password if newly generated"""
    global ADMIN_HASH, ADMIN_PASSWORD
    
    # Try to get credentials from auth-config first
    try:
        auth_config = config.get_cached_config('auth-config', force_refresh=True)
        if auth_config and 'users' in auth_config and 'admin' in auth_config['users']:
            admin_user = auth_config['users']['admin']
            ADMIN_HASH = admin_user.get('password')
            logger.info("Admin credentials loaded from auth-config")
            return None
    except Exception as e:
        logger.warning(f"Failed to retrieve admin credentials from auth-config: {e}")
    
    # Try to get admin password from Secret Manager
    admin_secret = get_secret("admin-initial-password")
    if admin_secret:
        ADMIN_PASSWORD = admin_secret
        ADMIN_HASH = hashlib.sha256(admin_secret.encode()).hexdigest()
        logger.info("Admin credentials loaded from admin-initial-password secret")
        return None
    
    # Generate a new secure password as last resort
    ADMIN_PASSWORD = base64.b64encode(os.urandom(9)).decode('utf-8')[:12]  # 12-char readable password
    ADMIN_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    
    # Store the password in Secret Manager
    create_secret("admin-initial-password", ADMIN_PASSWORD)
    
    # Store in auth-config as well
    try:
        if hasattr(config, 'add_user'):
            config.add_user('admin', ADMIN_PASSWORD, 'admin')
    except Exception as e:
        logger.error(f"Failed to add admin user to auth-config: {e}")
    
    # This is a new admin password, return it for logging
    return ADMIN_PASSWORD

# Set up admin credentials and log if newly generated
new_admin_password = setup_admin_credentials()
if new_admin_password:
    logger.warning("="*80)
    logger.warning(f"GENERATED NEW ADMIN PASSWORD: {new_admin_password}")
    logger.warning(f"Username: admin, Password: {new_admin_password}")
    logger.warning("="*80)

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

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH and not is_session_valid():
            session.clear()
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
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
        except Exception:
            pass
            
        # Try admin fallback
        if not is_valid and username == ADMIN_USERNAME:
            is_valid = verify_password(ADMIN_HASH, password)
            user_role = 'admin'
        
        if is_valid:
            # Update last login time
            try:
                if hasattr(config, 'update_user'):
                    config.update_user(username, {'last_login': datetime.utcnow().isoformat()})
            except Exception:
                pass
                
            # Set session data
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user_role
            session['last_activity'] = time.time()
            session.permanent = True
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template('auth.html', page_type='login')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
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
    except Exception:
        pass
    
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
