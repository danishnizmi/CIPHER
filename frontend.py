"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform using consolidated templates.
"""

import os
import json
import logging
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, abort
import requests
from flask_cors import CORS
from google.cloud import storage
from google.cloud import bigquery
from werkzeug.local import LocalProxy

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = config.project_id
REGION = config.region
API_URL = config.api_url

# Get API key from config with proper fallback
if not hasattr(config, 'api_key') or config.api_key is None:
    # Attempt to load API key from environment or config
    API_KEY = os.environ.get("API_KEY", "")
    if not API_KEY:
        # Try to get from cached config
        api_keys_config = config.get_cached_config('api-keys')
        API_KEY = api_keys_config.get('platform_api_key', "") if api_keys_config else ""
else:
    API_KEY = config.api_key

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", config.get("FLASK_SECRET_KEY", "dev-key-change-in-production"))
CORS(app)

# Initialize GCP clients
storage_client = None
bq_client = None

try:
    storage_client = storage.Client(project=PROJECT_ID)
    logger.info("Storage client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize storage client: {str(e)}")

try:
    bq_client = bigquery.Client(project=PROJECT_ID)
    logger.info("BigQuery client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize BigQuery client: {str(e)}")

# Authentication settings
REQUIRE_AUTH = config.get("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "true").lower() == "true")

# Utility Functions
def generate_temp_password(length=12):
    """Generate a secure temporary password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def hash_password(password):
    """Create a secure hash of the password"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify a password against a stored hash"""
    return stored_hash == hash_password(password)

# Load user data from config
def get_users():
    """Get user data from config with fallback to default users"""
    auth_config = config.get_cached_config('auth-config')
    users = auth_config.get("users", {}) if auth_config else {}
    
    if not users:
        # Create admin user with temporary password if no users found
        temp_password = generate_temp_password()
        users = {
            "admin": {
                "password": hash_password(temp_password),
                "role": "admin",
                "temp_password": True,
                "created_at": datetime.utcnow().isoformat()
            }
        }
        
        # Try to save default admin user to config
        try:
            if auth_config is None:
                auth_config = {}
            auth_config["users"] = users
            config.create_or_update_secret("auth-config", json.dumps(auth_config))
            logger.info("Created default admin user in auth-config")
            logger.info(f"TEMPORARY ADMIN PASSWORD: {temp_password} - Please login and change immediately!")
        except Exception as e:
            logger.warning(f"Failed to save default admin user: {e}")
    
    return users

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH and not session.get("logged_in"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login", next=request.url))
            
            user_role = session.get("role", "readonly")
            
            # Simple role hierarchy: admin > analyst > readonly
            if required_role == "admin" and user_role != "admin":
                flash("You don't have permission to access this page", "danger")
                return render_template('auth.html', page_type='not_authorized')
            
            if required_role == "analyst" and user_role not in ["admin", "analyst"]:
                flash("You don't have permission to access this page", "danger")
                return render_template('auth.html', page_type='not_authorized')
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper functions
def api_request(endpoint: str, params: Dict = None) -> Dict:
    """Make a request to the API service"""
    # Create a default response structure for error cases
    default_response = {
        "error": "API request failed",
        "feeds": {"total_sources": 0},
        "campaigns": {"total_campaigns": 0},
        "iocs": {"total": 0, "types": []},
        "analyses": {"total_analyses": 0}
    }
    
    # Build the URL properly - ensure we have a valid absolute URL
    if API_URL:
        # Make sure API_URL doesn't end with / to avoid double slashes
        base_url = API_URL.rstrip('/')
        url = f"{base_url}/api/{endpoint}"
    else:
        # For local development, use a proper absolute URL with localhost
        # The requests library requires an absolute URL with scheme
        url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/{endpoint}"
    
    headers = {}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    
    try:
        logger.info(f"Making API request to: {url}")
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        return default_response

def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
    """Format datetime objects or ISO strings for display"""
    if isinstance(value, str):
        try:
            # Try to parse as ISO format
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
        
        # Get latest users from config
        current_users = get_users()
        
        if username in current_users:
            user_data = current_users[username]
            if verify_password(user_data['password'], password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user_data.get('role', 'readonly')
                
                # Check if user is using a temporary password
                if user_data.get('temp_password', False):
                    flash("Please change your temporary password", "warning")
                    return redirect(url_for('profile'))
                
                # Update last login time
                try:
                    config.update_user(username, {"last_login": datetime.utcnow().isoformat()})
                except Exception as e:
                    logger.warning(f"Could not update last login: {str(e)}")
                
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username or password"
        else:
            error = "Invalid username or password"
    
    return render_template('auth.html', page_type='login', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    """User Profile page"""
    username = session.get('username')
    
    # Get latest users from config
    current_users = get_users()
    user_data = current_users.get(username, {})
    
    return render_template('auth.html', 
                           page_type='profile', 
                           username=username, 
                           user=user_data)

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    username = session.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Get latest users from config
    current_users = get_users()
    
    if not username or username not in current_users:
        flash("User not found", "danger")
        return redirect(url_for('profile'))
    
    if not current_password or not new_password or not confirm_password:
        flash("All fields are required", "danger")
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for('profile'))
    
    # Check current password
    if not verify_password(current_users[username]['password'], current_password):
        flash("Current password is incorrect", "danger")
        return redirect(url_for('profile'))
    
    # Update password
    updates = {
        "password": new_password,
        "temp_password": False,  # Clear the temp password flag if it was set
    }
    
    result = config.update_user(username, updates)
    if result:
        flash("Password changed successfully", "success")
    else:
        flash("Failed to change password", "danger")
    
    return redirect(url_for('profile'))

@app.route('/users')
@login_required
@role_required('admin')
def users():
    """User Management page"""
    # Get latest users from config
    current_users = get_users()
    
    return render_template(
        'content.html',
        page_title='User Management',
        page_icon='users',
        page_subtitle='Manage platform users and access',
        content_type='users',
        content_items=current_users,
        action_buttons=[{
            'text': 'Add User',
            'url': url_for('add_user_route'),
            'icon': 'user-plus',
            'type': 'primary'
        }]
    )

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user_route():
    """Add a new user"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role', 'readonly')
        
        if username:
            # Generate a temporary password
            temp_password = generate_temp_password()
            
            # Add user with temporary password
            result = config.add_user(username, temp_password, role)
            if result:
                # Update to set temp_password flag
                config.update_user(username, {"temp_password": True})
                # Log the temporary password - this allows the admin to share it
                logger.info(f"Created user {username} with role {role}")
                logger.info(f"TEMPORARY PASSWORD FOR {username}: {temp_password}")
                flash(f"User {username} added successfully. Check logs for temporary password.", "success")
                return redirect(url_for('users'))
            else:
                error = f"Failed to add user {username}"
        else:
            error = "Username is required"
    
    return render_template('auth.html', page_type='user_add', error=error)

@app.route('/users/edit/<username>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(username):
    """Edit an existing user"""
    # Get latest users from config
    current_users = get_users()
    error = None
    
    if username not in current_users:
        flash(f"User {username} not found", "danger")
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        new_role = request.form.get('role')
        new_password = request.form.get('password')
        
        updates = {}
        if new_role:
            updates["role"] = new_role
        
        if new_password:
            updates["password"] = new_password
            updates["temp_password"] = True  # Set temp password flag
            
            # Log that a temporary password was set
            logger.info(f"Reset password for {username}")
            logger.info(f"TEMPORARY PASSWORD FOR {username}: {new_password}")
            
        if updates:
            result = config.update_user(username, updates)
            if result:
                msg = "User updated successfully"
                if new_password:
                    msg += ". Temporary password set - check logs."
                flash(msg, "success")
            else:
                error = f"Failed to update user {username}"
        
        if not error:
            return redirect(url_for('users'))
    
    return render_template('auth.html', 
                          page_type='user_edit', 
                          username=username, 
                          user=current_users[username],
                          error=error)

@app.route('/users/delete/<username>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(username):
    """Delete a user"""
    # Get latest users from config
    current_users = get_users()
    
    if username not in current_users:
        flash(f"User {username} not found", "danger")
        return redirect(url_for('users'))
    
    # Cannot delete yourself
    if username == session.get('username'):
        flash("You cannot delete your own account", "danger")
        return redirect(url_for('users'))
    
    # Remove user from config
    auth_config = config.get_cached_config('auth-config', force_refresh=True)
    if 'users' in auth_config and username in auth_config['users']:
        del auth_config['users'][username]
        result = config.create_or_update_secret('auth-config', json.dumps(auth_config))
        if result:
            flash(f"User {username} deleted successfully", "success")
        else:
            flash(f"Failed to delete user {username}", "danger")
    else:
        flash(f"User {username} not found", "danger")
    
    return redirect(url_for('users'))

# Dashboard Routes
@app.route('/')
@login_required
def dashboard():
    """Dashboard page"""
    days = request.args.get('days', '30')
    
    # Get platform stats
    stats = api_request('stats', {'days': days})
    
    # If stats is empty or missing expected structure, populate with defaults
    if not stats or not isinstance(stats, dict):
        stats = {
            "feeds": {"total_sources": 0},
            "campaigns": {"total_campaigns": 0},
            "iocs": {"total": 0, "types": []},
            "analyses": {"total_analyses": 0}
        }
    
    # Ensure all required keys exist
    if "feeds" not in stats:
        stats["feeds"] = {"total_sources": 0}
    if "campaigns" not in stats:
        stats["campaigns"] = {"total_campaigns": 0}
    if "iocs" not in stats:
        stats["iocs"] = {"total": 0, "types": []}
    if "analyses" not in stats:
        stats["analyses"] = {"total_analyses": 0}
    
    # Get recent campaigns
    campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
    campaigns = campaigns_data.get('campaigns', [])
    
    # Get top IOCs
    iocs_data = api_request('iocs', {'days': days, 'limit': 5})
    top_iocs = iocs_data.get('records', [])
    
    # Get GCP metrics
    gcp_metrics = get_gcp_metrics()
    
    # Generate chart data
    ioc_type_labels = []
    ioc_type_values = []
    
    # Try to get real chart data
    if 'iocs' in stats and 'types' in stats['iocs']:
        ioc_types = stats['iocs']['types']
        labels = [item.get('type', 'unknown') for item in ioc_types]
        values = [item.get('count', 0) for item in ioc_types]
        if labels and values:
            ioc_type_labels = labels
            ioc_type_values = values
    
    # Generate activity data
    activity_data = api_request('feeds/alienvault_pulses/stats', {'days': days})
    
    # Default activity data if API fails
    default_dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
    default_counts = [int(5 + i * 2.5) for i in range(7)]
    
    activity_dates = default_dates
    activity_counts = default_counts
    
    # Try to use real activity data if available
    if activity_data and "daily_counts" in activity_data:
        dates = [item.get("date") for item in activity_data.get("daily_counts", [])]
        counts = [item.get("count", 0) for item in activity_data.get("daily_counts", [])]
        if dates and counts:
            activity_dates = dates
            activity_counts = counts
    
    # Provide trend data
    feed_trend = 5
    ioc_trend = 12
    campaign_trend = 8
    analysis_trend = 15
    
    return render_template(
        'dashboard.html',
        days=days,
        stats=stats,
        campaigns=campaigns,
        top_iocs=top_iocs,
        gcp_metrics=gcp_metrics,
        ioc_type_labels=json.dumps(ioc_type_labels),
        ioc_type_values=json.dumps(ioc_type_values),
        activity_dates=json.dumps(activity_dates),
        activity_counts=json.dumps(activity_counts),
        feed_trend=feed_trend,
        ioc_trend=ioc_trend,
        campaign_trend=campaign_trend,
        analysis_trend=analysis_trend
    )

# Feeds Routes
@app.route('/feeds')
@login_required
def feeds():
    """Feeds overview page"""
    days = request.args.get('days', '30')
    
    # Get feeds list
    feeds_data = api_request('feeds')
    feed_list = feeds_data.get('feeds', [])
    
    # Get stats for each feed
    feeds = []
    total_records = 0
    days_with_updates = 0
    
    for feed_name in feed_list:
        feed_stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
        
        feeds.append({
            'feed_name': feed_name,
            'record_count': feed_stats.get('total_records', 0),
            'latest_record': feed_stats.get('latest_record'),
            'earliest_record': feed_stats.get('earliest_record')
        })
        
        total_records += feed_stats.get('total_records', 0)
        days_with_updates += feed_stats.get('days_with_data', 0)
    
    # Prepare feed activity data
    feed_activity_data = {}
    for feed_name in feed_list[:5]:  # Limit to 5 feeds
        feed_stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
        
        dates = []
        counts = []
        
        for day_data in feed_stats.get('daily_counts', []):
            dates.append(day_data.get('date'))
            counts.append(day_data.get('count', 0))
        
        feed_activity_data[feed_name] = {
            'dates': dates,
            'counts': counts
        }
    
    return render_template(
        'content.html',
        page_title='Threat Intelligence Feeds',
        page_icon='rss',
        page_subtitle='Collection of threat data from various sources',
        days=days,
        current_endpoint='feeds',
        content_type='feeds',
        content_items=feeds,
        summary_stats=[
            {'label': 'Active Feeds', 'value': len(feeds), 'icon': 'plug', 'color': 'blue'},
            {'label': 'Total Records', 'value': total_records, 'icon': 'database', 'color': 'green'},
            {'label': 'Days with Updates', 'value': days_with_updates, 'icon': 'calendar-check', 'color': 'purple'}
        ],
        chart_data=feed_activity_data,
        chart_icon='chart-line',
        chart_title='Feed Activity',
        chart_type='line',
        feed_activity=json.dumps(feed_activity_data),
        action_buttons=[{
            'text': 'Run Ingestion',
            'url': url_for('ingest_threat_data'),
            'icon': 'sync',
            'type': 'success'
        }]
    )

@app.route('/ingest_threat_data')
@login_required
@role_required('analyst')
def ingest_threat_data():
    """Trigger the ingestion process"""
    try:
        # Determine the API URL
        if API_URL:
            base_url = API_URL.rstrip('/')
            url = f"{base_url}/api/ingest_threat_data"
        else:
            url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/ingest_threat_data"
        
        headers = {}
        if API_KEY:
            headers["X-API-Key"] = API_KEY
        
        # Make the request to trigger ingestion
        response = requests.post(
            url,
            headers=headers,
            json={"process_all": True},
            timeout=30
        )
        
        if response.status_code == 200:
            flash("Ingestion process started successfully", "success")
        else:
            flash(f"Error starting ingestion: {response.text}", "danger")
    
    except Exception as e:
        flash(f"Error starting ingestion: {str(e)}", "danger")
    
    return redirect(url_for('feeds'))

@app.route('/feeds/<feed_name>')
@login_required
def feed_detail(feed_name: str):
    """Feed detail page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    search = request.args.get('search', '')
    
    # Get feed stats
    stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
    
    # Get feed data
    params = {'days': days, 'limit': limit, 'offset': offset}
    if search:
        params['search'] = search
    
    feed_data = api_request(f'feeds/{feed_name}/data', params)
    
    records = feed_data.get('records', [])
    
    # Extract columns (use first record or empty list)
    columns = []
    if records:
        # Filter out internal columns
        columns = [col for col in records[0].keys() if not col.startswith('_')]
    
    # Prepare pagination
    pagination = {
        'total': feed_data.get('total', 0),
        'limit': limit,
        'offset': offset,
        'params': {'search': search} if search else {}
    }
    
    # Prepare daily counts chart data
    chart_data = {
        'dates': [day_data.get('date') for day_data in stats.get('daily_counts', [])],
        'counts': [day_data.get('count', 0) for day_data in stats.get('daily_counts', [])]
    }
    
    return render_template(
        'detail.html',
        page_title=f'{feed_name} Feed',
        page_icon='rss',
        page_subtitle='Detailed view of threat intelligence data',
        entity_type='feed',
        entity=stats,
        entity_id=feed_name,
        back_url=url_for('feeds'),
        parent_endpoint='feeds',
        current_endpoint='feed_detail',
        chart_data=chart_data,
        entity_tabs=[
            {
                'id': 'records',
                'label': 'Feed Records',
                'icon': 'table',
                'count': stats.get('total_records', 0),
                'columns': columns,
                'data': records,
                'pagination': pagination
            }
        ],
        entity_actions=[
            {
                'text': 'Run Ingestion',
                'url': url_for('ingest_threat_data'),
                'icon': 'sync'
            }
        ]
    )

# Campaigns Routes
@app.route('/campaigns')
@login_required
def campaigns():
    """Campaigns overview page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    min_sources = int(request.args.get('min_sources', '2'))
    search = request.args.get('search', '')
    
    # Get campaigns list
    params = {
        'days': days,
        'limit': limit,
        'offset': offset,
        'min_sources': min_sources
    }
    
    if search:
        # Use search API for text search
        search_data = api_request('search', {'q': search, 'days': days})
        campaigns = search_data.get('results', {}).get('campaigns', [])
        total = len(campaigns)
    else:
        # Get all campaigns
        campaigns_data = api_request('campaigns', params)
        campaigns = campaigns_data.get('campaigns', [])
        total = campaigns_data.get('count', 0)
    
    # Prepare pagination
    pagination = {
        'total': total,
        'limit': limit,
        'offset': offset,
        'params': {
            'min_sources': min_sources,
            'search': search
        }
    }
    
    # Count by actor and target for charts
    actor_data = {}
    target_data = {}
    
    for campaign in campaigns:
        # Count by actor
        actor = campaign.get('threat_actor', 'Unknown')
        if actor not in actor_data:
            actor_data[actor] = 0
        actor_data[actor] += 1
        
        # Target may be a single string or a list
        target = campaign.get('targets', 'Unknown')
        if isinstance(target, list):
            for t in target:
                if t not in target_data:
                    target_data[t] = 0
                target_data[t] += 1
        else:
            if target not in target_data:
                target_data[target] = 0
            target_data[target] += 1
    
    # Convert to chart data
    chart_data = {
        'labels': list(actor_data.keys()),
        'values': list(actor_data.values())
    }
    
    return render_template(
        'content.html',
        page_title='Threat Campaigns',
        page_icon='project-diagram',
        page_subtitle='Active and historical threat campaigns',
        days=days,
        current_endpoint='campaigns',
        content_type='campaigns',
        content_items=campaigns,
        chart_data=chart_data,
        chart_type='pie',
        chart_icon='chart-pie',
        chart_title='Campaigns by Threat Actor',
        show_filters=True,
        filter_types=[
            {'label': 'All Severities', 'value': ''},
            {'label': 'Critical', 'value': 'critical'},
            {'label': 'High', 'value': 'high'},
            {'label': 'Medium', 'value': 'medium'},
            {'label': 'Low', 'value': 'low'}
        ],
        selected_type=request.args.get('type', ''),
        min_sources=min_sources,
        search=search,
        limit=limit,
        pagination=pagination
    )

@app.route('/campaigns/<campaign_id>')
@login_required
def campaign_detail(campaign_id: str):
    """Campaign detail page"""
    # Get campaign details
    campaign_data = api_request(f'campaigns/{campaign_id}')
    
    if 'error' in campaign_data:
        flash("Campaign not found", "danger")
        return redirect(url_for("campaigns"))
    
    # Prepare IOC type chart data
    ioc_types = {}
    for ioc in campaign_data.get('iocs', []):
        ioc_type = ioc.get('type', 'unknown')
        if ioc_type not in ioc_types:
            ioc_types[ioc_type] = 0
        ioc_types[ioc_type] += 1
    
    chart_data = {
        'labels': list(ioc_types.keys()),
        'values': list(ioc_types.values())
    }
    
    return render_template(
        'detail.html',
        page_title=campaign_data.get('campaign_name', 'Campaign Details'),
        page_icon='project-diagram',
        page_subtitle='Comprehensive campaign intelligence',
        entity_type='campaign',
        entity=campaign_data,
        entity_id=campaign_id,
        back_url=url_for('campaigns'),
        parent_endpoint='campaigns',
        current_endpoint='campaign_detail',
        chart_data=chart_data,
        entity_tabs=[
            {
                'id': 'iocs',
                'label': 'Indicators',
                'icon': 'fingerprint',
                'count': len(campaign_data.get('iocs', [])),
                'data': campaign_data.get('iocs', [])
            },
            {
                'id': 'sources',
                'label': 'Intelligence Sources',
                'icon': 'database',
                'count': campaign_data.get('source_count', 0),
                'data': [{'source_id': src, 'source_type': 'feed'} for src in campaign_data.get('sources', [])]
            }
        ],
        show_visualization=True,
        viz_icon='project-diagram',
        viz_title='Campaign Relationships'
    )

# IOCs Routes
@app.route('/iocs')
@login_required
def iocs():
    """IOCs overview page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    search_value = request.args.get('value', '')
    search_type = request.args.get('type', '')
    
    # Get IOCs data
    params = {
        'days': days,
        'limit': limit,
        'offset': offset
    }
    
    if search_value:
        params['value'] = search_value
    if search_type:
        params['type'] = search_type
    
    iocs_data = api_request('iocs', params)
    
    # Get platform stats for IOC distribution
    stats = api_request('stats', {'days': days})
    ioc_types = stats.get('iocs', {}).get('types', [])
    
    # Prepare chart data
    chart_data = {
        'labels': [item.get('type', 'unknown') for item in ioc_types],
        'values': [item.get('count', 0) for item in ioc_types]
    }
    
    # Extract all individual IOCs from records
    all_iocs = []
    for record in iocs_data.get('records', []):
        for ioc in record.get('iocs', []):
            # Add source info to each IOC
            ioc['source'] = record.get('source_type')
            ioc['source_id'] = record.get('source_id')
            all_iocs.append(ioc)
    
    # Prepare pagination
    pagination = {
        'total': iocs_data.get('count', 0) * 5,  # Approximate: each record has multiple IOCs
        'limit': limit,
        'offset': offset,
        'params': {
            'type': search_type,
            'value': search_value
        }
    }
    
    return render_template(
        'content.html',
        page_title='Indicators of Compromise',
        page_icon='fingerprint',
        page_subtitle='Collected IOCs from all sources',
        days=days,
        current_endpoint='iocs',
        content_type='iocs',
        content_items=all_iocs[:limit],  # Limit displayed IOCs
        chart_data=chart_data,
        chart_type='pie',
        chart_icon='chart-pie',
        chart_title='IOC Type Distribution',
        show_filters=True,
        filter_types=[
            {'label': 'All Types', 'value': ''},
            {'label': 'IP Address', 'value': 'ip'},
            {'label': 'Domain', 'value': 'domain'},
            {'label': 'URL', 'value': 'url'},
            {'label': 'MD5 Hash', 'value': 'md5'},
            {'label': 'SHA1 Hash', 'value': 'sha1'},
            {'label': 'SHA256 Hash', 'value': 'sha256'},
            {'label': 'Email', 'value': 'email'}
        ],
        selected_type=search_type,
        search=search_value,
        limit=limit,
        pagination=pagination
    )

@app.route('/iocs/<type>/<value>')
@login_required
def ioc_detail(type: str, value: str):
    """IOC detail page"""
    # Get IOC details
    iocs_data = api_request('iocs', {'type': type, 'value': value, 'limit': 1})
    if not iocs_data.get('records'):
        flash("IOC not found", "danger")
        return redirect(url_for("iocs"))
    
    record = iocs_data.get('records')[0]
    
    # Find the specific IOC in the record
    ioc = None
    for i in record.get('iocs', []):
        if i.get('type') == type and i.get('value') == value:
            ioc = i
            break
    
    if not ioc:
        flash("IOC detail not found", "danger")
        return redirect(url_for("iocs"))
    
    # Add source information to the IOC
    ioc['source'] = record.get('source_type')
    ioc['source_id'] = record.get('source_id')
    
    # Get campaigns that reference this IOC
    search_data = api_request('search', {'q': value})
    campaigns = search_data.get('results', {}).get('campaigns', [])
    
    # Get sources that reference this IOC
    sources = search_data.get('results', {}).get('analyses', [])
    
    return render_template(
        'detail.html',
        page_title=f'IOC: {value}',
        page_icon='fingerprint',
        page_subtitle=f'Type: {type.upper()}',
        entity_type='ioc',
        entity=ioc,
        entity_id=f"{type}_{value}",
        back_url=url_for('iocs'),
        parent_endpoint='iocs',
        current_endpoint='ioc_detail',
        entity_tabs=[
            {
                'id': 'campaigns',
                'label': 'Campaigns',
                'icon': 'project-diagram',
                'count': len(campaigns),
                'data': campaigns
            },
            {
                'id': 'sources',
                'label': 'Intelligence Sources',
                'icon': 'database',
                'count': len(sources),
                'data': sources
            }
        ]
    )

# Reports Routes
@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    days = request.args.get('days', '30')
    
    # Get reports from API
    report_types = ["feed_summary", "campaign_analysis", "ioc_trend"]
    reports = []
    
    for report_type in report_types:
        try:
            report_data = api_request(f'reports/{report_type}', {'days': days})
            if 'error' not in report_data:
                # Add icon based on report type
                if 'feed' in report_type:
                    report_data['icon'] = 'rss'
                elif 'campaign' in report_type:
                    report_data['icon'] = 'project-diagram'
                elif 'ioc' in report_type:
                    report_data['icon'] = 'fingerprint'
                else:
                    report_data['icon'] = 'file-alt'
                
                reports.append(report_data)
            else:
                # Create structured report entry with minimal data
                reports.append({
                    'report_id': f'{report_type}_report',
                    'report_name': f'{report_type.replace("_", " ").title()} Report',
                    'report_type': report_type,
                    'generated_at': datetime.now().isoformat(),
                    'period_days': int(days),
                    'icon': 'file-alt'
                })
        except Exception as e:
            logger.warning(f"Error fetching report {report_type}: {str(e)}")
            # Create structured report entry with minimal data
            reports.append({
                'report_id': f'{report_type}_report',
                'report_name': f'{report_type.replace("_", " ").title()} Report',
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'period_days': int(days),
                'icon': 'file-alt'
            })
    
    return render_template(
        'content.html',
        page_title='Threat Intelligence Reports',
        page_icon='chart-bar',
        page_subtitle='Comprehensive threat analysis reports',
        days=days,
        current_endpoint='reports',
        content_type='reports',
        content_items=reports,
        action_buttons=[{
            'text': 'Generate Report',
            'url': url_for('generate_report'),
            'icon': 'file-export',
            'type': 'primary'
        }]
    )

@app.route('/generate_report')
@login_required
@role_required('analyst')
def generate_report():
    """Generate a report"""
    report_type = request.args.get('report_type', 'feed_summary')
    days = int(request.args.get('days', '30'))
    campaign_id = request.args.get('campaign_id')
    
    # Call API to generate report
    params = {'days': days, 'generate': 'true'}
    if campaign_id:
        params['campaign_id'] = campaign_id
        
    try:
        response = api_request(f'reports/{report_type}', params)
        if 'error' not in response:
            flash(f"Report '{report_type}' generated successfully", "success")
        else:
            flash(f"Error generating report: {response.get('error')}", "danger")
    except Exception as e:
        flash(f"Error generating report: {str(e)}", "danger")
    
    return redirect(url_for('reports'))

@app.route('/reports/<report_id>')
@login_required
def view_report(report_id: str):
    """View report details"""
    # Parse report type from ID
    parts = report_id.split('_')
    report_type = '_'.join(parts[:-1]) if len(parts) > 1 else parts[0]
    
    # Get report from API
    report_data = api_request(f'reports/{report_type}', {'report_id': report_id})
    
    if 'error' in report_data:
        flash("Report not found", "danger")
        return redirect(url_for("reports"))
    
    return render_template(
        'detail.html',
        page_title=report_data.get('report_name', 'Report Details'),
        page_icon='file-alt',
        page_subtitle=f"Generated: {format_datetime(report_data.get('generated_at'))}",
        entity_type='report',
        entity=report_data,
        entity_id=report_id,
        back_url=url_for('reports'),
        parent_endpoint='reports',
        current_endpoint='view_report'
    )

# Alerts Routes
@app.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    # Get alerts from API
    alerts_data = api_request('alerts')
    alerts_list = alerts_data.get('alerts', [])
    
    # Handle case of empty alerts with proper structure
    if not alerts_list:
        # Create structured alerts with minimal data
        current_time = datetime.now()
        alerts_list = [
            {
                'id': 'no_alerts_1',
                'title': 'No alerts currently active',
                'severity': 'low',
                'timestamp': current_time.isoformat(),
                'description': 'The system is working normally with no active threats detected.'
            }
        ]
    
    return render_template(
        'content.html',
        page_title='Threat Alerts',
        page_icon='bell',
        page_subtitle='Active security alerts requiring attention',
        content_type='alerts',
        content_items=alerts_list
    )

# Explorer Route
@app.route('/explore')
@login_required
def explore():
    """Data Explorer page"""
    # Get available data sources
    feeds_data = api_request('feeds')
    feeds = feeds_data.get('feeds', [])
    
    return render_template(
        'content.html',
        page_title='Data Explorer',
        page_icon='search',
        page_subtitle='Explore and analyze threat intelligence data',
        content_type='explore',
        content_html="""
        <div class="bg-white rounded-lg shadow-md p-6">
            <h3 class="text-lg font-semibold mb-4">Query Intelligence Data</h3>
            <p class="text-gray-600 mb-4">Use this explorer to run custom queries against the threat intelligence database.</p>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Data Source</label>
                    <select class="form-control">
                        <option value="">All Sources</option>
                        {% for feed in feeds %}
                        <option value="{{ feed }}">{{ feed }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Time Range</label>
                    <select class="form-control">
                        <option value="7">Last 7 Days</option>
                        <option value="30" selected>Last 30 Days</option>
                        <option value="90">Last 90 Days</option>
                        <option value="365">Last Year</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Format</label>
                    <select class="form-control">
                        <option value="table">Table</option>
                        <option value="chart">Chart</option>
                        <option value="raw">Raw JSON</option>
                    </select>
                </div>
            </div>
            
            <div class="mb-6">
                <label class="block text-sm font-medium text-gray-700 mb-2">Custom Query</label>
                <textarea class="form-control h-32 font-mono" placeholder="Enter your query..."></textarea>
            </div>
            
            <div class="flex justify-end">
                <button class="btn btn-primary">
                    <i class="fas fa-play mr-2"></i>Run Query
                </button>
            </div>
        </div>
        
        <div class="mt-6 bg-white rounded-lg shadow-md p-6">
            <h3 class="text-lg font-semibold mb-4">Results</h3>
            <p class="text-center text-gray-500">Run a query to see results</p>
        </div>
        """,
        feeds=feeds
    )

# Settings Routes
@app.route('/settings')
@login_required
@role_required('admin')
def settings():
    """Settings page"""
    return render_template(
        'content.html',
        page_title='Platform Settings',
        page_icon='cog',
        page_subtitle='Configure platform behavior and integrations',
        content_html="""
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            <a href="{{ url_for('api_keys_settings') }}" class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-indigo-100 p-3 mr-4">
                        <i class="fas fa-key text-indigo-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">API Keys</h3>
                </div>
                <p class="text-gray-600">Manage third-party API keys for feed ingestion</p>
            </a>
            
            <a href="{{ url_for('feed_settings') }}" class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-blue-100 p-3 mr-4">
                        <i class="fas fa-rss text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">Feed Settings</h3>
                </div>
                <p class="text-gray-600">Configure feed sources and ingestion options</p>
            </a>
            
            <a href="{{ url_for('users') }}" class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-green-100 p-3 mr-4">
                        <i class="fas fa-users-cog text-green-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">User Management</h3>
                </div>
                <p class="text-gray-600">Manage platform users and access controls</p>
            </a>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-red-100 p-3 mr-4">
                        <i class="fas fa-bell text-red-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">Alert Settings</h3>
                </div>
                <p class="text-gray-600">Configure alert thresholds and notifications</p>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-purple-100 p-3 mr-4">
                        <i class="fas fa-cloud text-purple-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">GCP Settings</h3>
                </div>
                <p class="text-gray-600">Configure Google Cloud Platform resources</p>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <div class="flex items-center mb-4">
                    <div class="rounded-full bg-yellow-100 p-3 mr-4">
                        <i class="fas fa-database text-yellow-600 text-xl"></i>
                    </div>
                    <h3 class="text-lg font-semibold">Data Retention</h3>
                </div>
                <p class="text-gray-600">Configure data retention policies and cleanup</p>
            </div>
        </div>
        """
    )

@app.route('/settings/api_keys', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def api_keys_settings():
    """API Keys Settings page"""
    # Get current API keys
    api_keys_data = config.get_cached_config('api-keys') or {}
    api_keys = {
        "virustotal": api_keys_data.get("virustotal", ""),
        "alienvault": api_keys_data.get("alienvault", ""),
        "misp": api_keys_data.get("misp", ""),
        "mandiant": api_keys_data.get("mandiant", "")
    }
    
    if request.method == 'POST':
        # Update API keys
        for service in api_keys.keys():
            new_key = request.form.get(f"{service}_api_key")
            if new_key is not None and new_key != api_keys[service]:
                config.update_api_key(service, new_key)
                flash(f"{service.title()} API key updated successfully", "success")
        
        # Reload the page to show updated keys
        return redirect(url_for('api_keys_settings'))
    
    return render_template(
        'content.html',
        page_title='API Keys Settings',
        page_icon='key',
        page_subtitle='Manage third-party API keys for data collection',
        content_html="""
        <div class="bg-white rounded-lg shadow-md overflow-hidden">
            <div class="px-6 py-4 border-b">
                <h3 class="font-semibold flex items-center">
                    <i class="fas fa-key mr-2 text-blue-600"></i>
                    External API Keys
                </h3>
            </div>
            <div class="p-6">
                <form method="post" action="{{ url_for('api_keys_settings') }}">
                    <div class="space-y-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">VirusTotal API Key</label>
                            <input type="text" name="virustotal_api_key" value="{{ api_keys.virustotal }}" 
                                   class="form-control" placeholder="Enter VirusTotal API key">
                            <p class="mt-1 text-xs text-gray-500">Used for file hash reputation checks and IOC enrichment</p>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">AlienVault OTX API Key</label>
                            <input type="text" name="alienvault_api_key" value="{{ api_keys.alienvault }}" 
                                   class="form-control" placeholder="Enter AlienVault OTX API key">
                            <p class="mt-1 text-xs text-gray-500">Used for retrieving AlienVault OTX pulses</p>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">MISP API Key</label>
                            <input type="text" name="misp_api_key" value="{{ api_keys.misp }}" 
                                   class="form-control" placeholder="Enter MISP API key">
                            <p class="mt-1 text-xs text-gray-500">Used for connecting to MISP instance</p>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Mandiant Advantage API Key</label>
                            <input type="text" name="mandiant_api_key" value="{{ api_keys.mandiant }}" 
                                   class="form-control" placeholder="Enter Mandiant API key">
                            <p class="mt-1 text-xs text-gray-500">Used for Mandiant threat intelligence</p>
                        </div>
                        
                        <div class="pt-4 border-t border-gray-200">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save mr-2"></i>Save API Keys
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        """,
        api_keys=api_keys
    )

@app.route('/settings/feeds', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def feed_settings():
    """Feed Settings page"""
    # Get current feed configurations
    feed_config_data = config.get_cached_config('feed-config') or {}
    feed_configs = feed_config_data.get("feeds", [])
    
    # Convert to dict for easier access
    feed_config_dict = {}
    for feed in feed_configs:
        feed_name = feed.get("name")
        if feed_name:
            feed_config_dict[feed_name] = feed
    
    if request.method == 'POST':
        # Update feed configuration
        feed_name = request.form.get("feed_name")
        if feed_name:
            updates = {
                "url": request.form.get(f"{feed_name}_url", ""),
                "auth_key": request.form.get(f"{feed_name}_auth_key", ""),
                "active": request.form.get(f"{feed_name}_active") == "on"
            }
            
            config.update_feed_config(feed_name, updates)
            flash(f"{feed_name.title()} feed configuration updated successfully", "success")
        
        # Reload the page to show updated configuration
        return redirect(url_for('feed_settings'))
    
    return render_template(
        'content.html',
        page_title='Feed Settings',
        page_icon='rss',
        page_subtitle='Configure threat data sources',
        content_html="""
        <div class="bg-white rounded-lg shadow-md overflow-hidden">
            <div class="px-6 py-4 border-b">
                <h3 class="font-semibold flex items-center">
                    <i class="fas fa-rss mr-2 text-blue-600"></i>
                    Threat Feed Configuration
                </h3>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Feed Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint URL</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for feed_name, feed in feed_config_dict.items() %}
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap font-medium">{{ feed_name }}</td>
                            <td class="px-6 py-4 truncate max-w-xs">{{ feed.url|default('Default URL') }}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                {% if feed.active %}
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                                    <span class="w-1.5 h-1.5 rounded-full bg-green-500 mr-1"></span>
                                    Active
                                </span>
                                {% else %}
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                                    <span class="w-1.5 h-1.5 rounded-full bg-gray-500 mr-1"></span>
                                    Inactive
                                </span>
                                {% endif %}
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <button class="text-blue-600 hover:text-blue-900" onclick="toggleFeedForm('{{ feed_name }}')">
                                    <i class="fas fa-edit mr-1"></i> Edit
                                </button>
                            </td>
                        </tr>
                        <tr id="form-{{ feed_name }}" class="hidden bg-gray-50">
                            <td colspan="4" class="px-6 py-4">
                                <form method="post" action="{{ url_for('feed_settings') }}" class="space-y-4">
                                    <input type="hidden" name="feed_name" value="{{ feed_name }}">
                                    
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-1">Feed URL</label>
                                        <input type="text" name="{{ feed_name }}_url" value="{{ feed.url }}" 
                                               class="form-control" placeholder="Enter feed URL">
                                    </div>
                                    
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-1">API Key / Auth Token</label>
                                        <input type="text" name="{{ feed_name }}_auth_key" value="{{ feed.auth_key }}" 
                                               class="form-control" placeholder="Enter API key if required">
                                    </div>
                                    
                                    <div class="flex items-center">
                                        <input type="checkbox" id="{{ feed_name }}_active" name="{{ feed_name }}_active" 
                                               {{ 'checked' if feed.active else '' }}
                                               class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                        <label for="{{ feed_name }}_active" class="ml-2 block text-sm text-gray-900">
                                            Active
                                        </label>
                                    </div>
                                    
                                    <div class="pt-2">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-save mr-2"></i>Save Changes
                                        </button>
                                        <button type="button" class="btn btn-secondary ml-2" onclick="toggleFeedForm('{{ feed_name }}')">
                                            Cancel
                                        </button>
                                    </div>
                                </form>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="4" class="px-6 py-4 text-center text-gray-500">
                                No feed configurations found
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function toggleFeedForm(feedName) {
                const formRow = document.getElementById('form-' + feedName);
                formRow.classList.toggle('hidden');
            }
        </script>
        """,
        feed_config_dict=feed_config_dict
    )

# Search Route
@app.route('/search')
@login_required
def search():
    """Search page"""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('dashboard'))
    
    # Search across all data
    search_data = api_request('search', {'q': query, 'days': 30})
    
    return render_template(
        'content.html',
        page_title='Search Results',
        page_icon='search',
        page_subtitle=f'Results for: {query}',
        content_html=f"""
        <div class="bg-white rounded-lg shadow-md mb-6">
            <div class="px-6 py-4 border-b">
                <h3 class="font-semibold flex items-center">
                    <i class="fas fa-project-diagram mr-2 text-blue-600"></i>
                    Campaigns
                </h3>
            </div>
            <div class="p-6">
                {{% if results.campaigns %}}
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {{% for campaign in results.campaigns %}}
                    <div class="border rounded-lg overflow-hidden hover:shadow-md transition-shadow">
                        <div class="bg-gray-50 p-3 border-b">
                            <h4 class="font-medium">
                                <a href="{{ url_for('campaign_detail', campaign_id=campaign.campaign_id) }}" class="text-blue-600 hover:underline">
                                    {{ campaign.campaign_name }}
                                </a>
                            </h4>
                        </div>
                        <div class="p-4">
                            <p class="text-sm text-gray-600 mb-2">
                                <span class="font-medium">Threat Actor:</span> {{ campaign.threat_actor|default('Unknown') }}
                            </p>
                            <p class="text-sm text-gray-600 mb-2">
                                <span class="font-medium">Malware:</span> {{ campaign.malware|default('Unknown') }}
                            </p>
                            <p class="text-sm text-gray-600">
                                <span class="font-medium">Sources:</span> {{ campaign.source_count }}
                            </p>
                        </div>
                    </div>
                    {{% endfor %}}
                </div>
                {{% else %}}
                <p class="text-center text-gray-500">No campaigns found matching your search.</p>
                {{% endif %}}
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow-md mb-6">
            <div class="px-6 py-4 border-b">
                <h3 class="font-semibold flex items-center">
                    <i class="fas fa-fingerprint mr-2 text-blue-600"></i>
                    Indicators of Compromise
                </h3>
            </div>
            <div class="p-6">
                {{% if results.iocs %}}
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Value</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {{% for ioc in results.iocs %}}
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="badge-ioc badge-{{ ioc.type }}">{{ ioc.type }}</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href="{{ url_for('ioc_detail', type=ioc.type, value=ioc.value) }}" class="text-blue-600 hover:underline">
                                        {{ ioc.value }}
                                    </a>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">{{ ioc.source_id }}</td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href="{{ url_for('ioc_detail', type=ioc.type, value=ioc.value) }}" class="text-blue-600 hover:underline">
                                        <i class="fas fa-eye mr-1"></i> View
                                    </a>
                                </td>
                            </tr>
                            {{% endfor %}}
                        </tbody>
                    </table>
                </div>
                {{% else %}}
                <p class="text-center text-gray-500">No indicators found matching your search.</p>
                {{% endif %}}
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow-md">
            <div class="px-6 py-4 border-b">
                <h3 class="font-semibold flex items-center">
                    <i class="fas fa-file-alt mr-2 text-blue-600"></i>
                    Analysis Results
                </h3>
            </div>
            <div class="p-6">
                {{% if results.analyses %}}
                <div class="space-y-4">
                    {{% for analysis in results.analyses %}}
                    <div class="border rounded-lg p-4">
                        <p class="font-medium mb-2">{{ analysis.source_id }}</p>
                        <p class="text-sm text-gray-600 mb-2">{{ analysis.summary }}</p>
                        <div class="text-xs text-gray-500">{{ analysis.analysis_timestamp|datetime }}</div>
                    </div>
                    {{% endfor %}}
                </div>
                {{% else %}}
                <p class="text-center text-gray-500">No analysis results found matching your search.</p>
                {{% endif %}}
            </div>
        </div>
        """,
        results=search_data.get('results', {})
    )

# Export Routes
@app.route('/export_feed')
@login_required
def export_feed():
    """Export feed data"""
    feed_name = request.args.get('feed_name')
    format_type = request.args.get('format', 'csv')
    
    # Call API to export data
    try:
        if API_URL:
            # Make sure API_URL doesn't end with / to avoid double slashes
            base_url = API_URL.rstrip('/')
            export_url = f"{base_url}/api/export/feeds/{feed_name}?format={format_type}"
        else:
            export_url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/export/feeds/{feed_name}?format={format_type}"
            
        headers = {}
        if API_KEY:
            headers["X-API-Key"] = API_KEY
            
        response = requests.get(export_url, headers=headers)
        
        if response.status_code == 200:
            # Create temporary file and serve it
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format_type}') as temp:
                temp.write(response.content)
                temp_path = temp.name
                
            return send_file(
                temp_path,
                as_attachment=True,
                download_name=f"{feed_name}_export.{format_type}",
                mimetype='text/csv' if format_type == 'csv' else 'application/json'
            )
        else:
            flash(f"Error exporting feed: {response.json().get('error', 'Unknown error')}", "danger")
    except Exception as e:
        flash(f"Error exporting feed: {str(e)}", "warning")
    
    return redirect(url_for('feed_detail', feed_name=feed_name))

@app.route('/export_iocs')
@login_required
def export_iocs():
    """Export IOCs data"""
    format_type = request.args.get('format', 'csv')
    ioc_type = request.args.get('type')
    
    # Call API to export data
    try:
        if API_URL:
            # Make sure API_URL doesn't end with / to avoid double slashes
            base_url = API_URL.rstrip('/')
            export_url = f"{base_url}/api/export/iocs?format={format_type}"
        else:
            export_url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/export/iocs?format={format_type}"
            
        if ioc_type:
            export_url += f"&type={ioc_type}"
            
        headers = {}
        if API_KEY:
            headers["X-API-Key"] = API_KEY
            
        response = requests.get(export_url, headers=headers)
        
        if response.status_code == 200:
            # Create temporary file and serve it
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format_type}') as temp:
                temp.write(response.content)
                temp_path = temp.name
                
            return send_file(
                temp_path,
                as_attachment=True,
                download_name=f"iocs_export.{format_type}",
                mimetype='text/csv' if format_type == 'csv' else 'application/json'
            )
        else:
            flash(f"Error exporting IOCs: {response.json().get('error', 'Unknown error')}", "danger")
    except Exception as e:
        flash(f"Error exporting IOCs: {str(e)}", "warning")
    
    return redirect(url_for('iocs'))

# Utility Functions
def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    metrics = {
        "table_count": 0,
        "storage_objects": 0,
        "storage_size": 0.0
    }
    
    try:
        if bq_client:
            # Get BigQuery table counts
            query = f"""
            SELECT COUNT(*) as tables
            FROM `{PROJECT_ID}.{config.bigquery_dataset}.__TABLES__`
            """
            try:
                query_job = bq_client.query(query)
                results = query_job.result()
                row = next(results)
                metrics["table_count"] = row.tables
            except Exception as e:
                logger.warning(f"Error querying BigQuery tables: {str(e)}")
        
        if storage_client:
            # Get Storage bucket info
            bucket_name = config.gcs_bucket
            try:
                bucket = storage_client.get_bucket(bucket_name)
                blobs = list(bucket.list_blobs())
                metrics["storage_objects"] = len(blobs)
                metrics["storage_size"] = sum(blob.size for blob in blobs) / (1024 * 1024)  # MB
            except Exception as e:
                logger.warning(f"Error getting storage info: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error getting GCP metrics: {str(e)}")
    
    return metrics

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    """404 Page not found"""
    return render_template('base.html', content='<h1>404 - Page Not Found</h1><p>The page you requested could not be found.</p>'), 404

@app.errorhandler(500)
def server_error(e):
    """500 Server error"""
    logger.error(f"Server error: {str(e)}")
    return render_template('base.html', content='<h1>500 - Server Error</h1><p>The server encountered an error. Please try again later.</p>'), 500

# API health check for Cloud Run
@app.route('/api/health', methods=['GET'])
def api_health():
    """API health check endpoint"""
    version = os.environ.get("VERSION", "1.0.0")
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": config.environment,
        "project": PROJECT_ID
    })

# Root health check
@app.route('/health', methods=['GET'])
def health():
    """Root health check endpoint"""
    return api_health()

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=config.environment != "production")
