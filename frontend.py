"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform.
"""

import os
import json
import logging
import hashlib
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, abort
from flask_cors import CORS
import requests
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import secretmanager

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
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
        API_KEY = api_keys_config.get('platform_api_key', "")
else:
    API_KEY = config.api_key

# Initialize Flask app with template directory safeguards
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
if not os.path.exists(template_dir):
    logger.warning(f"Template directory not found at {template_dir}, creating it")
    os.makedirs(template_dir, exist_ok=True)

app = Flask(__name__, template_folder=template_dir)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", config.get("FLASK_SECRET_KEY", "dev-key-change-in-production"))
app.config['TEMPLATES_AUTO_RELOAD'] = True
CORS(app)

# Initialize GCP clients
try:
    storage_client = storage.Client(project=PROJECT_ID)
    logger.info("Storage client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize storage client: {str(e)}")
    storage_client = None

try:
    bq_client = bigquery.Client(project=PROJECT_ID)
    logger.info("BigQuery client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize BigQuery client: {str(e)}")
    bq_client = None

try:
    secret_client = secretmanager.SecretManagerServiceClient()
    logger.info("Secret Manager client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize Secret Manager client: {str(e)}")
    secret_client = None

# Check for template files in Secret Manager
def check_secret_templates():
    """Check if templates exist in Secret Manager and save to filesystem if needed"""
    if not secret_client:
        return

    template_files = ['login.html', 'dashboard.html', '404.html', '500.html', 'base.html', 'content.html']
    
    for template_name in template_files:
        # Check if template already exists in filesystem
        template_path = os.path.join(template_dir, template_name)
        if os.path.exists(template_path):
            continue
            
        # Try to get template from Secret Manager
        secret_id = f"template-{template_name.replace('.html', '')}"
        try:
            name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
            response = secret_client.access_secret_version(request={"name": name})
            template_content = response.payload.data.decode("UTF-8")
            
            with open(template_path, 'w') as f:
                f.write(template_content)
                
            logger.info(f"Saved template {template_name} from Secret Manager")
        except Exception as e:
            logger.warning(f"Couldn't retrieve template {template_name} from Secret Manager: {e}")

# Run template check at startup
try:
    check_secret_templates()
except Exception as e:
    logger.error(f"Error checking secret templates: {e}")

# Authentication settings
REQUIRE_AUTH = config.get("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "true").lower() == "true")

# Load user data from config
def get_users():
    """Get user data from config with fallback to default users"""
    auth_config = config.get_cached_config('auth-config')
    users = auth_config.get("users", {})
    
    if not users:
        # Fallback users if none defined in config
        users = {
            "admin": {
                "password": hashlib.sha256("changeme".encode()).hexdigest(),
                "role": "admin"
            },
            "analyst": {
                "password": hashlib.sha256("analyst123".encode()).hexdigest(),
                "role": "analyst"
            },
            "readonly": {
                "password": hashlib.sha256("readonly".encode()).hexdigest(),
                "role": "readonly"
            }
        }
        
        # Try to save default users to config
        try:
            auth_config["users"] = users
            config.create_or_update_secret("auth-config", json.dumps(auth_config))
            logger.info("Created default users in auth-config")
        except Exception as e:
            logger.warning(f"Failed to save default users: {e}")
    
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
                return redirect(url_for("dashboard"))
            
            if required_role == "analyst" and user_role not in ["admin", "analyst"]:
                flash("You don't have permission to access this page", "danger")
                return redirect(url_for("dashboard"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper functions
def api_request(endpoint: str, params: Dict = None) -> Dict:
    """Make a request to the API service"""
    # First try direct API if on same instance
    try:
        import api
        if hasattr(api, 'api_bp') and endpoint in api.api_bp.view_functions:
            # Create test request context
            with app.test_request_context(f'/api/{endpoint}', query_string=params):
                response = api.api_bp.view_functions[endpoint]()
                if isinstance(response, tuple):
                    return response[0]
                return response
    except Exception as e:
        logger.debug(f"Direct API call failed, falling back to HTTP: {e}")
    
    # Fall back to HTTP request
    if API_URL:
        url = f"{API_URL}/api/{endpoint}"
    else:
        # Fallback to local API
        url = f"/api/{endpoint}"
    
    headers = {}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        return {"error": str(e)}

# Ensure templates exist
def ensure_template_exists(template_name):
    """Ensure the template exists, return fallback if it doesn't"""
    template_path = os.path.join(template_dir, template_name)
    if os.path.exists(template_path):
        return template_name
    
    logger.warning(f"Template {template_name} not found, using fallback")
    
    # Define fallbacks for critical templates
    fallbacks = {
        '404.html': 'error_404.html',
        '500.html': 'error_500.html',
        'login.html': 'fallback_login.html',
        'dashboard.html': 'base.html',
    }
    
    if template_name in fallbacks:
        fallback = fallbacks[template_name]
        if os.path.exists(os.path.join(template_dir, fallback)):
            return fallback
    
    # If no fallback exists, create a minimal emergency template
    emergency_templates = {
        '404.html': """<!DOCTYPE html><html><head><title>404 Not Found</title></head>
            <body><h1>404 - Page Not Found</h1><p>The page you requested could not be found.</p>
            <a href="/">Return to Home</a></body></html>""",
            
        '500.html': """<!DOCTYPE html><html><head><title>500 Server Error</title></head>
            <body><h1>500 - Server Error</h1><p>The server encountered an error processing your request.</p>
            <a href="/">Return to Home</a></body></html>""",
            
        'login.html': """<!DOCTYPE html><html><head><title>Login</title></head>
            <body><h1>Login</h1><form action="/login" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button></form></body></html>""",
            
        'dashboard.html': """<!DOCTYPE html><html><head><title>Dashboard</title></head>
            <body><h1>Dashboard</h1><p>Welcome to the Threat Intelligence Platform.</p>
            <a href="/logout">Logout</a></body></html>"""
    }
    
    if template_name in emergency_templates:
        emergency_content = emergency_templates[template_name]
        try:
            with open(template_path, 'w') as f:
                f.write(emergency_content)
            logger.info(f"Created emergency template for {template_name}")
            return template_name
        except Exception as e:
            logger.error(f"Failed to create emergency template: {e}")
    
    # If all else fails, use 500.html as a last resort
    if template_name != '500.html' and os.path.exists(os.path.join(template_dir, '500.html')):
        return '500.html'
    
    # We have no templates at all - return error string
    # This will bypass template rendering and just return the string
    abort(500, description=f"Template {template_name} not found and no fallbacks available")

# Safe render template function
def safe_render_template(template_name, **context):
    """Safely render a template with fallbacks"""
    try:
        # Ensure the template exists
        template_to_use = ensure_template_exists(template_name)
        return render_template(template_to_use, **context)
    except Exception as e:
        logger.error(f"Error rendering template {template_name}: {e}")
        logger.error(traceback.format_exc())
        
        # Fall back to a minimal error template
        error_message = f"Error rendering template: {str(e)}"
        return f"""<!DOCTYPE html><html><head><title>Error</title></head>
            <body><h1>Error Rendering Page</h1><p>{error_message}</p>
            <a href="/">Return to Home</a></body></html>"""

# Route handlers
@app.route('/')
@login_required
def dashboard():
    """Dashboard page"""
    days = request.args.get('days', '30')
    
    # Get platform stats with error handling
    try:
        stats = api_request('stats', {'days': days})
        if 'error' in stats:
            logger.warning(f"Error fetching stats: {stats['error']}")
            stats = {'feeds': {}, 'iocs': {}, 'campaigns': {}, 'analyses': {}}
    except Exception as e:
        logger.error(f"Exception fetching stats: {e}")
        stats = {'feeds': {}, 'iocs': {}, 'campaigns': {}, 'analyses': {}}
    
    # Get recent campaigns
    try:
        campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
        campaigns = campaigns_data.get('campaigns', [])
    except Exception as e:
        logger.error(f"Exception fetching campaigns: {e}")
        campaigns = []
    
    # Get top IOCs
    try:
        iocs_data = api_request('iocs', {'days': days, 'limit': 5})
        top_iocs = iocs_data.get('records', [])
    except Exception as e:
        logger.error(f"Exception fetching IOCs: {e}")
        top_iocs = []
    
    # Get GCP metrics
    gcp_metrics = get_gcp_metrics()
    
    # Default chart data if API fails
    ioc_type_labels = json.dumps(["ip", "domain", "url", "hash"])
    ioc_type_values = json.dumps([10, 20, 15, 25])
    activity_dates = json.dumps([])
    activity_counts = json.dumps([])
    
    # Try to get real chart data
    try:
        # Extract data from stats
        if 'iocs' in stats and 'types' in stats['iocs']:
            ioc_types = stats['iocs']['types']
            labels = [item.get('type', 'unknown') for item in ioc_types]
            values = [item.get('count', 0) for item in ioc_types]
            ioc_type_labels = json.dumps(labels)
            ioc_type_values = json.dumps(values)
        
        # Get activity data
        activity_data = api_request('feeds/alienvault_pulses/stats', {'days': days})
        if 'daily_counts' in activity_data:
            activity_dates = json.dumps([item.get("date") for item in activity_data.get("daily_counts", [])])
            activity_counts = json.dumps([item.get("count") for item in activity_data.get("daily_counts", [])])
    except Exception as e:
        logger.error(f"Error preparing chart data: {e}")
    
    return safe_render_template(
        'dashboard.html',
        days=days,
        stats=stats,
        campaigns=campaigns,
        top_iocs=top_iocs,
        gcp_metrics=gcp_metrics,
        ioc_type_labels=ioc_type_labels,
        ioc_type_values=ioc_type_values,
        activity_dates=activity_dates,
        activity_counts=activity_counts
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Username and password are required"
            logger.warning("Login attempt with missing username/password")
            return safe_render_template('login.html', error=error)
        
        # Get latest users from config
        try:
            current_users = get_users()
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            current_users = {}
        
        # Check if user exists and password matches
        if username in current_users and current_users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = username
            session['role'] = current_users[username].get('role', 'readonly')
            
            # Update last login time if possible
            try:
                config.update_user(username, {"last_login": datetime.utcnow().isoformat()})
            except Exception as e:
                logger.warning(f"Could not update last login: {str(e)}")
            
            logger.info(f"Successful login for user: {username}")
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
            logger.warning(f"Failed login attempt for user: {username}")
    
    return safe_render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username')
    session.clear()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.route('/feeds')
@login_required
def feeds():
    """Feeds overview page"""
    days = request.args.get('days', '30')
    
    # Get feeds list with error handling
    try:
        feeds_data = api_request('feeds')
        if 'error' in feeds_data:
            logger.warning(f"Error fetching feeds: {feeds_data['error']}")
            feeds_list = []
        else:
            feeds_list = feeds_data.get('feeds', [])
    except Exception as e:
        logger.error(f"Exception fetching feeds: {e}")
        feeds_list = []
    
    # Get stats for each feed
    feeds = []
    total_records = 0
    days_with_updates = 0
    
    for feed_name in feeds_list:
        try:
            feed_stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
            
            if 'error' in feed_stats:
                logger.warning(f"Error fetching feed stats for {feed_name}: {feed_stats['error']}")
                continue
                
            feeds.append({
                'feed_name': feed_name,
                'record_count': feed_stats.get('total_records', 0),
                'latest_record': feed_stats.get('latest_record'),
                'earliest_record': feed_stats.get('earliest_record')
            })
            
            total_records += feed_stats.get('total_records', 0)
            days_with_updates += feed_stats.get('days_with_data', 0)
        except Exception as e:
            logger.error(f"Exception fetching feed stats for {feed_name}: {e}")
    
    # Prepare feed activity data with default
    feed_activity = '{}'
    
    # Try to get real activity data
    try:
        activity_data = {}
        for feed_name in feeds_list[:5]:  # Limit to 5 feeds to avoid overloading
            feed_stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
            if 'error' not in feed_stats and 'daily_counts' in feed_stats:
                dates = []
                counts = []
                
                for day_data in feed_stats.get('daily_counts', []):
                    dates.append(day_data.get('date'))
                    counts.append(day_data.get('count', 0))
                
                activity_data[feed_name] = {
                    'dates': dates,
                    'counts': counts
                }
        
        feed_activity = json.dumps(activity_data)
    except Exception as e:
        logger.error(f"Error preparing feed activity data: {e}")
    
    return safe_render_template(
        'feeds.html',
        days=days,
        feeds=feeds,
        total_records=total_records,
        days_with_updates=days_with_updates,
        feed_activity=feed_activity
    )

@app.route('/feeds/<feed_name>')
@login_required
def feed_detail(feed_name: str):
    """Feed detail page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    search = request.args.get('search', '')
    
    # Get feed stats with error handling
    try:
        stats = api_request(f'feeds/{feed_name}/stats', {'days': days})
        if 'error' in stats:
            logger.warning(f"Error fetching feed stats: {stats['error']}")
            stats = {}
    except Exception as e:
        logger.error(f"Exception fetching feed stats: {e}")
        stats = {}
    
    # Get feed data with error handling
    params = {'days': days, 'limit': limit, 'offset': offset}
    if search:
        params['search'] = search
    
    try:
        feed_data = api_request(f'feeds/{feed_name}/data', params)
        if 'error' in feed_data:
            logger.warning(f"Error fetching feed data: {feed_data['error']}")
            records = []
            total = 0
        else:
            records = feed_data.get('records', [])
            total = feed_data.get('total', 0)
    except Exception as e:
        logger.error(f"Exception fetching feed data: {e}")
        records = []
        total = 0
    
    # Extract columns (use first record or empty list)
    columns = []
    if records:
        # Filter out internal columns
        columns = [col for col in records[0].keys() if not col.startswith('_')]
    
    # Prepare pagination
    pagination = {
        'total': total,
        'limit': limit,
        'offset': offset
    }
    
    # Prepare daily counts chart data with defaults
    daily_counts = {
        'dates': json.dumps([]),
        'counts': json.dumps([])
    }
    
    # Try to get real chart data
    try:
        if 'daily_counts' in stats:
            daily_counts = {
                'dates': json.dumps([day_data.get('date') for day_data in stats.get('daily_counts', [])]),
                'counts': json.dumps([day_data.get('count', 0) for day_data in stats.get('daily_counts', [])])
            }
    except Exception as e:
        logger.error(f"Error preparing daily counts chart: {e}")
    
    return safe_render_template(
        'feed_detail.html',
        feed_name=feed_name,
        days=days,
        stats=stats,
        records=records,
        columns=columns,
        pagination=pagination,
        search=search,
        daily_counts=daily_counts
    )

@app.route('/campaigns')
@login_required
def campaigns():
    """Campaigns overview page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    min_sources = int(request.args.get('min_sources', '2'))
    search = request.args.get('search', '')
    
    # Get campaigns list with error handling
    params = {
        'days': days,
        'limit': limit,
        'offset': offset,
        'min_sources': min_sources
    }
    
    try:
        if search:
            # Use search API for text search
            search_data = api_request('search', {'q': search, 'days': days})
            if 'error' in search_data:
                logger.warning(f"Error in search API: {search_data['error']}")
                campaigns = []
                total = 0
            else:
                campaigns = search_data.get('results', {}).get('campaigns', [])
                total = len(campaigns)
        else:
            # Get all campaigns
            campaigns_data = api_request('campaigns', params)
            if 'error' in campaigns_data:
                logger.warning(f"Error fetching campaigns: {campaigns_data['error']}")
                campaigns = []
                total = 0
            else:
                campaigns = campaigns_data.get('campaigns', [])
                total = campaigns_data.get('count', 0)
    except Exception as e:
        logger.error(f"Exception fetching campaigns: {e}")
        campaigns = []
        total = 0
    
    # Prepare pagination
    pagination = {
        'total': total,
        'limit': limit,
        'offset': offset
    }
    
    # Default chart data
    chart_data = {
        "actor_labels": json.dumps([]),
        "actor_values": json.dumps([]),
        "target_labels": json.dumps([]),
        "target_values": json.dumps([])
    }
    
    # Try to create real chart data
    try:
        # Count by actor
        actor_data = {}
        target_data = {}
        
        for campaign in campaigns:
            # Count by actor
            actor = campaign.get('threat_actor', 'Unknown')
            if actor not in actor_data:
                actor_data[actor] = 0
            actor_data[actor] += 1
            
            # Count by target
            target = campaign.get('targets', 'Unknown')
            if target not in target_data:
                target_data[target] = 0
            target_data[target] += 1
        
        # Convert to lists for charts
        actor_labels = list(actor_data.keys())
        actor_values = list(actor_data.values())
        
        target_labels = list(target_data.keys())
        target_values = list(target_data.values())
        
        chart_data = {
            "actor_labels": json.dumps(actor_labels),
            "actor_values": json.dumps(actor_values),
            "target_labels": json.dumps(target_labels),
            "target_values": json.dumps(target_values)
        }
    except Exception as e:
        logger.error(f"Error creating chart data: {e}")
    
    return safe_render_template(
        'campaigns.html',
        days=days,
        campaigns=campaigns,
        min_sources=min_sources,
        pagination=pagination,
        search=search,
        **chart_data
    )

@app.route('/campaigns/<campaign_id>')
@login_required
def campaign_detail(campaign_id: str):
    """Campaign detail page"""
    # Get campaign details with error handling
    try:
        campaign_data = api_request(f'campaigns/{campaign_id}')
        
        if 'error' in campaign_data:
            logger.warning(f"Error fetching campaign {campaign_id}: {campaign_data['error']}")
            flash("Campaign not found", "danger")
            return redirect(url_for("campaigns"))
    except Exception as e:
        logger.error(f"Exception fetching campaign {campaign_id}: {e}")
        flash("Error fetching campaign details", "danger")
        return redirect(url_for("campaigns"))
    
    # Prepare IOC type chart data
    ioc_types = {}
    for ioc in campaign_data.get('iocs', []):
        ioc_type = ioc.get('type', 'unknown')
        if ioc_type not in ioc_types:
            ioc_types[ioc_type] = 0
        ioc_types[ioc_type] += 1
    
    ioc_type_labels = json.dumps(list(ioc_types.keys()))
    ioc_type_values = json.dumps(list(ioc_types.values()))
    
    return safe_render_template(
        'campaign_detail.html',
        campaign=campaign_data,
        ioc_type_labels=ioc_type_labels,
        ioc_type_values=ioc_type_values
    )

@app.route('/iocs')
@login_required
def iocs():
    """IOCs overview page"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    search_value = request.args.get('value', '')
    search_type = request.args.get('type', '')
    
    # Get IOCs data with error handling
    params = {
        'days': days,
        'limit': limit,
        'offset': offset
    }
    
    if search_value:
        params['value'] = search_value
    if search_type:
        params['type'] = search_type
    
    try:
        iocs_data = api_request('iocs', params)
        if 'error' in iocs_data:
            logger.warning(f"Error fetching IOCs: {iocs_data['error']}")
            iocs = []
            total = 0
        else:
            iocs = iocs_data.get('records', [])
            total = iocs_data.get('count', 0)
    except Exception as e:
        logger.error(f"Exception fetching IOCs: {e}")
        iocs = []
        total = 0
    
    # Get platform stats for IOC distribution with error handling
    try:
        stats = api_request('stats', {'days': days})
        if 'error' in stats:
            logger.warning(f"Error fetching stats: {stats['error']}")
            ioc_types = []
        else:
            ioc_types = stats.get('iocs', {}).get('types', [])
    except Exception as e:
        logger.error(f"Exception fetching stats: {e}")
        ioc_types = []
    
    # Prepare chart data with defaults
    ioc_type_labels = json.dumps(["ip", "domain", "url", "hash"])
    ioc_type_values = json.dumps([10, 20, 15, 25])
    country_labels = json.dumps(["US", "RU", "CN", "DE"])
    country_values = json.dumps([30, 20, 25, 15])
    
    # Try to create real chart data
    try:
        # Prepare IOC type chart
        type_labels = [item.get('type', 'unknown') for item in ioc_types]
        type_values = [item.get('count', 0) for item in ioc_types]
        ioc_type_labels = json.dumps(type_labels)
        ioc_type_values = json.dumps(type_values)
        
        # Prepare country data (for IP IOCs)
        country_data = {}
        for ioc in iocs:
            for item in ioc.get('iocs', []):
                if item.get('type') == 'ip' and 'geo' in item and item.get('geo', {}).get('country'):
                    country = item.get('geo', {}).get('country')
                    if country not in country_data:
                        country_data[country] = 0
                    country_data[country] += 1
        
        if country_data:
            country_labels = json.dumps(list(country_data.keys()))
            country_values = json.dumps(list(country_data.values()))
    except Exception as e:
        logger.error(f"Error creating IOC charts: {e}")
    
    # Prepare pagination
    pagination = {
        'total': total,
        'limit': limit,
        'offset': offset
    }
    
    return safe_render_template(
        'iocs.html',
        days=days,
        iocs=iocs,
        search_value=search_value,
        search_type=search_type,
        pagination=pagination,
        ioc_type_labels=ioc_type_labels,
        ioc_type_values=ioc_type_values,
        country_labels=country_labels,
        country_values=country_values,
        limit=limit
    )

@app.route('/search')
@login_required
def search():
    """Search page"""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('dashboard'))
    
    # Search across all data with error handling
    try:
        search_data = api_request('search', {'q': query, 'days': 30})
        if 'error' in search_data:
            logger.warning(f"Error in search API: {search_data['error']}")
            results = {'feeds': [], 'analyses': [], 'campaigns': []}
        else:
            results = search_data.get('results', {})
    except Exception as e:
        logger.error(f"Exception searching: {e}")
        results = {'feeds': [], 'analyses': [], 'campaigns': []}
    
    return safe_render_template(
        'search_results.html',
        query=query,
        results=results
    )

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    days = request.args.get('days', '30')
    
    # Get reports from API with error handling
    report_types = ["feed_summary", "campaign_analysis", "ioc_trend"]
    reports = []
    
    for report_type in report_types:
        try:
            report_data = api_request(f'reports/{report_type}', {'days': days})
            if 'error' not in report_data:
                reports.append(report_data)
            else:
                # Create structured report entry with minimal data
                reports.append({
                    'report_id': f'{report_type}_report',
                    'report_name': f'{report_type.replace("_", " ").title()} Report',
                    'report_type': report_type,
                    'generated_at': datetime.now().isoformat(),
                    'period_days': int(days)
                })
        except Exception as e:
            logger.warning(f"Error fetching report {report_type}: {str(e)}")
            # Create structured report entry with minimal data
            reports.append({
                'report_id': f'{report_type}_report',
                'report_name': f'{report_type.replace("_", " ").title()} Report',
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'period_days': int(days)
            })
    
    return safe_render_template(
        'reports.html',
        days=days,
        reports=reports
    )

@app.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    # Get alerts from API with error handling
    try:
        alerts_data = api_request('alerts')
        if 'error' in alerts_data:
            logger.warning(f"Error fetching alerts: {alerts_data['error']}")
            alerts_list = []
        else:
            alerts_list = alerts_data.get('alerts', [])
    except Exception as e:
        logger.error(f"Exception fetching alerts: {e}")
        alerts_list = []
    
    # Handle case of empty alerts with proper structure
    if not alerts_list:
        # Create structured alerts with minimal data
        current_time = datetime.now()
        alerts_list = [
            {
                'id': 'no_alerts_1',
                'title': 'No alerts currently active',
                'severity': 'low',
                'created_at': current_time.isoformat(),
                'description': 'The system is working normally with no active threats detected.'
            }
        ]
    
    return safe_render_template(
        'alerts.html',
        alerts=alerts_list
    )

@app.route('/explore')
@login_required
def explore():
    """Data Explorer page"""
    # Get available data sources with error handling
    try:
        feeds_data = api_request('feeds')
        if 'error' in feeds_data:
            logger.warning(f"Error fetching feeds: {feeds_data['error']}")
            feeds = []
        else:
            feeds = feeds_data.get('feeds', [])
    except Exception as e:
        logger.error(f"Exception fetching feeds: {e}")
        feeds = []
    
    return safe_render_template(
        'explore.html',
        feeds=feeds
    )

@app.route('/settings')
@login_required
@role_required('admin')
def settings():
    """Settings page"""
    return safe_render_template(
        'settings.html'
    )

@app.route('/users')
@login_required
@role_required('admin')
def users():
    """User Management page"""
    # Get latest users from config
    try:
        current_users = get_users()
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        flash("Error retrieving user list", "danger")
        current_users = {}
    
    return safe_render_template(
        'users.html',
        users=current_users
    )

@app.route('/profile')
@login_required
def profile():
    """User Profile page"""
    username = session.get('username')
    
    # Get latest users from config
    try:
        current_users = get_users()
        user_data = current_users.get(username, {})
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        flash("Error retrieving profile data", "danger")
        user_data = {}
    
    return safe_render_template(
        'profile.html',
        username=username,
        user=user_data
    )

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    username = session.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Get latest users from config
    try:
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
        if current_users[username]['password'] != hashlib.sha256(current_password.encode()).hexdigest():
            flash("Current password is incorrect", "danger")
            return redirect(url_for('profile'))
        
        # Update password
        result = config.update_user(username, {"password": new_password})
        if result:
            flash("Password changed successfully", "success")
        else:
            flash("Failed to change password", "danger")
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        flash("Error changing password", "danger")
    
    return redirect(url_for('profile'))

# GCP Metrics helper function
def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    metrics = {
        "table_count": 0,
        "storage_objects": 0,
        "storage_size": 0
    }
    
    try:
        if bq_client:
            # Get BigQuery table counts with better error handling
            try:
                query = f"""
                SELECT COUNT(*) as tables
                FROM `{PROJECT_ID}.{config.bigquery_dataset}.__TABLES__`
                """
                query_job = bq_client.query(query)
                results = query_job.result()
                row = next(results)
                metrics["table_count"] = row.tables
            except Exception as e:
                logger.warning(f"Error getting BigQuery table count: {e}")
        
        if storage_client:
            # Get Storage bucket info with better error handling
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

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """404 Page not found"""
    logger.warning(f"404 error: {request.path}")
    return safe_render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """500 Server error"""
    logger.error(f"500 error: {str(e)}")
    logger.error(traceback.format_exc())
    return safe_render_template('500.html'), 500

# API endpoint for health checks
@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check API endpoint"""
    logger.info("Health check endpoint called")
    version = os.environ.get("VERSION", "1.0.0")
    
    # Try to import API module for direct call
    try:
        import api
        if hasattr(api, 'health_check'):
            return api.health_check()
    except Exception as e:
        logger.debug(f"Direct API health check failed: {e}")
    
    # Fallback health response
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": config.environment,
        "project": PROJECT_ID
    })

# Main health check endpoint at root level
@app.route('/health', methods=['GET'])
def health():
    """Root health check endpoint"""
    return api_health()

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

# Initialize during import
if __name__ != "__main__":
    # This code runs when the module is imported
    logger.info("Initializing frontend module")
    
    # Check if API routes should be registered here
    try:
        from api import init_app as init_api
        app = init_api(app)
        logger.info("API routes registered through frontend module")
    except Exception as e:
        logger.warning(f"Failed to register API routes: {e}")
        logger.warning("API routes will need to be registered separately")

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=config.environment != "production")
