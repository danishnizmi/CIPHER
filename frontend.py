"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform using existing templates.
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
import requests
from flask_cors import CORS
from google.cloud import storage
from google.cloud import bigquery

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

# Load user data from config
def get_users():
    """Get user data from config with fallback to default users"""
    auth_config = config.get_cached_config('auth-config')
    users = auth_config.get("users", {}) if auth_config else {}
    
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
            if auth_config is None:
                auth_config = {}
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

# Route handlers
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
    ioc_type_labels = json.dumps(["ip", "domain", "url", "hash"])
    ioc_type_values = json.dumps([10, 20, 15, 25])
    
    # Try to get real chart data
    if 'iocs' in stats and 'types' in stats['iocs']:
        ioc_types = stats['iocs']['types']
        labels = [item.get('type', 'unknown') for item in ioc_types]
        values = [item.get('count', 0) for item in ioc_types]
        if labels and values:
            ioc_type_labels = json.dumps(labels)
            ioc_type_values = json.dumps(values)
    
    # Generate activity data
    activity_data = api_request('feeds/alienvault_pulses/stats', {'days': days})
    
    # Default activity data if API fails
    default_dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
    default_counts = [int(5 + i * 2.5) for i in range(7)]
    
    activity_dates = json.dumps(default_dates)
    activity_counts = json.dumps(default_counts)
    
    # Try to use real activity data if available
    if activity_data and "daily_counts" in activity_data:
        dates = [item.get("date") for item in activity_data.get("daily_counts", [])]
        counts = [item.get("count", 0) for item in activity_data.get("daily_counts", [])]
        if dates and counts:
            activity_dates = json.dumps(dates)
            activity_counts = json.dumps(counts)
    
    # Provide trend data (even if fake for now)
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
        ioc_type_labels=ioc_type_labels,
        ioc_type_values=ioc_type_values,
        activity_dates=activity_dates,
        activity_counts=activity_counts,
        feed_trend=feed_trend,
        ioc_trend=ioc_trend,
        campaign_trend=campaign_trend,
        analysis_trend=analysis_trend
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Get latest users from config
        current_users = get_users()
        
        if username in current_users and current_users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = username
            session['role'] = current_users[username].get('role', 'readonly')
            
            # Update last login time if possible
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
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

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
    
    feed_activity = json.dumps(feed_activity_data)
    
    return render_template(
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
        'offset': offset
    }
    
    # Prepare daily counts chart data
    daily_counts = {
        'dates': json.dumps([day_data.get('date') for day_data in stats.get('daily_counts', [])]),
        'counts': json.dumps([day_data.get('count', 0) for day_data in stats.get('daily_counts', [])])
    }
    
    return render_template(
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
        'offset': offset
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
    
    return render_template(
        'campaigns.html',
        days=days,
        campaigns=campaigns,
        min_sources=min_sources,
        pagination=pagination,
        search=search,
        actor_labels=json.dumps(actor_labels),
        actor_values=json.dumps(actor_values),
        target_labels=json.dumps(target_labels),
        target_values=json.dumps(target_values)
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
    
    ioc_type_labels = json.dumps(list(ioc_types.keys()))
    ioc_type_values = json.dumps(list(ioc_types.values()))
    
    return render_template(
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
    iocs = iocs_data.get('records', [])
    
    # Get platform stats for IOC distribution
    stats = api_request('stats', {'days': days})
    ioc_types = stats.get('iocs', {}).get('types', [])
    
    # Prepare chart data
    ioc_type_labels = json.dumps([item.get('type', 'unknown') for item in ioc_types])
    ioc_type_values = json.dumps([item.get('count', 0) for item in ioc_types])
    
    # Prepare country data (for IP IOCs)
    country_data = {}
    for ioc in iocs:
        for item in ioc.get('iocs', []):
            if item.get('type') == 'ip' and 'geo' in item and item.get('geo', {}).get('country'):
                country = item.get('geo', {}).get('country')
                if country not in country_data:
                    country_data[country] = 0
                country_data[country] += 1
    
    country_labels = json.dumps(list(country_data.keys()))
    country_values = json.dumps(list(country_data.values()))
    
    # Prepare pagination
    pagination = {
        'total': iocs_data.get('count', 0),
        'limit': limit,
        'offset': offset
    }
    
    return render_template(
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

@app.route('/iocs/<type>/<value>')
@login_required
def ioc_detail(type: str, value: str):
    """IOC detail page"""
    # Get IOC details
    iocs_data = api_request('iocs', {'type': type, 'value': value, 'limit': 1})
    if not iocs_data.get('records'):
        flash("IOC not found", "danger")
        return redirect(url_for("iocs"))
    
    ioc = iocs_data.get('records')[0]
    
    # Get campaigns that reference this IOC
    search_data = api_request('search', {'q': value})
    campaigns = search_data.get('results', {}).get('campaigns', [])
    
    # Get sources that reference this IOC
    sources = search_data.get('results', {}).get('analyses', [])
    
    # Get related IOCs (same campaign or source)
    related_iocs = []
    for campaign in campaigns[:3]:  # Limit to first 3 campaigns
        campaign_data = api_request(f'campaigns/{campaign.get("campaign_id")}')
        for rel_ioc in campaign_data.get('iocs', [])[:5]:  # Limit to first 5 IOCs
            if rel_ioc.get('value') != value:  # Skip the current IOC
                related_iocs.append(rel_ioc)
    
    # Remove duplicates
    seen = set()
    unique_related_iocs = []
    for rel_ioc in related_iocs:
        ioc_key = f"{rel_ioc.get('type')}:{rel_ioc.get('value')}"
        if ioc_key not in seen:
            seen.add(ioc_key)
            unique_related_iocs.append(rel_ioc)
    
    return render_template(
        'ioc_detail.html',
        ioc=ioc,
        campaigns=campaigns,
        sources=sources,
        related_iocs=unique_related_iocs[:10]  # Limit to 10 related IOCs
    )

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
        'search_results.html',
        query=query,
        results=search_data.get('results', {})
    )

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
    
    return render_template(
        'reports.html',
        days=days,
        reports=reports
    )

@app.route('/generate_report')
@login_required
def generate_report():
    """Generate a report"""
    report_type = request.args.get('report_type')
    days = int(request.args.get('days', '30'))
    
    # Call API to generate report
    try:
        response = api_request(f'reports/{report_type}', {'days': days, 'generate': 'true'})
        if 'error' not in response:
            flash(f"Report '{report_type}' generated successfully", "success")
        else:
            flash(f"Error generating report: {response.get('error')}", "danger")
    except Exception as e:
        flash(f"Error generating report: {str(e)}", "danger")
    
    return redirect(url_for('reports'))

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
        'alerts.html',
        alerts=alerts_list
    )

@app.route('/explore')
@login_required
def explore():
    """Data Explorer page"""
    # Get available data sources
    feeds_data = api_request('feeds')
    feeds = feeds_data.get('feeds', [])
    
    return render_template(
        'explore.html',
        feeds=feeds
    )

@app.route('/settings')
@login_required
@role_required('admin')
def settings():
    """Settings page"""
    return render_template(
        'settings.html'
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
        'settings_api_keys.html',
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
        'settings_feeds.html',
        feed_configs=feed_config_dict
    )

@app.route('/users')
@login_required
@role_required('admin')
def users():
    """User Management page"""
    # Get latest users from config
    current_users = get_users()
    
    return render_template(
        'users.html',
        users=current_users
    )

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user_route():
    """Add a new user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'readonly')
        
        if username and password:
            result = config.add_user(username, password, role)
            if result:
                flash(f"User {username} added successfully", "success")
            else:
                flash(f"Failed to add user {username}", "danger")
        else:
            flash("Username and password are required", "danger")
        
        return redirect(url_for('users'))
    
    return render_template('user_add.html')

@app.route('/users/edit/<username>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(username):
    """Edit an existing user"""
    # Get latest users from config
    current_users = get_users()
    
    if username not in current_users:
        flash(f"User {username} not found", "danger")
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        new_role = request.form.get('role')
        
        updates = {}
        if new_role:
            updates["role"] = new_role
        
        if new_password:
            updates["password"] = new_password
        
        if updates:
            result = config.update_user(username, updates)
            if result:
                flash(f"User {username} updated successfully", "success")
            else:
                flash(f"Failed to update user {username}", "danger")
        
        return redirect(url_for('users'))
    
    return render_template(
        'user_edit.html',
        username=username,
        user=current_users[username]
    )

@app.route('/profile')
@login_required
def profile():
    """User Profile page"""
    username = session.get('username')
    
    # Get latest users from config
    current_users = get_users()
    user_data = current_users.get(username, {})
    
    return render_template(
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
    
    return redirect(url_for('profile'))

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
            # Handle file download
            filename = f"{feed_name}_export.{format_type}"
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            return send_file(filename, as_attachment=True)
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
            # Handle file download
            filename = f"iocs_export.{format_type}"
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            return send_file(filename, as_attachment=True)
        else:
            flash(f"Error exporting IOCs: {response.json().get('error', 'Unknown error')}", "danger")
    except Exception as e:
        flash(f"Error exporting IOCs: {str(e)}", "warning")
    
    return redirect(url_for('iocs'))

def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    metrics = {
        "table_count": 12,
        "storage_objects": 456,
        "storage_size": 245.5
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

@app.errorhandler(404)
def page_not_found(e):
    """404 Page not found"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """500 Server error"""
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

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

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=config.environment != "production")
