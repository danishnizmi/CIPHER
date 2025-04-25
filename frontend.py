"""
Threat Intelligence Platform - Simplified Frontend Module
Provides web interface for the threat intelligence platform.
"""

import os
import json
import logging
import hashlib
import secrets
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
from flask_cors import CORS
from functools import wraps
from google.cloud import storage
from google.cloud import bigquery

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

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", config.get("FLASK_SECRET_KEY", secrets.token_hex(32)))
CORS(app)

# Authentication settings
REQUIRE_AUTH = config.get("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "true").lower() == "true")

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!"
ADMIN_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

# Log the admin credentials
password_banner = f"\n======== INITIAL ADMIN CREDENTIALS ========\nUsername: {ADMIN_USERNAME}\nPassword: {ADMIN_PASSWORD}\n===========================================\nPLEASE CHANGE THIS PASSWORD AFTER FIRST LOGIN\n"
print(password_banner)
logger.info(password_banner)

# Utility Functions
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()
def verify_password(stored_hash, password): return stored_hash == hash_password(password)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH and not session.get("logged_in"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# API Helper
def api_request(endpoint: str, params: Dict = None) -> Dict:
    """Make a request to the API service"""
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
            if result: return result
    except (ImportError, AttributeError):
        pass
    
    # Build URL
    if API_URL:
        base_url = API_URL.rstrip('/')
        url = f"{base_url}/api/{endpoint}"
    else:
        url = f"http://localhost:{os.environ.get('PORT', '8080')}/api/{endpoint}"
    
    headers = {"X-API-Key": API_KEY} if API_KEY else {}
    
    try:
        logger.info(f"Making API request to: {url}")
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
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
        
        if username == ADMIN_USERNAME and verify_password(ADMIN_HASH, password):
            session['logged_in'] = True
            session['username'] = username
            session['role'] = "admin"
            
            logger.info(f"Admin user {username} logged in successfully")
            
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
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    """User Profile page"""
    return render_template('auth.html', 
                          page_type='profile', 
                          username=session.get('username'),
                          user={"role": session.get('role', 'user'), "last_login": datetime.now().isoformat()})

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    global ADMIN_HASH
    username = session.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Verify current admin password
    if username != ADMIN_USERNAME or not verify_password(ADMIN_HASH, current_password):
        flash("Current password is incorrect", "danger")
        return redirect(url_for('profile'))
    
    # Validate new password
    if not new_password or new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for('profile'))
    
    # Update admin password globally
    ADMIN_HASH = hash_password(new_password)
    logger.info("Admin password updated successfully")
    
    flash("Password changed successfully", "success")
    return redirect(url_for('profile'))

# Main Routes
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page with tabs"""
    days = request.args.get('days', '30')
    view_type = request.args.get('view', 'dashboard')
    
    # Get platform stats for all view types
    stats = api_request('stats', {'days': days})
    
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
        'campaigns': [],  # Initialize with empty lists
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
        ioc_type_labels = ["ip", "url", "domain", "hash", "email", "cve"]
        ioc_type_values = [42, 36, 28, 19, 12, 7]
        
        # Try to use real data if available
        if 'iocs' in stats and 'types' in stats['iocs'] and stats['iocs']['types']:
            types_data = stats['iocs']['types']
            if isinstance(types_data, list) and len(types_data) > 0:
                ioc_type_labels = []
                ioc_type_values = []
                for item in types_data:
                    if isinstance(item, dict):
                        ioc_type_labels.append(item.get('type', 'unknown'))
                        ioc_type_values.append(item.get('count', 0))
        
        # Activity data
        activity_dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30)]
        activity_counts = [10 + i % 20 for i in range(30)]
        
        # Update data for dashboard view
        common_data.update({
            'campaigns': campaigns_data.get('campaigns', []),
            'top_iocs': iocs_data.get('records', []),
            'gcp_metrics': gcp_metrics,
            'ioc_type_labels': json.dumps(ioc_type_labels),
            'ioc_type_values': json.dumps(ioc_type_values),
            'activity_dates': json.dumps(activity_dates),
            'activity_counts': json.dumps(activity_counts),
            'feed_trend': 5,
            'ioc_trend': 12,
            'campaign_trend': 8,
            'analysis_trend': 15
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

# Simplified route aliases - only keep the essential ones
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

# Ingest data route
@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger the ingestion process"""
    try:
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
        flash(f"Error starting ingestion: {str(e)}", "danger")
    
    return redirect(url_for('dashboard', view='feeds'))

# Catch-all route for any other paths
@app.route('/<path:path>')
@login_required
def catch_all(path):
    """Redirect all other routes to dashboard"""
    return redirect(url_for('dashboard'))

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

# Utility Functions
def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    metrics = {"table_count": 0, "storage_objects": 0, "storage_size": 0.0}
    
    try:
        # Get BigQuery table counts
        bq_client = bigquery.Client(project=PROJECT_ID)
        query = f"SELECT COUNT(*) as tables FROM `{PROJECT_ID}.{config.bigquery_dataset}.__TABLES__`"
        results = bq_client.query(query).result()
        metrics["table_count"] = next(results).tables
        
        # Get Storage bucket info
        storage_client = storage.Client(project=PROJECT_ID)
        bucket = storage_client.get_bucket(config.gcs_bucket)
        blobs = list(bucket.list_blobs())
        metrics["storage_objects"] = len(blobs)
        metrics["storage_size"] = sum(blob.size for blob in blobs) / (1024 * 1024)  # MB
    except Exception as e:
        logger.warning(f"Error getting GCP metrics: {str(e)}")
    
    return metrics

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=config.environment != "production")
