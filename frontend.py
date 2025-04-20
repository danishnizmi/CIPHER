"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform using external templates.
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_cors import CORS
import requests
from google.cloud import storage
from google.cloud import bigquery

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
REGION = os.environ.get("GCP_REGION", "us-central1")
API_URL = os.environ.get("API_URL", "http://localhost:8080")
API_KEY = os.environ.get("API_KEY", "")

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-in-production")
CORS(app)

# Initialize GCP clients
storage_client = storage.Client()
bq_client = bigquery.Client()

# Authentication settings
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"
USERS = {
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
    url = f"{API_URL}/api/{endpoint}"
    
    headers = {}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        return {"error": str(e)}


def prepare_chart_data(data_type: str, data: Dict) -> Dict:
    """Prepare data for charts based on type"""
    if data_type == "ioc_types":
        # Process IOC types data
        ioc_types = data.get("iocs", {}).get("types", [])
        labels = [item.get("type", "unknown") for item in ioc_types]
        values = [item.get("count", 0) for item in ioc_types]
        return {"labels": json.dumps(labels), "values": json.dumps(values)}
    
    elif data_type == "feed_activity":
        # Process feed activity data
        feeds_data = {}
        for feed in data.get("feeds", []):
            feed_stats = api_request(f'feeds/{feed}/stats', {'days': 30})
            
            dates = []
            counts = []
            
            for day_data in feed_stats.get('daily_counts', []):
                dates.append(day_data.get('date'))
                counts.append(day_data.get('count', 0))
            
            feeds_data[feed] = {
                'dates': dates,
                'counts': counts
            }
        
        return {"feed_activity": json.dumps(feeds_data)}
    
    elif data_type == "campaign_metrics":
        # Process campaign data for charts
        campaigns = data.get("campaigns", [])
        
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
        
        return {
            "actor_labels": json.dumps(actor_labels),
            "actor_values": json.dumps(actor_values),
            "target_labels": json.dumps(target_labels),
            "target_values": json.dumps(target_values)
        }
    
    return {}


def get_gcp_metrics() -> Dict:
    """Get metrics from GCP services"""
    metrics = {}
    
    try:
        # Get BigQuery table counts
        query = f"""
        SELECT COUNT(*) as tables
        FROM `{PROJECT_ID}.{os.environ.get("BIGQUERY_DATASET", "threat_intelligence")}.__TABLES__`
        """
        query_job = bq_client.query(query)
        results = query_job.result()
        row = next(results)
        metrics["table_count"] = row.tables
        
        # Get Storage bucket info
        bucket_name = f"{PROJECT_ID}-threat-data"
        try:
            bucket = storage_client.get_bucket(bucket_name)
            blobs = list(bucket.list_blobs())
            metrics["storage_objects"] = len(blobs)
            metrics["storage_size"] = sum(blob.size for blob in blobs) / (1024 * 1024)  # MB
        except Exception as e:
            logger.warning(f"Error getting storage info: {str(e)}")
            metrics["storage_objects"] = 0
            metrics["storage_size"] = 0
            
    except Exception as e:
        logger.error(f"Error getting GCP metrics: {str(e)}")
    
    return metrics


# Route handlers
@app.route('/')
@login_required
def dashboard():
    """Dashboard page"""
    days = request.args.get('days', '30')
    
    # Get platform stats
    stats = api_request('stats', {'days': days})
    
    # Get recent campaigns
    campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
    campaigns = campaigns_data.get('campaigns', [])
    
    # Get top IOCs
    iocs_data = api_request('iocs', {'days': days, 'limit': 5})
    top_iocs = iocs_data.get('records', [])
    
    # Get GCP metrics
    gcp_metrics = get_gcp_metrics()
    
    # Generate chart data
    chart_data = prepare_chart_data("ioc_types", stats)
    
    # Generate activity data
    activity_data = api_request('feeds/alienvault_pulses/stats', {'days': days})
    activity_dates = json.dumps([item.get("date") for item in activity_data.get("daily_counts", [])])
    activity_counts = json.dumps([item.get("count") for item in activity_data.get("daily_counts", [])])
    
    return render_template(
        'dashboard.html',
        days=days,
        stats=stats,
        campaigns=campaigns,
        top_iocs=top_iocs,
        gcp_metrics=gcp_metrics,
        ioc_type_labels=chart_data.get("labels"),
        ioc_type_values=chart_data.get("values"),
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
        
        if username in USERS and USERS[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = username
            session['role'] = USERS[username]['role']
            
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
    
    # Get stats for each feed
    feeds = []
    total_records = 0
    days_with_updates = 0
    
    for feed_name in feeds_data.get('feeds', []):
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
    chart_data = prepare_chart_data("feed_activity", {"feeds": feeds_data.get('feeds', [])})
    
    return render_template(
        'feeds.html',
        days=days,
        feeds=feeds,
        total_records=total_records,
        days_with_updates=days_with_updates,
        feed_activity=chart_data.get("feed_activity")
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
    
    # Get chart data
    chart_data = prepare_chart_data("campaign_metrics", {"campaigns": campaigns})
    
    return render_template(
        'campaigns.html',
        days=days,
        campaigns=campaigns,
        min_sources=min_sources,
        pagination=pagination,
        search=search,
        actor_labels=chart_data.get("actor_labels"),
        actor_values=chart_data.get("actor_values"),
        target_labels=chart_data.get("target_labels"),
        target_values=chart_data.get("target_values")
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
        if ioc.get('type') == 'ip' and ioc.get('geo', {}).get('country'):
            country = ioc.get('geo', {}).get('country')
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


@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    days = request.args.get('days', '30')
    
    # In a real app, we would fetch reports from storage or database
    # For now, simulate with dummy data
    reports = [
        {
            'report_id': 'feed_summary_report',
            'report_name': 'Feed Summary Report',
            'report_type': 'feed_summary',
            'generated_at': (datetime.now() - timedelta(days=1)).isoformat(),
            'period_days': 30
        },
        {
            'report_id': 'campaign_analysis_report',
            'report_name': 'Campaign Analysis Report',
            'report_type': 'campaign_analysis',
            'generated_at': (datetime.now() - timedelta(days=2)).isoformat(),
            'period_days': 30
        },
        {
            'report_id': 'ioc_trend_report',
            'report_name': 'IOC Trend Report',
            'report_type': 'ioc_trend',
            'generated_at': (datetime.now() - timedelta(days=3)).isoformat(),
            'period_days': 30
        }
    ]
    
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
    
    # In a real app, we would generate a report
    # For now, simulate with a redirect
    flash(f"Report '{report_type}' generated successfully", "success")
    return redirect(url_for('reports'))


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


@app.route('/export_feed')
@login_required
def export_feed():
    """Export feed data"""
    feed_name = request.args.get('feed_name')
    format = request.args.get('format', 'csv')
    
    # In a real app, we would generate the export file
    # For now, return a simple message
    flash(f"Export of feed '{feed_name}' in {format.upper()} format initiated. You will be notified when it's ready.", "success")
    return redirect(url_for('feed_detail', feed_name=feed_name))


@app.route('/export_campaign')
@login_required
def export_campaign():
    """Export campaign data"""
    campaign_id = request.args.get('campaign_id')
    format = request.args.get('format', 'pdf')
    
    # In a real app, we would generate the export file
    # For now, return a simple message
    flash(f"Export of campaign in {format.upper()} format initiated. You will be notified when it's ready.", "success")
    return redirect(url_for('campaign_detail', campaign_id=campaign_id))


@app.route('/export_iocs')
@login_required
def export_iocs():
    """Export IOCs data"""
    format = request.args.get('format', 'csv')
    
    # In a real app, we would generate the export file
    # For now, return a simple message
    flash(f"Export of IOCs in {format.upper()} format initiated. You will be notified when it's ready.", "success")
    return redirect(url_for('iocs'))


@app.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    # In a real app, we would fetch alerts from storage or database
    # For now, simulate with dummy data
    alerts = [
        {
            'id': 'alert1',
            'title': 'New Ransomware Campaign Detected',
            'severity': 'critical',
            'timestamp': datetime.now() - timedelta(hours=2),
            'description': 'Multiple indicators of BlackCat ransomware detected in financial sector.'
        },
        {
            'id': 'alert2',
            'title': 'APT Activity Detected',
            'severity': 'high',
            'timestamp': datetime.now() - timedelta(hours=5),
            'description': 'Suspected nation-state actor targeting critical infrastructure.'
        },
        {
            'id': 'alert3',
            'title': 'Unusual Authentication Activity',
            'severity': 'medium',
            'timestamp': datetime.now() - timedelta(days=1),
            'description': 'Multiple failed login attempts detected from unusual locations.'
        }
    ]
    
    return render_template(
        'alerts.html',
        alerts=alerts
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


@app.route('/users')
@login_required
@role_required('admin')
def users():
    """User Management page"""
    return render_template(
        'users.html',
        users=USERS
    )


@app.route('/profile')
@login_required
def profile():
    """User Profile page"""
    return render_template(
        'profile.html'
    )


@app.errorhandler(404)
def page_not_found(e):
    """404 Page not found"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """500 Server error"""
    return render_template('500.html'), 500


# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
