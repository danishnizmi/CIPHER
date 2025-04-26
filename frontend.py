"""
Threat Intelligence Platform - Frontend Module
Handles web interface, user authentication, and dashboard views.
"""

import os
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Add CORS support
CORS(app)

# Generate a secure secret key or get from environment
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Get from config or generate a new one
    auth_config = config.get_cached_config('auth-config')
    SECRET_KEY = auth_config.get('session_secret') if auth_config else None
    
    if not SECRET_KEY:
        # Generate a secure random key
        SECRET_KEY = hashlib.sha256(str(time.time()).encode()).hexdigest()
        logger.warning("Generated temporary secret key. For production, set SECRET_KEY in environment.")

# Configure Flask
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=config.environment == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    TEMPLATES_AUTO_RELOAD=config.environment != 'production',
)

# Default mock data for development/demo
MOCK_DATA = {
    "stats": {
        "feeds": {
            "total_sources": 5,
            "active_feeds": 5,
            "total_records": 320,
            "growth_rate": 5
        },
        "campaigns": {
            "total_campaigns": 3,
            "active_campaigns": 3,
            "unique_actors": 3,
            "growth_rate": 3
        },
        "iocs": {
            "total": 250,
            "types": [
                {"type": "ip", "count": 100},
                {"type": "domain", "count": 75},
                {"type": "url", "count": 50},
                {"type": "hash", "count": 20},
                {"type": "email", "count": 5}
            ],
            "growth_rate": 8
        },
        "analyses": {
            "total_analyses": 30,
            "last_analysis": datetime.utcnow().isoformat(),
            "growth_rate": 10
        },
        "timestamp": datetime.utcnow().isoformat(),
    }
}

# ======== Auth & Security Functions ========

def load_users() -> Dict[str, Dict]:
    """Load user data from auth config"""
    auth_config = config.get_cached_config('auth-config')
    if not auth_config or 'users' not in auth_config:
        # Create default admin user if no users exist
        if config.environment != 'production':
            default_users = {
                'admin': {
                    'password': hashlib.sha256('admin'.encode()).hexdigest(),
                    'role': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            return default_users
        return {}
    return auth_config.get('users', {})

def login_required(f):
    """Decorator to require login for views"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('Admin privileges required', 'danger')
            return render_template('auth.html', page_type='not_authorized')
        return f(*args, **kwargs)
    return decorated_function

# ======== Routes ========

@app.route('/')
def index():
    """Root redirects to dashboard if logged in, otherwise to login"""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        users = load_users()
        
        if username in users:
            user = users[username]
            stored_password = user.get('password', '')
            
            # Check password
            if check_password_hash(stored_password, password) or stored_password == hashlib.sha256(password.encode()).hexdigest():
                # Login successful
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user.get('role', 'readonly')
                session.permanent = remember
                
                # Update last login
                config.update_user(username, {'last_login': datetime.utcnow().isoformat()})
                
                flash(f'Welcome, {username}!', 'success')
                
                # Redirect to requested page or dashboard
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid password"
        else:
            error = "Invalid username"
    
    return render_template('auth.html', page_type='login', error=error, now=datetime.now())

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@app.route('/dashboard/<view>')
@login_required
def dashboard(view=None):
    """Main dashboard view with different sub-views"""
    # Get the view from query param if not in path
    current_view = view or request.args.get('view', 'dashboard')
    days = int(request.args.get('days', '30'))
    
    # Prepare page context
    context = {
        'current_view': current_view,
        'days': days,
    }
    
    # Set page titles based on view
    if current_view == 'feeds':
        context['page_title'] = 'Threat Feeds'
        context['page_subtitle'] = 'Intelligence sources and data collection'
        context['page_icon'] = 'rss'
    elif current_view == 'iocs':
        context['page_title'] = 'Indicators of Compromise'
        context['page_subtitle'] = 'Observed indicators and threat artifacts'
        context['page_icon'] = 'fingerprint'
    elif current_view == 'campaigns':
        context['page_title'] = 'Threat Campaigns'
        context['page_subtitle'] = 'Detected threat actor campaigns and activities'
        context['page_icon'] = 'project-diagram'
    else:
        context['page_title'] = 'Threat Intelligence Dashboard'
        context['page_subtitle'] = 'Platform overview and threat summary'
        context['page_icon'] = 'tachometer-alt'
    
    # Get stats data from API or cache
    try:
        # In a real implementation, we'd call the API here
        # For now, use mock data
        stats = MOCK_DATA["stats"]
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        stats = MOCK_DATA["stats"]
    
    # Calculate trends
    context['feed_trend'] = stats.get('feeds', {}).get('growth_rate', 0)
    context['ioc_trend'] = stats.get('iocs', {}).get('growth_rate', 0)
    context['campaign_trend'] = stats.get('campaigns', {}).get('growth_rate', 0)
    context['analysis_trend'] = stats.get('analyses', {}).get('growth_rate', 0)
    
    # Add all stats to context
    context['stats'] = stats
    
    # Add chart data
    context['ioc_type_labels'] = [item['type'] for item in stats.get('iocs', {}).get('types', [])]
    context['ioc_type_values'] = [item['count'] for item in stats.get('iocs', {}).get('types', [])]
    
    # Add view-specific data
    if current_view == 'feeds':
        context['feed_items'] = get_feeds_data(days)
        context['feed_type_descriptions'] = {
            'threatfox_iocs': 'ThreatFox IOCs - Malware indicators database',
            'phishtank_urls': 'PhishTank - Community-verified phishing URLs',
            'urlhaus_malware': 'URLhaus - Database of malicious URLs',
            'feodotracker_c2': 'Feodo Tracker - Botnet C2 IP Blocklist',
            'cisa_vulnerabilities': 'CISA Known Exploited Vulnerabilities Catalog',
            'tor_exit_nodes': 'Tor Exit Node List',
        }
    elif current_view == 'iocs':
        context['ioc_items'] = get_iocs_data(days)
    elif current_view == 'campaigns':
        context['campaigns'] = get_campaigns_data(days)
    else:
        # Dashboard view needs additional data
        context['activity_dates'] = get_date_range(days)
        context['activity_counts'] = get_random_counts(len(context['activity_dates']))
        context['campaigns'] = get_campaigns_data(days)[:3]  # Top 3 campaigns
        context['top_iocs'] = get_iocs_data(days)[:4]  # Top 4 IOCs
    
    return render_template('dashboard.html', **context, now=datetime.now())

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    username = session.get('username')
    users = load_users()
    user = users.get(username, {})
    
    if request.method == 'POST':
        # Handle password change
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        else:
            stored_password = user.get('password', '')
            
            # Verify current password
            if check_password_hash(stored_password, current_password) or stored_password == hashlib.sha256(current_password.encode()).hexdigest():
                # Update password
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                if config.update_user(username, {'password': hashed_password}):
                    flash('Password updated successfully', 'success')
                else:
                    flash('Error updating password', 'danger')
            else:
                flash('Current password is incorrect', 'danger')
    
    return render_template('auth.html', page_type='profile', username=username, user=user)

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
        else:
            # Add user
            if config.add_user(username, password, role):
                flash(f'User {username} added successfully', 'success')
                return redirect(url_for('users'))
            else:
                flash('Error adding user', 'danger')
    
    return render_template('auth.html', page_type='user_add')

@app.route('/user/edit/<username>', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    """Edit user page"""
    users = load_users()
    
    if username not in users:
        flash(f'User {username} not found', 'danger')
        return redirect(url_for('users'))
    
    user = users[username]
    
    if request.method == 'POST':
        password = request.form.get('password')
        role = request.form.get('role')
        
        updates = {'role': role}
        if password:
            updates['password'] = password
        
        if config.update_user(username, updates):
            flash(f'User {username} updated successfully', 'success')
            return redirect(url_for('users'))
        else:
            flash('Error updating user', 'danger')
    
    return render_template('auth.html', page_type='user_edit', username=username, user=user)

@app.route('/user/delete/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    """Delete user route"""
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
        else:
            flash('Error deleting user', 'danger')
    else:
        flash(f'User {username} not found in configuration', 'danger')
    
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
    return render_template('content.html', page_type='explore')

@app.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    return render_template('content.html', page_type='alerts')

@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger data ingestion manually"""
    # In a real implementation, this would call the API
    # For now, just redirect back to dashboard with a message
    flash('Threat data refresh initiated', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dynamic_content_detail/<content_type>/<identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Dynamic content detail page for IOCs, campaigns, etc."""
    context = {
        'content_type': content_type,
        'identifier': identifier,
        'data': get_mock_detail_data(content_type, identifier)
    }
    return render_template('detail.html', **context)

# ======== Helper Functions ========

def get_feeds_data(days=30):
    """Get feeds data for UI"""
    # Mock data for demonstration
    feeds = [
        {"name": "threatfox_iocs", "record_count": 100, "last_updated": datetime.utcnow().isoformat()},
        {"name": "phishtank_urls", "record_count": 80, "last_updated": datetime.utcnow().isoformat()},
        {"name": "urlhaus_malware", "record_count": 65, "last_updated": datetime.utcnow().isoformat()},
        {"name": "feodotracker_c2", "record_count": 50, "last_updated": datetime.utcnow().isoformat()},
        {"name": "cisa_vulnerabilities", "record_count": 25, "last_updated": datetime.utcnow().isoformat()}
    ]
    return feeds

def get_iocs_data(days=30):
    """Get IOCs data for UI"""
    # Mock data for demonstration
    iocs = [
        {
            "type": "ip",
            "value": "192.168.1.100",
            "source": "threatfox_iocs",
            "timestamp": datetime.utcnow().isoformat(),
            "sources": 12,
            "first_seen": (datetime.utcnow() - timedelta(days=20)).isoformat()
        },
        {
            "type": "domain",
            "value": "malicious-domain.com",
            "source": "urlhaus_malware",
            "timestamp": datetime.utcnow().isoformat(),
            "sources": 8,
            "first_seen": (datetime.utcnow() - timedelta(days=15)).isoformat()
        },
        {
            "type": "url",
            "value": "https://phishing-site.org/login",
            "source": "phishtank_urls",
            "timestamp": datetime.utcnow().isoformat(),
            "sources": 6,
            "first_seen": (datetime.utcnow() - timedelta(days=10)).isoformat()
        },
        {
            "type": "md5",
            "value": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "source": "threatfox_iocs",
            "timestamp": datetime.utcnow().isoformat(),
            "sources": 4,
            "first_seen": (datetime.utcnow() - timedelta(days=5)).isoformat()
        }
    ]
    return iocs

def get_campaigns_data(days=30):
    """Get campaigns data for UI"""
    # Mock data for demonstration
    campaigns = [
        {
            "campaign_id": "c123456",
            "campaign_name": "APT-123456",
            "threat_actor": "FancyBear",
            "source_count": 7,
            "last_seen": (datetime.utcnow() - timedelta(days=2)).isoformat(),
            "severity": "high",
            "first_seen": (datetime.utcnow() - timedelta(days=15)).isoformat()
        },
        {
            "campaign_id": "c234567",
            "campaign_name": "Ransomware-234567",
            "threat_actor": "Conti",
            "source_count": 5,
            "last_seen": (datetime.utcnow() - timedelta(days=5)).isoformat(),
            "severity": "critical",
            "first_seen": (datetime.utcnow() - timedelta(days=20)).isoformat()
        },
        {
            "campaign_id": "c345678",
            "campaign_name": "Phishing-345678",
            "threat_actor": "Lazarus",
            "source_count": 3,
            "last_seen": (datetime.utcnow() - timedelta(days=10)).isoformat(),
            "severity": "medium",
            "first_seen": (datetime.utcnow() - timedelta(days=25)).isoformat()
        }
    ]
    return campaigns

def get_date_range(days=30):
    """Get date range for charts"""
    today = datetime.now().date()
    return [(today - timedelta(days=i)).isoformat() for i in range(days)][::-1]

def get_random_counts(length):
    """Get random counts for charts"""
    import random
    base = 50
    result = []
    
    for i in range(length):
        result.append(base + random.randint(-10, 20))
        # Adjust base with some trend
        base = max(10, min(100, base + random.randint(-5, 8)))
    
    return result

def get_mock_detail_data(content_type, identifier):
    """Get mock detail data for dynamic content pages"""
    if content_type == 'ioc':
        ioc_type, ioc_value = identifier.split('/', 1)
        return {
            "type": ioc_type,
            "value": ioc_value,
            "first_seen": (datetime.utcnow() - timedelta(days=15)).isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "sources": ["threatfox_iocs", "alienvault_otx"],
            "confidence": "medium",
            "tags": ["malware", "ransomware"],
            "related_iocs": get_iocs_data(30)[:2],
            "campaigns": get_campaigns_data(30)[:1]
        }
    elif content_type == 'campaign':
        campaign_id = identifier
        campaigns = get_campaigns_data(30)
        campaign = next((c for c in campaigns if c["campaign_id"] == campaign_id), {})
        campaign["description"] = "This threat campaign involves targeted attacks against financial institutions using spear-phishing emails and custom malware."
        campaign["iocs"] = get_iocs_data(30)[:3]
        campaign["techniques"] = ["T1566 - Phishing", "T1204 - User Execution", "T1573 - Encrypted Channel"]
        return campaign
    elif content_type == 'feed':
        feed_name = identifier
        feed = next((f for f in get_feeds_data(30) if f["name"] == feed_name), {})
        feed["description"] = f"Data from {feed_name} threat intelligence feed."
        feed["sample_data"] = get_iocs_data(30)[:5]
        feed["daily_counts"] = [{"date": d, "count": c} for d, c in zip(get_date_range(14), get_random_counts(14))]
        return feed
    return {}

# ======== Template Filters ========

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

# ======== Error Handlers ========

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

# ======== Context Processors ========

@app.context_processor
def inject_global_data():
    """Inject global data into templates"""
    return {
        'now': datetime.now(),
        'environment': config.environment,
        'version': os.environ.get('VERSION', '1.0.0')
    }

# Initialize the app
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
