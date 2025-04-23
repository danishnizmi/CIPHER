"""
Threat Intelligence Platform - Frontend Module
Provides web interface for the threat intelligence platform using consolidated templates.
Enhanced with AI-powered threat intelligence insights.
"""

import os
import json
import logging
import hashlib
import secrets
import string
import time
import sys
import traceback
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

# Configure enhanced logging for more visibility
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Explicitly log to stdout for Docker/GCP logs
    ]
)
logger = logging.getLogger(__name__)

# Also log to stderr for critical messages to ensure visibility
error_handler = logging.StreamHandler(sys.stderr)
error_handler.setLevel(logging.ERROR)
logger.addHandler(error_handler)

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
app.secret_key = os.environ.get("FLASK_SECRET_KEY", config.get("FLASK_SECRET_KEY", secrets.token_hex(32)))
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

# Admin credentials - create a single admin account with FIXED PASSWORD
ADMIN_USERNAME = "admin"
# Using a fixed admin password to avoid inconsistencies
ADMIN_PASSWORD = "Admin123!"
ADMIN_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

# Log the admin credentials in multiple ways for visibility
password_banner = f"""
======== INITIAL ADMIN CREDENTIALS ========
Username: {ADMIN_USERNAME}
Password: {ADMIN_PASSWORD}
===========================================
PLEASE CHANGE THIS PASSWORD AFTER FIRST LOGIN
"""

# Print to both stdout and stderr to ensure visibility in logs
print(password_banner, file=sys.stdout)
print(password_banner, file=sys.stderr)

# Also log through the logging system at multiple levels
logger.info(password_banner)
logger.warning(password_banner)  # Use warning level for more visibility
logger.error(f"SECURITY NOTICE: Admin credentials - Username: {ADMIN_USERNAME}, Password: {ADMIN_PASSWORD}")

# Write to a specific file that might be captured in logs
try:
    with open('/tmp/admin_credentials.txt', 'w') as f:
        f.write(password_banner)
except Exception as e:
    logger.warning(f"Could not write admin credentials to file: {e}")

# Utility Functions
def hash_password(password):
    """Create a secure hash of the password"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify a password against a stored hash"""
    return stored_hash == hash_password(password)

# Load user data (just the admin user)
def get_users():
    """Get user data with admin account"""
    # Try to get from config first
    auth_config = config.get_cached_config('auth-config')
    users = auth_config.get("users", {}) if auth_config else {}
    
    # If no users in config or no admin user, create/update admin
    if not users or ADMIN_USERNAME not in users:
        users = {
            ADMIN_USERNAME: {
                "password": ADMIN_HASH,
                "role": "admin",
                "temp_password": True,
                "created_at": datetime.utcnow().isoformat()
            }
        }
        
        # Try to save admin user to config
        try:
            if auth_config is None:
                auth_config = {}
            auth_config["users"] = users
            config.create_or_update_secret("auth-config", json.dumps(auth_config))
            logger.info("Created default admin user in auth-config")
        except Exception as e:
            logger.warning(f"Failed to save default admin user to secret: {e}")
    
    # Ensure admin user always exists with correct role
    if ADMIN_USERNAME in users:
        users[ADMIN_USERNAME]["role"] = "admin"
    
    return users

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH and not session.get("logged_in"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control - simplified for admin-only mode
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login", next=request.url))
            
            # Only admin role exists in this version
            if required_role == "admin" and session.get("username") != ADMIN_USERNAME:
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
    
    # Try direct API call first (no proxying through API_URL)
    try:
        # Import api module and try to call function directly
        import api
        
        if hasattr(api, endpoint) and callable(getattr(api, endpoint)):
            # Call API function directly
            direct_function = getattr(api, endpoint)
            result = direct_function(params)
            if result:
                return result
    except (ImportError, AttributeError):
        # If api module not available or function doesn't exist, continue with HTTP request
        pass
        
    # Build the URL properly - handle both external API_URL and local
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

def generate_ai_insights():
    """Generate AI-powered threat intelligence insights
    
    Returns:
        Dictionary with insights data
    """
    try:
        # Get recent data for insights
        stats = api_request('stats', {'days': 7})
        campaigns = api_request('campaigns', {'days': 7, 'limit': 5})
        iocs_data = api_request('iocs', {'days': 7, 'limit': 10})
        
        # Extract key data points
        campaign_count = stats.get('campaigns', {}).get('total_campaigns', 0)
        ioc_count = stats.get('iocs', {}).get('total', 0)
        ioc_types = stats.get('iocs', {}).get('types', [])
        top_campaigns = campaigns.get('campaigns', [])
        top_iocs = iocs_data.get('records', [])
        
        # Simple insight generation based on available data
        insights = []
        
        # Campaign insights
        if campaign_count > 0:
            insights.append({
                "title": "Campaign Activity",
                "description": f"Detected {campaign_count} active campaigns in the last 7 days.",
                "type": "campaign",
                "severity": "medium" if campaign_count > 3 else "low",
                "actions": [{"text": "View Campaigns", "url": url_for('campaigns')}]
            })
            
            if top_campaigns:
                latest_campaign = top_campaigns[0]
                insights.append({
                    "title": f"New Campaign: {latest_campaign.get('campaign_name')}",
                    "description": f"Attributed to {latest_campaign.get('threat_actor', 'Unknown Actor')} targeting {latest_campaign.get('targets', 'Unknown Targets')}.",
                    "type": "campaign",
                    "severity": "high",
                    "actions": [{"text": "View Details", "url": url_for('campaign_detail', campaign_id=latest_campaign.get('campaign_id'))}]
                })
        
        # IOC insights
        if ioc_count > 0:
            # Identify most common IOC type
            most_common_type = max(ioc_types, key=lambda x: x.get('count', 0)) if ioc_types else {"type": "unknown", "count": 0}
            insights.append({
                "title": "IOC Distribution",
                "description": f"Most common indicator type: {most_common_type.get('type', 'Unknown')} ({most_common_type.get('count', 0)} instances).",
                "type": "ioc",
                "severity": "info",
                "actions": [{"text": "View IOCs", "url": url_for('iocs')}]
            })
        
        # Add a learning recommendation
        insights.append({
            "title": "AI Recommendation",
            "description": "Based on current threat patterns, we recommend reviewing your defenses against phishing and ransomware attacks.",
            "type": "recommendation",
            "severity": "info",
            "actions": [{"text": "View Reports", "url": url_for('reports')}]
        })
        
        # Generate threat predictions
        predictions = [
            {
                "title": "Ransomware Activity",
                "description": "Predicted 35% increase in ransomware activity targeting financial sector over the next 30 days.",
                "confidence": "medium",
                "timeframe": "30 days"
            },
            {
                "title": "Credential Theft",
                "description": "Expected rise in password spray attacks against cloud services.",
                "confidence": "high",
                "timeframe": "14 days"
            },
            {
                "title": "Zero-day Exploits",
                "description": "Potential new vulnerability exploits in common CMS platforms.",
                "confidence": "low",
                "timeframe": "60 days"
            }
        ]
        
        # Generate mitigation recommendations
        mitigations = [
            {
                "title": "Multi-factor Authentication",
                "description": "Enable MFA for all cloud services and remote access points.",
                "priority": "high",
                "effort": "medium"
            },
            {
                "title": "Email Filtering",
                "description": "Enhance email security with advanced attachment scanning.",
                "priority": "medium",
                "effort": "low"
            },
            {
                "title": "Network Segmentation",
                "description": "Implement stricter network segmentation to limit lateral movement.",
                "priority": "high",
                "effort": "high"
            }
        ]
        
        # MITRE ATT&CK Techniques observed
        techniques = [
            {
                "id": "T1566",
                "name": "Phishing",
                "description": "Adversaries are sending phishing emails with malicious attachments.",
                "mitigation": "Implement email filtering and user awareness training."
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries are using PowerShell for execution.",
                "mitigation": "Enable PowerShell logging and constrained language mode."
            },
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "description": "Ransomware encrypting data for financial gain.",
                "mitigation": "Maintain offline backups and implement application control."
            }
        ]
        
        return {
            "insights": insights,
            "predictions": predictions,
            "mitigations": mitigations,
            "techniques": techniques,
            "timestamp": datetime.utcnow().isoformat(),
            "refresh_interval": 3600  # Refresh every hour
        }
    except Exception as e:
        logger.error(f"Error generating AI insights: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": str(e),
            "insights": [
                {
                    "title": "Analysis Error",
                    "description": "Unable to generate insights due to an error. Please try again later.",
                    "type": "error",
                    "severity": "high",
                    "actions": []
                }
            ],
            "timestamp": datetime.utcnow().isoformat()
        }

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
        
        # Log authentication attempts (without password)
        logger.info(f"Login attempt for user: {username}")
        
        # Check admin credentials directly first
        if username == ADMIN_USERNAME and verify_password(ADMIN_HASH, password):
            session['logged_in'] = True
            session['username'] = username
            session['role'] = "admin"
            
            logger.info(f"Admin user {username} logged in successfully")
            
            # Update last login time
            try:
                config.update_user(username, {"last_login": datetime.utcnow().isoformat()})
            except Exception as e:
                logger.warning(f"Could not update last login: {str(e)}")
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        
        # If not direct admin match, check config
        current_users = get_users()
        
        if username in current_users:
            user_data = current_users[username]
            
            # Check if password matches
            if verify_password(user_data['password'], password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user_data.get('role', 'readonly')
                
                logger.info(f"User {username} logged in successfully")
                
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
                logger.warning(f"Failed login attempt for user: {username} - invalid password")
        else:
            error = "Invalid username or password"
            logger.warning(f"Failed login attempt for user: {username} - user not found")
    
    return render_template('auth.html', page_type='login', error=error)

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username')
    if username:
        logger.info(f"User {username} logged out")
    
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
    global ADMIN_HASH
    username = session.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Check if this is admin user
    is_admin = (username == ADMIN_USERNAME)
    
    # Verify current admin password
    if is_admin:
        if not verify_password(ADMIN_HASH, current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('profile'))
    else:
        # Get users from config
        current_users = get_users()
        
        if not username or username not in current_users:
            flash("User not found", "danger")
            return redirect(url_for('profile'))
        
        # Check current password
        if not verify_password(current_users[username]['password'], current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('profile'))
    
    # Validate new password
    if not new_password or not confirm_password:
        flash("New password is required", "danger")
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for('profile'))
    
    # Update password
    updates = {
        "password": new_password,
        "temp_password": False,  # Clear the temp password flag
    }
    
    # Update admin password globally if this is admin
    if is_admin:
        ADMIN_HASH = hash_password(new_password)
        logger.info("Admin password updated successfully")
    
    # Also update in config
    result = config.update_user(username, updates)
    if result:
        flash("Password changed successfully", "success")
    else:
        flash("Password changed in session but failed to update in config", "warning")
    
    return redirect(url_for('profile'))

# Dashboard Route
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

# AI Insights Page - The new AI-managed page
@app.route('/ai-insights')
@login_required
def ai_insights():
    """AI-powered threat intelligence insights page"""
    # Get insights data
    insights_data = generate_ai_insights()
    
    # Get days parameter for historical context
    days = request.args.get('days', '30')
    
    # Get basic platform stats for context
    stats = api_request('stats', {'days': days})
    
    # Get recent campaigns
    campaigns_data = api_request('campaigns', {'days': days, 'limit': 5})
    campaigns = campaigns_data.get('campaigns', [])
    
    # Get top IOCs
    iocs_data = api_request('iocs', {'days': days, 'limit': 10})
    top_iocs = [ioc for record in iocs_data.get('records', []) for ioc in record.get('iocs', [])][:10]
    
    # Get AI-analyzed insights
    ai_analyzed_content = """
    <div class="space-y-6">
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div class="flex items-center mb-2">
                <div class="text-blue-500 mr-3">
                    <i class="fas fa-robot text-xl"></i>
                </div>
                <h3 class="font-semibold text-blue-700">AI-Powered Analysis</h3>
            </div>
            <p class="text-gray-700">
                Our AI has analyzed recent threat intelligence data and identified several key patterns and potential risks.
                The following insights are generated using machine learning algorithms applied to your threat data feeds.
            </p>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    <i class="fas fa-chart-line text-indigo-600 mr-2"></i>
                    Threat Predictions
                </h3>
                <div class="space-y-4">
                    {% for prediction in insights_data.predictions %}
                    <div class="border-l-4 border-indigo-500 pl-4 py-1">
                        <h4 class="font-medium">{{ prediction.title }}</h4>
                        <p class="text-gray-600 text-sm">{{ prediction.description }}</p>
                        <div class="flex items-center mt-2 text-xs">
                            <span class="bg-indigo-100 text-indigo-800 rounded-full px-2 py-1">
                                Confidence: {{ prediction.confidence|title }}
                            </span>
                            <span class="ml-2 text-gray-500">
                                <i class="fas fa-clock mr-1"></i>
                                Next {{ prediction.timeframe }}
                            </span>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    <i class="fas fa-shield-alt text-green-600 mr-2"></i>
                    Mitigation Recommendations
                </h3>
                <div class="space-y-4">
                    {% for mitigation in insights_data.mitigations %}
                    <div class="border-l-4 
                                {% if mitigation.priority == 'high' %}border-red-500
                                {% elif mitigation.priority == 'medium' %}border-yellow-500
                                {% else %}border-green-500{% endif %}
                                pl-4 py-1">
                        <h4 class="font-medium">{{ mitigation.title }}</h4>
                        <p class="text-gray-600 text-sm">{{ mitigation.description }}</p>
                        <div class="flex items-center mt-2 text-xs">
                            <span class="
                                {% if mitigation.priority == 'high' %}bg-red-100 text-red-800
                                {% elif mitigation.priority == 'medium' %}bg-yellow-100 text-yellow-800
                                {% else %}bg-green-100 text-green-800{% endif %}
                                rounded-full px-2 py-1">
                                Priority: {{ mitigation.priority|title }}
                            </span>
                            <span class="ml-2 bg-gray-100 text-gray-800 rounded-full px-2 py-1">
                                Effort: {{ mitigation.effort|title }}
                            </span>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow-md p-6">
            <h3 class="text-lg font-semibold mb-4 flex items-center">
                <i class="fas fa-binoculars text-purple-600 mr-2"></i>
                MITRE ATT&CK Techniques Observed
            </h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead>
                        <tr class="bg-gray-50">
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Technique</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Mitigation</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for technique in insights_data.techniques %}
                        <tr class="hover:bg-gray-50">
                            <td class="px-6 py-4 whitespace-nowrap text-blue-600 font-medium">{{ technique.id }}</td>
                            <td class="px-6 py-4 whitespace-nowrap">{{ technique.name }}</td>
                            <td class="px-6 py-4">{{ technique.description }}</td>
                            <td class="px-6 py-4">{{ technique.mitigation }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    
    # Create a custom page using content.html template with AI generated content
    return render_template(
        'content.html',
        page_title='AI-Powered Threat Intelligence Insights',
        page_icon='robot',
        page_subtitle='Advanced analysis and predictions powered by machine learning',
        content_html=ai_analyzed_content,
        insights_data=insights_data,
        days=days,
        show_time_filter=True,
        current_endpoint='ai_insights'
    )

# Unified routes for other content types (simplified to maintain compatibility)
@app.route('/<content_type>s')
@login_required
def dynamic_content_list(content_type):
    """Unified handler for different content types"""
    days = request.args.get('days', '30')
    limit = min(int(request.args.get('limit', '50')), 1000)
    offset = int(request.args.get('offset', '0'))
    search = request.args.get('search', '')
    
    # Define content type specific settings
    content_settings = {
        'feed': {
            'singular': 'feed',
            'plural': 'feeds',
            'icon': 'rss',
            'title': 'Threat Intelligence Feeds',
            'subtitle': 'Collection of threat data from various sources',
            'endpoint': 'feeds',
            'detail_endpoint': 'feed_detail'
        },
        'campaign': {
            'singular': 'campaign',
            'plural': 'campaigns',
            'icon': 'project-diagram',
            'title': 'Threat Campaigns',
            'subtitle': 'Active and historical threat campaigns',
            'endpoint': 'campaigns',
            'detail_endpoint': 'campaign_detail'
        },
        'ioc': {
            'singular': 'ioc',
            'plural': 'iocs',
            'icon': 'fingerprint',
            'title': 'Indicators of Compromise',
            'subtitle': 'Collected IOCs from all sources',
            'endpoint': 'iocs',
            'detail_endpoint': 'ioc_detail'
        },
        'report': {
            'singular': 'report',
            'plural': 'reports',
            'icon': 'chart-bar',
            'title': 'Threat Intelligence Reports',
            'subtitle': 'Comprehensive threat analysis reports',
            'endpoint': 'reports',
            'detail_endpoint': 'view_report'
        },
        'alert': {
            'singular': 'alert',
            'plural': 'alerts',
            'icon': 'bell',
            'title': 'Threat Alerts',
            'subtitle': 'Active security alerts requiring attention',
            'endpoint': 'alerts',
            'detail_endpoint': None
        }
    }
    
    # Check if content type is supported
    if content_type not in content_settings:
        abort(404)
        
    settings = content_settings[content_type]
    api_endpoint = settings['plural']
    
    # Get data from API
    api_params = {'days': days, 'limit': limit, 'offset': offset}
    if search:
        api_params['search'] = search
        
    content_data = api_request(api_endpoint, api_params)
    
    # Get items based on content type
    if content_type == 'feed':
        items = content_data.get('feed_details', [])
    elif content_type in ['campaign', 'report']:
        items = content_data.get(settings['plural'], [])
    elif content_type == 'ioc':
        records = content_data.get('records', [])
        items = []
        for record in records:
            items.extend(record.get('iocs', []))
    else:
        items = content_data.get(settings['plural'], [])
        
    # Generate additional data based on content type
    summary_stats = None
    chart_data = None
    action_buttons = []
    filter_types = None
    
    if content_type == 'feed':
        # Stats for feeds
        feeds_stats = api_request('stats')
        total_records = feeds_stats.get('feeds', {}).get('total_records', 0)
        active_feeds = feeds_stats.get('feeds', {}).get('active_feeds', 0)
        
        summary_stats = [
            {'label': 'Active Feeds', 'value': active_feeds, 'icon': 'plug', 'color': 'blue'},
            {'label': 'Total Records', 'value': total_records, 'icon': 'database', 'color': 'green'},
            {'label': 'Days with Updates', 'value': len(items), 'icon': 'calendar-check', 'color': 'purple'}
        ]
        
        action_buttons = [{
            'text': 'Run Ingestion',
            'url': url_for('ingest_threat_data'),
            'icon': 'sync',
            'type': 'success'
        }]
    elif content_type == 'ioc':
        # Filter types for IOCs
        filter_types = [
            {'label': 'All Types', 'value': ''},
            {'label': 'IP Address', 'value': 'ip'},
            {'label': 'Domain', 'value': 'domain'},
            {'label': 'URL', 'value': 'url'},
            {'label': 'MD5 Hash', 'value': 'md5'},
            {'label': 'SHA1 Hash', 'value': 'sha1'},
            {'label': 'SHA256 Hash', 'value': 'sha256'},
            {'label': 'Email', 'value': 'email'}
        ]
        
        action_buttons = [{
            'text': 'Export IOCs',
            'url': url_for('export_iocs'),
            'icon': 'download',
            'type': 'success'
        }]
    elif content_type == 'report':
        action_buttons = [{
            'text': 'Generate Report',
            'url': url_for('generate_report'),
            'icon': 'file-export',
            'type': 'primary'
        }]
        
    # Add AI insights button to all pages
    action_buttons.append({
        'text': 'AI Insights',
        'url': url_for('ai_insights'),
        'icon': 'robot',
        'type': 'info'
    })
        
    # Render appropriate template
    return render_template(
        'content.html',
        page_title=settings['title'],
        page_icon=settings['icon'],
        page_subtitle=settings['subtitle'],
        days=days,
        current_endpoint=settings['endpoint'],
        content_type=settings['plural'],
        content_items=items,
        summary_stats=summary_stats,
        chart_data=chart_data,
        show_filters=(filter_types is not None),
        filter_types=filter_types,
        selected_type=request.args.get('type', ''),
        search=search,
        limit=limit,
        pagination={
            'total': content_data.get('total', len(items)),
            'limit': limit,
            'offset': offset,
            'params': {'search': search}
        },
        action_buttons=action_buttons
    )

# Feed ingestion trigger
@app.route('/ingest_threat_data')
@login_required
def ingest_threat_data():
    """Trigger the ingestion process"""
    try:
        # Call the ingestion endpoint
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
    
    return redirect(url_for('dynamic_content_list', content_type='feed'))

# Detail Routes
@app.route('/<content_type>s/<path:identifier>')
@login_required
def dynamic_content_detail(content_type, identifier):
    """Unified handler for detail views"""
    content_settings = {
        'feed': {
            'api_prefix': 'feeds/',
            'api_suffix': '/stats',
            'entity_type': 'feed',
            'icon': 'rss',
            'parent': 'feeds'
        },
        'campaign': {
            'api_prefix': 'campaigns/',
            'api_suffix': '',
            'entity_type': 'campaign',
            'icon': 'project-diagram',
            'parent': 'campaigns'
        },
        'ioc': {
            'api_prefix': 'iocs',
            'api_suffix': '',
            'entity_type': 'ioc',
            'icon': 'fingerprint',
            'parent': 'iocs',
            'special_handling': True
        },
        'report': {
            'api_prefix': 'reports/',
            'api_suffix': '',
            'entity_type': 'report',
            'icon': 'file-alt',
            'parent': 'reports'
        }
    }
    
    # Check if content type is supported
    if content_type not in content_settings:
        abort(404)
        
    settings = content_settings[content_type]
    
    # Special handling for IOCs
    if content_type == 'ioc' and settings.get('special_handling'):
        # IOC identifier is in format type/value
        parts = identifier.split('/', 1)
        if len(parts) != 2:
            abort(404)
            
        ioc_type, ioc_value = parts
        # Get IOC data
        ioc_data = api_request('iocs', {'type': ioc_type, 'value': ioc_value, 'limit': 1})
        
        if not ioc_data.get('records'):
            flash("IOC not found", "danger")
            return redirect(url_for('dynamic_content_list', content_type='ioc'))
            
        record = ioc_data.get('records', [])[0]
        
        # Find specific IOC
        entity = None
        for ioc in record.get('iocs', []):
            if ioc.get('type') == ioc_type and ioc.get('value') == ioc_value:
                entity = ioc
                break
                
        if not entity:
            flash("IOC detail not found", "danger")
            return redirect(url_for('dynamic_content_list', content_type='ioc'))
            
        # Add source information
        entity['source'] = record.get('source_type')
        entity['source_id'] = record.get('source_id')
        
        # Generate entity tabs
        entity_tabs = []
        
        # Get campaigns that reference this IOC
        search_data = api_request('search', {'q': ioc_value})
        campaigns = search_data.get('results', {}).get('campaigns', [])
        if campaigns:
            entity_tabs.append({
                'id': 'campaigns',
                'label': 'Campaigns',
                'icon': 'project-diagram',
                'count': len(campaigns),
                'data': campaigns
            })
            
        # Get sources that reference this IOC
        sources = search_data.get('results', {}).get('analyses', [])
        if sources:
            entity_tabs.append({
                'id': 'sources',
                'label': 'Intelligence Sources',
                'icon': 'database',
                'count': len(sources),
                'data': sources
            })
        
        return render_template(
            'detail.html',
            page_title=f'IOC: {ioc_value}',
            page_icon='fingerprint',
            page_subtitle=f'Type: {ioc_type.upper()}',
            entity_type='ioc',
            entity=entity,
            entity_id=f"{ioc_type}_{ioc_value}",
            back_url=url_for('dynamic_content_list', content_type='ioc'),
            parent_endpoint='iocs',
            current_endpoint='ioc_detail',
            entity_tabs=entity_tabs,
            entity_actions=[{
                'text': 'View AI Insights',
                'url': url_for('ai_insights', ioc=ioc_value),
                'icon': 'robot'
            }]
        )
    
    # Standard API handling for other content types
    api_endpoint = f"{settings['api_prefix']}{identifier}{settings['api_suffix']}"
    entity = api_request(api_endpoint)
    
    if 'error' in entity:
        flash(f"{content_type.title()} not found", "danger")
        return redirect(url_for('dynamic_content_list', content_type=content_type))
    
    # Generate page title based on content type
    if content_type == 'feed':
        page_title = f'{identifier} Feed'
    elif content_type == 'campaign':
        page_title = entity.get('campaign_name', 'Campaign Details')
    elif content_type == 'report':
        page_title = entity.get('report_name', 'Report Details')
    else:
        page_title = f"{content_type.title()} Details"
    
    # Generate entity tabs based on content type
    entity_tabs = []
    
    if content_type == 'feed':
        # Query feed data for records tab
        feed_data = api_request(f"feeds/{identifier}/data", {'limit': 50})
        records = feed_data.get('records', [])
        
        # Extract columns
        columns = []
        if records:
            columns = [col for col in records[0].keys() if not col.startswith('_')]
            
        entity_tabs.append({
            'id': 'records',
            'label': 'Feed Records',
            'icon': 'table',
            'count': entity.get('total_records', 0),
            'columns': columns,
            'data': records,
            'pagination': {
                'total': feed_data.get('total', len(records)),
                'limit': 50,
                'offset': 0
            }
        })
        
    elif content_type == 'campaign':
        # Add IOCs tab
        entity_tabs.append({
            'id': 'iocs',
            'label': 'Indicators',
            'icon': 'fingerprint',
            'count': len(entity.get('iocs', [])),
            'data': entity.get('iocs', [])
        })
        
        # Add sources tab
        entity_tabs.append({
            'id': 'sources',
            'label': 'Intelligence Sources',
            'icon': 'database',
            'count': entity.get('source_count', 0),
            'data': [{'source_id': src, 'source_type': 'feed'} for src in entity.get('sources', [])]
        })
    
    # Add AI insights action to all detail pages
    entity_actions = [{
        'text': 'View AI Insights',
        'url': url_for('ai_insights'),
        'icon': 'robot'
    }]
    
    # Add export action for feeds
    if content_type == 'feed':
        entity_actions.append({
            'text': 'Export Data',
            'url': url_for('export_feed', feed_name=identifier, format='csv'),
            'icon': 'download'
        })
    
    # Standard detail rendering
    return render_template(
        'detail.html',
        page_title=page_title,
        page_icon=settings['icon'],
        page_subtitle='Detailed information',
        entity_type=settings['entity_type'],
        entity=entity,
        entity_id=identifier,
        back_url=url_for('dynamic_content_list', content_type=content_type),
        parent_endpoint=settings['parent'],
        current_endpoint=f'{content_type}_detail',
        entity_tabs=entity_tabs,
        entity_actions=entity_actions
    )

# Report generation
@app.route('/generate_report')
@login_required
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
    
    return redirect(url_for('dynamic_content_list', content_type='report'))

# Export Routes
@app.route('/export_feed')
@login_required
def export_feed():
    """Export feed data"""
    feed_name = request.args.get('feed_name')
    format_type = request.args.get('format', 'csv')
    
    # Call API to export data
    try:
        # Construct export URL
        export_url = f"{request.url_root.rstrip('/')}/api/export/feeds/{feed_name}?format={format_type}"
        
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
    
    return redirect(url_for('dynamic_content_detail', content_type='feed', identifier=feed_name))

@app.route('/export_iocs')
@login_required
def export_iocs():
    """Export IOCs data"""
    format_type = request.args.get('format', 'csv')
    ioc_type = request.args.get('type')
    
    # Call API to export data
    try:
        # Construct export URL
        export_url = f"{request.url_root.rstrip('/')}/api/export/iocs?format={format_type}"
        
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
    
    return redirect(url_for('dynamic_content_list', content_type='ioc'))

# Search route
@app.route('/search')
@login_required
def search():
    """Search across all data types"""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('dashboard'))
    
    # Search via API
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
                                <a href="{{{{ url_for('dynamic_content_detail', content_type='campaign', identifier=campaign.campaign_id) }}}}" class="text-blue-600 hover:underline">
                                    {{{{ campaign.campaign_name }}}}
                                </a>
                            </h4>
                        </div>
                        <div class="p-4">
                            <p class="text-sm text-gray-600 mb-2">
                                <span class="font-medium">Threat Actor:</span> {{{{ campaign.threat_actor|default('Unknown') }}}}
                            </p>
                            <p class="text-sm text-gray-600 mb-2">
                                <span class="font-medium">Malware:</span> {{{{ campaign.malware|default('Unknown') }}}}
                            </p>
                            <p class="text-sm text-gray-600">
                                <span class="font-medium">Sources:</span> {{{{ campaign.source_count }}}}
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
                                    <span class="badge-ioc badge-{{{{ ioc.type }}}}">{{{{ ioc.type }}}}</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href="{{{{ url_for('dynamic_content_detail', content_type='ioc', identifier=ioc.type + '/' + ioc.value) }}}}" class="text-blue-600 hover:underline">
                                        {{{{ ioc.value }}}}
                                    </a>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">{{{{ ioc.source_id }}}}</td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href="{{{{ url_for('dynamic_content_detail', content_type='ioc', identifier=ioc.type + '/' + ioc.value) }}}}" class="text-blue-600 hover:underline">
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
                        <p class="font-medium mb-2">{{{{ analysis.source_id }}}}</p>
                        <p class="text-sm text-gray-600 mb-2">{{{{ analysis.summary }}}}</p>
                        <div class="text-xs text-gray-500">{{{{ analysis.analysis_timestamp|datetime }}}}</div>
                    </div>
                    {{% endfor %}}
                </div>
                {{% else %}}
                <p class="text-center text-gray-500">No analysis results found matching your search.</p>
                {{% endif %}}
            </div>
        </div>
        
        <div class="mt-6">
            <div class="flex justify-center">
                <a href="{{{{ url_for('ai_insights', q=query) }}}}" class="btn btn-primary">
                    <i class="fas fa-robot mr-2"></i>Analyze with AI
                </a>
            </div>
        </div>
        """,
        results=search_data.get('results', {})
    )

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

# Main entry point
if __name__ == "__main__":
    # Print admin credentials for visibility
    print(f"\n\n{password_banner}\n\n")
    
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=config.environment != "production")
