import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
from config import load_configs, get_cached_config, create_or_update_secret
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

def create_app():
    """Application factory function for gunicorn."""
    return app

# Load configuration
try:
    configs = load_configs()
    logger.info("Configurations loaded successfully")
    
    # Configure app based on loaded configs
    app.config['AUTH'] = configs.get('auth', {})
    
    # Set secret key for sessions if available
    session_secret = app.config['AUTH'].get('session_secret')
    if session_secret:
        app.secret_key = session_secret
    else:
        app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-in-production")
except Exception as e:
    logger.error(f"Failed to load configurations: {e}")
    app.config['AUTH'] = {}

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok", "environment": ENVIRONMENT})

@app.route('/api/config/<config_type>', methods=['GET'])
def get_config_api(config_type):
    """API endpoint to get configuration."""
    if config_type not in ['api-keys', 'database-credentials', 'feed-config', 'auth-config']:
        return jsonify({"error": "Invalid configuration type"}), 400
    
    config = get_cached_config(config_type, force_refresh=True)
    
    # Mask sensitive values in the response
    if config_type == 'api-keys' or config_type == 'database-credentials':
        masked_config = {k: "********" for k, v in config.items()}
        return jsonify({"config": masked_config})
    
    return jsonify({"config": config})

@app.route('/api/config/<config_type>', methods=['POST'])
def update_config_api(config_type):
    """API endpoint to update configuration."""
    if config_type not in ['api-keys', 'database-credentials', 'feed-config', 'auth-config']:
        return jsonify({"error": "Invalid configuration type"}), 400
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Get existing config
    existing_config = get_cached_config(config_type)
    
    # Update with new values
    if config_type == 'api-keys':
        # For API keys, merge with existing, but allow deleting specific keys
        for key, value in data.items():
            if value:  # Update or add
                existing_config[key] = value
            elif key in existing_config:  # Delete if empty
                del existing_config[key]
    else:
        # For other configs, completely replace
        existing_config = data
    
    # Save updated config
    success = create_or_update_secret(config_type, json.dumps(existing_config))
    if success:
        # Reload configs
        load_configs(force_refresh=True)
        return jsonify({"status": "success", "message": f"{config_type} updated successfully"})
    else:
        return jsonify({"error": "Failed to update configuration"}), 500

@app.route('/', methods=['GET'])
def index():
    """Main application route."""
    return render_template('dashboard.html')

# Register frontend routes
from frontend import app as frontend_app
# Import all routes from frontend
for rule in frontend_app.url_map.iter_rules():
    # Skip the static and health endpoints that might conflict
    endpoint = rule.endpoint
    if endpoint != 'static' and endpoint != 'health_check' and endpoint != 'index':
        view_func = frontend_app.view_functions[endpoint]
        app.add_url_rule(rule.rule, endpoint=endpoint, view_func=view_func, methods=rule.methods)

# Register API routes
from api import app as api_app
# Import API routes with /api prefix
for rule in api_app.url_map.iter_rules():
    # Skip the health endpoint that might conflict
    endpoint = rule.endpoint
    if endpoint != 'health_check':
        view_func = api_app.view_functions[endpoint]
        # Add /api prefix to all routes except those that already have it
        if not rule.rule.startswith('/api'):
            rule_with_prefix = f'/api{rule.rule}'
        else:
            rule_with_prefix = rule.rule
        app.add_url_rule(rule_with_prefix, endpoint=f'api_{endpoint}', view_func=view_func, methods=rule.methods)

# Register ingestion routes
try:
    from ingestion import ingest_threat_data
    
    @app.route('/ingest', methods=['POST'])
    def ingest_route():
        """Wrapper for the ingestion module."""
        return ingest_threat_data(request)
        
except ImportError as e:
    logger.warning(f"Could not import ingestion module: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=ENVIRONMENT != 'production')
