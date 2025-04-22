import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
from config import load_configs, get_cached_config, create_or_update_secret
import json

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

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

# Import routes from other modules
from frontend import frontend_routes
from api import api_routes
from ingestion import ingestion_routes

# Register blueprints
app.register_blueprint(frontend_routes)
app.register_blueprint(api_routes, url_prefix='/api')
app.register_blueprint(ingestion_routes, url_prefix='/ingest')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=ENVIRONMENT != 'production')
