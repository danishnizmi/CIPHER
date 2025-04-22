"""
Threat Intelligence Platform - Application Entry Point
Provides the main application factory and initialization logic.
"""

import os
import logging
import traceback
from datetime import datetime
from flask import Flask, Blueprint, redirect, url_for, render_template, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flag to track if Secret Manager is available
SECRET_MANAGER_AVAILABLE = False

def create_app() -> Flask:
    """
    Application factory function to create and configure the Flask application.
    """
    # Create Flask app
    app = Flask(__name__)
    
    # Basic configuration
    project_id = os.environ.get('PROJECT_ID', os.environ.get('GCP_PROJECT', 'primal-chariot-382610'))
    environment = os.environ.get('ENVIRONMENT', 'production')
    
    app.config['PROJECT_ID'] = project_id
    app.config['ENVIRONMENT'] = environment
    
    # Try to load Secret Manager
    global SECRET_MANAGER_AVAILABLE
    try:
        from google.cloud import secretmanager
        SECRET_MANAGER_AVAILABLE = True
        logger.info("Secret Manager library available")
    except ImportError:
        logger.warning("Secret Manager library not available - will use environment variables")
        SECRET_MANAGER_AVAILABLE = False
    
    # Generate a random key for Flask sessions
    import secrets
    secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
    app.config['SECRET_KEY'] = secret_key
    
    # Initialize config if possible
    try:
        if SECRET_MANAGER_AVAILABLE:
            from config import init_app_config
            config = init_app_config()
            logger.info("Configuration initialized successfully with Secret Manager")
        else:
            logger.warning("Using basic configuration without Secret Manager")
    except Exception as e:
        logger.error(f"Error initializing config: {str(e)}")
    
    # Import components
    try:
        from api import app as api_app
        main_app = api_app
        logger.info("Using API as primary application")
        
        try:
            from frontend import app as frontend_app
            
            # Import frontend blueprints
            for blueprint_name in frontend_app.blueprints:
                blueprint = frontend_app.blueprints[blueprint_name]
                if not main_app.blueprints.get(blueprint_name):
                    main_app.register_blueprint(blueprint)
            
            # Copy template and static folders
            if not main_app.template_folder and frontend_app.template_folder:
                main_app.template_folder = frontend_app.template_folder
                
            if not main_app.static_folder and frontend_app.static_folder:
                main_app.static_folder = frontend_app.static_folder
                main_app.static_url_path = frontend_app.static_url_path
                
            logger.info("Frontend components integrated")
        except Exception as e:
            logger.warning(f"Frontend not available: {str(e)}")
            
    except Exception as e:
        logger.warning(f"API not available: {str(e)}")
        main_app = app
        logger.info("Using basic Flask app")
    
    # Use the selected app
    app = main_app
    
    # Configure proxy support
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Register essential routes via blueprint to avoid conflicts
    health_bp = Blueprint('health_api', __name__)
    
    @health_bp.route('/api/health')
    def health_check():
        """Health check endpoint - always returns 200 OK"""
        return jsonify({
            "status": "ok",
            "environment": environment,
            "project": project_id,
            "timestamp": datetime.utcnow().isoformat(),
            "secret_manager_available": SECRET_MANAGER_AVAILABLE
        }), 200
    
    # Check if health endpoint already exists
    health_route_exists = False
    for rule in app.url_map.iter_rules():
        if rule.rule == '/api/health':
            health_route_exists = True
            break
    
    if not health_route_exists:
        app.register_blueprint(health_bp)
        logger.info("Registered health check endpoint")
    
    # Make sure root endpoint exists
    root_exists = False
    for rule in app.url_map.iter_rules():
        if rule.rule == '/':
            root_exists = True
            break
    
    if not root_exists:
        @app.route('/')
        def index():
            if 'dashboard' in app.view_functions:
                return redirect(url_for('dashboard'))
            try:
                return render_template('dashboard.html')
            except Exception:
                return "Threat Intelligence Platform"
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        try:
            return render_template('404.html'), 404
        except:
            return "Page not found", 404

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Server error: {str(e)}")
        try:
            return render_template('500.html'), 500
        except:
            return "Internal server error", 500
    
    # Initialize GCP clients
    try:
        # Initialize core GCP services
        from google.cloud import bigquery, storage, pubsub_v1
        
        app.config['BIGQUERY_CLIENT'] = bigquery.Client(project=project_id)
        app.config['STORAGE_CLIENT'] = storage.Client(project=project_id)
        app.config['PUBSUB_PUBLISHER'] = pubsub_v1.PublisherClient()
        app.config['PUBSUB_SUBSCRIBER'] = pubsub_v1.SubscriberClient()
        
        logger.info("GCP core services initialized")
    except Exception as e:
        logger.warning(f"Error initializing GCP services: {str(e)}")
    
    logger.info(f"Application initialized in {environment} environment")
    return app

# For local development
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
