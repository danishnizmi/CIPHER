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
    
    # Try to initialize config first
    config_initialized = False
    try:
        from config import init_app_config, get
        config = init_app_config()
        config_initialized = True
        logger.info("Configuration initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing config: {str(e)}")
        logger.error(traceback.format_exc())
        config = {}
    
    # Set secret key (critical for session security)
    if config_initialized:
        try:
            secret_key = get("FLASK_SECRET_KEY")
            if secret_key:
                app.config['SECRET_KEY'] = secret_key
                logger.info("Secret key loaded from Secret Manager")
            else:
                raise ValueError("Secret key not found")
        except Exception:
            # Fallback to environment variable or generate one
            secret_key = os.environ.get('FLASK_SECRET_KEY')
            if not secret_key:
                import secrets
                secret_key = secrets.token_hex(32)
                logger.warning("Using randomly generated secret key")
            app.config['SECRET_KEY'] = secret_key
    else:
        # Fallback if config module not available
        app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
    
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
    
    # Register essential routes
    health_bp = Blueprint('health_api', __name__)
    
    @health_bp.route('/api/health')
    def health_check():
        """Health check endpoint - always returns 200 OK"""
        return jsonify({
            "status": "ok",
            "environment": environment,
            "project": project_id,
            "timestamp": datetime.utcnow().isoformat(),
            "version": os.environ.get("VERSION", "1.0.0")
        }), 200
    
    # Add health endpoint only if not already present
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
                try:
                    return render_template('base.html')
                except Exception:
                    return "Threat Intelligence Platform"
        logger.info("Registered root endpoint")
    
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
    
    # Initialize GCP clients if needed
    try:
        # Initialize Secret Manager client (for other modules to access)
        from google.cloud import secretmanager
        secretmanager_client = secretmanager.SecretManagerServiceClient()
        app.config['SECRETMANAGER_CLIENT'] = secretmanager_client
        logger.info("Secret Manager client initialized")
        
        # Initialize other services as needed
        if not app.config.get('BIGQUERY_CLIENT'):
            from google.cloud import bigquery
            app.config['BIGQUERY_CLIENT'] = bigquery.Client(project=project_id)
            logger.info("BigQuery client initialized")
            
        if not app.config.get('STORAGE_CLIENT'):
            from google.cloud import storage
            app.config['STORAGE_CLIENT'] = storage.Client(project=project_id)
            logger.info("Storage client initialized")
            
        if not app.config.get('PUBSUB_PUBLISHER'):
            from google.cloud import pubsub_v1
            app.config['PUBSUB_PUBLISHER'] = pubsub_v1.PublisherClient()
            app.config['PUBSUB_SUBSCRIBER'] = pubsub_v1.SubscriberClient()
            logger.info("Pub/Sub clients initialized")
    except Exception as e:
        logger.warning(f"Error initializing GCP clients: {str(e)}")
        
    logger.info(f"Application initialized in {environment} environment")
    return app

# For local development
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
