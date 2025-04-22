"""
Threat Intelligence Platform - Application Entry Point
Provides the main application factory and initialization logic.
"""

import os
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Set, Optional
from flask import Flask, Blueprint, redirect, url_for, render_template, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging with proper format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """
    Application factory function to create and configure the Flask application.
    This is the entry point for gunicorn and handles both API and frontend components.
    
    Returns:
        Flask: Configured Flask application
    """
    # Create a minimal Flask app first to ensure we have something to return
    app = Flask(__name__)
    
    # Track registered routes to avoid duplicates
    registered_routes: Set[str] = set()
    
    # Initialize config first with error handling
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
    
    # Import components after config is initialized
    has_frontend = False
    has_api = False
    frontend_app = None
    api_app = None
    
    try:
        from frontend import app as frontend_app
        has_frontend = True
        # Collect frontend routes
        for rule in frontend_app.url_map.iter_rules():
            registered_routes.add(rule.rule)
        logger.info(f"Frontend module loaded successfully with {len(registered_routes)} routes")
    except Exception as e:
        logger.error(f"Error importing frontend module: {str(e)}")
        logger.error(traceback.format_exc())
    
    try:
        from api import app as api_app
        has_api = True
        # Collect API routes
        api_routes = set()
        for rule in api_app.url_map.iter_rules():
            api_routes.add(rule.rule)
            registered_routes.add(rule.rule)
        logger.info(f"API module loaded successfully with {len(api_routes)} routes")
    except Exception as e:
        logger.error(f"Error importing API module: {str(e)}")
        logger.error(traceback.format_exc())
    
    # Choose which app to use as the primary one with error handling
    if has_api:
        app = api_app
        logger.info("Using API as primary application")
        
        # Mount frontend as a blueprint if available
        if has_frontend:
            try:
                # Extract blueprints from frontend app to merge
                blueprint_count = 0
                for blueprint_name in frontend_app.blueprints:
                    blueprint = frontend_app.blueprints[blueprint_name]
                    # Avoid registering duplicate blueprints
                    if not app.blueprints.get(blueprint_name):
                        app.register_blueprint(blueprint)
                        blueprint_count += 1
                
                # Copy over template folder and static folder settings
                if not app.template_folder and frontend_app.template_folder:
                    app.template_folder = frontend_app.template_folder
                
                if not app.static_folder and frontend_app.static_folder:
                    app.static_folder = frontend_app.static_folder
                    app.static_url_path = frontend_app.static_url_path
                    
                logger.info(f"Integrated {blueprint_count} frontend blueprints into API application")
                
                # Remove duplicate routes by checking view functions
                duplicates = []
                for endpoint in frontend_app.view_functions:
                    if endpoint in app.view_functions and endpoint != 'static':
                        duplicates.append(endpoint)
                
                # Log duplicates for debugging
                if duplicates:
                    logger.warning(f"Found {len(duplicates)} duplicate endpoints: {', '.join(duplicates)}")
            except Exception as e:
                logger.error(f"Error integrating frontend components: {str(e)}")
                logger.error(traceback.format_exc())
    elif has_frontend:
        app = frontend_app
        logger.info("Using frontend as primary application")
    else:
        logger.warning("No API or frontend modules loaded. Using base Flask app.")
    
    # Apply common configurations with error handling
    try:
        # Set environment variables to app config
        project_id = os.environ.get('PROJECT_ID', os.environ.get('GCP_PROJECT', 'primal-chariot-382610'))
        environment = os.environ.get('ENVIRONMENT', 'production')
        region = os.environ.get('GCP_REGION', 'us-central1')
        
        app.config.update({
            'PROJECT_ID': project_id,
            'ENVIRONMENT': environment,
            'GCP_REGION': region
        })
        
        # Set the secret key (critical for session security)
        if config_initialized:
            secret_key = get("FLASK_SECRET_KEY")
        else:
            secret_key = os.environ.get('FLASK_SECRET_KEY')
            
        if not secret_key:
            # Generate a random key if none is available
            import secrets
            secret_key = secrets.token_hex(32)
            logger.warning("Using randomly generated secret key - sessions will not persist across restarts")
        
        app.config['SECRET_KEY'] = secret_key
        
        # Configure for running behind proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        
        # Add custom error handlers
        @app.errorhandler(404)
        def page_not_found(e):
            """Custom 404 handler"""
            try:
                return render_template('404.html'), 404
            except Exception:
                return "Page not found", 404

        @app.errorhandler(500)
        def server_error(e):
            """Custom 500 handler"""
            logger.error(f"Server error: {str(e)}")
            try:
                return render_template('500.html'), 500
            except Exception:
                return "Internal server error", 500
        
        # Create health check endpoint
        # Check if health endpoint is already registered
        health_endpoint_exists = False
        for rule in app.url_map.iter_rules():
            if rule.rule == '/api/health':
                health_endpoint_exists = True
                logger.info("Health check endpoint already exists")
                break
        
        if not health_endpoint_exists:
            # Remove any existing health_check endpoint first to avoid conflicts
            if 'health_check' in app.view_functions:
                view_func = app.view_functions.pop('health_check')
                for rule in list(app.url_map.iter_rules()):
                    if rule.endpoint == 'health_check':
                        app.url_map._rules.remove(rule)
                        if 'health_check' in app.url_map._rules_by_endpoint:
                            app.url_map._rules_by_endpoint.pop('health_check')
                logger.info("Removed conflicting health_check endpoint")
                
            # Create a separate Blueprint for health check
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
                
            # Register the blueprint
            app.register_blueprint(health_bp)
            logger.info("Registered health check endpoint via blueprint")
        
        # Make sure we have a root endpoint
        root_endpoint_exists = False
        for rule in app.url_map.iter_rules():
            if rule.rule == '/':
                root_endpoint_exists = True
                logger.info("Root endpoint already exists")
                break
        
        if not root_endpoint_exists:
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
        
        # Initialize GCP clients with proper error handling
        # Start with Secret Manager since it's critical
        try:
            # Secret Manager initialization with proper client library
            from google.cloud import secretmanager
            secretmanager_client = secretmanager.SecretManagerServiceClient()
            app.config['SECRETMANAGER_CLIENT'] = secretmanager_client
            logger.info("Secret Manager client initialized successfully (version 2.23.3)")
        except Exception as e:
            logger.error(f"Error initializing Secret Manager client: {str(e)}")
            logger.error(traceback.format_exc())
        
        # Initialize other GCP services
        gcp_services = {
            'bigquery': 'BigQuery',
            'storage': 'Storage',
            'pubsub_v1': 'Pub/Sub'
        }
        
        for module_name, service_name in gcp_services.items():
            try:
                module = __import__(f'google.cloud.{module_name}', fromlist=['*'])
                
                if module_name == 'bigquery':
                    client = module.Client(project=project_id)
                    app.config['BIGQUERY_CLIENT'] = client
                elif module_name == 'storage':
                    client = module.Client(project=project_id)
                    app.config['STORAGE_CLIENT'] = client
                elif module_name == 'pubsub_v1':
                    publisher = module.PublisherClient()
                    subscriber = module.SubscriberClient()
                    app.config['PUBSUB_PUBLISHER'] = publisher
                    app.config['PUBSUB_SUBSCRIBER'] = subscriber
                
                logger.info(f"{service_name} client initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing {service_name} client: {str(e)}")
                logger.error(traceback.format_exc())
        
        # Initialize Vertex AI if available
        try:
            import vertexai
            vertexai.init(project=project_id, location=region)
            app.config['VERTEXAI_INITIALIZED'] = True
            logger.info("Vertex AI initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing Vertex AI: {str(e)}")
            app.config['VERTEXAI_INITIALIZED'] = False
        
        # Log all registered routes for debugging
        route_count = len(list(app.url_map.iter_rules()))
        logger.info(f"Application initialized with {route_count} total routes in {environment} environment")
        
    except Exception as e:
        logger.error(f"Critical error during app configuration: {str(e)}")
        logger.error(traceback.format_exc())
    
    return app

# For local development
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
