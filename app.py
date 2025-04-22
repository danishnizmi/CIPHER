"""
Threat Intelligence Platform - Application Entry Point
Provides the main application factory and initialization logic.
"""

import os
import logging
import traceback
from datetime import datetime
from typing import Dict, Any
from flask import Flask, Blueprint, redirect, url_for, render_template, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.INFO)
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
    
    # Initialize config first with error handling
    try:
        from config import init_app_config
        config = init_app_config()
        logger.info("Configuration initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing config: {str(e)}")
        logger.error(traceback.format_exc())
        config = {}
    
    # Initialize base app configuration
    project_id = os.environ.get('PROJECT_ID', os.environ.get('GCP_PROJECT', 'primal-chariot-382610'))
    environment = os.environ.get('ENVIRONMENT', 'production')
    
    app.config['PROJECT_ID'] = project_id
    app.config['ENVIRONMENT'] = environment
    
    # Set the secret key
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    if not secret_key:
        # Generate a random key if none is available
        import secrets
        secret_key = secrets.token_hex(24)
        logger.warning("Using randomly generated secret key - sessions will not persist across restarts")
    
    app.config['SECRET_KEY'] = secret_key
    
    # Import components after config is initialized
    has_frontend = False
    has_api = False
    frontend_app = None
    api_app = None
    
    # Create route collection to detect conflicts
    registered_routes = set()
    
    # Check for reserved endpoints (routes we'll add ourselves)
    reserved_endpoints = {'/api/health'}
    
    # A function to safely register a route
    def safe_register_route(route_app, route, endpoint, view_func):
        if route in registered_routes or route in reserved_endpoints:
            logger.warning(f"Route {route} already registered, skipping registration")
            return False
        
        if endpoint in route_app.view_functions:
            logger.warning(f"Endpoint {endpoint} already registered, skipping registration")
            return False
            
        try:
            route_app.add_url_rule(route, endpoint, view_func)
            registered_routes.add(route)
            logger.info(f"Successfully registered route: {route}")
            return True
        except Exception as e:
            logger.error(f"Error registering route {route}: {str(e)}")
            return False
    
    # Try loading the frontend module
    try:
        from frontend import app as frontend_app
        has_frontend = True
        logger.info("Frontend module loaded successfully")
        
        # Track frontend routes 
        for rule in frontend_app.url_map.iter_rules():
            registered_routes.add(rule.rule)
            
    except Exception as e:
        logger.error(f"Error importing frontend module: {str(e)}")
        logger.error(traceback.format_exc())
    
    # Try loading the API module
    try:
        from api import app as api_app
        has_api = True
        logger.info("API module loaded successfully")
        
        # Track API routes
        for rule in api_app.url_map.iter_rules():
            registered_routes.add(rule.rule)
            
    except Exception as e:
        logger.error(f"Error importing API module: {str(e)}")
        logger.error(traceback.format_exc())
    
    # Choose which app to use as the primary one with error handling
    primary_app = app  # Default to our base app
    
    if has_api:
        primary_app = api_app
        logger.info("Using API as primary application")
        
        # Mount frontend as a blueprint if available
        if has_frontend:
            try:
                # Extract blueprints from frontend app to merge
                for blueprint_name in frontend_app.blueprints:
                    blueprint = frontend_app.blueprints[blueprint_name]
                    if not primary_app.blueprints.get(blueprint_name):  # Only register if not already registered
                        primary_app.register_blueprint(blueprint)
                
                # Copy over template folder and static folder settings
                if not primary_app.template_folder and frontend_app.template_folder:
                    primary_app.template_folder = frontend_app.template_folder
                
                if not primary_app.static_folder and frontend_app.static_folder:
                    primary_app.static_folder = frontend_app.static_folder
                    primary_app.static_url_path = frontend_app.static_url_path
                    
                logger.info("Integrated frontend components into API application")
            except Exception as e:
                logger.error(f"Error integrating frontend components: {str(e)}")
                logger.error(traceback.format_exc())
    elif has_frontend:
        primary_app = frontend_app
        logger.info("Using frontend as primary application")
    else:
        logger.warning("Neither API nor Frontend modules loaded, using minimal Flask app")
    
    # Use the selected primary app
    app = primary_app
    
    # Configure for running behind proxies
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Apply common configurations with error handling
    try:
        # Add custom error handlers
        @app.errorhandler(404)
        def page_not_found(e):
            """Custom 404 handler"""
            try:
                return render_template('404.html'), 404
            except:
                return "Page not found", 404

        @app.errorhandler(500)
        def server_error(e):
            """Custom 500 handler"""
            logger.error(f"Server error: {str(e)}")
            try:
                return render_template('500.html'), 500
            except:
                return "Internal server error", 500
        
        # Create a new health check blueprint to avoid endpoint conflicts
        health_bp = Blueprint('health_api', __name__)
        
        @health_bp.route('/api/health')
        def health_check():
            """Health check endpoint - always returns 200 OK"""
            return jsonify({
                "status": "ok",
                "environment": environment,
                "project": project_id,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
            
        # Register the health blueprint
        if '/api/health' not in registered_routes:
            app.register_blueprint(health_bp)
            registered_routes.add('/api/health')
            logger.info("Registered health check endpoint via blueprint")
        else:
            logger.info("Health check endpoint already exists, skipping registration")
        
        # Make sure we have a root endpoint
        if '/' not in registered_routes:
            @app.route('/')
            def index():
                if 'dashboard' in app.view_functions:
                    return redirect(url_for('dashboard'))
                try:
                    return render_template('dashboard.html')
                except:
                    try:
                        return render_template('base.html')
                    except:
                        return "Threat Intelligence Platform"
            logger.info("Registered root endpoint")
        
        # Initialize GCP clients with error handling
        try:
            # BigQuery initialization
            from google.cloud import bigquery
            bq_client = bigquery.Client(project=project_id)
            app.config['BIGQUERY_CLIENT'] = bq_client
            logger.info("BigQuery client initialized")
        except Exception as e:
            logger.error(f"Error initializing BigQuery client: {str(e)}")
        
        try:
            # Storage initialization
            from google.cloud import storage
            storage_client = storage.Client(project=project_id)
            app.config['STORAGE_CLIENT'] = storage_client
            logger.info("Storage client initialized")
        except Exception as e:
            logger.error(f"Error initializing Storage client: {str(e)}")
        
        try:
            # Pub/Sub initialization
            from google.cloud import pubsub_v1
            publisher = pubsub_v1.PublisherClient()
            subscriber = pubsub_v1.SubscriberClient()
            app.config['PUBSUB_PUBLISHER'] = publisher
            app.config['PUBSUB_SUBSCRIBER'] = subscriber
            logger.info("Pub/Sub clients initialized")
        except Exception as e:
            logger.error(f"Error initializing Pub/Sub clients: {str(e)}")
        
        # Initialize Vertex AI if available
        try:
            import vertexai
            vertexai.init(project=project_id, location=os.environ.get('GCP_REGION', 'us-central1'))
            app.config['VERTEXAI_INITIALIZED'] = True
            logger.info("Vertex AI initialized")
        except Exception as e:
            logger.error(f"Error initializing Vertex AI: {str(e)}")
            app.config['VERTEXAI_INITIALIZED'] = False
        
        logger.info(f"Application initialized in {environment} environment")
    except Exception as e:
        logger.error(f"Error during app configuration: {str(e)}")
        logger.error(traceback.format_exc())
    
    return app

# For local development
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
