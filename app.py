"""
Threat Intelligence Platform - Application Entry Point
Provides the main application factory and initialization logic.
"""

import os
import logging
import traceback
from typing import Optional
from datetime import datetime
from flask import Flask, Blueprint, redirect, url_for, render_template
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
        from config import init_app_config, get
        config = init_app_config()
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
        logger.info("Frontend module loaded successfully")
    except Exception as e:
        logger.error(f"Error importing frontend module: {str(e)}")
        logger.error(traceback.format_exc())
    
    try:
        from api import app as api_app
        has_api = True
        logger.info("API module loaded successfully")
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
                for blueprint_name in frontend_app.blueprints:
                    blueprint = frontend_app.blueprints[blueprint_name]
                    if not app.blueprints.get(blueprint_name):  # Only register if not already registered
                        app.register_blueprint(blueprint)
                
                # Copy over template folder and static folder settings
                if not app.template_folder and frontend_app.template_folder:
                    app.template_folder = frontend_app.template_folder
                
                if not app.static_folder and frontend_app.static_folder:
                    app.static_folder = frontend_app.static_folder
                    app.static_url_path = frontend_app.static_url_path
                    
                logger.info("Integrated frontend components into API application")
                
                # Remove duplicate routes (critical fix)
                for endpoint in list(frontend_app.view_functions.keys()):
                    if endpoint in app.view_functions and endpoint != 'static':
                        logger.warning(f"Removing duplicate endpoint '{endpoint}' from frontend")
                        # Skip registering this endpoint from frontend_app
                        frontend_app.view_functions.pop(endpoint, None)
            except Exception as e:
                logger.error(f"Error integrating frontend components: {str(e)}")
                logger.error(traceback.format_exc())
    elif has_frontend:
        app = frontend_app
        logger.info("Using frontend as primary application")
    
    # Apply common configurations with error handling
    try:
        # Set environment variables to app config
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
        
        # Configure for running behind proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        
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
        
        # Check if health_check route already exists
        health_check_exists = False
        for rule in app.url_map.iter_rules():
            if rule.rule == '/api/health':
                health_check_exists = True
                logger.info("Health check route already exists, skipping registration")
                break
        
        # Add health check endpoint only if it doesn't exist
        if not health_check_exists and 'health_check' not in app.view_functions:
            @app.route('/api/health')
            def health_check():
                """Health check endpoint - always returns 200 OK"""
                return {
                    "status": "ok",
                    "environment": environment,
                    "project": project_id,
                    "timestamp": datetime.utcnow().isoformat()
                }, 200
            logger.info("Registered health check endpoint")
        
        # Make sure we have a root endpoint
        root_exists = False
        for rule in app.url_map.iter_rules():
            if rule.rule == '/':
                root_exists = True
                break
        
        if not root_exists and 'index' not in app.view_functions:
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
