"""
Threat Intelligence Platform - Application Entry Point
Provides the main application factory and initialization logic.
"""

import os
import logging
from typing import Optional
from flask import Flask, Blueprint, redirect, url_for
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
    # Initialize config first
    from config import init_app_config, get
    config = init_app_config()
    
    # Import components after config is initialized
    try:
        from frontend import app as frontend_app
        has_frontend = True
    except ImportError:
        logger.warning("Frontend module not found, API-only mode")
        has_frontend = False
    
    try:
        from api import app as api_app
        has_api = True
    except ImportError:
        logger.warning("API module not found, frontend-only mode")
        has_api = False
    
    # Choose which app to use as the primary one
    if has_api:
        app = api_app
        logger.info("Using API as primary application")
        
        # Mount frontend as a blueprint if available
        if has_frontend:
            # Extract blueprints from frontend app to merge
            for blueprint_name in frontend_app.blueprints:
                blueprint = frontend_app.blueprints[blueprint_name]
                app.register_blueprint(blueprint)
            
            # Copy over template folder and static folder settings
            if not app.template_folder and frontend_app.template_folder:
                app.template_folder = frontend_app.template_folder
            
            if not app.static_folder and frontend_app.static_folder:
                app.static_folder = frontend_app.static_folder
                app.static_url_path = frontend_app.static_url_path
                
            logger.info("Integrated frontend components into API application")
    elif has_frontend:
        app = frontend_app
        logger.info("Using frontend as primary application")
    else:
        # Create a minimal Flask app if neither is available
        app = Flask(__name__)
        logger.warning("Neither API nor frontend available, creating minimal app")
        
        @app.route('/')
        def home():
            return "Threat Intelligence Platform - Service Running"
    
    # Apply common configurations
    app.config['PROJECT_ID'] = get('PROJECT_ID')
    app.config['ENVIRONMENT'] = get('ENVIRONMENT')
    
    # Set the secret key
    secret_key = get('FLASK_SECRET_KEY')
    if secret_key:
        app.config['SECRET_KEY'] = secret_key
    else:
        # Generate a random key if none is available
        app.config['SECRET_KEY'] = os.urandom(24).hex()
        logger.warning("Using randomly generated secret key - sessions will not persist across restarts")
    
    # Configure for running behind proxies
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Add custom error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        """Custom 404 handler"""
        if hasattr(app, 'render_template'):
            return app.render_template('404.html'), 404
        return "Page not found", 404

    @app.errorhandler(500)
    def server_error(e):
        """Custom 500 handler"""
        logger.error(f"Server error: {str(e)}")
        if hasattr(app, 'render_template'):
            return app.render_template('500.html'), 500
        return "Internal server error", 500
    
    # Add a health check endpoint
    @app.route('/api/health')
    def health_check():
        """Health check endpoint"""
        return {
            "status": "ok",
            "environment": get('ENVIRONMENT'),
            "project": get('PROJECT_ID')
        }, 200
    
    # Add a redirect from root to dashboard if applicable
    if has_frontend and 'dashboard' in app.view_functions:
        @app.route('/')
        def index():
            return redirect(url_for('dashboard'))
    
    # Log application startup
    logger.info(f"Application initialized in {get('ENVIRONMENT')} environment")
    return app

# For local development
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("DEBUG", "false").lower() == "true")
