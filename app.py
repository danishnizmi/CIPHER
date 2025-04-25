import os
import sys
import logging
import traceback
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up enhanced logging
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT', 'development') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)

# Create a fallback Flask app for graceful degradation
fallback_app = Flask(__name__)

# Modules that might be available
available_modules = {
    'config': False,
    'api': False,
    'frontend': False,
    'ingestion': False
}

# Main application initialization with robust error handling
try:
    logger.info("Beginning application initialization...")
    
    # Step 1: Import and initialize configuration
    logger.info("Importing config module...")
    import config
    logger.info("Initializing application configuration...")
    config_result = config.init_app_config()
    available_modules['config'] = True
    
    if isinstance(config_result, dict) and config_result.get('error'):
        logger.error(f"Configuration initialization failed: {config_result.get('error')}")
        raise RuntimeError(f"Configuration initialization failed: {config_result.get('error')}")
        
    logger.info(f"Configuration initialized successfully")
    
    # Step 2: Import API module for API endpoints
    logger.info("Importing API module...")
    import api
    logger.info("API module imported successfully")
    available_modules['api'] = True
    
    # Step 3: Import frontend module which has the fully configured Flask app
    logger.info("Importing frontend module...")
    import frontend
    logger.info("Frontend module imported successfully")
    available_modules['frontend'] = True
    
    # Step 4: Import ingestion module for threat data collection
    logger.info("Importing ingestion module...")
    try:
        import ingestion
        logger.info("Ingestion module imported successfully")
        available_modules['ingestion'] = True
    except ImportError as e:
        logger.warning(f"Ingestion module import failed (will run in minimal mode): {e}")
    
    # Step 5: Use the frontend's Flask app as our main app
    logger.info("Using frontend.app as the main application")
    app = frontend.app
    
    # Step 6: Initialize API with the app
    logger.info("Initializing API routes...")
    api.init_app(app)
    logger.info("API routes initialized successfully")
    
    # Add proxy fix for proper handling of forwarded headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Step 7: Register error handlers for consistent error handling
    @app.errorhandler(404)
    def handle_not_found(e):
        logger.info(f"404 error: {request.path}")
        if request.path.startswith('/api/'):
            return jsonify({
                "error": "Resource not found", 
                "status": 404,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }), 404
        return render_template('auth.html', page_type='login', error="Page not found"), 404
    
    @app.errorhandler(500)
    def handle_server_error(e):
        logger.error(f"500 error: {str(e)}")
        logger.error(traceback.format_exc())
        if request.path.startswith('/api/'):
            return jsonify({
                "error": "Internal server error", 
                "status": 500,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }), 500
        return render_template('auth.html', page_type='login', error="Server error occurred"), 500
    
    # Add a simple health check handler
    @app.route('/health-check')
    def health_check():
        return jsonify({
            "status": "ok", 
            "components": available_modules,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    logger.info("Application initialization completed successfully!")

except Exception as e:
    # Detailed error logging if anything fails
    error_tb = traceback.format_exc()
    logger.error(f"ERROR during application initialization: {str(e)}")
    logger.error(f"Traceback: {error_tb}")
    
    # Use fallback app instead
    app = fallback_app
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Initialize error details for display
    init_error = str(e)
    init_traceback = error_tb
    
    # Set up environment information
    environment = os.environ.get("ENVIRONMENT", "development")
    version = os.environ.get("VERSION", "1.0.0")
    
    # Fallback routes
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check that always succeeds but reports errors"""
        logger.info("Health check called (degraded mode)")
        return jsonify({
            "status": "degraded",
            "environment": environment,
            "version": version,
            "message": "Application running in degraded mode",
            "error": init_error,
            "timestamp": datetime.utcnow().isoformat()
        })

    @app.route('/health', methods=['GET'])
    def root_health_check():
        """Root health check endpoint (for k8s/cloud run probes)"""
        return health_check()
    
    @app.route('/', methods=['GET'])
    def index():
        """Basic index page with error information"""
        logger.info("Index page requested (degraded mode)")
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Intelligence Platform - Error</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>
        <body class="bg-gray-100 font-sans">
            <div class="container mx-auto px-4 py-8 max-w-4xl">
                <div class="flex items-center justify-center mb-8">
                    <i class="fas fa-shield-alt text-4xl text-blue-600 mr-3"></i>
                    <h1 class="text-3xl font-bold text-gray-800">Threat Intelligence Platform</h1>
                </div>
                
                <div class="bg-red-50 border border-red-300 rounded-lg p-6 mb-6">
                    <div class="flex items-start">
                        <div class="text-red-500 text-2xl mr-4">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div>
                            <h2 class="text-xl font-semibold text-red-700 mb-2">Initialization Error</h2>
                            <p class="text-red-700 mb-4"><strong>Error:</strong> {init_error}</p>
                            <div class="bg-white rounded p-4 max-h-64 overflow-auto">
                                <pre class="text-sm text-gray-700 whitespace-pre-wrap">{init_traceback}</pre>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="mt-6">
                    <div class="flex justify-center">
                        <button onclick="location.reload()" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
                            <i class="fas fa-redo mr-2"></i>Reload Page
                        </button>
                    </div>
                </div>
                
                <div class="text-center text-gray-500 text-sm mt-8">
                    <p>Environment: {environment} | Version: {version}</p>
                    <p>&copy; {datetime.utcnow().year} Threat Intelligence Platform</p>
                </div>
            </div>
        </body>
        </html>
        """

# Entry point for running the application directly (not via gunicorn)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug_mode = os.environ.get('ENVIRONMENT', 'development') != 'production'
    host = os.environ.get('HOST', '0.0.0.0')
    
    logger.info(f"Starting Flask app on {host}:{port} (debug={debug_mode})...")
    
    try:
        # Trigger initial data ingestion if in development mode
        if debug_mode and available_modules['ingestion']:
            try:
                logger.info("Triggering initial data ingestion for development mode...")
                ingestor = ingestion.ThreatDataIngestion()
                results = ingestor.process_all_feeds()
                logger.info(f"Initial ingestion completed with {len(results)} feeds processed")
            except Exception as e:
                logger.warning(f"Initial ingestion failed: {e}")
                logger.warning(traceback.format_exc())
        
        app.run(host=host, port=port, debug=debug_mode)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)
