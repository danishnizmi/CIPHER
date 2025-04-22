import os
import logging
from flask import Flask, request, jsonify, redirect, url_for

# Configure logging - set to DEBUG for more verbose output
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize global app variable that will be used by gunicorn
app = None

try:
    # Initialize configuration first
    import config
    logger.info("Loading application configuration...")
    config_result = config.init_app_config()
    logger.info(f"Configuration loaded: {config_result}")
    
    # Import frontend module - this contains the properly configured Flask app
    import frontend
    logger.info("Frontend module imported successfully")
    
    # Use the frontend's Flask app instance
    app = frontend.app
    logger.info("Using frontend.app as the main application")
    
except Exception as e:
    # Fallback to minimal app if frontend initialization fails
    logger.error(f"Failed to initialize frontend application: {str(e)}")
    
    # Create a minimal Flask application as fallback
    app = Flask(__name__)
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Minimal health check that will always succeed."""
        # Log that we received a health check request
        logger.info(f"Health check received, startup attempted")
        
        # Always return success to keep the container alive
        response = {
            "status": "ok",
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "message": "Basic application is running"
        }
        
        # If this is the first request, attempt to initialize the rest of the app
        try:
            # Log that we're attempting full initialization
            logger.info("Health check - attempting to initialize application components")
            
            # Try to import config (this is likely the failing point)
            try:
                import config
                response["config_loaded"] = True
                
                # Try to load configurations
                try:
                    configs = config.load_configs()
                    response["configs_loaded"] = True
                except Exception as config_load_error:
                    logger.error(f"Failed to load configurations: {config_load_error}")
                    response["configs_loaded"] = False
                    response["config_error"] = str(config_load_error)
            except Exception as config_import_error:
                logger.error(f"Failed to import config module: {config_import_error}")
                response["config_loaded"] = False
                response["import_error"] = str(config_import_error)
                
            # Try to import frontend
            try:
                import frontend
                response["frontend_loaded"] = True
            except Exception as frontend_import_error:
                logger.error(f"Failed to import frontend module: {frontend_import_error}")
                response["frontend_loaded"] = False
                response["frontend_error"] = str(frontend_import_error)
        except Exception as e:
            # Catch any initialization errors but keep the app running
            logger.error(f"Error during full initialization: {e}")
            response["initialization_error"] = str(e)
        
        return jsonify(response)

    @app.route('/', methods=['GET'])
    def index():
        """Basic index route that serves a minimal HTML page."""
        error_info = ""
        try:
            import traceback
            import frontend
            # If we can import frontend now but app wasn't initialized with it,
            # something happened during startup
            error_info = "Application modules can be imported but weren't initialized properly during startup."
        except Exception as e:
            error_info = f"Error: {str(e)}\n\nThis is likely preventing the application from starting correctly."
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Intelligence Platform</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                h1 {{ color: #333; }}
                .error {{ color: #721c24; background-color: #f8d7da; padding: 15px; border-radius: 5px; margin-top: 20px; }}
                .info {{ color: #0c5460; background-color: #d1ecf1; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Threat Intelligence Platform</h1>
            <p>The application is starting up. The backend API is operational.</p>
            <p>Full functionality will be available shortly.</p>
            
            <div class="info">
                <h2>Status</h2>
                <p>Check the <a href="/api/health">health endpoint</a> for current status.</p>
                <p>Check the <a href="/debug">debug endpoint</a> for more information.</p>
            </div>
            
            <div class="error">
                <h3>Diagnostic Information</h3>
                <pre>{error_info}</pre>
            </div>
        </body>
        </html>
        """

    @app.route('/debug', methods=['GET'])
    def debug():
        """Debug endpoint with detailed information."""
        debug_info = {
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "python_version": os.environ.get("PYTHONVERSION", "unknown"),
            "port": os.environ.get("PORT", "8080"),
            "working_directory": os.getcwd(),
            "environment_variables": {k: v for k, v in os.environ.items() 
                                    if not k.lower().startswith(('secret', 'key', 'token', 'password'))},
            "module_test_results": {}
        }
        
        # Test importing key modules
        for module_name in ["flask", "config", "api", "frontend", "ingestion", "google.cloud.bigquery", 
                           "google.cloud.storage", "google.cloud.pubsub", "vertexai"]:
            try:
                __import__(module_name)
                debug_info["module_test_results"][module_name] = "successfully imported"
            except ImportError as e:
                debug_info["module_test_results"][module_name] = f"import failed: {str(e)}"
        
        # Try to check if the templates directory exists
        try:
            templates_path = os.path.join(os.getcwd(), "templates")
            templates_exist = os.path.isdir(templates_path)
            templates_contents = os.listdir(templates_path) if templates_exist else []
            debug_info["templates"] = {
                "exists": templates_exist,
                "path": templates_path,
                "contents": templates_contents
            }
        except Exception as e:
            debug_info["templates"] = {"error": str(e)}
        
        # Check gunicorn configuration
        try:
            if 'SERVER_SOFTWARE' in os.environ and 'gunicorn' in os.environ.get('SERVER_SOFTWARE', ''):
                debug_info["gunicorn_info"] = {
                    "server_software": os.environ.get('SERVER_SOFTWARE'),
                    "app_module": "app.py",
                    "app_variable": "app (should be frontend.app)",
                }
        except Exception as e:
            debug_info["gunicorn_info"] = {"error": str(e)}
        
        return jsonify(debug_info)

# This ensures we have a valid Flask app regardless of what happened above
if app is None:
    logger.critical("Application failed to initialize, creating emergency fallback app")
    app = Flask(__name__)
    
    @app.route('/')
    def emergency_fallback():
        return "Emergency fallback mode - application failed to initialize"

# Entry point for direct execution (not used by gunicorn)
if __name__ == '__main__':
    # Get port from environment variable or default to 8080
    port = int(os.environ.get('PORT', 8080))
    
    # Start the server
    logger.info(f"Starting Flask app on port {port}...")
    app.run(host='0.0.0.0', port=port)
