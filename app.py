import os
import logging
from flask import Flask, request, jsonify

# Configure logging - set to DEBUG for more verbose output
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app with absolute minimum configuration
app = Flask(__name__)

# Set a flag to track initialization attempts
STARTUP_ATTEMPTED = False

@app.route('/api/health', methods=['GET'])
def health_check():
    """Minimal health check that will always succeed."""
    global STARTUP_ATTEMPTED
    
    # Log that we received a health check request
    logger.info(f"Health check received, startup attempted: {STARTUP_ATTEMPTED}")
    
    # Always return success to keep the container alive
    response = {
        "status": "ok",
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "message": "Basic application is running"
    }
    
    # If this is the first request, attempt to initialize the rest of the app
    if not STARTUP_ATTEMPTED:
        STARTUP_ATTEMPTED = True
        try:
            # Log that we're attempting full initialization
            logger.info("First health check - attempting to initialize full application")
            
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
        except Exception as e:
            # Catch any initialization errors but keep the app running
            logger.error(f"Error during full initialization: {e}")
            response["initialization_error"] = str(e)
    
    return jsonify(response)

@app.route('/', methods=['GET'])
def index():
    """Basic index route that serves a minimal HTML page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Intelligence Platform</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #333; }
        </style>
    </head>
    <body>
        <h1>Threat Intelligence Platform</h1>
        <p>The application is starting up. The backend API is operational.</p>
        <p>Full functionality will be available shortly.</p>
        
        <div>
            <h2>Status</h2>
            <p>Check the <a href="/api/health">health endpoint</a> for current status.</p>
            <p>Check the <a href="/debug">debug endpoint</a> for more information.</p>
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
    
    return jsonify(debug_info)

# Entry point for running the application
if __name__ == '__main__':
    # Get port from environment variable or default to 8080
    port = int(os.environ.get('PORT', 8080))
    
    # Start the server
    logger.info(f"Starting minimal Flask app on port {port}...")
    app.run(host='0.0.0.0', port=port)
