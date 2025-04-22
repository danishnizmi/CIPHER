import os
import sys
import logging
import traceback
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure verbose logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create a fallback Flask app for graceful degradation
fallback_app = Flask(__name__)

# Main application initialization with robust error handling
try:
    logger.info("Beginning application initialization...")
    
    # Step 1: Import and initialize configuration
    logger.info("Importing config module...")
    import config
    logger.info("Initializing application configuration...")
    config_result = config.init_app_config()
    logger.info(f"Configuration initialized: {config_result}")
    
    # Step 2: Import frontend module which has the fully configured Flask app
    logger.info("Importing frontend module...")
    import frontend
    logger.info("Frontend module imported successfully")
    
    # Step 3: Use the frontend's Flask app as our main app
    logger.info("Using frontend.app as the main application")
    app = frontend.app
    
    # Add proxy fix for proper handling of forwarded headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
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
    
    # Fallback routes
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check that always succeeds but reports errors"""
        response = {
            "status": "degraded",
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "message": "Application running in degraded mode",
            "error": init_error
        }
        return jsonify(response)

    @app.route('/', methods=['GET'])
    def index():
        """Basic index page with error information"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Intelligence Platform - Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                h1, h2 {{ color: #333; }}
                .error {{ color: #721c24; background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 20px 0; }}
                .error pre {{ white-space: pre-wrap; overflow-x: auto; background: #f8f8f8; padding: 10px; border-radius: 3px; }}
                .info {{ color: #0c5460; background-color: #d1ecf1; padding: 15px; border: 1px solid #bee5eb; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>Threat Intelligence Platform</h1>
            
            <div class="error">
                <h2>Initialization Error</h2>
                <p><strong>Error:</strong> {init_error}</p>
                <pre>{init_traceback}</pre>
            </div>
            
            <div class="info">
                <h2>Troubleshooting</h2>
                <p>The application is running in degraded mode due to initialization errors.</p>
                <p>For more information, check:</p>
                <ul>
                    <li><a href="/api/health">Health endpoint</a></li>
                    <li><a href="/debug">Debug information</a></li>
                </ul>
            </div>
        </body>
        </html>
        """

    @app.route('/debug', methods=['GET'])
    def debug():
        """Debug endpoint with detailed information"""
        sys_path = sys.path
        debug_info = {
            "environment": os.environ.get("ENVIRONMENT", "development"),
            "python_version": sys.version,
            "port": os.environ.get("PORT", "8080"),
            "working_directory": os.getcwd(),
            "python_path": sys_path,
            "environment_variables": {k: v for k, v in os.environ.items() 
                                if not k.lower().startswith(('secret', 'key', 'token', 'password'))},
            "initialization_error": init_error,
            "traceback": init_traceback,
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
        
        # Check templates directory
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

# Entry point for running the application directly (not via gunicorn)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting Flask app on port {port}...")
    app.run(host='0.0.0.0', port=port)
