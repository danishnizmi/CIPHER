import os
import sys
import logging
import traceback
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, Response
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up enhanced logging with more detailed format
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT', 'development') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
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
    
    if isinstance(config_result, dict) and config_result.get('error'):
        logger.error(f"Configuration initialization failed: {config_result.get('error')}")
        raise RuntimeError(f"Configuration initialization failed: {config_result.get('error')}")
        
    logger.info(f"Configuration initialized successfully: {len(config_result.keys()) if isinstance(config_result, dict) else 'OK'}")
    
    # Step 2: Import API module for API endpoints
    logger.info("Importing API module...")
    import api
    logger.info("API module imported successfully")
    
    # Step 3: Import frontend module which has the fully configured Flask app
    logger.info("Importing frontend module...")
    import frontend
    logger.info("Frontend module imported successfully")
    
    # Step 4: Import ingestion module for threat data collection
    logger.info("Importing ingestion module...")
    try:
        import ingestion
        logger.info("Ingestion module imported successfully")
        has_ingestion = True
    except ImportError as e:
        logger.warning(f"Ingestion module import failed (will run in minimal mode): {e}")
        has_ingestion = False
    
    # Step 5: Import analysis module for threat data processing
    logger.info("Importing analysis module...")
    try:
        import analysis
        logger.info("Analysis module imported successfully")
        has_analysis = True
    except ImportError as e:
        logger.warning(f"Analysis module import failed (will run in minimal mode): {e}")
        has_analysis = False
    
    # Step 6: Use the frontend's Flask app as our main app
    logger.info("Using frontend.app as the main application")
    app = frontend.app
    
    # Step 7: Initialize API with the app
    logger.info("Initializing API routes...")
    api.init_app(app)
    logger.info("API routes initialized successfully")
    
    # Add proxy fix for proper handling of forwarded headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Step 8: Add ingestion endpoints - with better error handling
    @app.route('/api/ingest_threat_data', methods=['POST'])
    def api_ingest_threat_data():
        """API endpoint for ingesting threat data"""
        try:
            if has_ingestion:
                # Initialize ingestion engine
                ingestor = ingestion.ThreatDataIngestion()
                
                # Process request
                result = ingestion.ingest_threat_data(request)
                
                # Return response (handle both dict and tuple responses)
                if isinstance(result, tuple):
                    return result
                return jsonify(result)
            else:
                return jsonify({
                    "error": "Ingestion module not available",
                    "status": "degraded",
                    "timestamp": datetime.utcnow().isoformat()
                }), 503
        except Exception as e:
            logger.error(f"Error in ingestion endpoint: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": str(e),
                "status": "error",
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    
    # Step 9: Add analysis endpoints if available
    if has_analysis:
        @app.route('/api/analyze_threat_data', methods=['POST'])
        def api_analyze_threat_data():
            """API endpoint for analyzing threat data"""
            try:
                # Create a request-like object for analyze_threat_data
                event = {"data": request.get_data()}
                context = {}
                
                # Call analysis function
                result = analysis.analyze_threat_data(event, context)
                
                # Return response
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error in analysis endpoint: {str(e)}")
                logger.error(traceback.format_exc())
                return jsonify({
                    "error": str(e),
                    "status": "error",
                    "timestamp": datetime.utcnow().isoformat()
                }), 500
    
    # Step 10: Add data refreshing endpoint for system health
    @app.route('/api/refresh_data', methods=['GET', 'POST'])
    def api_refresh_data():
        """Endpoint to refresh all threat data"""
        try:
            # Run ingestion process for all feeds
            if has_ingestion:
                ingestor = ingestion.ThreatDataIngestion()
                results = ingestor.process_all_feeds()
                
                # Generate response with stats
                success_count = len([r for r in results if r.get('status') == 'success'])
                total_records = sum(r.get('record_count', 0) for r in results)
                
                return jsonify({
                    "status": "success",
                    "feeds_processed": len(results),
                    "feeds_succeeded": success_count,
                    "total_records": total_records,
                    "details": results,
                    "timestamp": datetime.utcnow().isoformat()
                })
            else:
                return jsonify({
                    "status": "degraded",
                    "message": "Ingestion module not available",
                    "timestamp": datetime.utcnow().isoformat()
                }), 503
        except Exception as e:
            logger.error(f"Error refreshing data: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": str(e),
                "status": "error",
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    
    # Step 11: Add system status endpoint
    @app.route('/api/system_status', methods=['GET'])
    def api_system_status():
        """API endpoint to check overall system status"""
        try:
            # Check various components
            components = {
                "config": True,
                "frontend": True,
                "api": True,
                "ingestion": has_ingestion,
                "analysis": has_analysis
            }
            
            # Check database connectivity
            try:
                # Get BigQuery status using ingestion module's feed statistics
                if has_ingestion:
                    ingestor = ingestion.ThreatDataIngestion()
                    stats = ingestor.get_feed_statistics()
                    database_ok = True
                    feed_count = len(stats.get("feeds", []))
                    active_feeds = stats.get("active_feeds", 0)
                    total_records = stats.get("total_records", 0)
                else:
                    database_ok = False
                    feed_count = 0
                    active_feeds = 0
                    total_records = 0
            except Exception as db_e:
                logger.error(f"Database connectivity issue: {str(db_e)}")
                database_ok = False
                feed_count = 0
                active_feeds = 0
                total_records = 0
                components["database"] = False
            else:
                components["database"] = True
            
            # Overall status
            all_ok = all(components.values())
            status = "healthy" if all_ok else "degraded"
            
            return jsonify({
                "status": status,
                "environment": config.environment,
                "version": os.environ.get("VERSION", "1.0.0"),
                "components": components,
                "database": {
                    "connected": database_ok,
                    "feed_count": feed_count,
                    "active_feeds": active_feeds,
                    "total_records": total_records
                },
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Error checking system status: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    
    # Step 12: Verify critical routes exist
    if not hasattr(app, 'url_map') or not app.url_map:
        logger.error("Application URL map is empty, no routes defined!")
        raise RuntimeError("Application failed to initialize routes properly")
        
    route_count = len(list(app.url_map.iter_rules()))
    logger.info(f"Application initialized with {route_count} routes")
    
    # Step 13: Register global error handlers for consistent error handling
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
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def handle_server_error(e):
        logger.error(f"500 error: {str(e)}")
        if request.path.startswith('/api/'):
            return jsonify({
                "error": "Internal server error", 
                "status": 500,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }), 500
        return render_template('500.html'), 500
    
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
    
    @app.route('/api/ingest_threat_data', methods=['POST'])
    def fallback_ingest():
        """Fallback ingestion endpoint that reports error"""
        logger.info("Ingest endpoint called (degraded mode)")
        return jsonify({
            "status": "error",
            "message": "Application running in degraded mode, ingestion unavailable",
            "error": init_error,
            "timestamp": datetime.utcnow().isoformat()
        }), 503

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
                
                <div class="bg-blue-50 border border-blue-300 rounded-lg p-6 mb-6">
                    <div class="flex items-start">
                        <div class="text-blue-500 text-2xl mr-4">
                            <i class="fas fa-info-circle"></i>
                        </div>
                        <div>
                            <h2 class="text-xl font-semibold text-blue-700 mb-2">Troubleshooting</h2>
                            <p class="text-blue-700 mb-4">The application is running in degraded mode due to initialization errors.</p>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <a href="/api/health" class="bg-white p-4 rounded border border-gray-200 hover:border-blue-300 hover:shadow transition">
                                    <i class="fas fa-heartbeat text-blue-500 mr-2"></i>
                                    Health endpoint
                                </a>
                                <a href="/debug" class="bg-white p-4 rounded border border-gray-200 hover:border-blue-300 hover:shadow transition">
                                    <i class="fas fa-bug text-blue-500 mr-2"></i>
                                    Debug information
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="bg-green-50 border border-green-300 rounded-lg p-6 mb-6">
                    <div class="flex items-start">
                        <div class="text-green-500 text-2xl mr-4">
                            <i class="fas fa-sync-alt"></i>
                        </div>
                        <div>
                            <h2 class="text-xl font-semibold text-green-700 mb-2">Recovery Actions</h2>
                            <p class="text-green-700 mb-4">You can try the following actions to recover:</p>
                            <div class="grid grid-cols-1 gap-4">
                                <button onclick="location.reload()" class="bg-white p-4 rounded border border-gray-200 hover:border-green-300 hover:shadow transition">
                                    <i class="fas fa-redo text-green-500 mr-2"></i>
                                    Reload Page
                                </button>
                                <button onclick="clearCookiesAndReload()" class="bg-white p-4 rounded border border-gray-200 hover:border-green-300 hover:shadow transition">
                                    <i class="fas fa-cookie-bite text-green-500 mr-2"></i>
                                    Clear Cookies and Reload
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="text-center text-gray-500 text-sm">
                    <p>Environment: {environment} | Version: {version}</p>
                    <p>&copy; {datetime.utcnow().year} Threat Intelligence Platform</p>
                </div>
            </div>
            
            <script>
                function clearCookiesAndReload() {
                    document.cookie.split(";").forEach(function(c) {
                        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
                    });
                    localStorage.clear();
                    sessionStorage.clear();
                    location.reload();
                }
            </script>
        </body>
        </html>
        """

    @app.route('/debug', methods=['GET'])
    def debug():
        """Debug endpoint with detailed information"""
        logger.info("Debug page requested (degraded mode)")
        
        # System information
        sys_path = sys.path
        python_version = sys.version
        
        # Environment information
        env_vars = {k: v for k, v in os.environ.items() 
                    if not k.lower().startswith(('secret', 'key', 'token', 'password', 'credential'))}
        
        # Directory structure checking
        try:
            templates_path = os.path.join(os.getcwd(), "templates")
            templates_exist = os.path.isdir(templates_path)
            templates_contents = os.listdir(templates_path) if templates_exist else []
        except Exception as e:
            templates_exist = False
            templates_contents = [f"Error: {str(e)}"]
            
        try:
            static_path = os.path.join(os.getcwd(), "static")
            static_exist = os.path.isdir(static_path)
            static_contents = {
                "root": os.listdir(static_path) if static_exist else [],
                "dist": os.listdir(os.path.join(static_path, "dist")) 
                       if (static_exist and os.path.isdir(os.path.join(static_path, "dist"))) 
                       else []
            }
        except Exception as e:
            static_exist = False
            static_contents = {"error": str(e)}
            
        # Module testing
        module_results = {}
        for module_name in ["flask", "config", "api", "frontend", "ingestion", "analysis", 
                           "google.cloud.bigquery", "google.cloud.storage", 
                           "google.cloud.pubsub", "vertexai"]:
            try:
                __import__(module_name)
                module_results[module_name] = "successfully imported"
            except ImportError as e:
                module_results[module_name] = f"import failed: {str(e)}"
        
        # Try checking for ingestion module
        try:
            import ingestion
            ingestion_available = True
            ingestion_version = getattr(ingestion, "__version__", "unknown")
        except:
            ingestion_available = False
            ingestion_version = "unavailable"
            
        # Prepare debug information
        debug_info = {
            "environment": environment,
            "version": version,
            "timestamp": datetime.utcnow().isoformat(),
            "python_version": python_version,
            "port": os.environ.get("PORT", "8080"),
            "working_directory": os.getcwd(),
            "python_path": sys_path,
            "environment_variables": env_vars,
            "initialization_error": init_error,
            "traceback": init_traceback,
            "module_test_results": module_results,
            "ingestion": {
                "available": ingestion_available,
                "version": ingestion_version
            },
            "templates": {
                "exists": templates_exist,
                "path": templates_path,
                "contents": templates_contents
            },
            "static": {
                "exists": static_exist,
                "path": static_path,
                "contents": static_contents
            },
            "platform": sys.platform,
            "file_system_encoding": sys.getfilesystemencoding()
        }
        
        return jsonify(debug_info)

# Add graceful shutdown handler
import atexit

def cleanup():
    """Clean up resources on application shutdown"""
    logger.info("Application shutting down, cleaning up resources...")
    try:
        # Close any open database connections or clients
        if 'bq_client' in globals() and bq_client:
            logger.info("Closing BigQuery client")
            bq_client.close()
            
        if 'publisher' in globals() and publisher:
            logger.info("Closing PubSub publisher")
            publisher.close()
            
        # Try to clean up ingestion resources
        try:
            import ingestion
            if hasattr(ingestion, 'cleanup_resources') and callable(ingestion.cleanup_resources):
                ingestion.cleanup_resources()
        except:
            pass
            
        logger.info("Cleanup completed successfully")
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

atexit.register(cleanup)

# Entry point for running the application directly (not via gunicorn)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug_mode = os.environ.get('ENVIRONMENT', 'development') != 'production'
    host = os.environ.get('HOST', '0.0.0.0')
    
    logger.info(f"Starting Flask app on {host}:{port} (debug={debug_mode})...")
    
    # Add SSL if certificates are available (for local development)
    ssl_context = None
    cert_path = os.environ.get('SSL_CERT')
    key_path = os.environ.get('SSL_KEY')
    
    if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)
        logger.info(f"SSL enabled with certificate: {cert_path}")
    
    # Try to trigger initial data ingestion if in development mode
    if debug_mode:
        try:
            logger.info("Triggering initial data ingestion for development mode...")
            import ingestion
            ingestor = ingestion.ThreatDataIngestion()
            results = ingestor.process_all_feeds()
            logger.info(f"Initial ingestion completed with {len(results)} feeds processed")
        except Exception as e:
            logger.warning(f"Initial ingestion failed: {e}")
    
    try:
        app.run(host=host, port=port, debug=debug_mode, ssl_context=ssl_context)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)
