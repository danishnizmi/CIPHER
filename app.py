"""
Threat Intelligence Platform - Main Application Module
Initializes and configures the application, integrating all components.
Built for production use on Google Cloud Platform with comprehensive monitoring.
"""

import os
import sys
import logging
import traceback
import json
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, g
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT', 'development') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize environment
VERSION = os.environ.get("VERSION", "1.0.0")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
PORT = int(os.environ.get('PORT', 8080))
HOST = os.environ.get('HOST', '0.0.0.0')
DEBUG_MODE = ENVIRONMENT != 'production'
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
REGION = os.environ.get("GCP_REGION", "us-central1")

# Track startup time for health metrics
START_TIME = time.time()

# Create a fallback Flask app for graceful degradation
fallback_app = Flask(__name__)

# Modules that will be initialized
available_modules = {
    'config': False,
    'api': False,
    'frontend': False,
    'ingestion': False
}

# GCP service clients
gcp_clients = {}

# GCP service availability flag
GCP_SERVICES_AVAILABLE = False
try:
    from google.cloud import secretmanager, logging as cloud_logging, error_reporting, monitoring_v3
    import google.auth
    import google.auth.exceptions
    
    GCP_SERVICES_AVAILABLE = True
    logger.info("GCP libraries successfully imported")
    
    try:
        # Get GCP credentials - will verify we have access
        credentials, detected_project_id = google.auth.default()
        if detected_project_id != PROJECT_ID and detected_project_id:
            logger.warning(f"Detected project ID ({detected_project_id}) differs from configured PROJECT_ID ({PROJECT_ID})")
            PROJECT_ID = detected_project_id
        
        logger.info(f"Successfully authenticated with GCP for project: {PROJECT_ID}")
    except google.auth.exceptions.DefaultCredentialsError:
        logger.warning("GCP credentials not available - running without GCP integration")
        GCP_SERVICES_AVAILABLE = False
except ImportError:
    logger.warning("GCP libraries not available - reduced functionality")

# Create a dummy error reporting client to avoid failures
class DummyErrorClient:
    def report_exception(self, *args, **kwargs):
        logger.warning("Error reporting attempted but API not available")

# Set up Cloud Logging if in production
if GCP_SERVICES_AVAILABLE and ENVIRONMENT == 'production':
    try:
        # Configure Cloud Logging
        logging_client = cloud_logging.Client()
        cloud_handler = logging_client.get_default_handler()
        logger.setLevel(logging.INFO)
        cloud_logger = logging_client.logger('app')
        logger.addHandler(cloud_handler)
        
        # Store client for later use
        gcp_clients['logging'] = logging_client
        
        # Initialize Error Reporting with fallback
        try:
            error_client = error_reporting.Client(service="threat-intelligence-platform")
            gcp_clients['error_reporting'] = error_client
            logger.info("Error reporting client initialized")
        except Exception as e:
            logger.warning(f"Error reporting initialization failed: {e}")
            gcp_clients['error_reporting'] = DummyErrorClient()
        
        # Create monitoring client
        try:
            monitoring_client = monitoring_v3.MetricServiceClient()
            gcp_clients['monitoring'] = monitoring_client
            logger.info("Monitoring client initialized")
        except Exception as e:
            logger.warning(f"Monitoring initialization failed: {e}")
        
        logger.info("GCP logging and monitoring initialized")
    except Exception as e:
        logger.error(f"Error setting up GCP logging: {str(e)}")
        # Ensure we have a dummy error client for graceful fallback
        gcp_clients['error_reporting'] = DummyErrorClient()

def report_metric(metric_type, value=1):
    """Report a metric to Cloud Monitoring if available"""
    if not GCP_SERVICES_AVAILABLE or ENVIRONMENT != 'production' or 'monitoring' not in gcp_clients:
        return
    
    try:
        # Create full metric type
        metric_type = f"custom.googleapis.com/threat_intel/{metric_type}"
        
        # Get client
        client = gcp_clients['monitoring']
        
        # Define the metric
        project_name = f"projects/{PROJECT_ID}"
        series = monitoring_v3.TimeSeries()
        series.metric.type = metric_type
        series.metric.labels.update({"environment": ENVIRONMENT, "version": VERSION})
        
        # Create point
        point = series.points.add()
        point.value.double_value = float(value)
        now = time.time()
        point.interval.end_time.seconds = int(now)
        point.interval.end_time.nanos = int((now - int(now)) * 10**9)
        
        # Write metric
        client.create_time_series(name=project_name, time_series=[series])
        logger.debug(f"Reported metric {metric_type}: {value}")
    except Exception as e:
        logger.warning(f"Failed to report metric {metric_type}: {e}")

def safe_report_exception():
    """Safely report exception to Error Reporting if available"""
    if not GCP_SERVICES_AVAILABLE or ENVIRONMENT != 'production':
        return
    
    error_client = gcp_clients.get('error_reporting')
    if not error_client:
        return
    
    try:
        error_client.report_exception()
    except Exception as e:
        logger.warning(f"Failed to report exception: {e}")

# Main application initialization with robust error handling
try:
    logger.info("Beginning application initialization...")
    init_start_time = time.time()
    
    # Step 1: Import and initialize configuration
    logger.info("Importing config module...")
    import config
    logger.info("Initializing application configuration...")
    
    # Initialize secure configuration first
    config.secure_config_init()
    
    # Then load app config 
    config_result = config.init_app_config()
    available_modules['config'] = True
    
    # Print admin password to logs in dev mode for convenience
    if ENVIRONMENT == 'development' or DEBUG_MODE:
        admin_password = config.get_secret("admin-initial-password")
        if admin_password:
            logger.info(f"Admin password available: {admin_password}")
            print(f"\n=== ADMIN PASSWORD: {admin_password} ===\n")
    
    if isinstance(config_result, dict) and config_result.get('error'):
        logger.error(f"Configuration initialization failed: {config_result.get('error')}")
        raise RuntimeError(f"Configuration initialization failed: {config_result.get('error')}")
        
    logger.info(f"Configuration initialized successfully in {time.time() - init_start_time:.2f}s")
    report_metric("init_config_success")
    
    # Step 2: Import frontend module which has the Flask app
    logger.info("Importing frontend module...")
    frontend_start_time = time.time()
    import frontend
    logger.info(f"Frontend module imported successfully in {time.time() - frontend_start_time:.2f}s")
    available_modules['frontend'] = True
    report_metric("init_frontend_success")
    
    # Step 3: Import API module for API endpoints
    logger.info("Importing API module...")
    api_start_time = time.time()
    import api
    logger.info(f"API module imported successfully in {time.time() - api_start_time:.2f}s")
    available_modules['api'] = True
    report_metric("init_api_success")
    
    # Step 4: Import ingestion module for threat data collection
    logger.info("Importing ingestion module...")
    ingestion_start_time = time.time()
    try:
        import ingestion
        logger.info(f"Ingestion module imported successfully in {time.time() - ingestion_start_time:.2f}s")
        available_modules['ingestion'] = True
        report_metric("init_ingestion_success")
    except ImportError as e:
        logger.warning(f"Ingestion module import failed (will run in minimal mode): {e}")
        report_metric("init_ingestion_fail")
    
    # Step 5: Use the frontend's Flask app as our main app
    logger.info("Using frontend.app as the main application")
    app = frontend.app
    
    # Step 6: Initialize API with the app
    logger.info("Initializing API routes...")
    api_init_start_time = time.time()
    api.init_app(app)
    logger.info(f"API routes initialized successfully in {time.time() - api_init_start_time:.2f}s")
    
    # Add proxy fix for proper handling of forwarded headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Share GCP clients with the app context
    @app.before_request
    def setup_gcp_clients():
        g.gcp_clients = gcp_clients
        g.gcp_services_available = GCP_SERVICES_AVAILABLE
    
    # Step 7: Ensure all required routes exist (important routes if not in frontend)
    if not hasattr(app, 'view_functions') or 'login' not in app.view_functions:
        logger.warning("Login route not found in frontend - adding fallback login route")
        
        @app.route('/login', methods=['GET', 'POST'])
        def login_fallback():
            """Fallback login route if missing in frontend"""
            return render_template('auth.html', page_type='login', error=None, now=datetime.now())
    
    # Step 8: Register additional error handlers
    @app.errorhandler(404)
    def handle_not_found(e):
        report_metric("error_404")
        logger.info(f"404 error: {request.path}")
        if request.path.startswith('/api/'):
            return jsonify({
                "error": "Resource not found", 
                "status": 404,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }), 404
        return render_template('404.html', error="Page not found"), 404
    
    @app.errorhandler(500)
    def handle_server_error(e):
        report_metric("error_500")
        logger.error(f"500 error: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Safely report to Error Reporting
        safe_report_exception()
                
        if request.path.startswith('/api/'):
            return jsonify({
                "error": "Internal server error", 
                "status": 500,
                "path": request.path,
                "timestamp": datetime.utcnow().isoformat()
            }), 500
        return render_template('500.html', error="Server error occurred"), 500
    
    # Add enhanced health check handler for kubernetes/cloud run that reports component status
    @app.route('/health')
    @app.route('/health-check')
    @app.route('/_ah/health')  # App Engine health check path
    def health_check():
        """Enhanced health check endpoint for container orchestration"""
        # Calculate uptime
        uptime_seconds = int(time.time() - START_TIME)
        uptime_text = str(timedelta(seconds=uptime_seconds))
        
        # Check BigQuery connectivity if ingestion module is available
        db_status = "unknown"
        if available_modules['ingestion']:
            try:
                from google.cloud import bigquery
                client = bigquery.Client(project=PROJECT_ID)
                # Simple query to check connection
                query_job = client.query("SELECT 1")
                query_job.result()  # Wait for query to complete
                db_status = "ok"
            except Exception as e:
                logger.warning(f"Database connectivity check failed: {e}")
                db_status = "error"
                
        status_data = {
            "status": "ok", 
            "components": available_modules,
            "database": db_status,
            "timestamp": datetime.utcnow().isoformat(),
            "version": VERSION,
            "environment": ENVIRONMENT,
            "uptime": uptime_text,
            "project_id": PROJECT_ID,
            "region": REGION
        }
        
        # If any core module failed, report degraded status
        if not all(available_modules[m] for m in ['config', 'frontend', 'api']):
            status_data['status'] = 'degraded'
            
        # For Kubernetes liveness probes, always return 200 OK
        # For Kubernetes readiness probes, return status code based on component health
        is_readiness = request.args.get('readiness') == 'true'
        if is_readiness and status_data['status'] != 'ok':
            return jsonify(status_data), 503  # Service Unavailable
            
        return jsonify(status_data)
    
    # Add informational app routes
    @app.route('/version')
    def version():
        """Simple version endpoint"""
        return jsonify({
            "version": VERSION,
            "environment": ENVIRONMENT,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    # Add detailed status endpoint for internal use (requires authentication)
    @app.route('/internal/status')
    def internal_status():
        """Detailed status endpoint for internal diagnostics"""
        # Only allow in development or with authentication
        if ENVIRONMENT != 'development' and not hasattr(g, 'user'):
            return jsonify({"error": "Unauthorized"}), 401
            
        import platform
        import psutil
        
        # System information
        sys_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpus": psutil.cpu_count(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used_percent": psutil.virtual_memory().percent
            },
            "process": {
                "cpu_percent": psutil.Process().cpu_percent(),
                "memory_percent": psutil.Process().memory_percent(),
                "threads": len(psutil.Process().threads())
            }
        }
        
        # Module status with import times
        module_status = {
            name: {"available": status} for name, status in available_modules.items()
        }
        
        # Cloud services status
        cloud_status = {
            "gcp_available": GCP_SERVICES_AVAILABLE,
            "project_id": PROJECT_ID,
            "region": REGION,
            "environment": ENVIRONMENT
        }
        
        # Configuration summary (no secrets)
        config_summary = {
            "api_key_set": bool(config.api_key),
            "auth_config_available": bool(config.get_cached_config('auth-config')),
            "feed_config_available": bool(config.get_cached_config('feed-config')),
            "bigquery_dataset": config.bigquery_dataset,
            "gcs_bucket": config.gcs_bucket
        }
        
        return jsonify({
            "status": "ok",
            "version": VERSION,
            "uptime": str(timedelta(seconds=int(time.time() - START_TIME))),
            "timestamp": datetime.utcnow().isoformat(),
            "system": sys_info,
            "modules": module_status,
            "cloud": cloud_status,
            "config": config_summary
        })
    
    # Report successful initialization
    init_time = time.time() - init_start_time
    logger.info(f"Application initialization completed successfully in {init_time:.2f}s!")
    report_metric("init_complete_time", init_time)
    report_metric("init_success", 1)

except Exception as e:
    # Detailed error logging if anything fails
    error_tb = traceback.format_exc()
    logger.error(f"ERROR during application initialization: {str(e)}")
    logger.error(f"Traceback: {error_tb}")
    
    # Report initialization failure
    report_metric("init_failure", 1)
    
    # Report to Error Reporting if available
    safe_report_exception()
    
    # Use fallback app instead
    app = fallback_app
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Initialize error details for display
    init_error = str(e)
    init_traceback = error_tb
    
    # Fallback routes for essential functionality
    @app.route('/api/health', methods=['GET'])
    def api_health_check():
        """Health check that always succeeds but reports errors"""
        logger.info("Health check called (degraded mode)")
        return jsonify({
            "status": "degraded",
            "environment": ENVIRONMENT,
            "version": VERSION,
            "message": "Application running in degraded mode",
            "error": init_error,
            "timestamp": datetime.utcnow().isoformat()
        })

    @app.route('/health', methods=['GET'])
    @app.route('/health-check', methods=['GET'])
    @app.route('/_ah/health', methods=['GET'])  # App Engine health checks
    def root_health_check():
        """Root health check endpoint (for k8s/cloud run probes)"""
        return api_health_check()
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Emergency login page"""
        if request.method == 'POST':
            flash('System is in maintenance mode. Please try again later.', 'warning')
            return redirect('/login')
        return render_template('auth.html', page_type='login', 
                              error="System is in maintenance mode. Please try again later.",
                              now=datetime.now())
        
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
                    <p>Environment: {ENVIRONMENT} | Version: {VERSION}</p>
                    <p>&copy; {datetime.utcnow().year} Threat Intelligence Platform</p>
                </div>
            </div>
        </body>
        </html>
        """

# Entry point for running the application directly (not via gunicorn)
if __name__ == '__main__':
    logger.info(f"Starting Flask app on {HOST}:{PORT} (debug={DEBUG_MODE})...")
    
    try:
        # Trigger initial data ingestion if in development mode
        if DEBUG_MODE and available_modules['ingestion']:
            try:
                logger.info("Triggering initial data ingestion for development mode...")
                ingestor = ingestion.ThreatDataIngestion()
                results = ingestor.process_all_feeds()
                logger.info(f"Initial ingestion completed with {len(results)} feeds processed")
            except Exception as e:
                logger.warning(f"Initial ingestion failed: {e}")
                logger.warning(traceback.format_exc())
        
        # Add psutil dependency if missing
        try:
            import psutil
        except ImportError:
            logger.warning("psutil library not available - some metrics will be limited")
        
        # Start the application
        app.run(host=HOST, port=PORT, debug=DEBUG_MODE)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Report application startup failure
        safe_report_exception()
        
        # Exit with error code
        sys.exit(1)
