import os
import sys
import json
import logging
import traceback
import threading
import queue
import time
from datetime import datetime
from typing import Any, Callable
from flask import Flask, jsonify, render_template, redirect, url_for, session, g, current_app, Response, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging FIRST
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Import config to ensure ServiceManager is available
from config import Config, ServiceManager, ServiceStatus

# Event Bus for cross-module communication
class EventBus:
    """Simple event bus for cross-module communication."""
    def __init__(self):
        self._subscribers = {}
        self._lock = threading.Lock()
        self._event_queue = queue.Queue()
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_events)
        self._worker_thread.daemon = True
        self._worker_thread.start()
        
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
            logger.debug(f"Subscribed to event: {event_type}")
    
    def publish(self, event_type: str, data: Any = None):
        """Publish an event."""
        self._event_queue.put((event_type, data))
        logger.debug(f"Published event: {event_type}")
    
    def _process_events(self):
        """Process events in background thread."""
        while self._running:
            try:
                event_type, data = self._event_queue.get(timeout=1)
                with self._lock:
                    if event_type in self._subscribers:
                        for callback in self._subscribers[event_type]:
                            try:
                                callback(data)
                            except Exception as e:
                                logger.error(f"Error in event callback for {event_type}: {e}")
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
    
    def shutdown(self):
        """Shutdown the event bus."""
        self._running = False
        self._worker_thread.join(timeout=5)

# Create Flask app with proper template configuration
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Add proxy middleware to handle Cloud Run reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Basic configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    SERVER_NAME=None,
    APPLICATION_ROOT=None,
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_NAME='_threat_session',
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    SESSION_REFRESH_EACH_REQUEST=False
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Setup CORS
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-API-Key"]
    }
})

# Setup rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
    swallow_errors=True
)

# Create global event bus
event_bus = EventBus()

# Template filter
@app.template_filter('datetime')
def format_datetime(value):
    """Format a datetime string for display."""
    if not value:
        return 'N/A'
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        else:
            dt = value
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(value)

# Add event bus to app context
@app.before_request
def before_request():
    g.event_bus = event_bus
    g.service_manager = Config.get_service_manager()

# Health check endpoint
@app.route('/health', methods=['GET'])
@csrf.exempt
def health_check():
    """Enhanced health check with service status."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    health_data = {
        'status': status['overall'],
        'timestamp': datetime.utcnow().isoformat(),
        'app_version': Config.VERSION,
        'environment': Config.ENVIRONMENT,
        'services': status['services'],
        'errors': status['errors']
    }
    
    # Any status is OK for health check to avoid Cloud Run problems
    return jsonify(health_data), 200

# Readiness probe
@app.route('/ready', methods=['GET'])
@csrf.exempt
def readiness_check():
    """Readiness probe for Cloud Run."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    # Consider the app ready even if some services are degraded or initializing
    return jsonify({
        'status': 'ready',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

def initialize_service(service_name, init_func, *args, timeout=15, is_critical=False):
    """Initialize a service with proper timeout and error handling."""
    logger.info(f"Initializing {service_name} service...")
    service_manager = Config.get_service_manager()
    service_manager.update_status(service_name, ServiceStatus.INITIALIZING)
    
    def init_worker():
        try:
            result = init_func(*args)
            if result:
                service_manager.update_status(service_name, ServiceStatus.READY)
                logger.info(f"{service_name} service initialized successfully")
            else:
                service_manager.update_status(service_name, ServiceStatus.DEGRADED, f"{service_name} initialization returned False")
                logger.warning(f"{service_name} service initialization incomplete")
        except Exception as e:
            error_msg = f"Error initializing {service_name} service: {str(e)}"
            logger.error(error_msg)
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            # Set degraded instead of error for non-critical services
            service_manager.update_status(
                service_name, 
                ServiceStatus.ERROR if is_critical else ServiceStatus.DEGRADED, 
                error_msg
            )
    
    # Start initialization in a separate thread with timeout
    init_thread = threading.Thread(target=init_worker)
    init_thread.daemon = True
    init_thread.start()
    init_thread.join(timeout=timeout)
    
    if init_thread.is_alive():
        logger.warning(f"{service_name} service initialization timed out after {timeout}s")
        service_manager.update_status(
            service_name, 
            ServiceStatus.ERROR if is_critical else ServiceStatus.DEGRADED, 
            f"Initialization timed out after {timeout}s"
        )
        return False
    
    # Check final status
    status = service_manager.get_status()
    service_status = status['services'].get(service_name)
    return service_status == ServiceStatus.READY.value

def initialize_platform():
    """Initialize all platform components with improved error handling."""
    service_manager = Config.get_service_manager()
    
    try:
        logger.info("Starting platform initialization...")
        
        # 1. Initialize configuration
        Config.init_app()
        service_manager.update_status('app', ServiceStatus.INITIALIZING)
        
        # 2. Initialize GCP clients with reduced timeout and criticality
        from config import initialize_bigquery, initialize_storage, initialize_pubsub
        
        # Make all clients non-critical to allow the app to start even if GCP services are unavailable
        initialize_service('bigquery', initialize_bigquery, timeout=10, is_critical=False)
        initialize_service('storage', initialize_storage, timeout=10, is_critical=False)
        initialize_service('pubsub', initialize_pubsub, timeout=10, is_critical=False)
        
        # 3. Register blueprints properly within app context
        with app.app_context():
            # Register API blueprint first
            try:
                logger.info("Registering API blueprint...")
                from api import api_blueprint, configure_rate_limiter
                
                # Clear existing if present
                if 'api' in app.blueprints:
                    logger.info("Removing existing API blueprint")
                    del app.blueprints['api']
                
                app.register_blueprint(api_blueprint, url_prefix='/api')
                csrf.exempt(api_blueprint)
                
                # Configure rate limiter for API
                configure_rate_limiter(app)
                
                # Verify API routes were registered
                api_routes = [rule.rule for rule in app.url_map.iter_rules() if rule.rule.startswith('/api')]
                logger.info(f"API blueprint registered with {len(api_routes)} routes")
                service_manager.update_status('api', ServiceStatus.READY)
            except Exception as e:
                logger.error(f"Failed to register API blueprint: {str(e)}")
                logger.error(traceback.format_exc())
                service_manager.update_status('api', ServiceStatus.ERROR, str(e))
            
            # Register frontend blueprint
            try:
                logger.info("Registering frontend blueprint...")
                from frontend import frontend_app
                
                # Clear existing if present
                if 'frontend' in app.blueprints:
                    logger.info("Removing existing frontend blueprint")
                    del app.blueprints['frontend']
                
                # Register frontend blueprint
                app.register_blueprint(frontend_app)
                
                # Verify frontend routes were registered
                frontend_routes = [rule.rule for rule in app.url_map.iter_rules() if not rule.rule.startswith('/api')]
                logger.info(f"Frontend blueprint registered with {len(frontend_routes)} routes")
                service_manager.update_status('frontend', ServiceStatus.READY)
            except Exception as e:
                logger.error(f"Failed to register frontend blueprint: {str(e)}")
                logger.error(traceback.format_exc())
                service_manager.update_status('frontend', ServiceStatus.ERROR, str(e))
        
        # 4. Update service status to ready - app is operational even if some services failed
        service_manager.update_status('app', ServiceStatus.READY)
        logger.info("Platform initialization complete - core services ready")
        
        # 5. Start background processes (non-blocking, delayed to avoid impact on startup)
        def start_delayed_processes():
            logger.info("Starting delayed background processes...")
            time.sleep(15)  # Wait for app to stabilize
            
            # Start AI model initialization if enabled
            try:
                if Config.NLP_ENABLED:
                    from analysis import initialize_ai_models_background
                    logger.info("Starting AI model initialization in background")
                    initialize_ai_models_background()
            except Exception as e:
                logger.warning(f"Failed to initialize AI models: {e}")
            
            # Start ingestion if enabled
            try:
                if Config.AUTO_ANALYZE:
                    from ingestion import ingest_all_feeds
                    logger.info("Starting initial data ingestion in background")
                    threading.Thread(target=ingest_all_feeds, daemon=True).start()
            except Exception as e:
                logger.warning(f"Failed to start ingestion: {e}")
            
            logger.info("Background processes started")
            
        # Start delayed processes in background
        threading.Thread(target=start_delayed_processes, daemon=True).start()
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {str(e)}")
        logger.error(traceback.format_exc())
        service_manager.update_status('app', ServiceStatus.ERROR, str(e))
        return False

# Error handlers with robust fallbacks
@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors."""
    logger.error(f"400 error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Bad request', 'message': str(e)}), 400
    
    error_message = str(e)
    if 'CSRF' in error_message:
        error_message = "CSRF validation failed. Please refresh the page and try again."
    
    return jsonify({
        'error': 'Bad Request',
        'message': error_message,
        'code': 400
    }), 400

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.warning(f"Page not found: {request.url}")
    
    # Always return JSON for API endpoints
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found', 'message': 'Endpoint not found'}), 404
    
    # For frontend routes, check if they exist
    try:
        # Try to render template if frontend is ready
        if 'frontend.dashboard' in app.view_functions:
            return render_template('404.html', 
                                error_code=404, 
                                error_message="Page Not Found",
                                error_description="The page you're looking for doesn't exist or has been moved.",
                                error_icon="search-location"), 404
        else:
            # Return JSON if frontend is not ready
            return jsonify({
                'error': 'Service initializing',
                'message': 'The service is still starting up. Please try again in a moment.',
                'code': 404
            }), 404
    except Exception as template_error:
        logger.error(f"Error rendering 404 template: {template_error}")
        return jsonify({
            'error': 'Not found',
            'message': 'Page not found and template rendering failed',
            'code': 404
        }), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {request.url}")
    logger.error(traceback.format_exc())
    
    # Always return JSON for API endpoints
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500
    
    # For frontend, check if template rendering is possible
    try:
        if 'frontend.dashboard' in app.view_functions:
            return render_template('500.html',
                                error_code=500,
                                error_message="Internal Server Error",
                                error_description="An unexpected error occurred. Please try again later.",
                                error_icon="exclamation-triangle"), 500
        else:
            return jsonify({
                'error': 'Service error',
                'message': 'An error occurred. The service may be initializing.',
                'code': 500
            }), 500
    except Exception as template_error:
        logger.error(f"Error rendering 500 template: {template_error}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred and template rendering failed',
            'code': 500
        }), 500

# Root route handler - critical for application entry point
@app.route('/')
def index():
    """Root route handler with guaranteed frontend registration attempt."""
    logger.info("Index route accessed")
    
    try:
        service_manager = Config.get_service_manager()
        
        # Handle case where frontend blueprint is not yet registered
        if 'frontend.dashboard' not in app.view_functions:
            logger.warning("Frontend routes missing, attempting recovery")
            
            # IMPORTANT: Force register the frontend blueprint
            try:
                with app.app_context():
                    from frontend import frontend_app
                    if 'frontend' in app.blueprints:
                        del app.blueprints['frontend']
                    app.register_blueprint(frontend_app)
                    logger.info("Frontend blueprint registered on demand")
                    service_manager.update_status('frontend', ServiceStatus.READY)
            except Exception as e:
                logger.error(f"Error registering frontend on demand: {e}")
                # Fall through to the next check
        
        # Now try redirecting if frontend is available
        if 'frontend.dashboard' in app.view_functions:
            return redirect(url_for('frontend.dashboard'))
        else:
            # Return initialization message as a last resort
            return jsonify({
                'status': 'initializing',
                'message': 'Service is initializing. Please refresh the page in a few seconds.',
                'timestamp': datetime.utcnow().isoformat()
            }), 200  # Return 200 instead of 503 to avoid Cloud Run termination
                
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Service error',
            'message': 'An error occurred while accessing the service',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# API info endpoint
@app.route('/api')
@csrf.exempt
def api_info():
    """API information endpoint."""
    return jsonify({
        'name': 'Threat Intelligence Platform API',
        'version': Config.VERSION,
        'status': 'active',
        'endpoints': {
            '/api/health': 'Service health check',
            '/api/stats': 'Platform statistics',
            '/api/feeds': 'Threat feed information',
            '/api/iocs': 'Indicators of compromise',
            '/api/ai/analyses': 'AI analysis results'
        }
    })

# Status endpoint
@app.route('/status')
@csrf.exempt
def status_check():
    """Detailed status check."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    # Add route information for debugging
    route_info = {
        'total_routes': len(list(app.url_map.iter_rules())),
        'blueprints': list(app.blueprints.keys()),
        'has_frontend': 'frontend.dashboard' in app.view_functions,
        'has_api': 'api.get_stats' in app.view_functions
    }
    
    return jsonify({
        'status': status['overall'],
        'timestamp': datetime.utcnow().isoformat(),
        'version': Config.VERSION,
        'environment': Config.ENVIRONMENT,
        'services': status['services'],
        'errors': status['errors'],
        'routes': route_info,
        'config': {
            'gcp_project': Config.GCP_PROJECT,
            'bigquery_dataset': Config.BIGQUERY_DATASET,
            'gcs_bucket': Config.GCS_BUCKET,
            'feeds_configured': len(getattr(Config, 'FEEDS', []))
        }
    })

# Manual services initialization endpoint
@app.route('/init/<service_name>', methods=['POST'])
@csrf.exempt
def manual_init_service(service_name):
    """Manual trigger to initialize a specific service."""
    service_manager = Config.get_service_manager()
    
    # Only allow in development environment or with admin key
    if Config.ENVIRONMENT != 'production':
        try:
            if service_name == 'all':
                # Reinitialize everything
                initialize_platform()
                return jsonify({"status": "success", "message": "Platform reinitialization triggered"}), 200
                
            elif service_name == 'frontend':
                # Reinitialize frontend
                try:
                    with app.app_context():
                        from frontend import frontend_app
                        if 'frontend' in app.blueprints:
                            del app.blueprints['frontend']
                        app.register_blueprint(frontend_app)
                        service_manager.update_status('frontend', ServiceStatus.READY)
                    return jsonify({"status": "success", "message": "Frontend reinitialized"}), 200
                except Exception as e:
                    return jsonify({"status": "error", "message": f"Frontend error: {str(e)}"}), 500
                
            elif service_name == 'ai':
                # Initialize AI models
                from analysis import initialize_ai_models_background
                initialize_ai_models_background()
                return jsonify({"status": "success", "message": "AI model initialization triggered"}), 200
                
            elif service_name == 'pubsub':
                # Re-initialize PubSub
                from config import initialize_pubsub
                initialize_service('pubsub', initialize_pubsub, timeout=20, is_critical=False)
                return jsonify({"status": "success", "message": "PubSub initialization triggered"}), 200
                
            elif service_name == 'ingestion':
                # Trigger ingestion
                from ingestion import ingest_all_feeds
                
                def run_ingestion():
                    try:
                        service_manager.update_status('ingestion', ServiceStatus.INITIALIZING)
                        ingest_all_feeds()
                        service_manager.update_status('ingestion', ServiceStatus.READY)
                    except Exception as e:
                        service_manager.update_status('ingestion', ServiceStatus.ERROR, str(e))
                
                threading.Thread(target=run_ingestion, daemon=True).start()
                return jsonify({"status": "success", "message": "Ingestion triggered"}), 200
                
            else:
                return jsonify({"status": "error", "message": f"Unknown service: {service_name}"}), 400
                
        except Exception as e:
            logger.error(f"Error in manual service initialization: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        return jsonify({"status": "error", "message": "Not available in production"}), 403

# Shutdown handler
@app.teardown_appcontext
def shutdown_services(error=None):
    """Cleanup services on app shutdown."""
    if error:
        logger.error(f"App teardown with error: {error}")

# Entry point for Gunicorn
if __name__ != '__main__':
    logger.info("Initializing platform for Gunicorn")
    success = initialize_platform()
    if not success:
        logger.error("Platform initialization failed - application may not work correctly")
    else:
        logger.info("Platform initialized successfully")

# Entry point for local development
if __name__ == '__main__':
    try:
        logger.info("=== Starting Flask Application in Development Mode ===")
        success = initialize_platform()
        
        if not success:
            logger.error("Platform initialization failed, starting in degraded mode")
        
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"Starting server on port {port}")
        app.run(
            host='0.0.0.0', 
            port=port, 
            debug=False,
            use_reloader=False,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        # Shutdown event bus
        if event_bus:
            event_bus.shutdown()
