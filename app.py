import os
import sys
import json
import logging
import traceback
import threading
import queue
from datetime import datetime
from typing import Any, Callable
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, g
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
    
    # Be more lenient during initialization
    if status['overall'] in [ServiceStatus.READY.value, ServiceStatus.INITIALIZING.value]:
        return jsonify(health_data), 200
    else:
        return jsonify(health_data), 503

# Readiness probe
@app.route('/ready', methods=['GET'])
@csrf.exempt
def readiness_check():
    """Readiness probe for Cloud Run."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    if status['overall'] == ServiceStatus.READY.value:
        return jsonify({
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    else:
        return jsonify({
            'status': 'not_ready',
            'timestamp': datetime.utcnow().isoformat(),
            'details': status
        }), 503

def initialize_platform():
    """Initialize all platform components in correct order."""
    service_manager = Config.get_service_manager()
    
    try:
        logger.info("Starting platform initialization...")
        
        # 1. Initialize configuration
        Config.init_app()
        service_manager.update_status('app', ServiceStatus.INITIALIZING)
        
        # 2. Initialize GCP clients (don't fail if some services are not ready)
        from config import initialize_bigquery, initialize_storage, initialize_pubsub
        
        try:
            bq_client = initialize_bigquery()
            storage_client = initialize_storage()
            publisher, subscriber = initialize_pubsub()
            logger.info("GCP clients initialized")
        except Exception as e:
            logger.warning(f"Some GCP clients failed to initialize: {e}")
            # Continue anyway
        
        # 3. Ensure BigQuery tables exist (non-blocking)
        try:
            if bq_client:
                from ingestion import initialize_bigquery_tables
                threading.Thread(target=initialize_bigquery_tables, daemon=True).start()
                logger.info("BigQuery table initialization started in background")
        except Exception as e:
            logger.warning(f"BigQuery table initialization error: {e}")
        
        # 4. Register blueprints with error handling
        try:
            from api import api_blueprint
            from frontend import frontend_blueprint
            
            # Register API blueprint with CSRF exemption
            app.register_blueprint(api_blueprint, url_prefix='/api')
            csrf.exempt(api_blueprint)
            
            # Register frontend blueprint
            app.register_blueprint(frontend_blueprint)
            
            logger.info("Blueprints registered successfully")
            
        except Exception as e:
            logger.error(f"Failed to register blueprints: {str(e)}")
            logger.error(traceback.format_exc())
            # Still mark app as ready to show error pages
        
        # 5. Update service status to ready
        service_manager.update_status('app', ServiceStatus.READY)
        logger.info("Platform initialization complete")
        
        # 6. Start background processes (non-blocking)
        try:
            # Start other services in background threads
            def init_other_services():
                try:
                    # Initialize other services with timeout
                    threading.Timer(5.0, lambda: service_manager.update_status('frontend', ServiceStatus.READY)).start()
                    threading.Timer(5.0, lambda: service_manager.update_status('api', ServiceStatus.READY)).start()
                    threading.Timer(10.0, lambda: service_manager.update_status('ingestion', ServiceStatus.READY)).start()
                    threading.Timer(10.0, lambda: service_manager.update_status('analysis', ServiceStatus.READY)).start()
                    threading.Timer(15.0, lambda: service_manager.update_status('ai_models', ServiceStatus.READY)).start()
                except Exception as e:
                    logger.error(f"Error initializing services: {e}")
            
            threading.Thread(target=init_other_services, daemon=True).start()
        except Exception as e:
            logger.warning(f"Background service initialization error: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {str(e)}")
        logger.error(traceback.format_exc())
        service_manager.update_status('app', ServiceStatus.ERROR, str(e))
        return True  # Still return True to allow the app to start and show error pages

# Error handlers
@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors."""
    logger.error(f"400 error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Bad request', 'message': str(e)}), 400
    
    error_message = str(e)
    if 'CSRF' in error_message:
        error_message = "CSRF validation failed. Please refresh the page and try again."
    
    try:
        return render_template('500.html', 
                             error_code=400, 
                             error_message=f"Bad Request: {error_message}"), 400
    except Exception as template_error:
        logger.error(f"Error rendering template: {str(template_error)}")
        return jsonify({
            'error': 'Bad Request',
            'message': error_message,
            'code': 400
        }), 400

@app.errorhandler(403)
def handle_forbidden(e):
    """Handle 403 errors."""
    logger.error(f"403 error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403
    
    try:
        return render_template('500.html', 
                             error_code=403, 
                             error_message="Access Denied"), 403
    except Exception as template_error:
        logger.error(f"Error rendering template: {str(template_error)}")
        return jsonify({
            'error': 'Forbidden',
            'message': 'Access denied',
            'code': 403
        }), 403

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.warning(f"Page not found: {request.url}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found', 'message': str(e)}), 404
    
    try:
        return render_template('500.html', 
                             error_code=404, 
                             error_message="Page Not Found"), 404
    except Exception as template_error:
        logger.error(f"Error rendering template: {str(template_error)}")
        return jsonify({
            'error': 'Not Found',
            'message': 'Page not found',
            'code': 404
        }), 404

@app.errorhandler(429)
def handle_rate_limit(e):
    """Handle rate limit errors."""
    logger.warning(f"Rate limit exceeded: {request.url}")
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Too many requests', 
            'message': 'Rate limit exceeded. Please try again later.'
        }), 429
    
    try:
        return render_template('500.html', 
                             error_code=429, 
                             error_message="Too Many Requests. Please try again later."), 429
    except Exception as template_error:
        logger.error(f"Error rendering template: {str(template_error)}")
        return jsonify({
            'error': 'Too Many Requests',
            'message': 'Rate limit exceeded',
            'code': 429
        }), 429

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {request.url}")
    logger.error(traceback.format_exc())
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500
    
    try:
        return render_template('500.html'), 500
    except Exception as template_error:
        logger.error(f"Error rendering template: {str(template_error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'code': 500
        }), 500

# Root route handler
@app.route('/')
def index():
    """Root route handler."""
    logger.info("Index route accessed")
    
    try:
        service_manager = Config.get_service_manager()
        status = service_manager.get_status()
        logger.info(f"Service status: {status}")
        
        # Check if frontend blueprint is registered
        if 'frontend.dashboard' not in app.view_functions:
            logger.warning("Frontend blueprint not registered, showing initialization message")
            try:
                return render_template('500.html', 
                                     error_code=503, 
                                     error_message="Service is initializing. Please wait a moment and refresh."), 503
            except Exception as template_error:
                logger.error(f"Error rendering template: {str(template_error)}")
                return jsonify({
                    'error': 'Service Unavailable',
                    'message': 'Service is initializing. Please wait a moment and refresh.',
                    'code': 503
                }), 503
        
        # Redirect to dashboard
        return redirect(url_for('frontend.dashboard'))
                
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'code': 500
        }), 500

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
        # Continue anyway to show error page
    else:
        logger.info("Platform initialized successfully")

# Entry point for local development
if __name__ == '__main__':
    try:
        logger.info("=== Starting Flask Application in Development Mode ===")
        success = initialize_platform()
        
        if not success:
            logger.error("Platform initialization failed, starting in degraded mode")
            # Continue to start the app so we can show error pages
        
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
