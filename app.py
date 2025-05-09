import os
import sys
import logging
import traceback
from datetime import datetime
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from typing import Any

# Configure logging FIRST
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Add proxy middleware to handle Cloud Run reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Basic configuration - optimized for Cloud Run
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    SESSION_COOKIE_SECURE=True,  # Enable for Cloud Run (HTTPS)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    SERVER_NAME=None,
    APPLICATION_ROOT=None,
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max request size
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    WTF_CSRF_TIME_LIMIT=3600,
    # Minimal session configuration
    SESSION_COOKIE_NAME='_threat_session',
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    SESSION_REFRESH_EACH_REQUEST=False
)

# Initialize CSRF protection (keeping it for forms in the frontend)
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

# Event Bus for cross-module communication
class EventBus:
    """Simple event bus for cross-module communication."""
    def __init__(self):
        self._subscribers = {}
    
    def subscribe(self, event_type: str, callback):
        """Subscribe to an event."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def publish(self, event_type: str, data: Any = None):
        """Publish an event."""
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")

# Create global event bus
event_bus = EventBus()

# Health check endpoint - must work immediately
@app.route('/health', methods=['GET'])
@csrf.exempt
def health_check():
    """Enhanced health check with service status."""
    from config import Config, ServiceStatus
    
    try:
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
        
        # Determine HTTP status code based on overall status
        if status['overall'] == ServiceStatus.READY.value:
            return jsonify(health_data), 200
        elif status['overall'] == ServiceStatus.DEGRADED.value:
            return jsonify(health_data), 503
        else:
            return jsonify(health_data), 500
            
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Readiness probe
@app.route('/ready', methods=['GET'])
@csrf.exempt
def readiness_check():
    """Readiness probe for Cloud Run."""
    from config import Config, ServiceStatus
    
    try:
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
                'services': status['services']
            }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# Add event bus to Flask app context
@app.before_request
def before_request():
    g.event_bus = event_bus

def initialize_platform():
    """Initialize all platform components in correct order."""
    from config import Config, ServiceStatus
    
    try:
        logger.info("Starting platform initialization...")
        service_manager = Config.get_service_manager()
        
        # 1. Initialize configuration
        Config.init_app()
        if hasattr(Config, 'SECRET_KEY') and Config.SECRET_KEY:
            app.config['SECRET_KEY'] = Config.SECRET_KEY
            app.config['WTF_CSRF_SECRET_KEY'] = Config.SECRET_KEY
        logger.info("Configuration initialized")
        
        # 2. Initialize GCP clients
        from config import initialize_bigquery, initialize_storage, initialize_pubsub
        
        bq_client = initialize_bigquery()
        storage_client = initialize_storage()
        publisher, subscriber = initialize_pubsub()
        
        logger.info("GCP clients initialized")
        
        # 3. Ensure BigQuery tables exist (if client is available)
        if bq_client:
            from ingestion import initialize_bigquery_tables
            if initialize_bigquery_tables():
                logger.info("BigQuery tables initialized")
            else:
                logger.warning("BigQuery tables initialization reported issues")
        
        # 4. Register blueprints
        from api import api_blueprint
        from frontend import frontend_app as frontend_blueprint, format_datetime
        
        app.register_blueprint(api_blueprint, url_prefix='/api')
        app.register_blueprint(frontend_blueprint)
        
        # Register template filters
        app.template_filter('datetime')(format_datetime)
        
        # Update service status
        service_manager.update_status('api', ServiceStatus.READY)
        service_manager.update_status('frontend', ServiceStatus.READY)
        
        logger.info("Blueprints registered")
        
        # 5. Initialize background tasks if enabled
        if Config.AUTO_ANALYZE:
            from analysis import start_background_analysis
            start_background_analysis(limit=50)
            logger.info("Background analysis started")
        
        logger.info("Platform initialization complete")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Update service status to error
        try:
            service_manager = Config.get_service_manager()
            service_manager.update_status('platform', ServiceStatus.ERROR, str(e))
        except:
            pass
            
        return False

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.warning(f"Page not found: {request.url}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found', 'message': str(e)}), 404
    return render_template('500.html', error_code=404, error_message="Page Not Found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {request.url}")
    logger.error(traceback.format_exc())
    
    # Report error to Google Cloud Error Reporting
    try:
        from config import report_error
        report_error(e)
    except:
        pass
    
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500
    return render_template('500.html'), 500

@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors."""
    logger.error(f"400 error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Bad request', 'message': str(e)}), 400
    
    # For CSRF errors on web interface, show error page instead of redirecting to non-existent login
    error_message = str(e)
    if 'CSRF' in error_message:
        error_message = "CSRF validation failed. Please refresh the page and try again."
    
    return render_template('500.html', 
                         error_code=400, 
                         error_message=f"Bad Request: {error_message}"), 400

@app.errorhandler(403)
def handle_forbidden(e):
    """Handle 403 errors."""
    logger.error(f"403 error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403
    return render_template('500.html', 
                         error_code=403, 
                         error_message="Access Denied"), 403

@app.errorhandler(429)
def handle_rate_limit(e):
    """Handle rate limit errors."""
    logger.warning(f"Rate limit exceeded: {request.url}")
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Too many requests', 
            'message': 'Rate limit exceeded. Please try again later.'
        }), 429
    return render_template('500.html', 
                         error_code=429, 
                         error_message="Too Many Requests. Please try again later."), 429

# Root route handler
@app.route('/')
def index():
    """Root route handler."""
    from config import Config, ServiceStatus
    
    try:
        service_manager = Config.get_service_manager()
        status = service_manager.get_status()
        
        if status['overall'] == ServiceStatus.READY.value:
            return redirect(url_for('frontend.dashboard'))
        else:
            # Show initialization status page
            return render_template('500.html', 
                                 error_code=503, 
                                 error_message="Service is initializing. Please wait a moment and refresh."), 503
    except:
        return redirect(url_for('frontend.dashboard'))

# Entry point for Gunicorn
if __name__ != '__main__':
    # Initialize platform
    success = initialize_platform()
    if not success:
        logger.error("Platform initialization failed")
    else:
        logger.info("Platform initialized successfully")

# Entry point for local development
if __name__ == '__main__':
    try:
        logger.info("=== Starting Flask Application in Development Mode ===")
        success = initialize_platform()
        
        if not success:
            logger.error("Platform initialization failed, exiting")
            sys.exit(1)
        
        port = int(os.environ.get('PORT', 8080))
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
        
        # Report error
        try:
            from config import report_error
            report_error(e)
        except:
            pass
            
        sys.exit(1)
