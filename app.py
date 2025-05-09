import os
import sys
import logging
import traceback
from datetime import datetime
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

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

# Global initialization state
_initialization_status = {
    'config': False,
    'clients': False,
    'tables': False,
    'blueprints': False,
    'complete': False
}

# Health check endpoint - must work immediately
@app.route('/health', methods=['GET'])
@csrf.exempt
def health_check():
    """Minimal health check for startup."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'app_ready': _initialization_status['complete']
    }), 200

# Readiness probe
@app.route('/ready', methods=['GET'])
@csrf.exempt
def readiness_check():
    """Readiness probe for Cloud Run."""
    if _initialization_status['complete']:
        return jsonify({
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    else:
        return jsonify({
            'status': 'not_ready',
            'timestamp': datetime.utcnow().isoformat(),
            'initialization_status': _initialization_status
        }), 503

def initialize_platform():
    """Initialize all platform components in correct order."""
    global _initialization_status
    
    try:
        logger.info("Starting platform initialization...")
        
        # 1. Initialize configuration
        from config import Config
        Config.init_app()
        if hasattr(Config, 'SECRET_KEY') and Config.SECRET_KEY:
            app.config['SECRET_KEY'] = Config.SECRET_KEY
            app.config['WTF_CSRF_SECRET_KEY'] = Config.SECRET_KEY
        _initialization_status['config'] = True
        logger.info("Configuration initialized")
        
        # 2. Initialize GCP clients
        from config import initialize_bigquery, initialize_storage, initialize_pubsub
        
        bq_client = initialize_bigquery()
        storage_client = initialize_storage()
        publisher, subscriber = initialize_pubsub()
        
        # Store clients for use by other modules
        from api import set_clients
        set_clients(bq_client, storage_client, publisher, subscriber)
        
        _initialization_status['clients'] = True
        logger.info("GCP clients initialized")
        
        # 3. Ensure BigQuery tables exist (if client is available)
        if bq_client:
            from ingestion import initialize_bigquery_tables
            if initialize_bigquery_tables():
                _initialization_status['tables'] = True
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
        
        _initialization_status['blueprints'] = True
        logger.info("Blueprints registered")
        
        # 5. Mark initialization as complete
        _initialization_status['complete'] = True
        logger.info("Platform initialization complete")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {str(e)}")
        logger.error(traceback.format_exc())
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
    if _initialization_status['complete']:
        return redirect(url_for('frontend.dashboard'))
    else:
        # Show initialization status page
        return render_template('500.html', 
                             error_code=503, 
                             error_message="Service is initializing. Please wait a moment and refresh."), 503

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
        sys.exit(1)
