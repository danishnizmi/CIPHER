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

# Basic configuration - fixed for Cloud Run
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    SESSION_COOKIE_SECURE=False,  # Disabled for Cloud Run
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    SERVER_NAME=None,
    APPLICATION_ROOT=None,
    PERMANENT_SESSION_LIFETIME=43200,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR='/tmp/flask_session',
    SESSION_COOKIE_PATH='/',
    SESSION_PROTECTION='strong'
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Setup CORS
CORS(app)

# Setup rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
    swallow_errors=True
)

# Health check endpoint - must work immediately
@app.route('/health', methods=['GET'])
@csrf.exempt
def health_check():
    """Minimal health check for startup."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'app_ready': True
    }), 200

# Readiness probe
@app.route('/ready', methods=['GET'])
@csrf.exempt
def readiness_check():
    """Readiness probe for Cloud Run."""
    return jsonify({
        'status': 'ready',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

# Delayed registration of blueprints
def register_late_components():
    """Register components that require configuration after app startup."""
    try:
        # Import modules
        import config
        from config import Config
        from api import api_blueprint
        from frontend import frontend_app as frontend_blueprint, format_datetime
        
        # Load configuration
        Config.init_app()
        
        # Register blueprints
        app.register_blueprint(api_blueprint, url_prefix='/api')
        app.register_blueprint(frontend_blueprint)
        
        # Register template filters
        app.template_filter('datetime')(format_datetime)
        
        logger.info("Late components registered successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to register late components: {str(e)}")
        logger.error(traceback.format_exc())
        return False

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.warning(f"Page not found: {request.url}")
    return jsonify({'error': 'Not found', 'message': str(e)}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {request.url}")
    logger.error(traceback.format_exc())
    return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500

@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF errors."""
    logger.error(f"400 error: {str(e)}")
    if 'CSRF' in str(e):
        return redirect(url_for('frontend.login'))
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400

# Entry point for Gunicorn
if __name__ != '__main__':
    # Register late components
    success = register_late_components()
    if not success:
        logger.warning("Some components failed to register, but app will continue")

# Entry point for local development
if __name__ == '__main__':
    try:
        logger.info("=== Starting Flask Application in Development Mode ===")
        register_late_components()
        
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
