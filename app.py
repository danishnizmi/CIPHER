import os
import sys
import logging
import traceback
from datetime import datetime
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Import your modules
import config
from config import Config
from api import api_blueprint
from frontend import frontend_app as frontend_blueprint, format_datetime

# Configure logging
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

# Configure session settings before loading config
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    SERVER_NAME=None,  # Let Cloud Run handle this
    APPLICATION_ROOT=None,
    PERMANENT_SESSION_LIFETIME=43200,  # 12 hours
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max request size
)

# Load environment-specific configuration
app.config.from_object(Config)

# Setup CORS - be specific about origins in production
cors_origins = os.environ.get('CORS_ORIGINS', '*')
if cors_origins == '*':
    CORS(app)
else:
    CORS(app, origins=cors_origins.split(','))

# Setup rate limiting with memory storage (simpler for Cloud Run)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour", "10 per minute"],
    storage_uri="memory://",
    swallow_errors=True  # Don't crash if rate limiting fails
)

# Register blueprints
app.register_blueprint(api_blueprint, url_prefix='/api')
app.register_blueprint(frontend_blueprint)

# Register template filters properly on the main Flask app
app.template_filter('datetime')(format_datetime)

# Before request middleware
@app.before_request
def before_request():
    """Middleware to run before each request."""
    # Force HTTPS in production
    if os.environ.get('ENVIRONMENT') == 'production':
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

# After request middleware for security headers
@app.after_request
def after_request(response):
    """Add security headers to responses."""
    # Security headers
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP header - updated to work with all dependencies
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://*.googleapis.com https://*.gstatic.com https://*.googleusercontent.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com "
        "https://cdn.plot.ly https://*.googletagmanager.com https://*.google-analytics.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com "
        "https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https: blob:; "
        "connect-src 'self' https://*.googleapis.com https://*.google-analytics.com;"
    )
    
    return response

# Health check endpoint for Cloud Run
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for startup and liveness probes."""
    try:
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': os.environ.get('VERSION', '1.0.0'),
            'environment': os.environ.get('ENVIRONMENT', 'development'),
            'python_version': sys.version.split()[0],
            'app_ready': True
        }
        
        # Check optional dependencies
        dependencies = {}
        
        # Check config loading
        try:
            current_config = config.get_config()
            dependencies['config'] = 'loaded'
        except Exception as e:
            logger.warning(f"Config check failed: {str(e)}")
            dependencies['config'] = f'error: {str(e)[:50]}'
        
        # Check database connections (if initialized)
        if hasattr(config, '_clients') and config._clients:
            clients = config._clients
            dependencies['bigquery'] = 'connected' if clients.get('bigquery') else 'not initialized'
            dependencies['storage'] = 'connected' if clients.get('storage') else 'not initialized'
            dependencies['pubsub'] = 'connected' if clients.get('_publisher') else 'not initialized'
        else:
            dependencies['gcp_clients'] = 'not initialized'
        
        health_data['dependencies'] = dependencies
        
        return jsonify(health_data), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# Readiness probe
@app.route('/ready', methods=['GET'])
def readiness_check():
    """Readiness probe for Cloud Run."""
    try:
        ready_data = {
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {}
        }
        
        # Check if all critical components are ready
        try:
            from config import access_secret
            secret = access_secret('auth-config')
            ready_data['components']['secrets'] = 'accessible' if secret else 'not found'
        except Exception as e:
            logger.warning(f"Secret check failed: {str(e)}")
            ready_data['components']['secrets'] = 'not accessible'
        
        # Check if services can be initialized
        try:
            config.initialize_bigquery()
            ready_data['components']['bigquery'] = 'can connect'
        except Exception as e:
            logger.warning(f"BigQuery check failed: {str(e)}")
            ready_data['components']['bigquery'] = 'error'
        
        all_ready = all(status != 'not accessible' for status in ready_data['components'].values())
        
        if all_ready:
            return jsonify(ready_data), 200
        else:
            ready_data['status'] = 'not ready'
            return jsonify(ready_data), 503
            
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# Debug endpoint
@app.route('/debug', methods=['GET'])
def debug():
    """Debug endpoint to check application state."""
    if os.environ.get('ENVIRONMENT') != 'production':
        debug_info = {
            'status': 'running',
            'timestamp': datetime.utcnow().isoformat(),
            'environment': dict(os.environ),
            'config': {
                'auth_enabled': os.environ.get('AUTH_ENABLED'),
                'debug': app.debug,
                'testing': app.testing,
                'session_cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
                'preferred_url_scheme': app.config.get('PREFERRED_URL_SCHEME'),
            },
            'request': {
                'method': request.method,
                'scheme': request.scheme,
                'host': request.host,
                'path': request.path,
                'is_secure': request.is_secure,
                'headers': dict(request.headers),
            },
            'session': dict(session) if session else {}
        }
        return jsonify(debug_info)
    else:
        return jsonify({'error': 'Debug endpoint disabled in production'}), 403

# Error handlers
@app.errorhandler(400)
def bad_request(e):
    """Handle 400 errors."""
    logger.error(f"Bad request: {request.url}")
    if request.path.startswith('/api'):
        return jsonify({'error': 'Bad request', 'message': str(e)}), 400
    return render_template('error.html', error_code=400, error_message='Bad Request'), 400

@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors."""
    logger.error(f"Forbidden access: {request.url}")
    if request.path.startswith('/api'):
        return jsonify({'error': 'Forbidden', 'message': str(e)}), 403
    return render_template('error.html', error_code=403, error_message='Forbidden'), 403

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    logger.warning(f"Page not found: {request.url}")
    if request.path.startswith('/api'):
        return jsonify({'error': 'Not found', 'message': str(e)}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {request.url}")
    logger.error(traceback.format_exc())
    if request.path.startswith('/api'):
        return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())
    
    # Report to Cloud Error Reporting if enabled
    if os.environ.get('ENABLE_ERROR_REPORTING', 'false').lower() == 'true':
        try:
            config.report_error(e)
        except Exception as report_error:
            logger.error(f"Failed to report error: {str(report_error)}")
    
    if request.path.startswith('/api'):
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred',
            'request_id': request.headers.get('X-Request-ID')
        }), 500
    
    return render_template('error.html', error_code=500, error_message='Internal Server Error'), 500

# Initialize the application
def initialize_app():
    """Initialize application components."""
    try:
        logger.info("Initializing application...")
        
        # Initialize configuration with error handling
        try:
            Config.init_app()
            logger.info("Configuration initialized successfully")
        except Exception as e:
            logger.error(f"Config initialization failed but continuing: {str(e)}")
            # Don't fail the app if config init fails, some components can work without it
        
        # Ensure required directories exist
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('static/dist', exist_ok=True)
        os.makedirs('templates', exist_ok=True)
        
        # Initialize error reporting if enabled
        if os.environ.get('ENABLE_ERROR_REPORTING', 'false').lower() == 'true':
            try:
                Config.initialize_error_reporting()
                logger.info("Error reporting initialized")
            except Exception as e:
                logger.warning(f"Error reporting initialization failed: {str(e)}")
        
        # Start background services if in production
        if os.environ.get('ENVIRONMENT') == 'production':
            try:
                # Start background ingestion if enabled
                if os.environ.get('AUTO_INGEST', 'false').lower() == 'true':
                    from ingestion import trigger_ingestion_in_background
                    trigger_ingestion_in_background()
                    logger.info("Background ingestion started")
                
                # Start background analysis if enabled
                if os.environ.get('AUTO_ANALYZE', 'false').lower() == 'true':
                    from analysis import start_background_analysis
                    start_background_analysis()
                    logger.info("Background analysis started")
            except Exception as e:
                logger.warning(f"Background services initialization failed: {str(e)}")
        
        logger.info("Application initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Application initialization failed: {str(e)}")
        logger.error(traceback.format_exc())
        # Don't fail the app - just log the error
        return False

# Initialize when the module is imported (for Gunicorn)
try:
    initialize_app()
except Exception as e:
    logger.error(f"Error during module initialization: {str(e)}")
    logger.error(traceback.format_exc())

# Entry point for local development
if __name__ == '__main__':
    try:
        logger.info("=== Starting Flask Application ===")
        logger.info(f"Environment: {os.environ.get('ENVIRONMENT', 'development')}")
        logger.info(f"Port: {os.environ.get('PORT', 8080)}")
        logger.info(f"Auth Enabled: {os.environ.get('AUTH_ENABLED', 'true')}")
        logger.info(f"Debug Mode: {app.debug}")
        
        # This is used when running locally only
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
        # Re-raise to ensure the container fails if it can't start
        sys.exit(1)
