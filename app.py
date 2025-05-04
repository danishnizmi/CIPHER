import os
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template, request, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import your other modules (adjusted to fix the import error)
import config
from api import api_blueprint
from frontend import frontend_app as frontend_blueprint, format_datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(config.Config)

# Set secret key from environment variable
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Setup CORS
CORS(app)

# Setup rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Register blueprints
app.register_blueprint(api_blueprint, url_prefix='/api')
app.register_blueprint(frontend_blueprint)

# Register template filters properly on the main Flask app
app.template_filter('datetime')(format_datetime)

# Health check endpoint for startup and liveness probes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for startup and liveness probes."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': os.environ.get('VERSION', '1.0.0')
    }), 200

# Health check endpoint for readiness probe
@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Health check endpoint for readiness probe."""
    try:
        # Add any additional dependency checks here if needed
        # For example, database connection check
        
        return jsonify({
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat(),
            'api': 'operational',
            'version': os.environ.get('VERSION', '1.0.0')
        }), 200
    except Exception as e:
        logger.error(f"API Health check failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Service is not ready',
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Cloud Run,
    # a webserver process such as Gunicorn will serve the app.
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
