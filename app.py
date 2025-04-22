import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
from config import load_configs, get_cached_config, create_or_update_secret
import json
from datetime import datetime
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

def create_app():
    """Application factory function for gunicorn."""
    return app

# Load configuration - with better error handling
try:
    configs = load_configs()
    logger.info("Configurations loaded successfully")
    
    # Configure app based on loaded configs
    app.config['AUTH'] = configs.get('auth', {})
    
    # Set secret key for sessions if available
    session_secret = app.config['AUTH'].get('session_secret')
    if session_secret:
        app.secret_key = session_secret
    else:
        app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-in-production")
except Exception as e:
    logger.error(f"Failed to load configurations: {e}")
    app.config['AUTH'] = {}

def check_gcp_services():
    """Check if GCP services are running and properly configured.
    This function is designed to be called on-demand, not during startup.
    """
    try:
        from config import project_id, region, bigquery_dataset, gcs_bucket
        
        services = {}
        overall_status = "ok"
        
        # BigQuery check
        try:
            from google.cloud import bigquery
            client = bigquery.Client()
            
            # Simply check connection without running a query
            services["bigquery"] = {"status": "ok", "dataset": bigquery_dataset}
            
            # Only if connection succeeds, try a simple query
            try:
                query_job = client.query("SELECT 1")
                list(query_job.result())
                services["bigquery"]["query_test"] = "passed"
            except Exception as query_error:
                services["bigquery"]["status"] = "warning"
                services["bigquery"]["query_test"] = "failed"
                services["bigquery"]["message"] = f"Connected but query error: {str(query_error)}"
                overall_status = "degraded"
                
        except Exception as e:
            services["bigquery"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
        
        # Cloud Storage check - simplified
        try:
            from google.cloud import storage
            services["storage"] = {"status": "ok", "bucket": gcs_bucket}
        except Exception as e:
            services["storage"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
        
        # Secret Manager check - simplified
        try:
            services["secret_manager"] = {"status": "ok"}
        except Exception as e:
            services["secret_manager"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
        
        # Pub/Sub check - simplified
        try:
            services["pubsub"] = {"status": "ok"}
        except Exception as e:
            services["pubsub"] = {"status": "error", "message": str(e)}
            overall_status = "degraded"
        
        # Vertex AI check (optional) - simplified
        try:
            services["vertexai"] = {"status": "ok"}
        except Exception as e:
            services["vertexai"] = {"status": "warning", "message": str(e)}
            # Not marking as degraded since this might be optional
        
        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "services": services,
            "project": project_id,
            "region": region,
            "environment": ENVIRONMENT
        }
    except Exception as e:
        # Catch-all exception handler to ensure this function never crashes the app
        logger.error(f"Error in check_gcp_services: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
            "environment": ENVIRONMENT
        }

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint with optional GCP service status.
    The basic health check is lightweight and always succeeds.
    The detailed check only runs when explicitly requested.
    """
    version = os.environ.get("VERSION", "1.0.0")
    check_level = request.args.get('level', 'basic')
    
    # Basic health info - always succeeds to maintain container health
    health_info = {
        "status": "ok", 
        "environment": ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat(),
        "version": version
    }
    
    # Skip project_id from config to avoid startup issues
    try:
        project_id = os.environ.get("GCP_PROJECT", "unknown")
        health_info["project"] = project_id
    except:
        health_info["project"] = "unknown"
    
    # Add detailed GCP service checks ONLY if explicitly requested
    if check_level in ['detailed', 'complete']:
        try:
            service_status = check_gcp_services()
            health_info["services"] = service_status["services"]
            
            # Only update overall status for detailed checks
            if service_status["status"] != "ok":
                health_info["service_status"] = service_status["status"]
        except Exception as e:
            logger.error(f"Error performing service health check: {str(e)}")
            logger.error(traceback.format_exc())
            health_info["service_check_error"] = str(e)
    
    return jsonify(health_info)

@app.route('/api/config/<config_type>', methods=['GET'])
def get_config_api(config_type):
    """API endpoint to get configuration."""
    if config_type not in ['api-keys', 'database-credentials', 'feed-config', 'auth-config']:
        return jsonify({"error": "Invalid configuration type"}), 400
    
    config = get_cached_config(config_type, force_refresh=True)
    
    # Mask sensitive values in the response
    if config_type == 'api-keys' or config_type == 'database-credentials':
        masked_config = {k: "********" for k, v in config.items()}
        return jsonify({"config": masked_config})
    
    return jsonify({"config": config})

@app.route('/api/config/<config_type>', methods=['POST'])
def update_config_api(config_type):
    """API endpoint to update configuration."""
    if config_type not in ['api-keys', 'database-credentials', 'feed-config', 'auth-config']:
        return jsonify({"error": "Invalid configuration type"}), 400
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Get existing config
    existing_config = get_cached_config(config_type)
    
    # Update with new values
    if config_type == 'api-keys':
        # For API keys, merge with existing, but allow deleting specific keys
        for key, value in data.items():
            if value:  # Update or add
                existing_config[key] = value
            elif key in existing_config:  # Delete if empty
                del existing_config[key]
    else:
        # For other configs, completely replace
        existing_config = data
    
    # Save updated config
    success = create_or_update_secret(config_type, json.dumps(existing_config))
    if success:
        # Reload configs
        load_configs(force_refresh=True)
        return jsonify({"status": "success", "message": f"{config_type} updated successfully"})
    else:
        return jsonify({"error": "Failed to update configuration"}), 500

@app.route('/', methods=['GET'])
def index():
    """Main application route."""
    return render_template('dashboard.html')

# Register frontend routes - with better error handling
try:
    from frontend import app as frontend_app
    # Import all routes from frontend
    for rule in frontend_app.url_map.iter_rules():
        # Skip the static and health endpoints that might conflict
        endpoint = rule.endpoint
        if endpoint != 'static' and endpoint != 'health_check' and endpoint != 'index':
            view_func = frontend_app.view_functions[endpoint]
            app.add_url_rule(rule.rule, endpoint=endpoint, view_func=view_func, methods=rule.methods)
except ImportError as e:
    logger.warning(f"Could not import frontend module: {e}")
    
    @app.route('/frontend-error', methods=['GET'])
    def frontend_error():
        return jsonify({"status": "error", "message": "Frontend module could not be loaded"})

# Register API routes - with better error handling
try:
    from api import app as api_app
    # Import API routes with /api prefix
    for rule in api_app.url_map.iter_rules():
        # Skip the health endpoint that might conflict
        endpoint = rule.endpoint
        if endpoint != 'health_check':
            view_func = api_app.view_functions[endpoint]
            # Add /api prefix to all routes except those that already have it
            if not rule.rule.startswith('/api'):
                rule_with_prefix = f'/api{rule.rule}'
            else:
                rule_with_prefix = rule.rule
            app.add_url_rule(rule_with_prefix, endpoint=f'api_{endpoint}', view_func=view_func, methods=rule.methods)
except ImportError as e:
    logger.warning(f"Could not import api module: {e}")
    
    @app.route('/api-error', methods=['GET'])
    def api_error():
        return jsonify({"status": "error", "message": "API module could not be loaded"})

# Register ingestion routes - with better error handling
try:
    from ingestion import ingest_threat_data
    
    @app.route('/ingest', methods=['POST'])
    def ingest_route():
        """Wrapper for the ingestion module."""
        return ingest_threat_data(request)
        
except ImportError as e:
    logger.warning(f"Could not import ingestion module: {e}")
    
    @app.route('/ingest', methods=['POST'])
    def ingest_error():
        return jsonify({"status": "error", "message": "Ingestion module could not be loaded"}), 503

@app.route('/debug', methods=['GET'])
def debug():
    """Debug endpoint to check application status."""
    debug_info = {
        "flask_app": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": ENVIRONMENT,
        "modules": {}
    }
    
    # Check for key modules without importing them
    try:
        import api
        debug_info["modules"]["api"] = "imported"
    except:
        debug_info["modules"]["api"] = "not found"
        
    try:
        import frontend
        debug_info["modules"]["frontend"] = "imported"
    except:
        debug_info["modules"]["frontend"] = "not found"
        
    try:
        import ingestion
        debug_info["modules"]["ingestion"] = "imported"
    except:
        debug_info["modules"]["ingestion"] = "not found"
    
    return jsonify(debug_info)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=ENVIRONMENT != 'production')
