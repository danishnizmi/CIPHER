import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
from config import load_configs, get_cached_config, create_or_update_secret, access_secret
import json
from datetime import datetime

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

# Load configuration
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
    """Check if GCP services are running and properly configured."""
    from config import project_id, region, bigquery_dataset, gcs_bucket
    
    services = {}
    overall_status = "ok"
    
    # BigQuery check
    try:
        from google.cloud import bigquery
        client = bigquery.Client()
        
        # Run a minimal query to verify connection
        query_job = client.query("SELECT 1")
        results = list(query_job.result())
        
        # Check if our dataset exists
        try:
            dataset_ref = client.dataset(bigquery_dataset)
            dataset = client.get_dataset(dataset_ref)
            services["bigquery"] = {"status": "ok", "dataset": bigquery_dataset}
        except Exception as dataset_error:
            services["bigquery"] = {
                "status": "warning", 
                "message": f"Connected but dataset error: {str(dataset_error)}",
                "dataset": bigquery_dataset
            }
            overall_status = "degraded"
    except Exception as e:
        services["bigquery"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Cloud Storage check
    try:
        from google.cloud import storage
        client = storage.Client()
        
        # Check if our bucket exists
        try:
            bucket = client.get_bucket(gcs_bucket)
            services["storage"] = {"status": "ok", "bucket": gcs_bucket}
        except Exception as bucket_error:
            services["storage"] = {
                "status": "warning", 
                "message": f"Connected but bucket error: {str(bucket_error)}",
                "bucket": gcs_bucket
            }
            overall_status = "degraded"
    except Exception as e:
        services["storage"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Secret Manager check
    try:
        # Check if we can access secrets config
        secret_value = access_secret('api-keys')
        if secret_value:
            services["secret_manager"] = {"status": "ok"}
        else:
            services["secret_manager"] = {"status": "warning", "message": "Could not access api-keys secret"}
            overall_status = "degraded"
    except Exception as e:
        services["secret_manager"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Pub/Sub check
    try:
        from google.cloud import pubsub_v1
        publisher = pubsub_v1.PublisherClient()
        
        # List topics to verify connection
        project_path = f"projects/{project_id}"
        
        # Check specific topics
        pubsub_topic = os.environ.get("PUBSUB_TOPIC", "threat-data-ingestion")
        topic_path = publisher.topic_path(project_id, pubsub_topic)
        
        try:
            topic = publisher.get_topic(request={"topic": topic_path})
            services["pubsub"] = {"status": "ok", "topic": pubsub_topic}
        except Exception as topic_error:
            services["pubsub"] = {
                "status": "warning", 
                "message": f"Topic error: {str(topic_error)}",
                "topic": pubsub_topic
            }
            overall_status = "degraded"
    except Exception as e:
        services["pubsub"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Check Vertex AI (used for threat analysis)
    try:
        import vertexai
        vertexai.init(project=project_id, location=region)
        
        # Try to load a model to verify configuration
        try:
            from vertexai.language_models import TextGenerationModel
            model = TextGenerationModel.from_pretrained("text-bison")
            services["vertexai"] = {"status": "ok", "model": "text-bison"}
        except Exception as model_error:
            services["vertexai"] = {
                "status": "warning", 
                "message": f"Model initialization error: {str(model_error)}"
            }
    except Exception as e:
        services["vertexai"] = {"status": "error", "message": str(e)}
        # Not marking as degraded since this might be optional
    
    # Check Cloud Functions (optional)
    try:
        from google.cloud import functions_v1
        client = functions_v1.CloudFunctionsServiceClient()
        
        # List functions to verify access
        parent = f"projects/{project_id}/locations/{region}"
        functions = list(client.list_functions(request={"parent": parent, "page_size": 1}))
        services["cloud_functions"] = {"status": "ok"}
    except Exception as e:
        services["cloud_functions"] = {"status": "warning", "message": str(e)}
        # Not marking as degraded since this might be optional
    
    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "services": services,
        "project": project_id,
        "region": region,
        "environment": ENVIRONMENT
    }

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint with optional GCP service status."""
    from config import project_id
    
    version = os.environ.get("VERSION", "1.0.0")
    
    # Basic health info
    health_info = {
        "status": "ok", 
        "environment": ENVIRONMENT,
        "project": project_id,
        "timestamp": datetime.utcnow().isoformat(),
        "version": version
    }
    
    # Add detailed GCP service checks if requested
    if request.args.get('check_services', 'false').lower() == 'true':
        service_status = check_gcp_services()
        health_info["service_check"] = service_status
        
        # Update overall status based on service status
        if service_status["status"] != "ok":
            health_info["status"] = service_status["status"]
    
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

# Register frontend routes
from frontend import app as frontend_app
# Import all routes from frontend
for rule in frontend_app.url_map.iter_rules():
    # Skip the static and health endpoints that might conflict
    endpoint = rule.endpoint
    if endpoint != 'static' and endpoint != 'health_check' and endpoint != 'index':
        view_func = frontend_app.view_functions[endpoint]
        app.add_url_rule(rule.rule, endpoint=endpoint, view_func=view_func, methods=rule.methods)

# Register API routes
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

# Register ingestion routes
try:
    from ingestion import ingest_threat_data
    
    @app.route('/ingest', methods=['POST'])
    def ingest_route():
        """Wrapper for the ingestion module."""
        return ingest_threat_data(request)
        
except ImportError as e:
    logger.warning(f"Could not import ingestion module: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=ENVIRONMENT != 'production')
