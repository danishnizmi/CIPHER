import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import logging
from config import load_configs, get_cached_config, create_or_update_secret, access_secret
import json
from datetime import datetime
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
REGION = os.environ.get("GCP_REGION", "us-central1")

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
    """Check if GCP services are running and properly configured.
    Based on the services used in the threat intelligence platform.
    """
    from config import project_id, region, bigquery_dataset, gcs_bucket
    
    services = {}
    overall_status = "ok"
    
    # BigQuery check - Dataset threat_intelligence
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
            
            # Check if key tables exist
            tables = ["alienvault_pulses", "misp_events", "threatfox_iocs", 
                     "phishtank_urls", "urlhaus_malware", "threat_analysis", 
                     "threat_campaigns"]
            
            existing_tables = []
            missing_tables = []
            
            for table in tables:
                try:
                    table_ref = dataset_ref.table(table)
                    client.get_table(table_ref)
                    existing_tables.append(table)
                except Exception:
                    missing_tables.append(table)
            
            services["bigquery"] = {
                "status": "ok" if not missing_tables else "warning",
                "dataset": bigquery_dataset,
                "tables": {
                    "existing": existing_tables,
                    "missing": missing_tables
                }
            }
            
            if missing_tables:
                overall_status = "degraded"
                
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
            blob_count = len(list(client.list_blobs(gcs_bucket, max_results=5)))
            services["storage"] = {
                "status": "ok", 
                "bucket": gcs_bucket,
                "sample_blob_count": blob_count
            }
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
        # Check if we can access required secrets
        required_secrets = ['api-keys', 'database-credentials', 'feed-config', 'auth-config']
        secret_statuses = {}
        all_secrets_ok = True
        
        for secret_id in required_secrets:
            try:
                secret_value = access_secret(secret_id)
                if secret_value:
                    secret_statuses[secret_id] = "ok"
                else:
                    secret_statuses[secret_id] = "missing"
                    all_secrets_ok = False
            except Exception as secret_error:
                secret_statuses[secret_id] = f"error: {str(secret_error)}"
                all_secrets_ok = False
        
        services["secret_manager"] = {
            "status": "ok" if all_secrets_ok else "warning",
            "secrets": secret_statuses
        }
        
        if not all_secrets_ok:
            overall_status = "degraded"
            
    except Exception as e:
        services["secret_manager"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Pub/Sub check - Based on the logs, we have specific topics to check
    try:
        from google.cloud import pubsub_v1
        publisher = pubsub_v1.PublisherClient()
        
        # Check specific topics from logs
        topics = {
            "threat-data-ingestion": "Main data ingestion topic",
            "threat-analysis-events": "Analysis events topic"
        }
        
        topic_statuses = {}
        all_topics_ok = True
        
        for topic_id, description in topics.items():
            topic_path = publisher.topic_path(project_id, topic_id)
            try:
                topic = publisher.get_topic(request={"topic": topic_path})
                topic_statuses[topic_id] = "ok"
            except Exception as topic_error:
                topic_statuses[topic_id] = f"error: {str(topic_error)}"
                all_topics_ok = False
        
        services["pubsub"] = {
            "status": "ok" if all_topics_ok else "warning",
            "topics": topic_statuses
        }
        
        if not all_topics_ok:
            overall_status = "degraded"
            
    except Exception as e:
        services["pubsub"] = {"status": "error", "message": str(e)}
        overall_status = "degraded"
    
    # Cloud Functions check - From logs, we see two specific functions
    try:
        from google.cloud import functions_v1
        client = functions_v1.CloudFunctionsServiceClient()
        
        # Check specific functions from logs
        functions = {
            "ingest_threat_data": "Data ingestion function",
            "analyze_threat_data": "Threat analysis function"
        }
        
        function_statuses = {}
        all_functions_ok = True
        
        for function_id, description in functions.items():
            function_path = f"projects/{project_id}/locations/{region}/functions/{function_id}"
            try:
                function = client.get_function(name=function_path)
                function_statuses[function_id] = function.status.name
                if function.status.name != "ACTIVE":
                    all_functions_ok = False
            except Exception as function_error:
                function_statuses[function_id] = f"error: {str(function_error)}"
                all_functions_ok = False
        
        services["cloud_functions"] = {
            "status": "ok" if all_functions_ok else "warning",
            "functions": function_statuses
        }
        
        if not all_functions_ok:
            overall_status = "degraded"
            
    except Exception as e:
        services["cloud_functions"] = {"status": "error", "message": str(e)}
        # Not marking as degraded since this might be optional
    
    # Cloud Run check - From logs, we see the service was deployed
    try:
        from google.cloud.run_v2 import ServicesClient
        
        # Specific service from logs
        service_name = "threat-intelligence-platform"
        client = ServicesClient()
        service_path = f"projects/{project_id}/locations/{region}/services/{service_name}"
        
        try:
            service = client.get_service(name=service_path)
            
            # Check if service is ready
            ready = True
            for condition in service.status.conditions:
                if condition.type_ == "Ready" and condition.status is False:
                    ready = False
            
            services["cloud_run"] = {
                "status": "ok" if ready else "initializing",
                "service": service_name,
                "url": service.uri if hasattr(service, 'uri') else None,
                "ready": ready
            }
            
            if not ready:
                overall_status = "initializing"
                
        except Exception as service_error:
            services["cloud_run"] = {
                "status": "warning",
                "message": f"Error checking Cloud Run service: {str(service_error)}",
                "service": service_name
            }
            overall_status = "degraded"
            
    except Exception as e:
        # Fall back to a simpler check (Cloud Run API might not be enabled)
        import requests
        
        try:
            # Try to access the service URL
            # From logs: https://threat-intelligence-platform-4aihb26uiq-uc.a.run.app
            service_url = os.environ.get("SERVICE_URL", f"https://{service_name}-4aihb26uiq-uc.a.run.app")
            
            response = requests.get(f"{service_url}/api/health", timeout=5)
            status_code = response.status_code
            
            services["cloud_run"] = {
                "status": "ok" if status_code == 200 else "warning",
                "service": service_name,
                "url": service_url,
                "http_status": status_code
            }
            
            if status_code != 200:
                overall_status = "degraded"
                
        except Exception as request_error:
            services["cloud_run"] = {
                "status": "error", 
                "message": f"Error checking Cloud Run service URL: {str(request_error)}",
                "service": service_name
            }
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
            # Not marking as degraded since this might be optional
    except Exception as e:
        services["vertexai"] = {"status": "error", "message": str(e)}
        # Not marking as degraded since this might be optional
    
    # Check Cloud Scheduler - From logs, we see a specific job
    try:
        from google.cloud import scheduler_v1
        client = scheduler_v1.CloudSchedulerClient()
        
        # Check specific job from logs
        job_name = "update-threat-feeds"
        parent = f"projects/{project_id}/locations/{region}/jobs/{job_name}"
        
        try:
            job = client.get_job(name=parent)
            services["cloud_scheduler"] = {
                "status": "ok",
                "job": job_name,
                "state": job.state.name if hasattr(job, 'state') else "Unknown"
            }
        except Exception as job_error:
            services["cloud_scheduler"] = {
                "status": "warning",
                "message": f"Error checking scheduler job: {str(job_error)}",
                "job": job_name
            }
            overall_status = "degraded"
            
    except Exception as e:
        services["cloud_scheduler"] = {"status": "error", "message": str(e)}
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
    version = os.environ.get("VERSION", "1.0.0")
    check_level = request.args.get('level', 'basic')
    
    # Basic health info
    health_info = {
        "status": "ok", 
        "environment": ENVIRONMENT,
        "project": PROJECT_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "version": version
    }
    
    # Add detailed GCP service checks if requested
    if check_level in ['detailed', 'complete']:
        try:
            service_status = check_gcp_services()
            health_info["services"] = service_status["services"]
            
            # Update overall status based on service status
            if service_status["status"] != "ok":
                health_info["status"] = service_status["status"]
                
        except Exception as e:
            logger.error(f"Error performing service health check: {str(e)}")
            logger.error(traceback.format_exc())
            health_info["status"] = "error"
            health_info["error"] = str(e)
    
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
