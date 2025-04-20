"""
Configuration module for Threat Intelligence Platform.
Loads environment variables from GCP Secret Manager or environment.
"""

import os
from typing import Dict, Any, Optional
import json
import logging
from google.cloud import secretmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
REGION = os.environ.get("GCP_REGION", "us-central1")
SERVICE_ACCOUNT = os.environ.get("SERVICE_ACCOUNT", "malware-platform-sa@primal-chariot-382610.iam.gserviceaccount.com")

# Default environment type
ENV = os.environ.get("ENVIRONMENT", "development")

# Secret names
SECRET_NAMES = [
    "api-keys",
    "database-credentials",
    "feed-config",
    "auth-config"
]

# Configuration cache
_config_cache = {}


def load_secret(secret_name: str) -> Optional[Dict[str, Any]]:
    """Load a secret from Secret Manager"""
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")
        
        # Try to parse as JSON
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            # Return as string if not valid JSON
            return {"value": payload}
            
    except Exception as e:
        logger.warning(f"Error loading secret {secret_name}: {str(e)}")
        return None


def get_config() -> Dict[str, Any]:
    """Get the complete configuration"""
    global _config_cache
    
    # Return cached config if available
    if _config_cache:
        return _config_cache
    
    # Start with environment variables
    config = {
        "PROJECT_ID": PROJECT_ID,
        "REGION": REGION,
        "ENVIRONMENT": ENV,
        "API_URL": os.environ.get("API_URL", f"https://api-{ENV}.{PROJECT_ID}.cloudfunctions.net"),
        "BIGQUERY_DATASET": os.environ.get("BIGQUERY_DATASET", "threat_intelligence"),
        "GCS_BUCKET": os.environ.get("GCS_BUCKET", f"{PROJECT_ID}-threat-data"),
        "PUBSUB_TOPIC": os.environ.get("PUBSUB_TOPIC", "threat-data-ingestion"),
        "FLASK_SECRET_KEY": os.environ.get("FLASK_SECRET_KEY", "dev-key-change-in-production"),
    }
    
    # Load secrets
    for secret_name in SECRET_NAMES:
        secret_data = load_secret(secret_name)
        if secret_data:
            # Flatten the secrets into the config
            for key, value in secret_data.items():
                config[key] = value
    
    # Cache and return
    _config_cache = config
    return config


def get(key: str, default: Any = None) -> Any:
    """Get a specific configuration value"""
    config = get_config()
    return config.get(key, default)


# Expose key configuration variables
project_id = PROJECT_ID
region = REGION
environment = ENV
bigquery_dataset = get("BIGQUERY_DATASET")
gcs_bucket = get("GCS_BUCKET")
api_url = get("API_URL")
api_key = get("API_KEY")
feed_configs = get("FEED_CONFIG", {})


def init_app_config():
    """Initialize all configuration from GCP Secret Manager and environment variables"""
    config = get_config()
    logger.info(f"Configuration loaded for environment: {config['ENVIRONMENT']}")
    logger.info(f"Using project: {config['PROJECT_ID']}")
    
    # Set missing environment variables from config
    for key, value in config.items():
        if isinstance(value, str) and not os.environ.get(key):
            os.environ[key] = value
    
    return config
