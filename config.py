"""
Configuration module for Threat Intelligence Platform.
Loads environment variables from GCP Secret Manager or environment.
"""

import os
from typing import Dict, List, Any, Optional
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


def create_or_update_secret(secret_name: str, secret_data: Dict[str, Any]) -> bool:
    """Create or update a secret in Secret Manager"""
    try:
        client = secretmanager.SecretManagerServiceClient()
        parent = f"projects/{PROJECT_ID}/secrets/{secret_name}"
        payload = json.dumps(secret_data).encode("UTF-8")
        
        # Check if secret exists
        try:
            client.get_secret(request={"name": parent})
        except Exception:
            # Create secret if it doesn't exist
            parent_resource = f"projects/{PROJECT_ID}"
            client.create_secret(
                request={
                    "parent": parent_resource,
                    "secret_id": secret_name,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
            logger.info(f"Created new secret: {secret_name}")
        
        # Add new version
        client.add_secret_version(
            request={"parent": parent, "payload": {"data": payload}}
        )
        logger.info(f"Updated secret: {secret_name}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to update secret {secret_name}: {str(e)}")
        return False


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
    
    # Create default API key if missing
    if not config.get("API_KEY"):
        logger.warning("API_KEY missing, setting default (insecure)")
        api_keys_data = {
            "API_KEY": f"dev-key-{PROJECT_ID}",
            "VIRUSTOTAL_API_KEY": "",
            "ALIENVAULT_API_KEY": "",
            "MISP_API_KEY": ""
        }
        create_or_update_secret("api-keys", api_keys_data)
    
    # Create default feed configurations if missing
    if not config.get("FEED_CONFIG"):
        logger.warning("Feed configuration missing, setting defaults")
        default_feed_config = {
            "FEED_CONFIG": {
                "alienvault": {
                    "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                    "auth_header": "X-OTX-API-KEY",
                    "auth_key": "",
                    "table_id": "alienvault_pulses"
                },
                "misp": {
                    "url": "https://your-misp-instance.com/events/restSearch",
                    "auth_header": "Authorization",
                    "auth_key": "",
                    "table_id": "misp_events"
                },
                "threatfox": {
                    "url": "https://threatfox-api.abuse.ch/api/v1/",
                    "table_id": "threatfox_iocs"
                }
            }
        }
        create_or_update_secret("feed-config", default_feed_config)
    
    # Create default auth config if missing
    if not config.get("FLASK_SECRET_KEY"):
        logger.warning("Auth configuration missing, setting defaults")
        import hashlib
        import uuid
        
        # Generate a random secret key
        random_key = str(uuid.uuid4())
        
        auth_config = {
            "FLASK_SECRET_KEY": random_key,
            "USERS": {
                "admin": {
                    "password": hashlib.sha256("changeme".encode()).hexdigest(),
                    "role": "admin"
                },
                "analyst": {
                    "password": hashlib.sha256("analyst123".encode()).hexdigest(),
                    "role": "analyst"
                },
                "readonly": {
                    "password": hashlib.sha256("readonly".encode()).hexdigest(),
                    "role": "readonly"
                }
            }
        }
        create_or_update_secret("auth-config", auth_config)
    
    # Create default database credentials if missing
    if not config.get("DATABASE_USER"):
        logger.warning("Database credentials missing, setting defaults")
        db_credentials = {
            "DATABASE_USER": "",
            "DATABASE_PASSWORD": "",
            "DATABASE_NAME": "threat_intelligence",
            "DATABASE_HOST": ""
        }
        create_or_update_secret("database-credentials", db_credentials)
    
    # Reload config after potentially creating secrets
    global _config_cache
    _config_cache = {}  # Clear cache to force reload
    updated_config = get_config()
    
    return updated_config
