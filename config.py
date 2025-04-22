import os
import json
import logging
from google.cloud import secret_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

# Secret Manager client
secret_client = None

def get_secret_client():
    """Get or initialize Secret Manager client."""
    global secret_client
    if secret_client is None:
        try:
            secret_client = secret_manager.SecretManagerServiceClient()
        except Exception as e:
            logger.error(f"Failed to initialize Secret Manager client: {e}")
            raise
    return secret_client

def access_secret(secret_id, version_id="latest"):
    """Access the secret with the given name and version."""
    client = get_secret_client()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/{version_id}"
    try:
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception as e:
        logger.error(f"Failed to access secret {secret_id}: {e}")
        return None

def create_or_update_secret(secret_id, secret_value):
    """Create or update a secret in Secret Manager."""
    client = get_secret_client()
    parent = f"projects/{PROJECT_ID}"
    
    # Check if secret exists
    try:
        client.get_secret(request={"name": f"{parent}/secrets/{secret_id}"})
        secret_exists = True
    except Exception:
        secret_exists = False
    
    # Create secret if it doesn't exist
    if not secret_exists:
        try:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
        except Exception as e:
            logger.error(f"Failed to create secret {secret_id}: {e}")
            return False
    
    # Add new version
    try:
        client.add_secret_version(
            request={
                "parent": f"{parent}/secrets/{secret_id}",
                "payload": {"data": secret_value.encode("UTF-8")},
            }
        )
        return True
    except Exception as e:
        logger.error(f"Failed to add version to secret {secret_id}: {e}")
        return False

def get_config(config_name):
    """Get configuration from Secret Manager."""
    config_json = access_secret(config_name)
    if config_json:
        try:
            return json.loads(config_json)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in {config_name} config")
            return {}
    return {}

# Cache for configurations
_config_cache = {}

def get_cached_config(config_name, force_refresh=False):
    """Get cached configuration or refresh from Secret Manager."""
    global _config_cache
    if force_refresh or config_name not in _config_cache:
        _config_cache[config_name] = get_config(config_name)
    return _config_cache[config_name]

# Load configurations
def load_configs(force_refresh=False):
    """Load all configurations from Secret Manager."""
    configs = {
        'api_keys': get_cached_config('api-keys', force_refresh),
        'database': get_cached_config('database-credentials', force_refresh),
        'feeds': get_cached_config('feed-config', force_refresh),
        'auth': get_cached_config('auth-config', force_refresh)
    }
    return configs
