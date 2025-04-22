import os
import json
import logging
import hashlib
from datetime import datetime
from google.cloud import secretmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
REGION = os.environ.get("GCP_REGION", "us-central1")
API_URL = os.environ.get("API_URL", "")

# API key initialization with default
api_key = os.environ.get("API_KEY", "")

# Secret Manager client
secret_client = None

def get_secret_client():
    """Get or initialize Secret Manager client."""
    global secret_client
    if secret_client is None:
        try:
            secret_client = secretmanager.SecretManagerServiceClient()
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
    
    # Update global API key if available in api_keys config
    global api_key
    if configs['api_keys'] and 'platform_api_key' in configs['api_keys']:
        api_key = configs['api_keys']['platform_api_key']
    
    return configs

def init_app_config():
    """Initialize application configuration from secrets."""
    try:
        return load_configs()
    except Exception as e:
        logger.error(f"Error initializing app config: {e}")
        return {'error': str(e)}

def get(key, default=None):
    """Get configuration value from environment or secrets."""
    if key in os.environ:
        return os.environ[key]
    
    # Try to get from auth config in Secret Manager
    try:
        auth_config = get_cached_config('auth-config')
        if auth_config and key in auth_config:
            return auth_config[key]
    except Exception as e:
        logger.warning(f"Could not get config from Secret Manager: {e}")
    
    return default

def add_user(username, password, role="readonly"):
    """Add a new user"""
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    user_data = {
        "password": hashed_password,
        "role": role,
        "created_at": datetime.utcnow().isoformat()
    }
    
    return update_user(username, user_data)

def update_user(username, updates):
    """Update user information in the auth config."""
    auth_config = get_cached_config('auth-config', force_refresh=True)
    
    if 'users' not in auth_config:
        auth_config['users'] = {}
    
    if username not in auth_config['users']:
        auth_config['users'][username] = {}
    
    # Update user data
    for key, value in updates.items():
        if key == 'password':
            # Hash the password if not already hashed
            if len(value) != 64:  # SHA-256 produces 64 character hex string
                value = hashlib.sha256(value.encode()).hexdigest()
            auth_config['users'][username]['password'] = value
        else:
            auth_config['users'][username][key] = value
    
    # Save updated config
    result = create_or_update_secret('auth-config', json.dumps(auth_config))
    
    # Update cache
    if result:
        _config_cache['auth-config'] = auth_config
    
    return result

def update_api_key(service, api_key):
    """Update API key for a service."""
    api_keys = get_cached_config('api-keys', force_refresh=True)
    
    # Update API key
    api_keys[service] = api_key
    
    # Save updated config
    result = create_or_update_secret('api-keys', json.dumps(api_keys))
    
    # Update cache
    if result:
        _config_cache['api-keys'] = api_keys
    
    return result

def update_feed_config(feed_name, updates):
    """Update feed configuration."""
    feed_config = get_cached_config('feed-config', force_refresh=True)
    
    if 'feeds' not in feed_config:
        feed_config['feeds'] = []
    
    # Find feed in the list
    found = False
    for i, feed in enumerate(feed_config['feeds']):
        if feed.get('name') == feed_name:
            # Update feed
            for key, value in updates.items():
                feed_config['feeds'][i][key] = value
            found = True
            break
    
    # If feed not found, add it
    if not found:
        updates['name'] = feed_name
        feed_config['feeds'].append(updates)
    
    # Save updated config
    result = create_or_update_secret('feed-config', json.dumps(feed_config))
    
    # Update cache
    if result:
        _config_cache['feed-config'] = feed_config
    
    return result

# Properties used by other modules
project_id = PROJECT_ID
region = REGION
gcs_bucket = os.environ.get("GCS_BUCKET", f"{PROJECT_ID}-threat-data")
bigquery_dataset = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
api_url = API_URL
