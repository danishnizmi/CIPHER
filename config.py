"""
Threat Intelligence Platform - Configuration Module
Centralized configuration management with GCP Secret Manager integration.
Provides secure secret handling, configuration caching, and user management.
"""

import os
import json
import logging
import hashlib
import base64
import time
import secrets
from datetime import datetime
from functools import lru_cache
from typing import Dict, Any, Optional, List, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Environment variables - read once at module load time
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
REGION = os.environ.get("GCP_REGION", "us-central1")
API_URL = os.environ.get("API_URL", "")
GCS_BUCKET = os.environ.get("GCS_BUCKET", f"{PROJECT_ID}-threat-data")
BIGQUERY_DATASET = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
api_key = os.environ.get("API_KEY", "")

# Overrides from environment variables
AUTH_CONFIG_ENV = os.environ.get("AUTH_CONFIG", "")
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() == "true"
BYPASS_SECRET_MANAGER = os.environ.get("BYPASS_SECRET_MANAGER", "false").lower() == "true"

# Check if running on GCP
RUNNING_ON_GCP = os.environ.get("K_SERVICE") is not None or os.environ.get("GOOGLE_CLOUD_PROJECT") is not None

# Default authentication config for development
DEFAULT_AUTH_CONFIG = {
    "users": {
        "admin": {
            "password": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",  # 'admin'
            "role": "admin",
            "created_at": datetime.utcnow().isoformat()
        }
    },
    "session_secret": secrets.token_hex(32)
}

# Lazy-loaded Secret Manager client
_secret_client = None
# Config cache with 30-minute TTL
_config_cache = {}
_cache_timestamp = {}
CACHE_TTL_SECONDS = 1800  # 30 minutes

# GCP services availability flag
GCP_SERVICES_AVAILABLE = False
try:
    from google.cloud import secretmanager
    GCP_SERVICES_AVAILABLE = True
    logger.info("GCP Secret Manager library available")
except ImportError:
    logger.warning("GCP Secret Manager library not available - will operate in degraded mode")

def get_secret_client():
    """Get Secret Manager client (lazy initialization to save costs)"""
    global _secret_client, GCP_SERVICES_AVAILABLE
    
    if BYPASS_SECRET_MANAGER:
        logger.info("Secret Manager bypassed due to BYPASS_SECRET_MANAGER flag")
        return None
        
    if not GCP_SERVICES_AVAILABLE:
        logger.warning("Secret Manager library not available")
        return None
        
    if _secret_client is None:
        try:
            from google.cloud import secretmanager
            _secret_client = secretmanager.SecretManagerServiceClient()
            logger.info("Secret Manager client initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize Secret Manager client: {e}")
            # Don't raise - allow operation in degraded mode without secrets
    
    return _secret_client

def get_secret(secret_id: str, version_id: str = "latest") -> Optional[str]:
    """Get a secret from Secret Manager with error handling

    Args:
        secret_id: ID of the secret
        version_id: Version of the secret (default: latest)
        
    Returns:
        Secret content or None if error
    """
    if not GCP_SERVICES_AVAILABLE:
        logger.warning(f"Secret Manager not available, cannot retrieve secret {secret_id}")
        return None
        
    client = get_secret_client()
    if not client:
        logger.warning(f"Secret Manager client not available, cannot retrieve secret {secret_id}")
        return None
        
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {str(e)}")
        return None

@lru_cache(maxsize=10)
def access_secret(secret_id: str, version_id: str = "latest") -> Optional[str]:
    """Access secret with efficient caching to reduce API costs
    
    Args:
        secret_id: ID of the secret to access
        version_id: Version of the secret (default: latest)
        
    Returns:
        Secret payload or None if not available
    """
    # If we have an environment variable override for auth-config, use it
    if secret_id == "auth-config" and AUTH_CONFIG_ENV:
        logger.info("Using AUTH_CONFIG environment variable instead of Secret Manager")
        return AUTH_CONFIG_ENV
        
    # Delegate to get_secret which handles all error cases
    return get_secret(secret_id, version_id)

def create_or_update_secret(secret_id: str, secret_value: str) -> bool:
    """Create or update a secret in Secret Manager
    
    Args:
        secret_id: Secret identifier
        secret_value: Secret content
        
    Returns:
        Success status
    """
    if not GCP_SERVICES_AVAILABLE:
        logger.warning(f"Secret Manager not available, cannot create/update secret {secret_id}")
        return False
        
    client = get_secret_client()
    if not client:
        logger.warning(f"Secret Manager client not available, cannot create/update secret {secret_id}")
        return False
        
    try:
        parent = f"projects/{PROJECT_ID}"
        
        # Check if secret exists
        try:
            client.get_secret(request={"name": f"{parent}/secrets/{secret_id}"})
            secret_exists = True
        except Exception:
            secret_exists = False
        
        # Create secret if it doesn't exist
        if not secret_exists:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
            logger.info(f"Created secret: {secret_id}")
        
        # Add new version
        client.add_secret_version(
            request={
                "parent": f"{parent}/secrets/{secret_id}",
                "payload": {"data": secret_value.encode("UTF-8")},
            }
        )
        logger.info(f"Updated secret: {secret_id}")
        
        # Clear cache for this config
        if secret_id in _config_cache:
            del _config_cache[secret_id]
            if secret_id in _cache_timestamp:
                del _cache_timestamp[secret_id]
                
        # Also clear the lru_cache for access_secret
        access_secret.cache_clear()
                
        return True
    except Exception as e:
        logger.error(f"Failed to update secret {secret_id}: {str(e)}")
        return False

def get_config(config_name: str) -> Dict[str, Any]:
    """Get configuration from Secret Manager with caching
    
    Args:
        config_name: Name of the config secret
        
    Returns:
        Configuration dict
    """
    # Check cache first
    now = datetime.now().timestamp()
    if config_name in _config_cache:
        # Return cached value if it's not expired
        if now - _cache_timestamp.get(config_name, 0) < CACHE_TTL_SECONDS:
            return _config_cache[config_name]
    
    # Special handling for auth-config
    if config_name == 'auth-config':
        # Load from Secret Manager
        config_json = access_secret(config_name)
        if config_json:
            try:
                config_data = json.loads(config_json)
                # Update cache
                _config_cache[config_name] = config_data
                _cache_timestamp[config_name] = now
                logger.info(f"Loaded auth-config from Secret Manager")
                return config_data
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {config_name} config: {e}")
        
        # Fallback to environment variable if present
        if AUTH_CONFIG_ENV:
            try:
                config_data = json.loads(AUTH_CONFIG_ENV)
                _config_cache[config_name] = config_data
                _cache_timestamp[config_name] = now
                logger.info("Using auth-config from environment variable")
                return config_data
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in AUTH_CONFIG environment variable: {e}")
        
        # Use default auth config as last resort
        logger.warning(f"Using default auth-config because Secret Manager and environment variable failed")
        _config_cache[config_name] = DEFAULT_AUTH_CONFIG
        _cache_timestamp[config_name] = now
        return DEFAULT_AUTH_CONFIG
    
    # Standard flow for other configs
    config_json = access_secret(config_name)
    if config_json:
        try:
            config_data = json.loads(config_json)
            # Update cache
            _config_cache[config_name] = config_data
            _cache_timestamp[config_name] = now
            return config_data
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in {config_name} config")
    
    # Return empty dict if config not found or invalid
    return {}

def get_cached_config(config_name: str, force_refresh: bool = False) -> Dict[str, Any]:
    """Get cached configuration
    
    Args:
        config_name: Configuration name
        force_refresh: Force refresh from source
        
    Returns:
        Configuration dict
    """
    if force_refresh or config_name not in _config_cache:
        return get_config(config_name)
    return _config_cache.get(config_name, {})

def load_configs(force_refresh: bool = False) -> Dict[str, Dict]:
    """Load all configurations (minimized for cost efficiency)
    
    Args:
        force_refresh: Force refresh from source
        
    Returns:
        Dict of configurations
    """
    global api_key
    
    configs = {
        'api_keys': get_cached_config('api-keys', force_refresh),
        'auth': get_cached_config('auth-config', force_refresh)
    }
    
    # Only load additional configs when needed
    if ENVIRONMENT == 'production':
        configs['database'] = get_cached_config('database-credentials', force_refresh)
        configs['feeds'] = get_cached_config('feed-config', force_refresh)
    
    # Update global API key if available in config
    if configs['api_keys'] and 'platform_api_key' in configs['api_keys']:
        api_key = configs['api_keys']['platform_api_key']
    
    return configs

def init_app_config() -> Dict[str, Any]:
    """Initialize application configuration
    
    Returns:
        Configuration dict or error dict
    """
    try:
        configs = load_configs()
        
        # Make sure auth config has required structure
        auth_config = configs.get('auth', {})
        if not auth_config.get('users'):
            logger.warning("Auth config missing required 'users' field, using default")
            auth_config['users'] = DEFAULT_AUTH_CONFIG['users']
            configs['auth'] = auth_config
            
        if not auth_config.get('session_secret'):
            logger.warning("Auth config missing required 'session_secret' field, using default")
            auth_config['session_secret'] = DEFAULT_AUTH_CONFIG['session_secret']
            configs['auth'] = auth_config
        
        # If in production, make sure we have key configs
        if ENVIRONMENT == 'production':
            # Ensure API key exists
            if not configs.get('api_keys') or not configs['api_keys'].get('platform_api_key'):
                logger.warning("API key not found in production, generating and storing one")
                
                # Generate and store API key
                api_key_config = configs.get('api_keys', {})
                api_key_config['platform_api_key'] = secrets.token_hex(24)
                
                if create_or_update_secret('api-keys', json.dumps(api_key_config)):
                    configs['api_keys'] = api_key_config
                    api_key = api_key_config['platform_api_key']
                    logger.info("Generated and stored new API key")
        
        return configs
    except Exception as e:
        logger.error(f"Error initializing app config: {e}")
        return {'error': str(e), 'auth': DEFAULT_AUTH_CONFIG}

def get(key: str, default: Any = None) -> Any:
    """Get configuration value from environment or secrets
    
    Args:
        key: Configuration key
        default: Default value if not found
        
    Returns:
        Configuration value
    """
    # Check environment first (no API cost)
    if key in os.environ:
        return os.environ[key]
    
    # Try auth config (using cache when possible)
    try:
        auth_config = get_cached_config('auth-config')
        if auth_config and key in auth_config:
            return auth_config[key]
    except Exception as e:
        logger.warning(f"Error accessing auth config for key {key}: {e}")
    
    return default

def update_user(username: str, updates: Dict[str, Any]) -> bool:
    """Update user in auth config
    
    Args:
        username: Username to update
        updates: User data updates
        
    Returns:
        Success status
    """
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
        auth_config['users'][username][key] = value
    
    # First, update local cache
    _config_cache['auth-config'] = auth_config
    _cache_timestamp['auth-config'] = datetime.now().timestamp()
    
    # Then try to save to Secret Manager if available
    if not BYPASS_SECRET_MANAGER:
        return create_or_update_secret('auth-config', json.dumps(auth_config))
    return True

def add_user(username: str, password: str, role: str = "readonly") -> bool:
    """Add a new user
    
    Args:
        username: Username
        password: Password
        role: User role
        
    Returns:
        Success status
    """
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    user_data = {
        "password": hashed_password,
        "role": role,
        "created_at": datetime.utcnow().isoformat()
    }
    
    return update_user(username, user_data)

def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure password
    
    Args:
        length: Password length
        
    Returns:
        Secure password
    """
    # Use all character classes to ensure complexity
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Generate password with at least one character from each class
    secure_pwd = [
        secrets.choice("abcdefghijklmnopqrstuvwxyz"),  # lowercase
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),  # uppercase
        secrets.choice("0123456789"),                  # digit
        secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?")   # special
    ]
    
    # Fill the rest with random characters
    secure_pwd.extend(secrets.choice(characters) for _ in range(length - 4))
    
    # Shuffle to avoid predictable pattern
    secrets.SystemRandom().shuffle(secure_pwd)
    
    return ''.join(secure_pwd)

def set_initial_admin_password(force: bool = False) -> Optional[str]:
    """Set or retrieve initial admin password from Secret Manager
    
    Args:
        force: Force creation of new password
        
    Returns:
        Admin password if successful, None otherwise
    """
    # If not forcing update, check if auth config already has admin user
    if not force:
        auth_config = get_cached_config('auth-config')
        if auth_config and 'users' in auth_config and 'admin' in auth_config['users']:
            # Try to get password from Secret Manager
            admin_password = get_secret("admin-initial-password")
            if admin_password:
                logger.info("Retrieved initial admin password from Secret Manager")
                return admin_password
    
    # Generate a secure admin password
    admin_password = generate_secure_password(16)
    
    # Store in Secret Manager for retrieval
    if create_or_update_secret("admin-initial-password", admin_password):
        logger.info(f"Set initial admin password in Secret Manager: {admin_password}")
        
        # Also update the admin user with this password
        admin_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        add_user("admin", admin_password, "admin")
        
        return admin_password
    
    logger.error("Failed to set initial admin password in Secret Manager")
    return None

def secure_config_init() -> bool:
    """Initialize secure configurations and sensitive data
    
    Returns:
        Success status
    """
    # Ensure required configuration is available
    try:
        # Initialize app configuration from Secret Manager
        configs = init_app_config()
        
        # Ensure robust session secret
        auth_config = get_cached_config('auth-config')
        if not auth_config.get('session_secret') or len(auth_config.get('session_secret', '')) < 32:
            logger.info("Generating new session secret")
            auth_config['session_secret'] = secrets.token_hex(32)
            
            # Update auth config with new session secret
            create_or_update_secret('auth-config', json.dumps(auth_config))
        
        # Set initial admin password
        admin_password = set_initial_admin_password()
        if admin_password:
            logger.info(f"Admin user ready with initial password: {admin_password}")
            # Print to console for admin access
            if ENVIRONMENT == 'development' or DEBUG_MODE:
                print(f"\n=== ADMIN PASSWORD: {admin_password} ===\n")
        
        return True
    except Exception as e:
        logger.error(f"Error in secure config initialization: {e}")
        return False

# Initialize secure configuration when module is imported
if not DEBUG_MODE:
    secure_config_init()

# Exported properties for other modules
project_id = PROJECT_ID
region = REGION
gcs_bucket = GCS_BUCKET
bigquery_dataset = BIGQUERY_DATASET
environment = ENVIRONMENT
api_url = API_URL
