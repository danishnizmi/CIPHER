"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management with proper secret initialization.
"""

import os
import sys
import json
import logging
import hashlib
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from functools import wraps, lru_cache

# Global client variables with lazy initialization
_clients = {}
_secret_client = None
_logging_client = None
_error_client = None

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ===== Constants and Default Configuration =====
DEFAULT_API_RATE_LIMIT = "200 per day, 50 per hour"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
DEFAULT_SECRET_TTL = 86400  # 24 hours
FEED_TYPES = ["indicators", "vulnerabilities", "threat_actors", "campaigns", "malware"]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Default feed configurations
DEFAULT_FEED_CONFIGS = [
    {
        "id": "phishtank",
        "name": "PhishTank URLs",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "description": "URLs verified as phishing by PhishTank community",
        "format": "json",
        "type": "url",
        "update_frequency": "daily",
        "enabled": True
    },
    {
        "id": "urlhaus",
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recent malware URLs from URLhaus",
        "format": "csv",
        "type": "url",
        "update_frequency": "daily",
        "enabled": True
    },
    {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent indicators from ThreatFox",
        "format": "json",
        "type": "mixed",
        "update_frequency": "daily",
        "enabled": True
    }
]

# ===== Utility Functions =====
@lru_cache(maxsize=1)
def get_project_id() -> Optional[str]:
    """Get Google Cloud project ID with cache."""
    # Check environment variable first (most efficient)
    project_id = os.environ.get('GCP_PROJECT')
    if project_id:
        return project_id
    
    # Try google.auth default credentials if available
    try:
        import google.auth
        try:
            credentials, project_id = google.auth.default()
            if project_id:
                os.environ['GCP_PROJECT'] = project_id  # Cache in env var
                return project_id
        except Exception:
            pass
    except ImportError:
        pass
    
    # Use fallback ID
    return os.environ.get('FALLBACK_PROJECT_ID', "primal-chariot-382610")

def get_env_bool(var_name: str, default: bool = False) -> bool:
    """Get boolean value from environment variable."""
    val = os.environ.get(var_name, str(default)).lower()
    return val in ('true', 't', 'yes', 'y', '1')

def get_env_list(var_name: str, default: Optional[List] = None, separator: str = ',') -> List:
    """Get list from environment variable."""
    if default is None:
        default = []
    val = os.environ.get(var_name)
    if not val:
        return default
    return [item.strip() for item in val.split(separator) if item.strip()]

def get_env_dict(var_name: str, default: Optional[Dict] = None) -> Dict:
    """Get dictionary from JSON-formatted environment variable."""
    if default is None:
        default = {}
    val = os.environ.get(var_name)
    if not val:
        return default
    try:
        return json.loads(val)
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in {var_name} environment variable")
        return default

def hash_password(password: str) -> str:
    """Hash password using SHA-256 for storage."""
    return hashlib.sha256(password.encode()).hexdigest()

# ===== Secret Management =====
class SecretManager:
    """Manages secrets with cloud and environment variable strategy."""
    
    _cache = {}  # In-memory cache
    _cache_timestamp = {}  # Last refresh timestamps
    _initialized = False
    _lock = threading.RLock()  # Lock for thread safety
    _secret_exists_cache = {}  # Cache for whether secrets exist to minimize API calls
    
    @classmethod
    def init(cls):
        """Initialize the secret manager and verify required secrets."""
        with cls._lock:
            if cls._initialized:
                return
                
            # Initialize the secrets - only create defaults if they don't exist
            cls._ensure_admin_password()
            cls._ensure_api_keys()
            cls._ensure_auth_config()
            cls._ensure_feed_config()
            
            cls._initialized = True
            logger.info("Secret Manager initialized successfully")
    
    @classmethod
    def _ensure_admin_password(cls):
        """Initialize admin password secret ONLY if it doesn't exist."""
        secret_id = 'admin-initial-password'
        # Check if secret exists (without creating a new version)
        if cls._secret_exists(secret_id):
            admin_password = cls._get_secret_without_version(secret_id)
            if admin_password:
                logger.info("Using existing admin password from secret manager")
                # Update cache but don't create new version
                cls._update_cache_only(secret_id, admin_password)
                # Make sure it's accessible via environment variable
                os.environ['ADMIN_PASSWORD'] = admin_password
                return admin_password
        
        # Only create if it doesn't exist
        admin_password = DEFAULT_ADMIN_PASSWORD
        logger.info("Creating default admin password since none exists")
        cls._create_secret(secret_id, admin_password)
        # Make environment variable available
        os.environ['ADMIN_PASSWORD'] = admin_password
        return admin_password
    
    @classmethod
    def _ensure_api_keys(cls):
        """Initialize API keys secret ONLY if it doesn't exist."""
        secret_id = 'api-keys'
        # Check if secret exists (without creating a new version)
        if cls._secret_exists(secret_id):
            api_keys = cls._get_secret_without_version(secret_id)
            if api_keys and isinstance(api_keys, dict) and 'platform_api_key' in api_keys:
                logger.info("Using existing API keys from secret manager")
                # Update cache but don't create new version
                cls._update_cache_only(secret_id, api_keys)
                return api_keys
        
        # Only create if it doesn't exist or is invalid
        api_keys = {'platform_api_key': os.environ.get('API_KEY', 'dev-api-key')}
        logger.info("Creating default API keys configuration")
        cls._create_secret(secret_id, api_keys)
        return api_keys
    
    @classmethod
    def _ensure_auth_config(cls):
        """Initialize authentication configuration with proper admin credentials."""
        secret_id = 'auth-config'
        
        # CRITICAL: First get admin password - must be done before checking auth_config
        admin_password = cls._ensure_admin_password()
        
        # Now check if auth_config exists
        if cls._secret_exists(secret_id):
            auth_config = cls._get_secret_without_version(secret_id)
            if auth_config and isinstance(auth_config, dict):
                # Secret exists and is valid - update cache without creating version
                cls._update_cache_only(secret_id, auth_config)
                
                # Always update admin user with correct password hash
                needs_update = False
                
                # Ensure required fields exist
                if 'session_secret' not in auth_config:
                    auth_config['session_secret'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
                    needs_update = True
                
                if 'enabled' not in auth_config:
                    auth_config['enabled'] = True
                    needs_update = True
                
                if 'users' not in auth_config:
                    auth_config['users'] = {}
                    needs_update = True
                
                # CRITICAL: Always update admin user password to match admin-initial-password
                if admin_password:
                    # Compute password hash
                    password_hash = hash_password(admin_password)
                    
                    # Check if admin user exists or password hash is different
                    if ('admin' not in auth_config['users'] or 
                        auth_config['users']['admin'].get('password') != password_hash):
                        
                        auth_config['users']['admin'] = {
                            'password': password_hash,
                            'role': 'admin',
                            'created_at': datetime.utcnow().isoformat()
                        }
                        logger.info("Updated admin user password hash in auth_config")
                        needs_update = True
                
                # Only push update if absolutely necessary
                if needs_update:
                    logger.info("Updating auth config with necessary changes")
                    cls._update_secret(secret_id, auth_config)
                
                return auth_config
        
        # Create new config if none exists
        logger.info("Creating new auth configuration")
        auth_config = {
            'session_secret': os.environ.get('SECRET_KEY', 'dev-secret-key'),
            'enabled': True,
            'users': {}
        }
        
        # Add admin user with password hash
        if admin_password:
            auth_config['users']['admin'] = {
                'password': hash_password(admin_password),
                'role': 'admin',
                'created_at': datetime.utcnow().isoformat()
            }
            logger.info("Added admin user to new auth_config")
        
        # Create the secret
        cls._create_secret(secret_id, auth_config)
        return auth_config
    
    @classmethod
    def _ensure_feed_config(cls):
        """Initialize feed configuration ONLY if it doesn't exist."""
        secret_id = 'feed-config'
        # Check if secret exists (without creating a new version)
        if cls._secret_exists(secret_id):
            feed_config = cls._get_secret_without_version(secret_id)
            if feed_config and isinstance(feed_config, dict) and 'feeds' in feed_config:
                logger.info("Using existing feed configuration from secret manager")
                # Update cache but don't create new version
                cls._update_cache_only(secret_id, feed_config)
                return feed_config
        
        # Only create if it doesn't exist or is invalid
        feed_config = {
            'feeds': DEFAULT_FEED_CONFIGS,
            'update_interval_hours': 6
        }
        logger.info("Creating default feed configuration")
        cls._create_secret(secret_id, feed_config)
        return feed_config
    
    @classmethod
    def ensure_password_sync(cls):
        """
        Explicitly synchronize admin password between admin-initial-password and auth-config.
        This method ensures passwords are consistent across secrets.
        """
        if not cls._initialized:
            cls.init()
            
        logger.info("Ensuring admin password synchronization...")
        
        # Get admin password
        admin_password = cls.get_secret('admin-initial-password')
        if not admin_password:
            logger.warning("Admin password not found, creating default")
            admin_password = DEFAULT_ADMIN_PASSWORD
            cls._create_secret('admin-initial-password', admin_password)
        
        # Get auth config
        auth_config = cls.get_secret('auth-config')
        if not auth_config or not isinstance(auth_config, dict):
            logger.warning("Auth config not found or invalid, creating new")
            auth_config = {
                'session_secret': os.environ.get('SECRET_KEY', 'dev-secret-key'),
                'enabled': True,
                'users': {}
            }
        
        # Ensure users dictionary exists
        if 'users' not in auth_config:
            auth_config['users'] = {}
        
        # Update admin user with correct password hash
        password_hash = hash_password(admin_password)
        auth_config['users']['admin'] = {
            'password': password_hash,
            'role': 'admin',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Update auth config
        result = cls._update_secret('auth-config', auth_config)
        
        if result:
            logger.info("Admin password successfully synchronized")
        else:
            logger.error("Failed to synchronize admin password")
        
        return result
    
    @classmethod
    def _secret_exists(cls, secret_id: str) -> bool:
        """Check if a secret exists without fetching its value."""
        # Check cache first for performance
        if secret_id in cls._secret_exists_cache:
            return cls._secret_exists_cache[secret_id]
        
        # Check via secret client
        client = cls._get_secret_client()
        if not client:
            return False
            
        project_id = get_project_id()
        if not project_id:
            return False
            
        try:
            client.get_secret(request={"name": f"projects/{project_id}/secrets/{secret_id}"})
            # Cache the result
            cls._secret_exists_cache[secret_id] = True
            return True
        except Exception:
            # Cache the result
            cls._secret_exists_cache[secret_id] = False
            return False
    
    @classmethod
    def _get_secret_without_version(cls, secret_id: str) -> Any:
        """Get a secret value without creating a new version or updating cache."""
        # Skip environment variables to ensure we get from Secret Manager
        client = cls._get_secret_client()
        if not client:
            return None
            
        project_id = get_project_id()
        if not project_id:
            return None
            
        try:
            name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            secret_data = response.payload.data.decode("UTF-8")
            
            try:
                return json.loads(secret_data)
            except json.JSONDecodeError:
                return secret_data
        except Exception as e:
            logger.debug(f"Could not fetch secret {secret_id}: {e}")
            return None
    
    @classmethod
    def get_secret(cls, secret_id: str, force_refresh: bool = False) -> Any:
        """Get a secret value with cache."""
        if not cls._initialized:
            cls.init()
            
        return cls._get_secret(secret_id, force_refresh)
    
    @classmethod
    def _get_secret(cls, secret_id: str, force_refresh: bool = False) -> Any:
        """Internal method to get a secret."""
        # Check environment variables first (fastest, no cost)
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        if env_var_name in os.environ:
            try:
                return json.loads(os.environ[env_var_name])
            except json.JSONDecodeError:
                return os.environ[env_var_name]
        
        # Check cache
        if not force_refresh and secret_id in cls._cache:
            timestamp = cls._cache_timestamp.get(secret_id)
            if timestamp and (datetime.now() - timestamp).total_seconds() < DEFAULT_SECRET_TTL:
                return cls._cache[secret_id]
        
        # Try to fetch from Secret Manager
        result = cls._fetch_from_cloud(secret_id)
        if result is not None:
            cls._cache[secret_id] = result
            cls._cache_timestamp[secret_id] = datetime.now()
            return result
            
        return None
    
    @classmethod
    def _fetch_from_cloud(cls, secret_id: str) -> Optional[Any]:
        """Fetch a secret from Google Cloud Secret Manager."""
        if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            return None
            
        client = cls._get_secret_client()
        if not client:
            return None
            
        project_id = get_project_id()
        if not project_id:
            return None
            
        try:
            name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            secret_data = response.payload.data.decode("UTF-8")
            
            # Update the exists cache
            cls._secret_exists_cache[secret_id] = True
            
            try:
                return json.loads(secret_data)
            except json.JSONDecodeError:
                return secret_data
        except Exception as e:
            logger.debug(f"Could not fetch secret {secret_id}: {e}")
            return None
    
    @classmethod
    def update_secret(cls, secret_id: str, value: Any):
        """Update a secret value in cache and cloud."""
        if not cls._initialized:
            cls.init()
            
        return cls._update_secret(secret_id, value)
    
    @classmethod
    def _update_cache_only(cls, secret_id: str, value: Any):
        """Only update the cache, not the secret in Secret Manager."""
        # Update cache
        cls._cache[secret_id] = value
        cls._cache_timestamp[secret_id] = datetime.now()
        
        # Update environment variable
        if not isinstance(value, str):
            env_value = json.dumps(value)
        else:
            env_value = value
            
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        os.environ[env_var_name] = env_value
    
    @classmethod
    def _create_secret(cls, secret_id: str, value: Any) -> bool:
        """Create a new secret only if it doesn't exist."""
        # Check if secret exists first
        if cls._secret_exists(secret_id):
            logger.info(f"Secret {secret_id} already exists, not creating")
            # Just update cache
            cls._update_cache_only(secret_id, value)
            return True
        
        # Serialize value if needed
        if not isinstance(value, str):
            value_str = json.dumps(value)
        else:
            value_str = value
            
        # Update cache
        cls._cache[secret_id] = value
        cls._cache_timestamp[secret_id] = datetime.now()
        
        # Update environment variable
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        os.environ[env_var_name] = value_str
        
        # Push to cloud if not using env vars
        if not get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            return cls._create_cloud_secret(secret_id, value_str)
            
        return True
    
    @classmethod
    def _update_secret(cls, secret_id: str, value: Any) -> bool:
        """Internal method to update a secret."""
        # Serialize value if needed
        if not isinstance(value, str):
            value_str = json.dumps(value)
        else:
            value_str = value
            
        # Update cache
        cls._cache[secret_id] = value
        cls._cache_timestamp[secret_id] = datetime.now()
        
        # Update environment variable
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        os.environ[env_var_name] = value_str
        
        # Push to cloud if not using env vars
        if not get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            return cls._push_to_cloud(secret_id, value_str)
            
        return True
    
    @classmethod
    def _create_cloud_secret(cls, secret_id: str, value: str) -> bool:
        """Create a secret in Google Cloud Secret Manager only if it doesn't exist."""
        client = cls._get_secret_client()
        if not client:
            return False
            
        project_id = get_project_id()
        if not project_id:
            return False
            
        try:
            # Check if secret exists
            try:
                client.get_secret(request={"name": f"projects/{project_id}/secrets/{secret_id}"})
                # Secret exists, don't create it
                logger.info(f"Secret {secret_id} already exists, not creating")
                cls._secret_exists_cache[secret_id] = True
                return True
            except Exception:
                # Secret doesn't exist, create it
                client.create_secret(
                    request={
                        "parent": f"projects/{project_id}",
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}}
                    }
                )
                logger.info(f"Created new secret: {secret_id}")
                cls._secret_exists_cache[secret_id] = True
                
                # Add initial version
                client.add_secret_version(
                    request={
                        "parent": f"projects/{project_id}/secrets/{secret_id}",
                        "payload": {"data": value.encode("UTF-8")}
                    }
                )
                logger.info(f"Added initial version to secret: {secret_id}")
                return True
        except Exception as e:
            logger.error(f"Error creating secret in cloud: {e}")
            return False
    
    @classmethod
    def _push_to_cloud(cls, secret_id: str, value: str) -> bool:
        """Push a secret to Google Cloud Secret Manager."""
        client = cls._get_secret_client()
        if not client:
            return False
            
        project_id = get_project_id()
        if not project_id:
            return False
        
        # Compare with existing value to avoid creating unnecessary versions
        existing_value = cls._get_secret_without_version(secret_id)
        if existing_value is not None:
            # Convert both to strings for comparison
            if not isinstance(existing_value, str):
                existing_value_str = json.dumps(existing_value)
            else:
                existing_value_str = existing_value
                
            # Skip update if values are identical
            if existing_value_str == value:
                logger.info(f"Secret {secret_id} value unchanged, skipping version creation")
                return True
            
        try:
            # Check if secret exists
            try:
                client.get_secret(request={"name": f"projects/{project_id}/secrets/{secret_id}"})
                secret_exists = True
                cls._secret_exists_cache[secret_id] = True
            except Exception:
                secret_exists = False
                cls._secret_exists_cache[secret_id] = False
                
            if not secret_exists:
                client.create_secret(
                    request={
                        "parent": f"projects/{project_id}",
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}}
                    }
                )
                logger.info(f"Created new secret: {secret_id}")
                cls._secret_exists_cache[secret_id] = True
                
            # Add new version
            client.add_secret_version(
                request={
                    "parent": f"projects/{project_id}/secrets/{secret_id}",
                    "payload": {"data": value.encode("UTF-8")}
                }
            )
            logger.info(f"Updated secret: {secret_id}")
            return True
        except Exception as e:
            logger.error(f"Error pushing secret to cloud: {e}")
            return False
    
    @classmethod
    def _get_secret_client(cls):
        """Get or create Secret Manager client."""
        global _secret_client
        
        if _secret_client:
            return _secret_client
            
        try:
            from google.cloud import secretmanager
            _secret_client = secretmanager.SecretManagerServiceClient()
            return _secret_client
        except Exception as e:
            logger.warning(f"Could not initialize Secret Manager client: {e}")
            return None

# ===== Main Configuration Class =====
class Config:
    """Base configuration class with proper secret handling."""
    
    # ===== Basic Application Configuration =====
    DEBUG = get_env_bool('DEBUG', False)
    TESTING = get_env_bool('TESTING', False)
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    VERSION = os.environ.get('VERSION', '1.0.3')
    
    # ===== Google Cloud Configuration =====
    GCP_PROJECT = get_project_id()
    GCP_REGION = os.environ.get('GCP_REGION', 'us-central1')
    
    # ===== BigQuery Configuration =====
    BIGQUERY_DATASET = os.environ.get('BIGQUERY_DATASET', 'threat_intelligence')
    BIGQUERY_LOCATION = os.environ.get('BIGQUERY_LOCATION', 'US')
    BIGQUERY_MAX_BYTES_BILLED = int(os.environ.get('BIGQUERY_MAX_BYTES_BILLED', 104857600))  # 100MB
    BIGQUERY_TABLES = {
        'indicators': 'indicators',
        'vulnerabilities': 'vulnerabilities',
        'threat_actors': 'threat_actors',
        'campaigns': 'campaigns',
        'malware': 'malware',
        'users': 'users',
        'audit_log': 'audit_log'
    }
    
    # ===== Storage Configuration =====
    GCS_BUCKET = os.environ.get('GCS_BUCKET', f"{GCP_PROJECT}-threat-data" if GCP_PROJECT else 'threat-data')
    
    # ===== PubSub Configuration =====
    PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', 'threat-data-ingestion')
    PUBSUB_ANALYSIS_TOPIC = os.environ.get('PUBSUB_ANALYSIS_TOPIC', 'threat-analysis-events')
    
    # ===== Secret Management =====
    USE_ENV_VARS_FOR_SECRETS = get_env_bool('USE_ENV_VARS_FOR_SECRETS', True)
    SECRET_TTL = int(os.environ.get('SECRET_TTL', DEFAULT_SECRET_TTL))
    
    # ===== Server Configuration =====
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))
    
    # ===== API Configuration =====
    API_KEY = None  # Will be initialized in init_app
    API_VERSION = 'v1'
    API_RATE_LIMIT = os.environ.get('API_RATE_LIMIT', DEFAULT_API_RATE_LIMIT)
    
    # ===== Auth Configuration =====
    SECRET_KEY = None  # Will be initialized in init_app
    AUTH_ENABLED = get_env_bool('AUTH_ENABLED', True)
    AUTH_SESSION_TIMEOUT = int(os.environ.get('AUTH_SESSION_TIMEOUT', 12 * 60 * 60))  # 12 hours
    ADMIN_USERNAME = DEFAULT_ADMIN_USERNAME
    ADMIN_PASSWORD = None  # Will be initialized in init_app
    
    # ===== Feed Configuration =====
    FEEDS = []  # Will be initialized in init_app
    FEED_UPDATE_INTERVAL = int(os.environ.get('FEED_UPDATE_INTERVAL', 3))  # hours
    
    # ===== Analysis Configuration =====
    ANALYSIS_ENABLED = get_env_bool('ANALYSIS_ENABLED', True)
    ANALYSIS_AUTO_ENRICH = get_env_bool('ANALYSIS_AUTO_ENRICH', True)
    
    # ===== NLP Configuration =====
    NLP_ENABLED = get_env_bool('NLP_ENABLED', True)
    VERTEXAI_LOCATION = os.environ.get('VERTEXAI_LOCATION', 'us-central1')
    VERTEXAI_MODEL = os.environ.get('VERTEXAI_MODEL', 'text-bison@latest')
    
    # ===== Error and Logging =====
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_CLOUD = get_env_bool('LOG_TO_CLOUD', False)
    ENABLE_ERROR_REPORTING = get_env_bool('ENABLE_ERROR_REPORTING', False)
    
    # ===== Initialization Methods =====
    @classmethod
    def init_app(cls):
        """Initialize the application configuration."""
        # Configure logging
        cls.configure_logging()
        logger.info(f"Initializing {cls.ENVIRONMENT} configuration")
        
        # Initialize Secret Manager
        SecretManager.init()
        
        # Explicitly synchronize passwords to fix login issues
        SecretManager.ensure_password_sync()
        
        # Load API keys
        api_keys = SecretManager.get_secret('api-keys')
        if api_keys and isinstance(api_keys, dict):
            cls.API_KEY = api_keys.get('platform_api_key', os.environ.get('API_KEY', 'dev-api-key'))
            cls.EXTERNAL_API_KEYS = {k: v for k, v in api_keys.items() if k != 'platform_api_key'}
        else:
            cls.API_KEY = os.environ.get('API_KEY', 'dev-api-key')
        
        # Load authentication configuration
        auth_config = SecretManager.get_secret('auth-config')
        if auth_config and isinstance(auth_config, dict):
            cls.SECRET_KEY = auth_config.get('session_secret', os.environ.get('SECRET_KEY', 'dev-secret-key'))
            cls.AUTH_ENABLED = auth_config.get('enabled', cls.AUTH_ENABLED)
            
            # Set admin password for easier access in runtime
            admin_password = SecretManager.get_secret('admin-initial-password')
            if admin_password:
                cls.ADMIN_PASSWORD = admin_password
                logger.info(f"Admin password loaded from Secret Manager")
                
                # Verify the admin user in auth_config has the correct password hash
                if ('users' in auth_config and 'admin' in auth_config['users'] and 
                    auth_config['users']['admin'].get('password') != hash_password(admin_password)):
                    logger.warning("Admin password hash mismatch detected, synchronizing...")
                    SecretManager.ensure_password_sync()
        else:
            cls.SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
        
        # Load feed configuration
        feed_config = SecretManager.get_secret('feed-config')
        if feed_config and isinstance(feed_config, dict) and 'feeds' in feed_config:
            cls.FEEDS = feed_config['feeds']
            logger.info(f"Loaded {len(cls.FEEDS)} feeds from configuration")
        else:
            # Initialize with default feeds
            cls.FEEDS = DEFAULT_FEED_CONFIGS
            logger.info(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
            
            # Save default feed configuration
            feed_config = {
                'feeds': cls.FEEDS,
                'update_interval_hours': cls.FEED_UPDATE_INTERVAL
            }
            SecretManager.update_secret('feed-config', feed_config)
        
        # Log configuration status
        logger.info(f"Configuration initialized with admin login: admin/{cls.ADMIN_PASSWORD}")
        logger.info(f"API Key: {cls.API_KEY[:4]}...{cls.API_KEY[-4:] if len(cls.API_KEY) > 8 else ''}")
        
        # Validate configuration
        cls.validate_configuration()
    
    @classmethod
    def configure_logging(cls):
        """Configure logging based on settings."""
        log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Add cloud logging if enabled
        if cls.LOG_TO_CLOUD and cls.GCP_PROJECT:
            try:
                from google.cloud.logging_v2 import Client as LoggingClient
                global _logging_client
                if _logging_client is None:
                    _logging_client = LoggingClient(project=cls.GCP_PROJECT)
                cloud_handler = _logging_client.get_default_handler()
                cloud_handler.setLevel(log_level)
                root_logger.addHandler(cloud_handler)
                logger.info("Cloud Logging enabled")
            except Exception as e:
                logger.warning(f"Failed to set up Cloud Logging: {e}")
    
    @classmethod
    def validate_configuration(cls):
        """Validate configuration values and print warnings for issues."""
        warnings = []
        errors = []
        
        if cls.ENVIRONMENT == 'production':
            if cls.SECRET_KEY == 'dev-secret-key':
                warnings.append("Production environment using default development secret key!")
            
            if cls.API_KEY == 'dev-api-key':
                warnings.append("Production environment using default development API key!")
            
            # Verify admin password is properly synchronized
            admin_password = SecretManager.get_secret('admin-initial-password')
            auth_config = SecretManager.get_secret('auth-config')
            
            if auth_config and isinstance(auth_config, dict) and 'users' in auth_config and 'admin' in auth_config['users']:
                admin_hash = auth_config['users']['admin'].get('password')
                expected_hash = hash_password(admin_password) if admin_password else None
                
                if admin_hash != expected_hash:
                    errors.append("Admin password hash mismatch between secrets! Authentication will fail.")
        
        if not cls.GCP_PROJECT:
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        for warning in warnings:
            logger.warning(warning)
        
        for error in errors:
            logger.error(error)
        
        return len(errors) == 0
    
    @classmethod
    def get_feed_by_id(cls, feed_id):
        """Get feed configuration by ID."""
        for feed in cls.FEEDS:
            if feed.get('id') == feed_id:
                return feed
        return None
    
    @classmethod
    def get_enabled_feeds(cls):
        """Get all enabled feed configurations."""
        return [feed for feed in cls.FEEDS if feed.get('enabled', True)]
    
    @classmethod
    def get_table_name(cls, table_key):
        """Get the full BigQuery table name including project and dataset."""
        if not cls.GCP_PROJECT or not cls.BIGQUERY_DATASET:
            return None
        
        table_name = cls.BIGQUERY_TABLES.get(table_key)
        if not table_name:
            return None
        
        return f"{cls.GCP_PROJECT}.{cls.BIGQUERY_DATASET}.{table_name}"
    
    @classmethod
    def ensure_feed_configuration(cls):
        """Ensure that the feed configuration exists and is valid."""
        feed_config = SecretManager.get_secret('feed-config')
        if not feed_config or not isinstance(feed_config, dict) or 'feeds' not in feed_config:
            logger.info("Creating default feed configuration")
            feed_config = {
                'feeds': DEFAULT_FEED_CONFIGS,
                'update_interval_hours': cls.FEED_UPDATE_INTERVAL
            }
            SecretManager.update_secret('feed-config', feed_config)
            cls.FEEDS = feed_config['feeds']
        return cls.FEEDS

# ===== Error Reporting =====
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting if enabled."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
    
    try:
        from google.cloud import error_reporting
        global _error_client
        if _error_client is None:
            _error_client = error_reporting.Client(project=Config.GCP_PROJECT)
        _error_client.report_exception()
    except Exception as e:
        logger.error(f"Failed to report error: {e}")

# ===== GCP Client Initialization =====
def initialize_bigquery():
    """Initialize and return a BigQuery client."""
    if 'bigquery' in _clients:
        return _clients['bigquery']
    
    try:
        from google.cloud import bigquery
        client = bigquery.Client(project=Config.GCP_PROJECT, location=Config.BIGQUERY_LOCATION)
        _clients['bigquery'] = client
        return client
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {e}")
        return None

def initialize_storage():
    """Initialize and return a Cloud Storage client."""
    if 'storage' in _clients:
        return _clients['storage']
    
    try:
        from google.cloud import storage
        client = storage.Client(project=Config.GCP_PROJECT)
        _clients['storage'] = client
        return client
    except Exception as e:
        logger.error(f"Failed to initialize Storage client: {e}")
        return None

def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients."""
    if 'publisher' in _clients and 'subscriber' in _clients:
        return _clients['publisher'], _clients['subscriber']
    
    try:
        from google.cloud import pubsub_v1
        publisher = pubsub_v1.PublisherClient()
        subscriber = pubsub_v1.SubscriberClient()
        
        _clients['publisher'] = publisher
        _clients['subscriber'] = subscriber
        
        return publisher, subscriber
    except Exception as e:
        logger.error(f"Failed to initialize PubSub clients: {e}")
        return None, None

def get_cached_config(name: str, force_refresh: bool = False):
    """Helper function to get cached config for other modules."""
    return SecretManager.get_secret(name, force_refresh)

def create_or_update_secret(name: str, value: Any):
    """Helper function to create or update a secret."""
    return SecretManager.update_secret(name, value)

# ===== Testing Utilities =====
def verify_admin_password_sync():
    """Verify and fix admin password synchronization."""
    # Get admin password
    admin_password = SecretManager.get_secret('admin-initial-password')
    if not admin_password:
        logger.error("Admin password not found!")
        return False
    
    # Get auth config
    auth_config = SecretManager.get_secret('auth-config')
    if not auth_config or not isinstance(auth_config, dict) or 'users' not in auth_config:
        logger.error("Auth config not found or invalid!")
        return False
    
    # Check admin user and password hash
    if 'admin' not in auth_config['users']:
        logger.error("Admin user not in auth_config!")
        return False
    
    correct_hash = hash_password(admin_password)
    current_hash = auth_config['users']['admin'].get('password')
    
    if current_hash != correct_hash:
        logger.error(f"Admin password hash mismatch! Authentication will fail.")
        logger.error(f"Password from admin-initial-password: {admin_password}")
        logger.error(f"Current hash in auth-config: {current_hash}")
        logger.error(f"Expected hash: {correct_hash}")
        
        # Fix the issue
        auth_config['users']['admin']['password'] = correct_hash
        SecretManager.update_secret('auth-config', auth_config)
        logger.info("Fixed admin password hash in auth_config")
        return True
    
    logger.info("Admin password is properly synchronized")
    return True

# Initialize configuration if imported
if __name__ != "__main__":
    # We don't initialize here to avoid circular imports, let the app do it
    pass

# Command-line testing functionality
if __name__ == "__main__":
    logger.info("Testing configuration module...")
    
    # Initialize Secret Manager
    SecretManager.init()
    
    # Check password synchronization
    verify_admin_password_sync()
    
    # Print configuration
    logger.info(f"Environment: {Config.ENVIRONMENT}")
    logger.info(f"GCP Project: {Config.GCP_PROJECT}")
    logger.info(f"Admin username: {Config.ADMIN_USERNAME}")
    logger.info("Configuration test complete")
