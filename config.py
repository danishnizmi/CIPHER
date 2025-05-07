"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management with cost-effective secret handling.
Uses environment variables with periodic cloud validation.
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
DEFAULT_SECRET_TTL = 86400  # 24 hours (previously 3600/1 hour)
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
    
    # Last resort - metadata server
    try:
        import requests
        response = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            headers={'Metadata-Flavor': 'Google'},
            timeout=2
        )
        if response.status_code == 200:
            project_id = response.text
            os.environ['GCP_PROJECT'] = project_id  # Cache in env var
            return project_id
    except Exception:
        pass
    
    # Default to a fallback ID if nothing else works
    fallback_id = os.environ.get('FALLBACK_PROJECT_ID', "primal-chariot-382610")
    logger.info(f"Using fallback project ID: {fallback_id}")
    return fallback_id

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

# ===== Secret Management with Cost Optimization =====
class SecretManager:
    """Manages secrets with cost-efficient cloud and environment variable strategy."""
    
    _cache = {}  # In-memory cache
    _cache_timestamp = {}  # Last refresh timestamps
    _offline_backups = {}  # Offline backups for secrets
    _last_cloud_check = None  # Last time we checked the cloud for updates
    _lock = threading.RLock()  # Lock for thread safety
    
    @classmethod
    def init(cls):
        """Initialize the secret manager."""
        # Load any secrets saved to disk from previous runs
        cls._load_offline_backups()
        # Initialize last cloud check timestamp
        cls._last_cloud_check = datetime.now() - timedelta(hours=25)  # Force initial check
        
    @classmethod
    def get_secret(cls, secret_id: str, force_refresh: bool = False) -> Any:
        """
        Get a secret with optimized fetching strategy.
        
        1. Try environment variables first (fastest)
        2. Check in-memory cache if environment variable not available
        3. Load from offline backup if cache miss and cloud check not needed
        4. Check cloud if cache expired or forced refresh
        """
        with cls._lock:
            # Step 1: Check environment variables (fastest, no cost)
            env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
            if env_var_name in os.environ:
                # Try to parse JSON if it's a JSON string
                try:
                    return json.loads(os.environ[env_var_name])
                except json.JSONDecodeError:
                    return os.environ[env_var_name]
            
            # Step 2: Check in-memory cache
            cached = cls._get_from_cache(secret_id)
            if cached is not None and not force_refresh:
                return cached
                
            # Step 3: Check if we need to refresh from cloud
            now = datetime.now()
            cloud_check_needed = (
                force_refresh or 
                (now - cls._last_cloud_check).total_seconds() > DEFAULT_SECRET_TTL
            )
            
            # Step 4: Get from cloud if needed, otherwise use offline backup
            if cloud_check_needed:
                # Update last cloud check time
                cls._last_cloud_check = now
                
                # Bundle cloud requests for efficiency
                all_secrets = cls._fetch_all_from_cloud()
                
                # If we got the secret we need from cloud, return it
                if secret_id in all_secrets:
                    cls._update_cache(secret_id, all_secrets[secret_id])
                    cls._update_offline_backup(secret_id, all_secrets[secret_id])
                    return all_secrets[secret_id]
            
            # Step 5: Fall back to offline backup
            backup = cls._get_from_offline_backup(secret_id)
            if backup is not None:
                cls._update_cache(secret_id, backup)
                return backup
                
            # Step 6: Last resort, use default values
            return cls._get_default_value(secret_id)
    
    @classmethod
    def _get_from_cache(cls, secret_id: str) -> Optional[Any]:
        """Get secret from in-memory cache if not expired."""
        if secret_id not in cls._cache:
            return None
            
        # Check if cache is expired
        if secret_id in cls._cache_timestamp:
            now = datetime.now()
            timestamp = cls._cache_timestamp[secret_id]
            if (now - timestamp).total_seconds() < DEFAULT_SECRET_TTL:
                return cls._cache[secret_id]
        
        return None
    
    @classmethod
    def _update_cache(cls, secret_id: str, value: Any):
        """Update in-memory cache."""
        cls._cache[secret_id] = value
        cls._cache_timestamp[secret_id] = datetime.now()
    
    @classmethod
    def _get_from_offline_backup(cls, secret_id: str) -> Optional[Any]:
        """Get secret from offline backup."""
        return cls._offline_backups.get(secret_id)
    
    @classmethod
    def _update_offline_backup(cls, secret_id: str, value: Any):
        """Update offline backup and persist to disk."""
        cls._offline_backups[secret_id] = value
        cls._save_offline_backups()
    
    @classmethod
    def _load_offline_backups(cls):
        """Load offline backups from disk."""
        backup_path = os.environ.get('SECRET_BACKUP_PATH', '/app/data/secret_backups.json')
        try:
            if os.path.exists(backup_path):
                with open(backup_path, 'r') as f:
                    cls._offline_backups = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load offline secret backups: {e}")
            cls._offline_backups = {}
    
    @classmethod
    def _save_offline_backups(cls):
        """Save offline backups to disk."""
        backup_path = os.environ.get('SECRET_BACKUP_PATH', '/app/data/secret_backups.json')
        try:
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            with open(backup_path, 'w') as f:
                json.dump(cls._offline_backups, f)
        except Exception as e:
            logger.warning(f"Could not save offline secret backups: {e}")
    
    @classmethod
    def _fetch_all_from_cloud(cls) -> Dict[str, Any]:
        """Fetch all secrets from cloud in one batch to reduce API calls."""
        results = {}
        
        # If we're configured to not use Secret Manager, skip cloud fetch
        if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            return results
        
        # List of essential secrets to fetch
        secret_ids = ['api-keys', 'auth-config', 'feed-config', 'admin-initial-password']
        
        # Initialize Secret Manager client if needed
        client = cls._get_secret_client()
        if not client:
            return results
            
        # Get project ID
        project_id = get_project_id()
        if not project_id:
            return results
        
        # Fetch all secrets
        for secret_id in secret_ids:
            try:
                name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
                response = client.access_secret_version(request={"name": name})
                secret_data = response.payload.data.decode("UTF-8")
                
                # Try to parse JSON
                try:
                    results[secret_id] = json.loads(secret_data)
                except json.JSONDecodeError:
                    results[secret_id] = secret_data
            except Exception as e:
                logger.debug(f"Could not fetch secret {secret_id}: {e}")
        
        return results
    
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
        except (ImportError, Exception) as e:
            logger.warning(f"Could not initialize Secret Manager client: {e}")
            return None
    
    @classmethod
    def _get_default_value(cls, secret_id: str) -> Any:
        """Get default value for a secret if all else fails."""
        if secret_id == 'api-keys':
            return {'platform_api_key': os.environ.get('API_KEY', 'dev-api-key')}
        elif secret_id == 'auth-config':
            return {
                'session_secret': os.environ.get('SECRET_KEY', 'dev-secret-key'),
                'enabled': True
            }
        elif secret_id == 'feed-config':
            return {'feeds': DEFAULT_FEED_CONFIGS}
        elif secret_id == 'admin-initial-password':
            return os.environ.get('ADMIN_PASSWORD', 'admin')
        return None
    
    @classmethod
    def update_secret(cls, secret_id: str, value: Any) -> bool:
        """
        Update a secret in the cloud and local caches.
        For cost efficiency, we update environment vars and caches immediately,
        but only push to cloud if forced or on a schedule.
        """
        # Serialize value to string if needed
        if not isinstance(value, str):
            value = json.dumps(value)
            
        # Update environment variable
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        os.environ[env_var_name] = value
        
        # Update caches
        cls._update_cache(secret_id, value)
        cls._update_offline_backup(secret_id, value)
        
        # Only push to cloud if we're not configured to use env vars
        if not get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            try:
                return cls._push_to_cloud(secret_id, value)
            except Exception as e:
                logger.warning(f"Could not push secret {secret_id} to cloud: {e}")
        
        return True
    
    @classmethod
    def _push_to_cloud(cls, secret_id: str, value: str) -> bool:
        """Push a secret to the cloud."""
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
                secret_exists = True
            except Exception:
                secret_exists = False
                
            # Create secret if it doesn't exist
            if not secret_exists:
                client.create_secret(
                    request={
                        "parent": f"projects/{project_id}",
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}}
                    }
                )
                
            # Add new version
            client.add_secret_version(
                request={
                    "parent": f"projects/{project_id}/secrets/{secret_id}",
                    "payload": {"data": value.encode("UTF-8")}
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error pushing secret to cloud: {e}")
            return False

# Initialize the secret manager
SecretManager.init()

# ===== Main Configuration Class =====
class Config:
    """Base configuration class with secure, cost-effective secret handling."""
    
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
    BIGQUERY_MAX_BYTES_BILLED = int(os.environ.get('BIGQUERY_MAX_BYTES_BILLED', 1073741824))  # 1GB
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
    USE_ENV_VARS_FOR_SECRETS = get_env_bool('USE_ENV_VARS_FOR_SECRETS', True)  # Default to true for cost savings
    SECRET_TTL = int(os.environ.get('SECRET_TTL', DEFAULT_SECRET_TTL))  # Default 24 hours
    
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
    
    # ===== Feed Configuration =====
    FEEDS = []  # Will be initialized in init_app
    FEED_UPDATE_INTERVAL = int(os.environ.get('FEED_UPDATE_INTERVAL', 3))  # hours
    
    # ===== Analysis Configuration =====
    ANALYSIS_ENABLED = get_env_bool('ANALYSIS_ENABLED', True)
    ANALYSIS_AUTO_ENRICH = get_env_bool('ANALYSIS_AUTO_ENRICH', True)
    
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
        
        # Initialize essential secrets with cost-effective strategy
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
        else:
            cls.SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
        
        # Initialize feed configuration
        cls.ensure_feed_configuration()
        
        # Validate configuration
        valid = cls.validate_configuration()
        if not valid:
            logger.warning("Configuration validation found issues but continuing")
    
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
                logging_client = LoggingClient(project=cls.GCP_PROJECT)
                cloud_handler = logging_client.get_default_handler()
                cloud_handler.setLevel(log_level)
                root_logger.addHandler(cloud_handler)
                logger.info("Cloud Logging enabled")
            except Exception as e:
                logger.warning(f"Failed to set up Cloud Logging: {e}")
    
    @classmethod
    def validate_configuration(cls):
        """Validate configuration values and return whether configuration is valid."""
        warnings = []
        errors = []
        
        if cls.ENVIRONMENT == 'production':
            if cls.SECRET_KEY == 'dev-secret-key':
                warnings.append("Production environment using default development secret key!")
            
            if cls.API_KEY == 'dev-api-key':
                warnings.append("Production environment using default development API key!")
        
        if not cls.GCP_PROJECT:
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        for warning in warnings:
            logger.warning(warning)
        
        for error in errors:
            logger.error(error)
        
        return len(errors) == 0
    
    @classmethod
    def ensure_feed_configuration(cls):
        """Ensure feed configuration is properly loaded."""
        # Skip if already loaded
        if cls.FEEDS and len(cls.FEEDS) > 0:
            logger.info(f"Using existing feed configuration with {len(cls.FEEDS)} feeds")
            return True
        
        # Try to load from secret manager
        feed_config = SecretManager.get_secret('feed-config')
        if feed_config and isinstance(feed_config, dict) and 'feeds' in feed_config and feed_config['feeds']:
            cls.FEEDS = feed_config['feeds']
            logger.info(f"Loaded {len(cls.FEEDS)} feeds from configuration")
            return True
        
        # Fall back to default feeds
        cls.FEEDS = DEFAULT_FEED_CONFIGS
        logger.info(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
        
        # Try to save this configuration
        feed_config = {
            "feeds": cls.FEEDS,
            "update_interval_hours": cls.FEED_UPDATE_INTERVAL
        }
        
        SecretManager.update_secret('feed-config', feed_config)
        return True
    
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

# ===== Error Reporting =====
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting if enabled."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
    
    try:
        from google.cloud import error_reporting
        client = error_reporting.Client(project=Config.GCP_PROJECT)
        client.report_exception()
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

# ===== Resource Management =====
def ensure_resource_exists(retry_on_failure=True):
    """Ensure GCP resources exist for the application."""
    import threading
    
    def delayed_resource_check():
        time.sleep(5)  # Wait for app startup
        
        # Check BigQuery dataset
        try:
            from google.cloud import bigquery
            bq_client = initialize_bigquery()
            if bq_client:
                dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
                try:
                    bq_client.get_dataset(dataset_id)
                    logger.info(f"BigQuery dataset {dataset_id} exists")
                except Exception:
                    # Create dataset
                    dataset = bigquery.Dataset(dataset_id)
                    dataset.location = Config.BIGQUERY_LOCATION
                    bq_client.create_dataset(dataset)
                    logger.info(f"Created BigQuery dataset {dataset_id}")
        except Exception as e:
            logger.error(f"Error checking BigQuery resources: {e}")
        
        # Check GCS bucket
        try:
            storage_client = initialize_storage()
            if storage_client:
                bucket = storage_client.bucket(Config.GCS_BUCKET)
                if not bucket.exists():
                    storage_client.create_bucket(bucket, location=Config.GCP_REGION)
                    logger.info(f"Created GCS bucket {Config.GCS_BUCKET}")
                else:
                    logger.info(f"GCS bucket {Config.GCS_BUCKET} exists")
        except Exception as e:
            logger.error(f"Error checking GCS resources: {e}")
    
    thread = threading.Thread(target=delayed_resource_check)
    thread.daemon = True
    thread.start()

# ===== Module Initialization =====
if __name__ != "__main__":
    # Auto-initialize configuration when imported
    if get_env_bool('ENSURE_GCP_RESOURCES', False):
        ensure_resource_exists()
