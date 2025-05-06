"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management, Google Cloud client initialization, and secret management.
Cost-optimized to reduce Secret Manager, Cloud Run, and overall resource usage.
"""

import os
import sys
import json
import logging
import tempfile
import hashlib
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from functools import wraps, lru_cache

# Global client variables
_clients = {}
_logging_client = None
_error_client = None
_secret_client = None
_redis_client = None
_vertex_client = None

# Google Cloud imports with safe fallbacks
HAS_GCP = True
HAS_VERTEX = False
try:
    from google.cloud import secretmanager, storage, bigquery, pubsub_v1, error_reporting
    from google.cloud.logging_v2 import Client as LoggingClient
    from google.cloud.exceptions import NotFound, Forbidden, BadRequest, Conflict
    from google.api_core.exceptions import GoogleAPIError, PermissionDenied, ResourceExhausted, NotFound as ApiNotFound
    from google.auth.exceptions import DefaultCredentialsError, TransportError
    import google.auth
    try:
        import vertexai
        from vertexai.language_models import TextGenerationModel
        from vertexai.preview.generative_models import GenerativeModel
        HAS_VERTEX = True
    except ImportError:
        HAS_VERTEX = False
except ImportError as e:
    HAS_GCP = False
    print(f"Warning: Google Cloud libraries not installed: {e}")

# Redis (for production caching)
HAS_REDIS = False
try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

# Add the missing GCP_SERVICES_AVAILABLE attribute
GCP_SERVICES_AVAILABLE = HAS_GCP

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_API_RATE_LIMIT = "200 per day, 50 per hour"
DEFAULT_ADMIN_USERNAME = "admin"
FEED_TYPES = ["indicators", "vulnerabilities", "threat_actors", "campaigns", "malware"]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
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

# Utility Functions
@lru_cache(maxsize=1)
def get_project_id() -> Optional[str]:
    """Get Google Cloud project ID from environment or GCP metadata with improved error handling."""
    project_id = os.environ.get('GCP_PROJECT')
    if project_id:
        return project_id
    
    if HAS_GCP:
        try:
            credentials, project_id = google.auth.default()
            if project_id:
                os.environ['GCP_PROJECT'] = project_id
                return project_id
        except (DefaultCredentialsError, TransportError) as e:
            logger.debug(f"Unable to determine GCP project ID from metadata: {str(e)}")
        except Exception as e:
            logger.debug(f"Unexpected error getting project ID: {str(e)}")
    
    try:
        import requests
        response = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            headers={'Metadata-Flavor': 'Google'},
            timeout=2
        )
        if response.status_code == 200:
            project_id = response.text
            os.environ['GCP_PROJECT'] = project_id
            return project_id
    except Exception:
        pass
    
    fallback_id = "primal-chariot-382610"
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

def should_ignore_permission_errors() -> bool:
    """Check if permission errors should be ignored."""
    return get_env_bool('IGNORE_PERMISSION_ERRORS', False)

# Decorators
def handle_gcp_errors(func):
    """Decorator to handle GCP errors consistently."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionDenied as e:
            if should_ignore_permission_errors():
                logger.warning(f"Permission denied in {func.__name__}, but continuing: {str(e)}")
                return None
            else:
                logger.error(f"Permission denied in {func.__name__}. Check service account roles: {str(e)}")
                raise
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            if os.environ.get('ENVIRONMENT') != 'production':
                import traceback
                logger.error(traceback.format_exc())
            report_error(e)
            return None
    return wrapper

def cache_client(client_name: str):
    """Decorator to cache GCP clients."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global _clients
            if client_name in _clients and _clients[client_name] is not None:
                return _clients[client_name]
            
            client = func(*args, **kwargs)
            if client is not None:
                _clients[client_name] = client
            return client
        return wrapper
    return decorator

# Base Client Manager
class ClientManager:
    """Base class for managing GCP clients."""
    
    @staticmethod
    def get_client(client_type: str, constructor_func, *args, **kwargs):
        """Generic client getter with caching and error handling."""
        client_key = f"_{client_type}_client"
        
        if not HAS_GCP:
            logger.warning(f"Google Cloud libraries not installed, cannot initialize {client_type}")
            return None
        
        try:
            client = constructor_func(*args, **kwargs)
            if client:
                logger.info(f"{client_type} client initialized successfully")
            return client
        except Exception as e:
            logger.error(f"Failed to initialize {client_type} client: {str(e)}")
            return None

# GCP Service Initialization Functions
@cache_client('bigquery')
@handle_gcp_errors
def initialize_bigquery():
    """Initialize and return a BigQuery client with improved error handling."""
    project_id = get_project_id()
    if not project_id:
        logger.error("Project ID not available, cannot initialize BigQuery client")
        return None
    
    try:
        # Create the client with explicit location
        client = bigquery.Client(
            project=project_id, 
            location=Config.BIGQUERY_LOCATION if hasattr(Config, 'BIGQUERY_LOCATION') else 'US'
        )
        
        # Test client by running a simple query
        test_query = "SELECT 1"
        test_job = client.query(test_query, job_config=bigquery.QueryJobConfig(maximum_bytes_billed=1048576)) # 1MB limit for test
        test_result = list(test_job.result())
        
        if test_result and len(test_result) == 1 and test_result[0][0] == 1:
            logger.info("BigQuery client initialized and tested successfully")
            return client
        else:
            logger.error("BigQuery client test query failed")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

@cache_client('storage')
@handle_gcp_errors
def initialize_storage():
    """Initialize and return a Cloud Storage client with error handling."""
    project_id = get_project_id()
    if not project_id:
        logger.error("Project ID not available, cannot initialize Storage client")
        return None
    
    return storage.Client(project=project_id)

@cache_client('pubsub')
@handle_gcp_errors
def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients with error handling."""
    global _publisher, _subscriber
    
    if ('_publisher' in _clients and _clients['_publisher'] is not None and 
        '_subscriber' in _clients and _clients['_subscriber'] is not None):
        return _clients['_publisher'], _clients['_subscriber']
    
    try:
        _publisher = pubsub_v1.PublisherClient()
        _subscriber = pubsub_v1.SubscriberClient()
        
        _clients['_publisher'] = _publisher
        _clients['_subscriber'] = _subscriber
        
        logger.info("PubSub clients initialized successfully")
        return _publisher, _subscriber
    except Exception as e:
        logger.error(f"Failed to initialize PubSub clients: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None, None

@cache_client('error_reporting')
@handle_gcp_errors
def initialize_error_reporting(project_id: str = None):
    """Initialize Google Cloud Error Reporting."""
    if project_id is None:
        project_id = get_project_id()
        if not project_id:
            logger.error("Project ID not available, cannot initialize Error Reporting")
            return None
    
    return error_reporting.Client(project=project_id)

@cache_client('secretmanager')
@handle_gcp_errors
def initialize_secret_manager():
    """Initialize and return a Secret Manager client with error handling."""
    # Only initialize if we're running in a cloud environment
    if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
        logger.info("Using environment variables for secrets, not initializing Secret Manager")
        return None
    
    return secretmanager.SecretManagerServiceClient()

# Centralized Error Reporting
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting."""
    if not os.environ.get('ENABLE_ERROR_REPORTING', 'false').lower() == 'true':
        return
    
    client = initialize_error_reporting()
    if client:
        try:
            client.report_exception()
        except Exception as e:
            logger.error(f"Failed to report error: {str(e)}")

# Secret Management Functions with Cost Optimization
@handle_gcp_errors
def access_secret(secret_id: str, version_id: str = "latest") -> Optional[Any]:
    """
    Access secrets from environment variables first, then Google Cloud Secret Manager.
    
    This optimized function prioritizes environment variables for non-sensitive configs
    to reduce Secret Manager costs.
    """
    # First check environment variables (most cost-efficient)
    env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
    if os.environ.get(env_var_name):
        logger.info(f"Using environment variable {env_var_name} as fallback for secret {secret_id}")
        secret_value = os.environ.get(env_var_name)
        try:
            # Try to parse as JSON if applicable
            return json.loads(secret_value)
        except json.JSONDecodeError:
            # Return as string if not JSON
            return secret_value
    
    # Check if we should use Secret Manager at all
    if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
        logger.debug(f"Configured to use only environment variables for secrets, not accessing Secret Manager for {secret_id}")
        return None
    
    # Initialize Secret Manager only if needed
    secret_client = initialize_secret_manager()
    if not secret_client:
        logger.debug(f"Secret Manager client not available, checking environment variables for {secret_id}")
        for env_name, env_value in os.environ.items():
            # Check for possible matches in environment
            if secret_id.lower() in env_name.lower():
                logger.info(f"Using environment variable {env_name} as potential match for secret {secret_id}")
                try:
                    return json.loads(env_value)
                except json.JSONDecodeError:
                    return env_value
        return None
    
    project_id = get_project_id()
    if not project_id:
        logger.warning(f"Unable to access secret {secret_id}: No project ID available")
        return None
    
    try:
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = secret_client.access_secret_version(request={"name": name})
        secret_data = response.payload.data.decode("UTF-8")
        
        try:
            return json.loads(secret_data)
        except json.JSONDecodeError:
            return secret_data
    except NotFound as e:
        logger.debug(f"Secret {secret_id} not found in project {project_id}")
        # Try to create default config if it's a standard config secret
        if secret_id == 'feed-config':
            if create_default_feed_config():
                return access_secret(secret_id, version_id)
        elif secret_id == 'auth-config':
            if create_default_auth_config():
                return access_secret(secret_id, version_id)
        logger.debug(f"Secret {secret_id} not found and could not be created")
        return None
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {str(e)}")
        return None

# Cached Config Management
class ConfigCache:
    """Centralized configuration cache management with optimized storage."""
    _cache = {}
    _last_refresh = {}
    _cache_ttl = 3600  # 1 hour TTL to reduce Secret Manager calls
    
    @classmethod
    def get(cls, key: str, force_refresh: bool = False) -> Optional[Dict]:
        """Get and cache configuration from Secret Manager or environment variables."""
        cache_key = f"_cached_{key.replace('-', '_')}"
        
        # Return from cache if it's still valid
        if (not force_refresh and 
            cache_key in cls._cache and 
            key in cls._last_refresh and 
            (time.time() - cls._last_refresh[key]) < cls._cache_ttl):
            return cls._cache[cache_key]
        
        # Try environment variables first (cost optimization)
        env_var_name = f"SECRET_{key.replace('-', '_').upper()}"
        if os.environ.get(env_var_name):
            try:
                config_data = os.environ.get(env_var_name)
                try:
                    config_data = json.loads(config_data)
                except json.JSONDecodeError:
                    pass
                    
                if config_data:
                    cls._cache[cache_key] = config_data
                    cls._last_refresh[key] = time.time()
                    return config_data
            except Exception:
                pass
        
        # Fall back to Secret Manager if environment variable not available
        config_data = access_secret(key)
        if config_data:
            cls._cache[cache_key] = config_data
            cls._last_refresh[key] = time.time()
        
        return config_data
    
    @classmethod
    def clear(cls, key: Optional[str] = None):
        """Clear cached configuration."""
        if key:
            cache_key = f"_cached_{key.replace('-', '_')}"
            if cache_key in cls._cache:
                del cls._cache[cache_key]
            if key in cls._last_refresh:
                del cls._last_refresh[key]
        else:
            cls._cache.clear()
            cls._last_refresh.clear()

# Simplified config access function
def get_cached_config(secret_id: str, force_refresh: bool = False) -> Optional[Dict]:
    """Get and cache configuration from environment variables or Secret Manager."""
    return ConfigCache.get(secret_id, force_refresh)

# Configuration Class
class Config:
    """Base configuration class with common settings."""
    
    # Basic Flask configuration
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    
    # Environment and version
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    VERSION = os.environ.get('VERSION', '1.0.0')
    
    # Host and port configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))
    
    # Google Cloud configuration
    GCP_PROJECT = get_project_id()
    GCP_REGION = os.environ.get('GCP_REGION', 'us-central1')
    
    # BigQuery configuration
    BIGQUERY_DATASET = os.environ.get('BIGQUERY_DATASET', 'threat_intelligence')
    BIGQUERY_TABLES = {
        'indicators': 'indicators',
        'vulnerabilities': 'vulnerabilities',
        'threat_actors': 'threat_actors',
        'campaigns': 'campaigns',
        'malware': 'malware',
        'users': 'users',
        'audit_log': 'audit_log'
    }
    BIGQUERY_LOCATION = os.environ.get('BIGQUERY_LOCATION', 'US')
    
    # BigQuery cost controls
    BIGQUERY_MAX_BYTES_BILLED = int(os.environ.get('BIGQUERY_MAX_BYTES_BILLED', 1073741824))  # 1GB default
    
    # Storage configuration
    GCS_BUCKET = os.environ.get('GCS_BUCKET', f"{GCP_PROJECT}-threat-data" if GCP_PROJECT else 'threat-data')
    GCS_RAW_DATA_PREFIX = 'raw'
    GCS_PROCESSED_DATA_PREFIX = 'processed'
    GCS_EXPORT_PREFIX = 'exports'
    GCS_TEMP_PREFIX = 'temp'
    
    # PubSub configuration
    PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', 'threat-data-ingestion')
    PUBSUB_SUBSCRIPTION = os.environ.get('PUBSUB_SUBSCRIPTION', 'threat-data-ingestion-sub')
    PUBSUB_ANALYSIS_TOPIC = os.environ.get('PUBSUB_ANALYSIS_TOPIC', 'threat-analysis-events')
    PUBSUB_ANALYSIS_SUBSCRIPTION = os.environ.get(
        'PUBSUB_ANALYSIS_SUBSCRIPTION', 'threat-analysis-events-sub'
    )
    
    # API configuration
    API_KEY = os.environ.get('API_KEY', 'dev-api-key')
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    API_RATE_LIMIT = os.environ.get('API_RATE_LIMIT', DEFAULT_API_RATE_LIMIT)
    API_RATE_LIMIT_EXEMPT_IPS = get_env_list('API_RATE_LIMIT_EXEMPT_IPS', ['127.0.0.1'])
    API_CORS_ORIGINS = get_env_list('API_CORS_ORIGINS', ['*'])
    API_MAX_PAGE_SIZE = int(os.environ.get('API_MAX_PAGE_SIZE', 1000))
    API_DEFAULT_PAGE_SIZE = int(os.environ.get('API_DEFAULT_PAGE_SIZE', 100))
    
    # Authentication configuration
    AUTH_ENABLED = get_env_bool('AUTH_ENABLED', True)
    AUTH_SESSION_TIMEOUT = int(os.environ.get('AUTH_SESSION_TIMEOUT', 12 * 60 * 60))  # 12 hours in seconds
    AUTH_REQUIRED_ROUTES = ['/dashboard', '/admin', '/api/admin']
    AUTH_PUBLIC_ROUTES = ['/', '/login', '/logout', '/health', '/api/health', '/static']
    AUTH_USERNAME_FIELD = 'username'
    AUTH_PASSWORD_FIELD = 'password'
    
    # Admin configuration
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', DEFAULT_ADMIN_USERNAME)
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', None)
    
    # Session configuration - Cloud-based
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=AUTH_SESSION_TIMEOUT)
    SESSION_COOKIE_NAME = 'threat_intelligence_session'
    SESSION_COOKIE_SECURE = get_env_bool('SESSION_COOKIE_SECURE', True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'threat_intel:'
    SESSION_COOKIE_DOMAIN = None
    SESSION_COOKIE_PATH = '/'
    SESSION_REFRESH_EACH_REQUEST = False
    REMEMBER_COOKIE_DURATION = timedelta(seconds=AUTH_SESSION_TIMEOUT)
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_REFRESH_EACH_REQUEST = False
    SESSION_PROTECTION = 'basic'
    
    # Security configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', SECRET_KEY)
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_CLOUD = get_env_bool('LOG_TO_CLOUD', False)
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Error reporting configuration
    ENABLE_ERROR_REPORTING = get_env_bool('ENABLE_ERROR_REPORTING', False)
    
    # Threat intelligence feed configuration
    FEEDS = []
    FEED_UPDATE_INTERVAL = int(os.environ.get('FEED_UPDATE_INTERVAL', 3))  # hours
    DEFAULT_FEED_CONFIDENCE = 70  # Default confidence level (0-100)
    
    # Analysis configuration
    ANALYSIS_ENABLED = get_env_bool('ANALYSIS_ENABLED', True)
    ANALYSIS_AUTO_ENRICH = get_env_bool('ANALYSIS_AUTO_ENRICH', True)
    ANALYSIS_CONFIDENCE_THRESHOLD = int(os.environ.get('ANALYSIS_CONFIDENCE_THRESHOLD', 60))
    ANALYSIS_MAX_INDICATORS_PER_BATCH = int(os.environ.get('ANALYSIS_MAX_INDICATORS_PER_BATCH', 1000))
    
    # Natural Language Processing configuration
    NLP_ENABLED = get_env_bool('NLP_ENABLED', True)
    NLP_MIN_CONFIDENCE = float(os.environ.get('NLP_MIN_CONFIDENCE', 0.7))
    
    # Vertex AI configuration
    VERTEXAI_LOCATION = os.environ.get('VERTEXAI_LOCATION', 'us-central1')
    VERTEXAI_MODEL = os.environ.get('VERTEXAI_MODEL', 'text-bison')
    
    # Frontend configuration
    TEMPLATES_AUTO_RELOAD = get_env_bool('TEMPLATES_AUTO_RELOAD', False)
    FRONTEND_THEME = os.environ.get('FRONTEND_THEME', 'default')
    
    # Cache configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'SimpleCache')
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 300))
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
    
    # Export configuration
    EXPORT_FORMATS = ['csv', 'json', 'stix']
    MAX_EXPORT_SIZE = int(os.environ.get('MAX_EXPORT_SIZE', 100000))
    
    # Ignore permission errors
    IGNORE_PERMISSION_ERRORS = get_env_bool('IGNORE_PERMISSION_ERRORS', False)
    
    # Auto ingestion and analysis flags
    AUTO_INGEST = get_env_bool('AUTO_INGEST', True)
    AUTO_ANALYZE = get_env_bool('AUTO_ANALYZE', True)
    
    # COST OPTIMIZED CONFIG: Secret Management Options
    USE_ENV_VARS_FOR_SECRETS = get_env_bool('USE_ENV_VARS_FOR_SECRETS', False)
    SECRETS_CACHE_TTL = int(os.environ.get('SECRETS_CACHE_TTL', 3600))  # 1 hour by default
    CONSOLIDATED_SECRETS = get_env_bool('CONSOLIDATED_SECRETS', True)  # Use single secrets for multiple values
    
    # Centralized Methods
    @classmethod
    def configure_logging(cls):
        """Configure logging based on settings."""
        try:
            log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)
            root_logger = logging.getLogger()
            root_logger.setLevel(log_level)
            
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            formatter = logging.Formatter(cls.LOG_FORMAT)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
            
            if cls.LOG_TO_CLOUD and cls.GCP_PROJECT and HAS_GCP:
                try:
                    global _logging_client
                    if _logging_client is None:
                        _logging_client = LoggingClient(project=cls.GCP_PROJECT)
                    cloud_handler = _logging_client.get_default_handler()
                    cloud_handler.setLevel(log_level)
                    root_logger.addHandler(cloud_handler)
                    logger.info("Cloud Logging enabled")
                except Exception as e:
                    logger.error(f"Failed to set up Cloud Logging: {str(e)}")
        except Exception as e:
            print(f"Error configuring logging: {str(e)}")
    
    @classmethod
    def initialize_error_reporting(cls):
        """Initialize Google Cloud Error Reporting."""
        if not cls.ENABLE_ERROR_REPORTING or not cls.GCP_PROJECT or not HAS_GCP:
            return None
        
        return initialize_error_reporting(cls.GCP_PROJECT)
    
    @classmethod
    def validate_configuration(cls):
        """Validate configuration values and check GCP permissions."""
        warnings = []
        errors = []
        
        if cls.ENVIRONMENT == 'production':
            if cls.SECRET_KEY == 'dev-secret-key':
                warnings.append("Production environment using default development secret key!")
            
            if cls.API_KEY == 'dev-api-key':
                warnings.append("Production environment using default development API key!")
            
            if not cls.SESSION_COOKIE_SECURE:
                warnings.append("Session cookies not set to secure in production!")
        
        if not cls.GCP_PROJECT:
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        # Test BigQuery connection if configuration is critical
        if cls.GCP_PROJECT and HAS_GCP:
            bq_client = initialize_bigquery()
            if not bq_client:
                warnings.append("Could not initialize BigQuery client")
        
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
    def get_feeds_by_schedule(cls, schedule):
        """Get feeds configured for a specific schedule."""
        return [feed for feed in cls.FEEDS if feed.get('schedule') == schedule and feed.get('enabled', True)]
    
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
    def get_gcs_path(cls, prefix, filename=None):
        """Construct a GCS path with the given prefix and optional filename."""
        if not cls.GCS_BUCKET:
            return None
        
        path = f"gs://{cls.GCS_BUCKET}/{prefix}"
        if filename:
            path = f"{path}/{filename}"
        
        return path
    
    @classmethod
    def get_pubsub_topic_path(cls, topic_name):
        """Get full path for a Pub/Sub topic."""
        if not cls.GCP_PROJECT:
            return None
        
        return f"projects/{cls.GCP_PROJECT}/topics/{topic_name}"
    
    @classmethod
    def get_pubsub_subscription_path(cls, subscription_name):
        """Get full path for a Pub/Sub subscription."""
        if not cls.GCP_PROJECT:
            return None
        
        return f"projects/{cls.GCP_PROJECT}/subscriptions/{subscription_name}"
    
    @classmethod
    def get_feed_config_from_secret(cls):
        """Retrieve feed configuration from Secret Manager or environment with cost optimization."""
        try:
            # Try environment variable first (cost-efficient)
            env_feed_config = os.environ.get('FEED_CONFIG')
            if env_feed_config:
                try:
                    feed_config = json.loads(env_feed_config)
                    if isinstance(feed_config, dict) and 'feeds' in feed_config:
                        logger.info("Successfully loaded feed configuration from environment variable")
                        return feed_config
                except json.JSONDecodeError:
                    logger.warning("Failed to parse FEED_CONFIG environment variable")
            
            # Then try Secret Manager
            feed_config = access_secret("feed-config")
            
            if feed_config and isinstance(feed_config, dict):
                logger.info("Successfully loaded feed configuration from Secret Manager")
                return feed_config
            else:
                logger.warning("Failed to load valid feed configuration from Secret Manager")
                return None
        except Exception as e:
            logger.error(f"Error retrieving feed configuration: {str(e)}")
            return None
    
    @classmethod
    def ensure_feed_configuration(cls):
        """Ensure feed configuration is properly loaded."""
        # First check if FEEDS is already populated
        if cls.FEEDS and len(cls.FEEDS) > 0:
            logger.info(f"Using existing feed configuration with {len(cls.FEEDS)} feeds")
            return True
        
        # Try to load from environment or Secret Manager
        feed_config = cls.get_feed_config_from_secret()
        if feed_config and 'feeds' in feed_config and feed_config['feeds']:
            cls.FEEDS = feed_config['feeds']
            logger.info(f"Loaded {len(cls.FEEDS)} feeds from configuration source")
            return True
        
        # Fall back to environment variable
        if os.environ.get('FEED_CONFIG'):
            try:
                feed_config = json.loads(os.environ.get('FEED_CONFIG'))
                if 'feeds' in feed_config and feed_config['feeds']:
                    cls.FEEDS = feed_config['feeds']
                    logger.info(f"Loaded {len(cls.FEEDS)} feeds from environment variable")
                    return True
            except json.JSONDecodeError:
                logger.warning("Failed to parse feed configuration from environment variable")
        
        # Last resort: use default feeds
        try:
            # Import here to avoid circular import
            from ingestion import DEFAULT_FEEDS
            cls.FEEDS = DEFAULT_FEEDS
            logger.info(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
        except ImportError:
            # If import fails, use the constants defined at the top of this file
            cls.FEEDS = DEFAULT_FEED_CONFIGS
            logger.info(f"Using builtin default feed configuration with {len(cls.FEEDS)} feeds")
        
        # Try to save this configuration as environment variable for future use
        try:
            feed_config = {
                "feeds": cls.FEEDS,
                "update_interval_hours": cls.FEED_UPDATE_INTERVAL,
                "default_tags": cls.FEED_DEFAULT_TAGS if hasattr(cls, 'FEED_DEFAULT_TAGS') else []
            }
            os.environ['FEED_CONFIG'] = json.dumps(feed_config)
            logger.info("Saved default feed configuration to environment variable")
            
            # Only save to Secret Manager if necessary and not using env vars
            if not cls.USE_ENV_VARS_FOR_SECRETS:
                create_or_update_secret("feed-config", json.dumps(feed_config, indent=2))
                logger.info("Saved default feed configuration to Secret Manager")
        except Exception as e:
            logger.warning(f"Failed to save feed configuration: {str(e)}")
        
        return True
    
    @classmethod
    def init_secrets(cls):
        """Initialize configuration from environment variables or Secret Manager."""
        # First check if we should skip Secret Manager entirely
        if cls.USE_ENV_VARS_FOR_SECRETS:
            logger.info("Using environment variables for secrets")
            try:
                # Set up API keys from environment
                cls.API_KEY = os.environ.get('API_KEY', cls.API_KEY)
                cls.SECRET_KEY = os.environ.get('SECRET_KEY', cls.SECRET_KEY)
                cls.WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', cls.SECRET_KEY)
                
                # Set up session secret from environment
                cls.SESSION_SECRET = os.environ.get('SESSION_SECRET', cls.SECRET_KEY)
                
                # Ensure feed configuration
                cls.ensure_feed_configuration()
                
                # Load admin password if available
                cls.ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', cls.ADMIN_PASSWORD)
                
                return
            except Exception as e:
                logger.warning(f"Error loading from environment variables: {str(e)}")
        
        # Fall back to Secret Manager if needed and available
        if not cls.GCP_PROJECT or not HAS_GCP:
            logger.info("Skipping secret initialization - not in GCP environment or missing libraries")
            try:
                create_default_feed_config()
                create_default_auth_config()
            except Exception as e:
                logger.warning(f"Failed to create default configurations: {str(e)}")
            return
        
        try:
            # Load API keys
            api_keys = access_secret('api-keys')
            if api_keys and isinstance(api_keys, dict):
                platform_api_key = api_keys.get('platform_api_key')
                if platform_api_key:
                    cls.API_KEY = platform_api_key
                
                cls.EXTERNAL_API_KEYS = {
                    k: v for k, v in api_keys.items() if k != 'platform_api_key'
                }
                logger.info("Loaded API keys from Secret Manager")
            
            # Load authentication configuration
            auth_config = access_secret('auth-config')
            if auth_config and isinstance(auth_config, dict):
                cls.AUTH_ENABLED = auth_config.get('enabled', cls.AUTH_ENABLED)
                cls.SESSION_SECRET = auth_config.get('session_secret')
                
                if cls.SESSION_SECRET:
                    cls.SECRET_KEY = cls.SESSION_SECRET
                    cls.WTF_CSRF_SECRET_KEY = cls.SESSION_SECRET
                    logger.info("Loaded session secret from Secret Manager")
                else:
                    # Generate a secure session secret if not provided
                    import secrets
                    cls.SESSION_SECRET = secrets.token_hex(32)
                    cls.SECRET_KEY = cls.SESSION_SECRET
                    cls.WTF_CSRF_SECRET_KEY = cls.SESSION_SECRET
                    logger.warning("Generated new session secret - this should be stored in Secret Manager")
                
                if 'providers' in auth_config:
                    cls.AUTH_PROVIDERS = auth_config['providers']
                
                logger.info("Loaded authentication configuration from Secret Manager")
            
            # Ensure feed configuration is loaded
            cls.ensure_feed_configuration()
            
            # Load admin password if available
            admin_password = access_secret('admin-initial-password')
            if admin_password:
                cls.ADMIN_PASSWORD = admin_password
                logger.info("Loaded admin password from Secret Manager")
                
        except Exception as e:
            logger.error(f"Error initializing secrets: {str(e)}")
            if cls.IGNORE_PERMISSION_ERRORS:
                create_default_feed_config()
                create_default_auth_config()
    
    @classmethod
    def init_app(cls):
        """Initialize application configuration with fault tolerance."""
        try:
            cls.configure_logging()
            logger.info("Logging configured")
        except Exception as e:
            print(f"Error configuring logging: {str(e)}")
        
        try:
            if get_env_bool('LOAD_SECRETS', True):
                cls.init_secrets()
                logger.info("Secrets initialized")
        except Exception as e:
            logger.warning(f"Error initializing secrets: {str(e)}")
            # Continue without secrets if needed
        
        try:
            cls.initialize_error_reporting()
            logger.info("Error reporting initialized")
        except Exception as e:
            logger.warning(f"Error reporting initialization failed: {str(e)}")
        
        try:
            valid = cls.validate_configuration()
            if not valid:
                logger.warning("Configuration validation failed but continuing")
        except Exception as e:
            logger.warning(f"Configuration validation failed: {str(e)}")
        
        logger.info(f"Initialized {cls.ENVIRONMENT} configuration")
    
    @classmethod
    def test_bigquery_connection(cls):
        """Test BigQuery connection and create dataset if it doesn't exist."""
        if not cls.GCP_PROJECT:
            logger.warning("Cannot test BigQuery connection: No project ID available")
            return False
        
        try:
            bq_client = initialize_bigquery()
            if not bq_client:
                logger.error("Failed to initialize BigQuery client")
                return False
            
            # Test simple query with cost controls
            try:
                query_job = bq_client.query(
                    "SELECT 1", 
                    job_config=bigquery.QueryJobConfig(
                        maximum_bytes_billed=1048576  # 1MB limit for test query
                    )
                )
                query_job.result()
                logger.info("BigQuery connection test successful")
            except Exception as e:
                logger.error(f"BigQuery query test failed: {str(e)}")
                return False
            
            # Try to create dataset if it doesn't exist
            try:
                dataset_id = f"{cls.GCP_PROJECT}.{cls.BIGQUERY_DATASET}"
                try:
                    bq_client.get_dataset(dataset_id)
                    logger.info(f"BigQuery dataset {cls.BIGQUERY_DATASET} already exists")
                except NotFound:
                    # Create dataset
                    dataset = bigquery.Dataset(dataset_id)
                    dataset.location = cls.BIGQUERY_LOCATION
                    bq_client.create_dataset(dataset)
                    logger.info(f"Created BigQuery dataset {cls.BIGQUERY_DATASET}")
            except Exception as e:
                logger.warning(f"Failed to ensure BigQuery dataset exists: {str(e)}")
                if not cls.IGNORE_PERMISSION_ERRORS:
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Error testing BigQuery connection: {str(e)}")
            return False

# Helper Functions
def get_config():
    """Return the current configuration."""
    return Config

def get_gcp_clients():
    """Get a dictionary of initialized GCP clients."""
    return {
        "bigquery": initialize_bigquery(),
        "storage": initialize_storage(),
        "pubsub": initialize_pubsub(),
        "error_reporting": initialize_error_reporting()
    }

def create_default_feed_config() -> bool:
    """Create a default feed configuration if it doesn't exist."""
    try:
        # First check if we can use environment variable
        if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            feed_config = {
                "feeds": DEFAULT_FEED_CONFIGS,
                "update_interval_hours": 6,
                "default_tags": [],
                "user_agent": f"ThreatIntelligencePlatform/{os.environ.get('VERSION', '1.0.0')}",
                "request_timeout": 30,
                "max_retries": 3
            }
            os.environ['FEED_CONFIG'] = json.dumps(feed_config)
            logger.info("Created default feed-config in environment variable")
            Config.FEEDS = DEFAULT_FEED_CONFIGS
            return True
            
        # Otherwise use Secret Manager if needed
        feed_config = access_secret("feed-config")
        if feed_config:
            logger.info("Feed configuration already exists in Secret Manager")
            return True
        
        feed_config = {
            "feeds": DEFAULT_FEED_CONFIGS,
            "update_interval_hours": 6,
            "default_tags": [],
            "user_agent": f"ThreatIntelligencePlatform/{os.environ.get('VERSION', '1.0.0')}",
            "request_timeout": 30,
            "max_retries": 3
        }
        
        success = create_or_update_secret("feed-config", json.dumps(feed_config, indent=2))
        if success:
            logger.info("Created default feed-config in Secret Manager")
            return True
        
        if should_ignore_permission_errors():
            logger.warning("Using in-memory fallback for feed-config")
            Config.FEEDS = DEFAULT_FEED_CONFIGS
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error creating default feed config: {str(e)}")
        return False

def create_default_auth_config() -> bool:
    """Create a default auth configuration if it doesn't exist."""
    try:
        # First check if we can use environment variable
        if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
            import secrets
            session_secret = secrets.token_hex(32)
            auth_config = {
                "session_secret": session_secret,
                "enabled": True,
                "users": {
                    "admin": {
                        "password": hashlib.sha256("admin".encode()).hexdigest(),
                        "role": "admin", 
                        "created_at": datetime.utcnow().isoformat()
                    }
                }
            }
            os.environ['SECRET_KEY'] = session_secret
            os.environ['WTF_CSRF_SECRET_KEY'] = session_secret
            os.environ['SECRET_AUTH_CONFIG'] = json.dumps(auth_config)
            logger.info("Created default auth-config in environment variables")
            return True
        
        # Otherwise use Secret Manager
        auth_config = access_secret("auth-config")
        if auth_config:
            logger.info("Auth configuration already exists in Secret Manager")
            return True
        
        import secrets
        session_secret = secrets.token_hex(32)
        auth_config = {
            "session_secret": session_secret,
            "enabled": True,
            "users": {
                "admin": {
                    "password": hashlib.sha256("admin".encode()).hexdigest(),
                    "role": "admin", 
                    "created_at": datetime.utcnow().isoformat()
                }
            }
        }
        
        success = create_or_update_secret("auth-config", json.dumps(auth_config, indent=2))
        if success:
            logger.info("Created default auth-config in Secret Manager")
            return True
        
        if should_ignore_permission_errors():
            logger.warning("Using in-memory fallback for auth-config")
            Config.SECRET_KEY = session_secret
            Config.WTF_CSRF_SECRET_KEY = session_secret
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error creating default auth config: {str(e)}")
        return False

def create_or_update_secret(secret_id: str, secret_value: str) -> bool:
    """Create or update a secret in Secret Manager."""
    # Skip if we're using environment variables
    if get_env_bool('USE_ENV_VARS_FOR_SECRETS', False):
        env_var_name = f"SECRET_{secret_id.replace('-', '_').upper()}"
        os.environ[env_var_name] = secret_value
        logger.info(f"Set environment variable {env_var_name} instead of Secret Manager")
        return True
    
    secret_client = initialize_secret_manager()
    if not secret_client:
        logger.warning(f"Secret Manager client not available, cannot create/update secret {secret_id}")
        return False
    
    project_id = get_project_id()
    if not project_id:
        logger.warning(f"Unable to create/update secret {secret_id}: No project ID available")
        return False
    
    try:
        parent = f"projects/{project_id}"
        
        secret_exists = True
        try:
            secret_client.get_secret(request={"name": f"{parent}/secrets/{secret_id}"})
        except Exception:
            secret_exists = False
        
        if not secret_exists:
            try:
                secret_client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
                logger.info(f"Created new secret: {secret_id}")
            except Exception as e:
                logger.error(f"Error creating secret {secret_id}: {str(e)}")
                return False
        
        try:
            secret_client.add_secret_version(
                request={
                    "parent": f"{parent}/secrets/{secret_id}",
                    "payload": {"data": secret_value.encode("UTF-8")},
                }
            )
            logger.info(f"Updated secret: {secret_id}")
            return True
        except Exception as e:
            logger.error(f"Error adding secret version for {secret_id}: {str(e)}")
            return False
    except Exception as e:
        logger.error(f"Error creating/updating secret {secret_id}: {str(e)}")
        return False

def ensure_resource_exists(retry_on_failure=True):
    """Ensure GCP resources exist for the application with improved error reporting."""
    if not HAS_GCP or not Config.GCP_PROJECT:
        logger.warning("Cannot ensure GCP resources: GCP libraries not available or project ID not set")
        return False
    
    resources_created = True
    errors = []
    
    # Test BigQuery connection and create dataset
    try:
        logger.info("Ensuring BigQuery resources...")
        if Config.test_bigquery_connection():
            logger.info("✅ BigQuery resources verified")
        else:
            error_msg = "Failed to verify BigQuery resources"
            logger.error(f"❌ {error_msg}")
            errors.append(error_msg)
            resources_created = False
            
            # Try force updating tables on failure
            if retry_on_failure:
                logger.info("Attempting to force update BigQuery tables...")
                from ingestion import force_update_bigquery_tables
                if force_update_bigquery_tables():
                    logger.info("✅ Successfully forced BigQuery tables update")
                    resources_created = True
                else:
                    logger.error("❌ Failed to force update BigQuery tables")
    except Exception as e:
        error_msg = f"Error ensuring BigQuery resources: {str(e)}"
        logger.error(f"❌ {error_msg}")
        errors.append(error_msg)
        resources_created = False
    
    # Ensure GCS bucket exists with lifecycle policy
    try:
        logger.info("Ensuring GCS bucket exists...")
        storage_client = initialize_storage()
        if storage_client:
            bucket = storage_client.bucket(Config.GCS_BUCKET)
            if not bucket.exists():
                # Create bucket with lifecycle policy
                bucket = storage_client.create_bucket(bucket, location=Config.GCP_REGION)
                logger.info(f"✅ Created GCS bucket: {Config.GCS_BUCKET}")
                
                # Set lifecycle policy to reduce storage costs
                lifecycle_rules = {
                    'rule': [
                        {'action': {'type': 'Delete'}, 'condition': {'age': 30, 'isLive': True}},
                        {'action': {'type': 'Delete'}, 'condition': {'numNewerVersions': 3, 'isLive': False}}
                    ]
                }
                bucket.lifecycle_rules = lifecycle_rules
                bucket.patch()
                logger.info("✅ Applied cost-optimized lifecycle policy to bucket")
                
                # Create necessary folder structure
                for folder in ['raw', 'processed', 'cache', 'exports', 'feeds']:
                    blob = bucket.blob(f"{folder}/")
                    blob.upload_from_string('')
                    logger.info(f"✅ Created folder: {folder}/")
            else:
                logger.info(f"✅ GCS bucket {Config.GCS_BUCKET} already exists")
                
                # Update lifecycle policy if needed
                lifecycle_rules = {
                    'rule': [
                        {'action': {'type': 'Delete'}, 'condition': {'age': 30, 'isLive': True}},
                        {'action': {'type': 'Delete'}, 'condition': {'numNewerVersions': 3, 'isLive': False}}
                    ]
                }
                bucket.lifecycle_rules = lifecycle_rules
                bucket.patch()
                logger.info("✅ Updated cost-optimized lifecycle policy")
        else:
            error_msg = "Could not initialize Storage client to check bucket"
            logger.error(f"❌ {error_msg}")
            errors.append(error_msg)
            resources_created = False
    except Exception as e:
        error_msg = f"Failed to ensure GCS bucket exists: {str(e)}"
        logger.error(f"❌ {error_msg}")
        errors.append(error_msg)
        resources_created = False
    
    # Ensure Pub/Sub topics exist
    try:
        logger.info("Ensuring Pub/Sub topics exist...")
        publisher, _ = initialize_pubsub()
        if publisher:
            # Check and create main ingestion topic
            topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
            try:
                publisher.get_topic(request={"topic": topic_path})
                logger.info(f"✅ Pub/Sub topic {Config.PUBSUB_TOPIC} already exists")
            except NotFound:
                publisher.create_topic(request={"name": topic_path})
                logger.info(f"✅ Created Pub/Sub topic: {Config.PUBSUB_TOPIC}")
            
            # Check and create analysis topic
            analysis_topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_ANALYSIS_TOPIC)
            try:
                publisher.get_topic(request={"topic": analysis_topic_path})
                logger.info(f"✅ Pub/Sub topic {Config.PUBSUB_ANALYSIS_TOPIC} already exists")
            except NotFound:
                publisher.create_topic(request={"name": analysis_topic_path})
                logger.info(f"✅ Created Pub/Sub topic: {Config.PUBSUB_ANALYSIS_TOPIC}")
                
            # Publish a test message to verify permissions
            try:
                test_message = {
                    "operation": "resource_test",
                    "timestamp": datetime.utcnow().isoformat()
                }
                future = publisher.publish(
                    topic_path,
                    json.dumps(test_message).encode('utf-8'),
                    operation="test"
                )
                message_id = future.result()
                logger.info(f"✅ Successfully published test message (ID: {message_id}) to {Config.PUBSUB_TOPIC}")
            except Exception as e:
                error_msg = f"Failed to publish test message: {str(e)}"
                logger.warning(f"⚠️ {error_msg}")
                # Don't fail on this
        else:
            error_msg = "Could not initialize Pub/Sub clients to check topics"
            logger.error(f"❌ {error_msg}")
            errors.append(error_msg)
            resources_created = False
    except Exception as e:
        error_msg = f"Failed to ensure Pub/Sub topics exist: {str(e)}"
        logger.error(f"❌ {error_msg}")
        errors.append(error_msg)
        resources_created = False
    
    # Ensure feed configuration
    try:
        logger.info("Ensuring feed configuration...")
        if Config.ensure_feed_configuration():
            logger.info(f"✅ Feed configuration verified with {len(Config.FEEDS)} feeds")
        else:
            error_msg = "Failed to ensure feed configuration"
            logger.error(f"❌ {error_msg}")
            errors.append(error_msg)
            resources_created = False
    except Exception as e:
        error_msg = f"Error ensuring feed configuration: {str(e)}"
        logger.error(f"❌ {error_msg}")
        errors.append(error_msg)
        resources_created = False
    
    # Summary
    if resources_created:
        logger.info("✅ All resources verified successfully")
    else:
        logger.error(f"❌ Resource verification failed with {len(errors)} errors")
        for i, error in enumerate(errors):
            logger.error(f"  Error {i+1}: {error}")
    
    return resources_created

# Module exports
__all__ = [
    'Config', 
    'get_config', 
    'initialize_bigquery', 
    'initialize_storage', 
    'initialize_pubsub',
    'initialize_error_reporting',
    'initialize_secret_manager',
    'report_error',
    'access_secret',
    'create_or_update_secret',
    'get_cached_config',
    'create_default_feed_config',
    'create_default_auth_config',
    'get_gcp_clients',
    'ensure_resource_exists',
    'GCP_SERVICES_AVAILABLE',
    'HAS_GCP'
]

# Initialize resources if requested
if __name__ != "__main__" and get_env_bool('ENSURE_GCP_RESOURCES', False):
    # Wait until imported to avoid startup issues
    logger.info("Auto-initializing GCP resources")
    def delayed_resource_init():
        time.sleep(2)  # Small delay to allow other initialization
        ensure_resource_exists()
    
    init_thread = threading.Thread(target=delayed_resource_init)
    init_thread.daemon = True
    init_thread.start()
