import os
import sys
import json
import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Google Cloud imports
try:
    from google.cloud import secretmanager, storage, bigquery, pubsub_v1, error_reporting
    from google.cloud.logging_v2 import Client as LoggingClient
    from google.api_core.exceptions import NotFound
    from google.auth.exceptions import DefaultCredentialsError
    import google.auth
    HAS_GCP = True
except ImportError:
    HAS_GCP = False

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
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

def get_project_id():
    """Get Google Cloud project ID from environment or GCP metadata."""
    project_id = os.environ.get('GCP_PROJECT')
    
    if not project_id and HAS_GCP:
        try:
            # Try to get project ID from Google Cloud metadata
            credentials, project_id = google.auth.default()
        except DefaultCredentialsError:
            logger.warning("Unable to determine GCP project ID from metadata")
            project_id = None
    
    return project_id

def access_secret(secret_id, version_id="latest"):
    """Access secrets from Google Cloud Secret Manager."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot access secrets")
        return None
        
    project_id = get_project_id()
    
    # If not running in GCP or project ID not available, return None
    if not project_id:
        logger.warning(f"Unable to access secret {secret_id}: No project ID available")
        return None
    
    try:
        # Create the Secret Manager client
        client = secretmanager.SecretManagerServiceClient()
        
        # Build the resource name of the secret version
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        
        # Access the secret version
        response = client.access_secret_version(request={"name": name})
        
        # Return the decoded payload
        secret_data = response.payload.data.decode("UTF-8")
        
        # Try to parse as JSON if it's a JSON string
        try:
            return json.loads(secret_data)
        except json.JSONDecodeError:
            # Return as plain string if not JSON
            return secret_data
            
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {str(e)}")
        return None

def get_env_bool(var_name: str, default: bool = False) -> bool:
    """Get boolean value from environment variable."""
    val = os.environ.get(var_name, str(default)).lower()
    return val in ('true', 't', 'yes', 'y', '1')

def get_env_list(var_name: str, default: List = None, separator: str = ',') -> List:
    """Get list from environment variable."""
    if default is None:
        default = []
    val = os.environ.get(var_name)
    if not val:
        return default
    return [item.strip() for item in val.split(separator) if item.strip()]

def get_env_dict(var_name: str, default: Dict = None) -> Dict:
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

class BaseConfig:
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
    
    # Cloud Functions configuration
    INGEST_FUNCTION_NAME = 'ingest_threat_data'
    ANALYSIS_FUNCTION_NAME = 'analyze_threat_data'
    
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
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', None)  # Should be set via secret or env var
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=AUTH_SESSION_TIMEOUT)
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', tempfile.gettempdir())
    SESSION_COOKIE_NAME = 'threat_intelligence_session'
    SESSION_COOKIE_SECURE = get_env_bool('SESSION_COOKIE_SECURE', False)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_USE_SIGNER = True
    
    # Security configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', SECRET_KEY)
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))  # 1 hour
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_CLOUD = get_env_bool('LOG_TO_CLOUD', False)
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Error reporting configuration
    ENABLE_ERROR_REPORTING = get_env_bool('ENABLE_ERROR_REPORTING', False)
    
    # Threat intelligence feed configuration
    FEEDS = []  # Will be populated from feed-config secret
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
    
    # Export configuration
    EXPORT_FORMATS = ['csv', 'json', 'stix']
    MAX_EXPORT_SIZE = int(os.environ.get('MAX_EXPORT_SIZE', 100000))
    
    # Initialization methods
    @classmethod
    def init_secrets(cls):
        """Initialize configuration from Secret Manager."""
        # Only attempt to access secrets if we're in a GCP environment
        if not cls.GCP_PROJECT or not HAS_GCP:
            logger.info("Skipping secret initialization - not in GCP environment or missing libraries")
            return
            
        try:
            # Load database credentials
            db_creds = access_secret('database-credentials')
            if db_creds:
                if isinstance(db_creds, dict):
                    cls.DATABASE_USER = db_creds.get('username')
                    cls.DATABASE_PASSWORD = db_creds.get('password')
                    cls.DATABASE_HOST = db_creds.get('host')
                    cls.DATABASE_PORT = db_creds.get('port')
                    cls.DATABASE_NAME = db_creds.get('database')
                logger.info("Loaded database credentials from Secret Manager")
            
            # Load API keys
            api_keys = access_secret('api-keys')
            if api_keys and isinstance(api_keys, dict):
                # Override environment API key if available in secrets
                platform_api_key = api_keys.get('platform_api_key')
                if platform_api_key:
                    cls.API_KEY = platform_api_key
                
                # Store external API keys if present
                cls.EXTERNAL_API_KEYS = {
                    k: v for k, v in api_keys.items() if k != 'platform_api_key'
                }
                logger.info("Loaded API keys from Secret Manager")
            
            # Load authentication configuration
            auth_config = access_secret('auth-config')
            if auth_config and isinstance(auth_config, dict):
                cls.AUTH_ENABLED = auth_config.get('enabled', cls.AUTH_ENABLED)
                cls.SESSION_SECRET = auth_config.get('session_secret')
                # If session secret is available, use it for Flask's secret key
                if cls.SESSION_SECRET:
                    cls.SECRET_KEY = cls.SESSION_SECRET
                
                # Load custom authentication settings if available
                if 'providers' in auth_config:
                    cls.AUTH_PROVIDERS = auth_config['providers']
                logger.info("Loaded authentication configuration from Secret Manager")
            
            # Load feed configuration
            feed_config = access_secret('feed-config')
            if feed_config and isinstance(feed_config, dict):
                cls.FEEDS = feed_config.get('feeds', [])
                cls.FEED_UPDATE_INTERVAL = feed_config.get('update_interval_hours', cls.FEED_UPDATE_INTERVAL)
                
                # Additional feed-specific configuration
                cls.FEED_DEFAULT_TAGS = feed_config.get('default_tags', [])
                cls.FEED_USER_AGENT = feed_config.get('user_agent', f"ThreatIntelligencePlatform/{cls.VERSION}")
                cls.FEED_REQUEST_TIMEOUT = feed_config.get('request_timeout', 30)
                cls.FEED_MAX_RETRIES = feed_config.get('max_retries', 3)
                
                logger.info("Loaded feed configuration from Secret Manager")
            
            # Load admin password if available
            admin_password = access_secret('admin-initial-password')
            if admin_password:
                cls.ADMIN_PASSWORD = admin_password
                logger.info("Loaded admin password from Secret Manager")
                
        except Exception as e:
            logger.error(f"Error initializing secrets: {str(e)}")
    
    @classmethod
    def configure_logging(cls):
        """Configure logging based on settings."""
        log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers to avoid duplicates
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        formatter = logging.Formatter(cls.LOG_FORMAT)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Set up Cloud Logging if enabled
        if cls.LOG_TO_CLOUD and cls.GCP_PROJECT and HAS_GCP:
            try:
                logging_client = LoggingClient(project=cls.GCP_PROJECT)
                cloud_handler = logging_client.get_default_handler()
                cloud_handler.setLevel(log_level)
                root_logger.addHandler(cloud_handler)
                logger.info("Cloud Logging enabled")
            except Exception as e:
                logger.error(f"Failed to set up Cloud Logging: {str(e)}")
    
    @classmethod
    def initialize_error_reporting(cls):
        """Initialize Google Cloud Error Reporting."""
        if not cls.ENABLE_ERROR_REPORTING or not cls.GCP_PROJECT or not HAS_GCP:
            return None
            
        try:
            client = error_reporting.Client(project=cls.GCP_PROJECT)
            logger.info("Error reporting initialized")
            return client
        except Exception as e:
            logger.error(f"Failed to initialize error reporting: {str(e)}")
            return None
    
    @classmethod
    def validate_configuration(cls):
        """Validate configuration values."""
        warnings = []
        
        # Check for insecure defaults in production
        if cls.ENVIRONMENT == 'production':
            if cls.SECRET_KEY == 'dev-secret-key':
                warnings.append("Production environment using default development secret key!")
            
            if cls.API_KEY == 'dev-api-key':
                warnings.append("Production environment using default development API key!")
            
            if not cls.SESSION_COOKIE_SECURE:
                warnings.append("Session cookies not set to secure in production!")
        
        # Check for essential configuration
        if not cls.GCP_PROJECT:
            warnings.append("GCP_PROJECT not set - some functionality may be limited")
        
        # Log all warnings
        for warning in warnings:
            logger.warning(warning)
            
        return len(warnings) == 0
    
    @classmethod
    def get_feed_by_id(cls, feed_id):
        """Get feed configuration by ID."""
        for feed in cls.FEEDS:
            if feed.get('id') == feed_id:
                return feed
        return None
    
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
    def get_function_url(cls, function_name):
        """Get the URL for a Cloud Function."""
        if not cls.GCP_PROJECT or not cls.GCP_REGION:
            return None
            
        return f"https://{cls.GCP_REGION}-{cls.GCP_PROJECT}.cloudfunctions.net/{function_name}"

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    TESTING = False
    
    # Override with development-specific settings
    BIGQUERY_DATASET = 'threat_intelligence_dev'
    GCS_BUCKET = f"{BaseConfig.GCP_PROJECT}-threat-data-dev" if BaseConfig.GCP_PROJECT else 'threat-data-dev'
    
    # Development settings
    TEMPLATES_AUTO_RELOAD = True
    WTF_CSRF_ENABLED = True  # Enable CSRF even in development
    
    # Less restrictive session settings for development
    SESSION_COOKIE_SECURE = False
    
    # More verbose logging in development
    LOG_LEVEL = 'DEBUG'
    
    # Cache settings for development
    CACHE_TYPE = 'SimpleCache'
    
    @classmethod
    def init_app(cls):
        """Initialize development-specific configuration."""
        # Configure logging
        cls.configure_logging()
        
        # Only load secrets if explicitly configured to do so in development
        if get_env_bool('LOAD_SECRETS_IN_DEV', False):
            cls.init_secrets()
        
        # Validate configuration
        cls.validate_configuration()
        
        logger.info("Initialized development configuration")

class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = False
    TESTING = True
    
    # Test-specific configuration
    BIGQUERY_DATASET = 'threat_intelligence_test'
    GCS_BUCKET = f"{BaseConfig.GCP_PROJECT}-threat-data-test" if BaseConfig.GCP_PROJECT else 'threat-data-test'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Test-specific settings
    SERVER_NAME = 'localhost'
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    
    # Use in-memory cache for testing
    CACHE_TYPE = 'SimpleCache'
    
    @classmethod
    def init_app(cls):
        """Initialize testing-specific configuration."""
        # Configure logging
        cls.configure_logging()
        
        # Do not load secrets in testing environment
        # instead, use mock values where needed
        
        logger.info("Initialized testing configuration")

class ProductionConfig(BaseConfig):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    
    # Stricter session configuration for production
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    # Enhanced security configuration
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Production logging
    LOG_LEVEL = 'INFO'
    LOG_TO_CLOUD = True
    
    # Enable error reporting
    ENABLE_ERROR_REPORTING = True
    
    # Production caching
    CACHE_TYPE = 'SimpleCache'  # In a real scenario, you might use Redis or Memcached
    
    @classmethod
    def init_app(cls):
        """Initialize production-specific configuration."""
        # Configure logging
        cls.configure_logging()
        
        # Always load secrets in production
        cls.init_secrets()
        
        # Initialize error reporting
        cls.initialize_error_reporting()
        
        # Validate configuration
        cls.validate_configuration()
        
        logger.info("Initialized production configuration")

# Dictionary of environment configurations
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    
    # Default to development for any other environment name
    'default': DevelopmentConfig
}

# Get the current environment
current_env = os.environ.get('ENVIRONMENT', 'development').lower()

# Load the appropriate configuration
Config = config_by_name.get(current_env, config_by_name['default'])

# Initialize environment-specific configuration
if hasattr(Config, 'init_app'):
    Config.init_app()

# Export for usage in other modules
def get_config():
    """Return the current configuration."""
    return Config

# Helper functions for other modules
def initialize_bigquery():
    """Initialize and return a BigQuery client."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize BigQuery")
        return None
        
    try:
        return bigquery.Client(project=Config.GCP_PROJECT)
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {str(e)}")
        return None

def initialize_storage():
    """Initialize and return a Cloud Storage client."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize Storage")
        return None
        
    try:
        return storage.Client(project=Config.GCP_PROJECT)
    except Exception as e:
        logger.error(f"Failed to initialize Storage client: {str(e)}")
        return None

def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize PubSub")
        return None, None
        
    try:
        publisher = pubsub_v1.PublisherClient()
        subscriber = pubsub_v1.SubscriberClient()
        return publisher, subscriber
    except Exception as e:
        logger.error(f"Failed to initialize PubSub clients: {str(e)}")
        return None, None

def get_error_client():
    """Get the error reporting client."""
    return Config.initialize_error_reporting()

def report_error(exception):
    """Report an error to Cloud Error Reporting."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
        
    client = get_error_client()
    if client:
        try:
            client.report_exception()
        except Exception as e:
            logger.error(f"Failed to report error: {str(e)}")

# Module exports
__all__ = [
    'Config', 
    'get_config', 
    'initialize_bigquery', 
    'initialize_storage', 
    'initialize_pubsub',
    'get_error_client',
    'report_error'
]
