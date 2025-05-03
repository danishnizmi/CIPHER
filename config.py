import os
import sys
import json
import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

# Google Cloud imports
try:
    from google.cloud import secretmanager, storage, bigquery, pubsub_v1, error_reporting
    from google.cloud.logging_v2 import Client as LoggingClient
    from google.cloud.exceptions import NotFound, Forbidden, BadRequest
    from google.api_core.exceptions import GoogleAPIError, PermissionDenied, ResourceExhausted
    from google.auth.exceptions import DefaultCredentialsError, TransportError
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

# Global clients
_bigquery_client = None
_storage_client = None
_publisher = None
_subscriber = None
_logging_client = None
_error_client = None
_secret_client = None

def get_project_id() -> Optional[str]:
    """Get Google Cloud project ID from environment or GCP metadata with improved error handling."""
    # First try environment variable
    project_id = os.environ.get('GCP_PROJECT')
    if project_id:
        return project_id
    
    # If not in environment, try to get from GCP metadata
    if HAS_GCP:
        try:
            # Try to get project ID from metadata
            credentials, project_id = google.auth.default()
            if project_id:
                # Cache this in environment for future calls
                os.environ['GCP_PROJECT'] = project_id
                return project_id
        except DefaultCredentialsError:
            logger.warning("Unable to determine GCP project ID from metadata (DefaultCredentialsError)")
        except TransportError:
            logger.warning("Unable to determine GCP project ID from metadata (TransportError)")
        except Exception as e:
            logger.warning(f"Unable to determine GCP project ID from metadata: {str(e)}")
    
    logger.error("No project ID found in environment or metadata")
    return None

def initialize_credentials():
    """Initialize Google credentials with fallback options."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize credentials")
        return None, None
        
    try:
        # Try default credentials first
        credentials, project_id = google.auth.default()
        logger.info(f"Using default credentials with project: {project_id}")
        return credentials, project_id
    except DefaultCredentialsError:
        logger.warning("Default credentials not found")
        return None, None
    except Exception as e:
        logger.warning(f"Error initializing credentials: {str(e)}")
        return None, None

def access_secret(secret_id: str, version_id: str = "latest") -> Optional[Any]:
    """Access secrets from Google Cloud Secret Manager with robust error handling."""
    global _secret_client
    
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot access secrets")
        return None
        
    project_id = get_project_id()
    if not project_id:
        logger.warning(f"Unable to access secret {secret_id}: No project ID available")
        return None
    
    try:
        # Create the Secret Manager client if not already initialized
        if _secret_client is None:
            _secret_client = secretmanager.SecretManagerServiceClient()
        
        # Build the resource name of the secret version
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        
        # Access the secret version
        response = _secret_client.access_secret_version(request={"name": name})
        
        # Return the decoded payload
        secret_data = response.payload.data.decode("UTF-8")
        
        # Try to parse as JSON if it's a JSON string
        try:
            return json.loads(secret_data)
        except json.JSONDecodeError:
            # Return as plain string if not JSON
            return secret_data
            
    except PermissionDenied:
        logger.error(f"Permission denied when accessing secret {secret_id}. Ensure service account has Secret Manager Secret Accessor role.")
        return None
    except NotFound:
        logger.error(f"Secret {secret_id} not found in project {project_id}")
        return None
    except Exception as e:
        logger.error(f"Error accessing secret {secret_id}: {str(e)}")
        return None

def create_or_update_secret(secret_id: str, secret_value: str) -> bool:
    """Create or update a secret in Secret Manager."""
    global _secret_client
    
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot create/update secret")
        return False
        
    project_id = get_project_id()
    if not project_id:
        logger.warning(f"Unable to create/update secret {secret_id}: No project ID available")
        return False
    
    try:
        # Create the Secret Manager client if not already initialized
        if _secret_client is None:
            _secret_client = secretmanager.SecretManagerServiceClient()
        
        # Build the parent resource name
        parent = f"projects/{project_id}"
        
        # Check if secret exists
        secret_exists = True
        try:
            _secret_client.get_secret(request={"name": f"{parent}/secrets/{secret_id}"})
        except Exception:
            secret_exists = False
        
        # Create secret if it doesn't exist
        if not secret_exists:
            try:
                _secret_client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
            except Exception as e:
                logger.error(f"Error creating secret {secret_id}: {str(e)}")
                return False
        
        # Add new version with the secret value
        try:
            _secret_client.add_secret_version(
                request={
                    "parent": f"{parent}/secrets/{secret_id}",
                    "payload": {"data": secret_value.encode("UTF-8")},
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error adding secret version for {secret_id}: {str(e)}")
            return False
            
    except Exception as e:
        logger.error(f"Error creating/updating secret {secret_id}: {str(e)}")
        return False

def get_cached_config(secret_id: str, force_refresh: bool = False) -> Optional[Dict]:
    """Get and cache configuration from Secret Manager."""
    # Return from memory cache for subsequent calls
    if hasattr(get_cached_config, f"_cached_{secret_id}") and not force_refresh:
        return getattr(get_cached_config, f"_cached_{secret_id}")
        
    # Fetch from Secret Manager
    config_data = access_secret(secret_id)
    
    # Cache for future use
    if config_data:
        setattr(get_cached_config, f"_cached_{secret_id}", config_data)
        
    return config_data

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

def set_initial_admin_password() -> Optional[str]:
    """Sets initial admin password if not already set."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot set initial admin password")
        return "admin"  # Default password for local development
    
    try:
        # Get existing password
        admin_password = access_secret("admin-initial-password")
        
        # If no password exists, generate a random one
        if not admin_password:
            import secrets
            import string
            admin_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            create_or_update_secret("admin-initial-password", admin_password)
            logger.info("Created new admin password in Secret Manager")
        
        # For development environments, log the password
        if os.environ.get('ENVIRONMENT', 'development') == 'development':
            logger.info(f"Admin password: {admin_password}")
        
        return admin_password
    except Exception as e:
        logger.error(f"Error setting initial admin password: {str(e)}")
        # Return a default password for development
        return "admin"

def update_user(username: str, updates: Dict) -> bool:
    """Update user data in auth config."""
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot update user data")
        return False
    
    try:
        # Get current auth config
        auth_config = get_cached_config("auth-config", force_refresh=True)
        if not auth_config or not isinstance(auth_config, dict):
            auth_config = {"users": {}}
        
        # Ensure users dict exists
        if "users" not in auth_config:
            auth_config["users"] = {}
        
        # Ensure user exists
        if username not in auth_config["users"]:
            auth_config["users"][username] = {"role": "readonly"}
        
        # Update user data
        for key, value in updates.items():
            auth_config["users"][username][key] = value
        
        # Save updated auth config
        result = create_or_update_secret("auth-config", json.dumps(auth_config))
        
        # Clear cache if successful
        if result:
            if hasattr(get_cached_config, "_cached_auth-config"):
                delattr(get_cached_config, "_cached_auth-config")
        
        return result
    except Exception as e:
        logger.error(f"Error updating user {username}: {str(e)}")
        return False

def add_user(username: str, password: str, role: str = "readonly") -> bool:
    """Add a new user to auth config."""
    import hashlib
    
    try:
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Create user data
        user_data = {
            "password": hashed_password,
            "role": role,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Update auth config
        return update_user(username, user_data)
    except Exception as e:
        logger.error(f"Error adding user {username}: {str(e)}")
        return False

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
    
    # Threat intelligence feed configuration - Default empty array, will be populated
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
    
    # Export configuration
    EXPORT_FORMATS = ['csv', 'json', 'stix']
    MAX_EXPORT_SIZE = int(os.environ.get('MAX_EXPORT_SIZE', 100000))
    
    # Initialization methods
    @classmethod
    def init_secrets(cls):
        """Initialize configuration from Secret Manager with improved error handling."""
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
                global _logging_client
                if _logging_client is None:
                    _logging_client = LoggingClient(project=cls.GCP_PROJECT)
                cloud_handler = _logging_client.get_default_handler()
                cloud_handler.setLevel(log_level)
                root_logger.addHandler(cloud_handler)
                logger.info("Cloud Logging enabled")
            except PermissionDenied:
                logger.error("Permission denied accessing Cloud Logging. Ensure service account has Logs Writer role.")
            except Exception as e:
                logger.error(f"Failed to set up Cloud Logging: {str(e)}")
    
    @classmethod
    def initialize_error_reporting(cls):
        """Initialize Google Cloud Error Reporting."""
        if not cls.ENABLE_ERROR_REPORTING or not cls.GCP_PROJECT or not HAS_GCP:
            return None
            
        try:
            global _error_client
            if _error_client is None:
                _error_client = error_reporting.Client(project=cls.GCP_PROJECT)
            logger.info("Error reporting initialized")
            return _error_client
        except PermissionDenied:
            logger.error("Permission denied accessing Error Reporting. Service account may need Error Reporting Writer role.")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize error reporting: {str(e)}")
            return None
    
    @classmethod
    def validate_configuration(cls):
        """Validate configuration values and check GCP permissions."""
        warnings = []
        errors = []
        
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
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        # Test service client initialization if in GCP environment
        if cls.GCP_PROJECT and HAS_GCP:
            # Check BigQuery access
            try:
                bq_client = initialize_bigquery()
                if bq_client:
                    # Try listing datasets as a permission check
                    list(bq_client.list_datasets(max_results=1))
                    logger.info("BigQuery permissions OK")
                else:
                    warnings.append("BigQuery client initialization failed")
            except PermissionDenied:
                errors.append("Permission denied accessing BigQuery - check service account roles")
            except Exception as e:
                warnings.append(f"BigQuery access check failed: {str(e)}")
                
            # Check Storage access
            try:
                storage_client = initialize_storage()
                if storage_client:
                    # Try listing buckets as a permission check
                    list(storage_client.list_buckets(max_results=1))
                    logger.info("Storage permissions OK")
                else:
                    warnings.append("Storage client initialization failed")
            except PermissionDenied:
                errors.append("Permission denied accessing Storage - check service account roles")
            except Exception as e:
                warnings.append(f"Storage access check failed: {str(e)}")
                
            # Check Pub/Sub access 
            try:
                publisher, _ = initialize_pubsub()
                if publisher:
                    # Try listing topics as a permission check
                    publisher.list_topics(request={"project": f"projects/{cls.GCP_PROJECT}"})
                    logger.info("Pub/Sub permissions OK")
                else:
                    warnings.append("Pub/Sub client initialization failed")
            except PermissionDenied:
                errors.append("Permission denied accessing Pub/Sub - check service account roles")
            except Exception as e:
                warnings.append(f"Pub/Sub access check failed: {str(e)}")
        
        # Log all warnings and errors
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
    def get_function_url(cls, function_name):
        """Get the URL for a Cloud Function."""
        if not cls.GCP_PROJECT or not cls.GCP_REGION:
            return None
            
        return f"https://{cls.GCP_REGION}-{cls.GCP_PROJECT}.cloudfunctions.net/{function_name}"
    
    @classmethod
    def ensure_gcp_resources(cls):
        """Ensure required GCP resources exist."""
        if not cls.GCP_PROJECT or not HAS_GCP:
            logger.warning("Skipping GCP resource validation - not in GCP environment or missing libraries")
            return False
            
        success = True
        
        # Ensure BigQuery dataset exists
        try:
            bq_client = initialize_bigquery()
            if bq_client:
                dataset_id = f"{cls.GCP_PROJECT}.{cls.BIGQUERY_DATASET}"
                try:
                    bq_client.get_dataset(dataset_id)
                    logger.info(f"BigQuery dataset {cls.BIGQUERY_DATASET} exists")
                except NotFound:
                    logger.warning(f"BigQuery dataset {cls.BIGQUERY_DATASET} not found, creating it")
                    dataset = bigquery.Dataset(dataset_id)
                    dataset.location = cls.BIGQUERY_LOCATION
                    bq_client.create_dataset(dataset)
                    logger.info(f"Created BigQuery dataset {cls.BIGQUERY_DATASET}")
        except Exception as e:
            logger.error(f"Error ensuring BigQuery dataset: {str(e)}")
            success = False
            
        # Ensure GCS bucket exists
        try:
            storage_client = initialize_storage()
            if storage_client:
                bucket = storage_client.bucket(cls.GCS_BUCKET)
                if not bucket.exists():
                    logger.warning(f"GCS bucket {cls.GCS_BUCKET} not found, creating it")
                    storage_client.create_bucket(bucket, location=cls.GCP_REGION)
                    logger.info(f"Created GCS bucket {cls.GCS_BUCKET}")
                else:
                    logger.info(f"GCS bucket {cls.GCS_BUCKET} exists")
        except Exception as e:
            logger.error(f"Error ensuring GCS bucket: {str(e)}")
            success = False
            
        # Ensure Pub/Sub topics exist
        try:
            publisher, _ = initialize_pubsub()
            if publisher:
                topics_to_check = [
                    cls.PUBSUB_TOPIC,
                    cls.PUBSUB_ANALYSIS_TOPIC
                ]
                
                for topic_name in topics_to_check:
                    topic_path = publisher.topic_path(cls.GCP_PROJECT, topic_name)
                    try:
                        publisher.get_topic(request={"topic": topic_path})
                        logger.info(f"Pub/Sub topic {topic_name} exists")
                    except NotFound:
                        logger.warning(f"Pub/Sub topic {topic_name} not found, creating it")
                        publisher.create_topic(request={"name": topic_path})
                        logger.info(f"Created Pub/Sub topic {topic_name}")
        except Exception as e:
            logger.error(f"Error ensuring Pub/Sub topics: {str(e)}")
            success = False
            
        return success

    @classmethod
    def init_app(cls):
        """Initialize application configuration."""
        # Configure logging
        cls.configure_logging()
        
        # Initialize secrets if enabled
        if get_env_bool('LOAD_SECRETS', True):
            cls.init_secrets()
        
        # Initialize error reporting
        cls.initialize_error_reporting()
        
        # Validate configuration
        cls.validate_configuration()
        
        # Ensure GCP resources if enabled
        if get_env_bool('ENSURE_GCP_RESOURCES', True):
            cls.ensure_gcp_resources()
            
        logger.info(f"Initialized {cls.ENVIRONMENT} configuration")

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
        
        # Ensure admin user exists with password "admin" in development
        if not get_env_bool('LOAD_SECRETS_IN_DEV', False):
            add_user('admin', 'admin', 'admin')
            
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
        
        # Ensure GCP resources exist
        cls.ensure_gcp_resources()
        
        # Ensure admin user is set up
        admin_password = set_initial_admin_password()
        if admin_password:
            add_user('admin', admin_password, 'admin')
        
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
    """Initialize and return a BigQuery client with error handling."""
    global _bigquery_client
    
    if _bigquery_client is not None:
        return _bigquery_client
        
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize BigQuery")
        return None
        
    try:
        _bigquery_client = bigquery.Client(project=Config.GCP_PROJECT)
        return _bigquery_client
    except PermissionDenied:
        logger.error("Permission denied initializing BigQuery client. Check service account roles.")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {str(e)}")
        return None

def initialize_storage():
    """Initialize and return a Cloud Storage client with error handling."""
    global _storage_client
    
    if _storage_client is not None:
        return _storage_client
        
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize Storage")
        return None
        
    try:
        _storage_client = storage.Client(project=Config.GCP_PROJECT)
        return _storage_client
    except PermissionDenied:
        logger.error("Permission denied initializing Storage client. Check service account roles.")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize Storage client: {str(e)}")
        return None

def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients with error handling."""
    global _publisher, _subscriber
    
    if _publisher is not None and _subscriber is not None:
        return _publisher, _subscriber
        
    if not HAS_GCP:
        logger.warning("Google Cloud libraries not installed, cannot initialize PubSub")
        return None, None
        
    try:
        if _publisher is None:
            _publisher = pubsub_v1.PublisherClient()
        if _subscriber is None:
            _subscriber = pubsub_v1.SubscriberClient()
        return _publisher, _subscriber
    except PermissionDenied:
        logger.error("Permission denied initializing Pub/Sub clients. Check service account roles.")
        return None, None
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
        except PermissionDenied:
            logger.error("Permission denied reporting error. Service account may need Error Reporting Writer role.")
        except Exception as e:
            logger.error(f"Failed to report error: {str(e)}")

def get_gcp_clients():
    """Get a dictionary of initialized GCP clients."""
    return {
        "bigquery": initialize_bigquery(),
        "storage": initialize_storage(),
        "pubsub": initialize_pubsub(),
        "error_reporting": get_error_client()
    }

def check_gcp_permissions():
    """Check if service account has the necessary GCP permissions."""
    permissions = {
        "bigquery": False,
        "storage": False,
        "pubsub": False,
        "secretmanager": False,
        "logging": False,
        "errorreporting": False
    }
    
    # Check BigQuery permissions
    try:
        bq_client = initialize_bigquery()
        if bq_client:
            list(bq_client.list_datasets(max_results=1))
            permissions["bigquery"] = True
    except Exception:
        pass
        
    # Check Storage permissions
    try:
        storage_client = initialize_storage()
        if storage_client:
            list(storage_client.list_buckets(max_results=1))
            permissions["storage"] = True
    except Exception:
        pass
        
    # Check Pub/Sub permissions
    try:
        publisher, _ = initialize_pubsub()
        if publisher:
            publisher.list_topics(request={"project": f"projects/{Config.GCP_PROJECT}"})
            permissions["pubsub"] = True
    except Exception:
        pass
        
    # Check Secret Manager permissions
    try:
        secret = access_secret('api-keys', 'latest')
        permissions["secretmanager"] = secret is not None
    except Exception:
        pass
        
    # Check Logging permissions
    try:
        if Config.LOG_TO_CLOUD and Config.GCP_PROJECT and HAS_GCP:
            global _logging_client
            if _logging_client is None:
                _logging_client = LoggingClient(project=Config.GCP_PROJECT)
            _logging_client.logger('test').log_text('Test log entry')
            permissions["logging"] = True
    except Exception:
        pass
        
    # Check Error Reporting permissions
    try:
        if Config.ENABLE_ERROR_REPORTING and Config.GCP_PROJECT and HAS_GCP:
            client = error_reporting.Client(project=Config.GCP_PROJECT)
            client.report("Test error report")
            permissions["errorreporting"] = True
    except Exception:
        pass
        
    return permissions

# Define a constant for GCP services availability
GCP_SERVICES_AVAILABLE = HAS_GCP

# Module exports
__all__ = [
    'Config', 
    'get_config', 
    'initialize_bigquery', 
    'initialize_storage', 
    'initialize_pubsub',
    'get_error_client',
    'report_error',
    'check_gcp_permissions',
    'access_secret',
    'create_or_update_secret',
    'get_cached_config',
    'add_user',
    'update_user',
    'set_initial_admin_password',
    'get_gcp_clients',
    'GCP_SERVICES_AVAILABLE'
]
