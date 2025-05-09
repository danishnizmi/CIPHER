"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management for production deployment with centralized service management.
"""

import os
import sys
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from functools import wraps, lru_cache
from enum import Enum

# Global client variables with lazy initialization
_clients = {}
_logging_client = None
_error_client = None

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ===== Service Status Management =====
class ServiceStatus(Enum):
    INITIALIZING = "initializing"
    READY = "ready"
    DEGRADED = "degraded"
    ERROR = "error"

class ServiceManager:
    """Centralized service management and monitoring."""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self._services = {
            'config': ServiceStatus.INITIALIZING,
            'bigquery': ServiceStatus.INITIALIZING,
            'storage': ServiceStatus.INITIALIZING,
            'pubsub': ServiceStatus.INITIALIZING,
            'ai_models': ServiceStatus.INITIALIZING,
            'ingestion': ServiceStatus.INITIALIZING,
            'analysis': ServiceStatus.INITIALIZING,
            'frontend': ServiceStatus.INITIALIZING,
            'api': ServiceStatus.INITIALIZING
        }
        self._clients = {}
        self._errors = {}
        self._lock = threading.Lock()
    
    def update_status(self, service: str, status: ServiceStatus, error: str = None):
        """Update service status."""
        with self._lock:
            self._services[service] = status
            if error:
                self._errors[service] = error
            elif service in self._errors:
                del self._errors[service]
            logger.info(f"Service {service} status updated to {status.value}")
    
    def get_status(self) -> Dict:
        """Get overall system status."""
        with self._lock:
            return {
                'services': {k: v.value for k, v in self._services.items()},
                'errors': dict(self._errors),
                'overall': self._calculate_overall_status().value,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _calculate_overall_status(self) -> ServiceStatus:
        """Calculate overall system status."""
        statuses = list(self._services.values())
        if all(s == ServiceStatus.READY for s in statuses):
            return ServiceStatus.READY
        elif any(s == ServiceStatus.ERROR for s in statuses):
            return ServiceStatus.ERROR
        elif any(s == ServiceStatus.DEGRADED for s in statuses):
            return ServiceStatus.DEGRADED
        else:
            return ServiceStatus.INITIALIZING
    
    def get_client(self, client_type: str):
        """Get a client instance."""
        return self._clients.get(client_type)
    
    def set_client(self, client_type: str, client):
        """Set a client instance."""
        with self._lock:
            self._clients[client_type] = client

# ===== Constants and Default Configuration =====
DEFAULT_API_RATE_LIMIT = "1000 per day, 100 per hour"
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

# ===== Simple Configuration Storage =====
class ConfigStore:
    """Simple configuration storage without complex secret management."""
    
    _cache = {}  # In-memory cache
    _initialized = False
    _lock = threading.RLock()  # Lock for thread safety
    
    @classmethod
    def init(cls):
        """Initialize the configuration store."""
        with cls._lock:
            if cls._initialized:
                return
                
            # Load feed configuration
            cls._ensure_feed_config()
            
            # Load API configuration
            cls._ensure_api_config()
            
            cls._initialized = True
            logger.info("Configuration store initialized successfully")
    
    @classmethod
    def _ensure_feed_config(cls):
        """Initialize feed configuration."""
        # Try environment variable first
        env_feeds = os.environ.get('FEED_CONFIG')
        if env_feeds:
            try:
                feed_config = json.loads(env_feeds)
                cls._cache['feed-config'] = feed_config
                logger.info("Loaded feed configuration from environment")
                return feed_config
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in FEED_CONFIG environment variable")
        
        # Use default feeds
        feed_config = {
            'feeds': DEFAULT_FEED_CONFIGS,
            'update_interval_hours': 6
        }
        cls._cache['feed-config'] = feed_config
        logger.info("Using default feed configuration")
        return feed_config
    
    @classmethod
    def _ensure_api_config(cls):
        """Initialize API configuration."""
        # Get API key from environment
        api_key = os.environ.get('API_KEY', 'default-api-key')
        api_config = {'platform_api_key': api_key}
        cls._cache['api-keys'] = api_config
        logger.info("Loaded API configuration")
        return api_config
    
    @classmethod
    def get_config(cls, key: str) -> Any:
        """Get configuration value."""
        if not cls._initialized:
            cls.init()
            
        return cls._cache.get(key)
    
    @classmethod
    def set_config(cls, key: str, value: Any):
        """Set configuration value."""
        if not cls._initialized:
            cls.init()
            
        cls._cache[key] = value

# ===== Main Configuration Class =====
class Config:
    """Base configuration class for production deployment."""
    
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
        'malware': 'malware'
    }
    
    # ===== Storage Configuration =====
    GCS_BUCKET = os.environ.get('GCS_BUCKET', f"{GCP_PROJECT}-threat-data" if GCP_PROJECT else 'threat-data')
    
    # ===== PubSub Configuration =====
    PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', 'threat-data-ingestion')
    PUBSUB_ANALYSIS_TOPIC = os.environ.get('PUBSUB_ANALYSIS_TOPIC', 'threat-analysis-events')
    
    # ===== Server Configuration =====
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))
    
    # ===== API Configuration =====
    API_KEY = None  # Will be initialized in init_app
    API_VERSION = 'v1'
    API_RATE_LIMIT = os.environ.get('API_RATE_LIMIT', DEFAULT_API_RATE_LIMIT)
    
    # ===== Feed Configuration =====
    FEEDS = []  # Will be initialized in init_app
    FEED_UPDATE_INTERVAL = int(os.environ.get('FEED_UPDATE_INTERVAL', 3))  # hours
    
    # ===== Analysis Configuration =====
    ANALYSIS_ENABLED = get_env_bool('ANALYSIS_ENABLED', True)
    ANALYSIS_AUTO_ENRICH = get_env_bool('ANALYSIS_AUTO_ENRICH', True)
    AUTO_ANALYZE = get_env_bool('AUTO_ANALYZE', False)
    
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
        service_manager = cls.get_service_manager()
        
        try:
            # Configure logging
            cls.configure_logging()
            logger.info(f"Initializing {cls.ENVIRONMENT} configuration")
            
            # Initialize configuration store
            ConfigStore.init()
            
            # Load API keys
            api_keys = ConfigStore.get_config('api-keys')
            if api_keys and isinstance(api_keys, dict):
                cls.API_KEY = api_keys.get('platform_api_key', os.environ.get('API_KEY', 'default-api-key'))
                cls.EXTERNAL_API_KEYS = {k: v for k, v in api_keys.items() if k != 'platform_api_key'}
            else:
                cls.API_KEY = os.environ.get('API_KEY', 'default-api-key')
            
            # Load feed configuration
            feed_config = ConfigStore.get_config('feed-config')
            if feed_config and isinstance(feed_config, dict) and 'feeds' in feed_config:
                cls.FEEDS = feed_config['feeds']
                logger.info(f"Loaded {len(cls.FEEDS)} feeds from configuration")
            else:
                # Initialize with default feeds
                cls.FEEDS = DEFAULT_FEED_CONFIGS
                logger.info(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
            
            # Log configuration status
            logger.info(f"Configuration initialized - Environment: {cls.ENVIRONMENT}")
            logger.info(f"API Key: {cls.API_KEY[:4]}...{cls.API_KEY[-4:] if len(cls.API_KEY) > 8 else ''}")
            
            # Validate configuration
            if cls.validate_configuration():
                service_manager.update_status('config', ServiceStatus.READY)
            else:
                service_manager.update_status('config', ServiceStatus.DEGRADED, "Configuration validation warnings")
                
        except Exception as e:
            logger.error(f"Error initializing configuration: {e}")
            service_manager.update_status('config', ServiceStatus.ERROR, str(e))
            raise
    
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
            if cls.API_KEY == 'default-api-key':
                warnings.append("Production environment using default API key!")
        
        if not cls.GCP_PROJECT:
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        for warning in warnings:
            logger.warning(warning)
        
        for error in errors:
            logger.error(error)
        
        return len(errors) == 0
    
    @classmethod
    def get_service_manager(cls) -> ServiceManager:
        """Get the service manager instance."""
        return ServiceManager()
    
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
        feed_config = ConfigStore.get_config('feed-config')
        if not feed_config or not isinstance(feed_config, dict) or 'feeds' not in feed_config:
            logger.info("Creating default feed configuration")
            feed_config = {
                'feeds': DEFAULT_FEED_CONFIGS,
                'update_interval_hours': cls.FEED_UPDATE_INTERVAL
            }
            ConfigStore.set_config('feed-config', feed_config)
            cls.FEEDS = feed_config['feeds']
        return cls.FEEDS

# ===== Error Reporting =====
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting if enabled."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
    
    service_manager = Config.get_service_manager()
    
    try:
        from google.cloud import error_reporting
        global _error_client
        if _error_client is None:
            _error_client = error_reporting.Client(project=Config.GCP_PROJECT)
        _error_client.report_exception()
    except Exception as e:
        logger.error(f"Failed to report error: {e}")
        service_manager.update_status('error_reporting', ServiceStatus.ERROR, str(e))

# ===== GCP Client Initialization =====
def initialize_bigquery():
    """Initialize and return a BigQuery client."""
    service_manager = Config.get_service_manager()
    
    # Check if already initialized
    existing_client = service_manager.get_client('bigquery')
    if existing_client:
        return existing_client
    
    try:
        from google.cloud import bigquery
        client = bigquery.Client(project=Config.GCP_PROJECT, location=Config.BIGQUERY_LOCATION)
        service_manager.set_client('bigquery', client)
        service_manager.update_status('bigquery', ServiceStatus.READY)
        return client
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {e}")
        service_manager.update_status('bigquery', ServiceStatus.ERROR, str(e))
        return None

def initialize_storage():
    """Initialize and return a Cloud Storage client."""
    service_manager = Config.get_service_manager()
    
    # Check if already initialized
    existing_client = service_manager.get_client('storage')
    if existing_client:
        return existing_client
    
    try:
        from google.cloud import storage
        client = storage.Client(project=Config.GCP_PROJECT)
        service_manager.set_client('storage', client)
        service_manager.update_status('storage', ServiceStatus.READY)
        return client
    except Exception as e:
        logger.error(f"Failed to initialize Storage client: {e}")
        service_manager.update_status('storage', ServiceStatus.ERROR, str(e))
        return None

def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients."""
    service_manager = Config.get_service_manager()
    
    # Check if already initialized
    existing_publisher = service_manager.get_client('publisher')
    existing_subscriber = service_manager.get_client('subscriber')
    
    if existing_publisher and existing_subscriber:
        return existing_publisher, existing_subscriber
    
    try:
        from google.cloud import pubsub_v1
        publisher = pubsub_v1.PublisherClient()
        subscriber = pubsub_v1.SubscriberClient()
        
        service_manager.set_client('publisher', publisher)
        service_manager.set_client('subscriber', subscriber)
        service_manager.update_status('pubsub', ServiceStatus.READY)
        
        return publisher, subscriber
    except Exception as e:
        logger.error(f"Failed to initialize PubSub clients: {e}")
        service_manager.update_status('pubsub', ServiceStatus.ERROR, str(e))
        return None, None

def get_cached_config(name: str, force_refresh: bool = False):
    """Helper function to get cached config for other modules."""
    return ConfigStore.get_config(name)

def create_or_update_secret(name: str, value: Any):
    """Helper function to create or update a config value."""
    ConfigStore.set_config(name, value)
    return True

# Initialize configuration if imported
if __name__ != "__main__":
    # We don't initialize here to avoid circular imports, let the app do it
    pass

# Command-line testing functionality
if __name__ == "__main__":
    logger.info("Testing configuration module...")
    
    # Initialize Configuration
    Config.init_app()
    
    # Print configuration
    logger.info(f"Environment: {Config.ENVIRONMENT}")
    logger.info(f"GCP Project: {Config.GCP_PROJECT}")
    logger.info(f"API Key: {Config.API_KEY[:4]}...{Config.API_KEY[-4:] if len(Config.API_KEY) > 8 else ''}")
    logger.info(f"Feeds configured: {len(Config.FEEDS)}")
    
    # Test service manager
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    logger.info(f"Service Status: {json.dumps(status, indent=2)}")
    
    logger.info("Configuration test complete")
