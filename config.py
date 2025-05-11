"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management for production deployment.
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

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Service Status Enum
class ServiceStatus(Enum):
    INITIALIZING = "initializing"
    READY = "ready"
    DEGRADED = "degraded"
    ERROR = "error"

# Centralized Service Manager
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
            'api': ServiceStatus.INITIALIZING,
            'app': ServiceStatus.INITIALIZING
        }
        self._clients = {}
        self._errors = {}
        self._cache = {}
        self._lock = threading.Lock()
    
    def update_status(self, service: str, status: ServiceStatus, error: str = None):
        """Update service status."""
        with self._lock:
            self._services[service] = status
            if error:
                self._errors[service] = error
                logger.error(f"Service {service} error: {error}")
            elif service in self._errors:
                del self._errors[service]
            logger.info(f"Service {service} status: {status.value}")
    
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
            logger.info(f"Registered {client_type} client")
    
    def get_cache(self, key: str):
        """Get cached value."""
        return self._cache.get(key)
    
    def set_cache(self, key: str, value: Any):
        """Set cached value."""
        with self._lock:
            self._cache[key] = value

# Constants and Default Configuration
DEFAULT_API_RATE_LIMIT = "1000 per day, 100 per hour"
DEFAULT_SECRET_TTL = 86400  # 24 hours
FEED_TYPES = ["indicators", "vulnerabilities", "threat_actors", "campaigns", "malware"]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Default feed configurations
DEFAULT_FEED_CONFIGS = [
    {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent indicators from ThreatFox",
        "format": "json",
        "type": "mixed",
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
    }
]

# Utility Functions
@lru_cache(maxsize=1)
def get_project_id() -> Optional[str]:
    """Get Google Cloud project ID with cache."""
    project_id = os.environ.get('GCP_PROJECT')
    if project_id:
        return project_id
    
    try:
        import google.auth
        try:
            credentials, project_id = google.auth.default()
            if project_id:
                os.environ['GCP_PROJECT'] = project_id
                return project_id
        except Exception:
            pass
    except ImportError:
        pass
    
    return os.environ.get('FALLBACK_PROJECT_ID', "primal-chariot-382610")

def get_env_bool(var_name: str, default: bool = False) -> bool:
    """Get boolean value from environment variable."""
    val = os.environ.get(var_name, str(default)).lower()
    return val in ('true', 't', 'yes', 'y', '1')

# Main Configuration Class
class Config:
    """Base configuration class for production deployment."""
    
    # Basic Application Configuration
    DEBUG = get_env_bool('DEBUG', False)
    TESTING = get_env_bool('TESTING', False)
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    VERSION = os.environ.get('VERSION', '1.0.3')
    
    # Google Cloud Configuration
    GCP_PROJECT = get_project_id()
    GCP_REGION = os.environ.get('GCP_REGION', 'us-central1')
    
    # BigQuery Configuration
    BIGQUERY_DATASET = os.environ.get('BIGQUERY_DATASET', 'threat_intelligence')
    BIGQUERY_LOCATION = os.environ.get('BIGQUERY_LOCATION', 'US')
    BIGQUERY_MAX_BYTES_BILLED = int(os.environ.get('BIGQUERY_MAX_BYTES_BILLED', 104857600))
    BIGQUERY_TABLES = {
        'indicators': 'indicators',
        'vulnerabilities': 'vulnerabilities',
        'threat_actors': 'threat_actors',
        'campaigns': 'campaigns',
        'malware': 'malware',
        'users': 'users',
        'audit_log': 'audit_log'
    }
    
    # Storage Configuration
    GCS_BUCKET = os.environ.get('GCS_BUCKET', f"{GCP_PROJECT}-threat-data" if GCP_PROJECT else 'threat-data')
    
    # PubSub Configuration
    PUBSUB_TOPIC = os.environ.get('PUBSUB_TOPIC', 'threat-data-ingestion')
    PUBSUB_ANALYSIS_TOPIC = os.environ.get('PUBSUB_ANALYSIS_TOPIC', 'threat-analysis-events')
    
    # Server Configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))
    
    # API Configuration
    API_KEY = None  # Will be initialized in init_app
    API_VERSION = 'v1'
    API_RATE_LIMIT = os.environ.get('API_RATE_LIMIT', DEFAULT_API_RATE_LIMIT)
    
    # Feed Configuration
    FEEDS = []  # Will be initialized in init_app
    FEED_UPDATE_INTERVAL = int(os.environ.get('FEED_UPDATE_INTERVAL', 3))
    
    # Analysis Configuration
    ANALYSIS_ENABLED = get_env_bool('ANALYSIS_ENABLED', True)
    ANALYSIS_AUTO_ENRICH = get_env_bool('ANALYSIS_AUTO_ENRICH', True)
    AUTO_ANALYZE = get_env_bool('AUTO_ANALYZE', False)
    
    # NLP Configuration
    NLP_ENABLED = get_env_bool('NLP_ENABLED', True)
    VERTEXAI_LOCATION = os.environ.get('VERTEXAI_LOCATION', 'us-central1')
    VERTEXAI_MODEL = os.environ.get('VERTEXAI_MODEL', 'text-bison@latest')
    
    # Error and Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_CLOUD = get_env_bool('LOG_TO_CLOUD', False)
    ENABLE_ERROR_REPORTING = get_env_bool('ENABLE_ERROR_REPORTING', False)
    
    @classmethod
    def init_app(cls):
        """Initialize the application configuration."""
        service_manager = cls.get_service_manager()
        service_manager.update_status('config', ServiceStatus.INITIALIZING)
        
        try:
            cls.configure_logging()
            logger.info(f"Initializing {cls.ENVIRONMENT} configuration")
            
            # Load API key from environment or Secret Manager
            cls._load_api_key()
            
            # Load feed configuration
            cls._load_feed_config()
            
            # Validate configuration
            cls.validate_configuration()
            
            service_manager.update_status('config', ServiceStatus.READY)
            logger.info(f"Configuration initialized - Environment: {cls.ENVIRONMENT}")
            
        except Exception as e:
            logger.error(f"Configuration initialization failed: {str(e)}")
            service_manager.update_status('config', ServiceStatus.ERROR, str(e))
            raise
    
    @classmethod
    def _load_api_key(cls):
        """Load API key from environment or Secret Manager."""
        # Try environment variable first
        api_key = os.environ.get('API_KEY')
        
        if api_key and api_key != 'default-api-key':
            cls.API_KEY = api_key.strip()
            logger.info(f"Loaded API key from environment: {cls.API_KEY[:4]}...{cls.API_KEY[-4:]}")
            return
        
        # Try Secret Manager if available
        if cls.GCP_PROJECT:
            try:
                from google.cloud import secretmanager
                client = secretmanager.SecretManagerServiceClient()
                secret_name = f"projects/{cls.GCP_PROJECT}/secrets/api-keys/versions/latest"
                
                try:
                    response = client.access_secret_version(request={"name": secret_name})
                    secret_value = response.payload.data.decode("UTF-8")
                    
                    # Parse JSON if it's JSON format
                    if secret_value.strip().startswith('{'):
                        api_config = json.loads(secret_value)
                        cls.API_KEY = api_config.get('platform_api_key', '').strip()
                    else:
                        cls.API_KEY = secret_value.strip()
                    
                    logger.info(f"Loaded API key from Secret Manager: {cls.API_KEY[:4]}...{cls.API_KEY[-4:]}")
                    return
                except Exception as e:
                    logger.warning(f"Could not access secret {secret_name}: {str(e)}")
            except ImportError:
                logger.warning("Secret Manager client not available")
        
        # Use default if nothing else works
        cls.API_KEY = 'default-api-key'
        logger.warning("Using default API key")
    
    @classmethod
    def _load_feed_config(cls):
        """Load feed configuration."""
        # Try environment variable first
        env_feeds = os.environ.get('FEED_CONFIG')
        if env_feeds:
            try:
                feed_config = json.loads(env_feeds)
                cls.FEEDS = feed_config.get('feeds', DEFAULT_FEED_CONFIGS)
                logger.info(f"Loaded {len(cls.FEEDS)} feeds from environment")
                return
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in FEED_CONFIG environment variable")
        
        # Try Secret Manager for feed config
        if cls.GCP_PROJECT:
            try:
                from google.cloud import secretmanager
                client = secretmanager.SecretManagerServiceClient()
                secret_name = f"projects/{cls.GCP_PROJECT}/secrets/feed-config/versions/latest"
                
                try:
                    response = client.access_secret_version(request={"name": secret_name})
                    secret_value = response.payload.data.decode("UTF-8")
                    feed_config = json.loads(secret_value)
                    cls.FEEDS = feed_config.get('feeds', DEFAULT_FEED_CONFIGS)
                    logger.info(f"Loaded {len(cls.FEEDS)} feeds from Secret Manager")
                    return
                except Exception as e:
                    logger.warning(f"Could not access feed config from Secret Manager: {str(e)}")
            except ImportError:
                pass
        
        # Use default feeds
        cls.FEEDS = DEFAULT_FEED_CONFIGS
        logger.info(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
    
    @classmethod
    def configure_logging(cls):
        """Configure logging based on settings."""
        log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)
        
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
        """Validate configuration values."""
        warnings = []
        errors = []
        
        if cls.ENVIRONMENT == 'production':
            if cls.API_KEY == 'default-api-key':
                warnings.append("Production environment using default API key!")
        
        if not cls.GCP_PROJECT:
            errors.append("GCP_PROJECT not set - multiple GCP services will fail")
        
        if not cls.GCS_BUCKET:
            errors.append("GCS_BUCKET not set - data storage will fail")
        
        if not cls.BIGQUERY_DATASET:
            errors.append("BIGQUERY_DATASET not set - data storage will fail")
        
        for warning in warnings:
            logger.warning(warning)
        
        for error in errors:
            logger.error(error)
        
        # Allow startup even with errors to show error messages
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
        """Get the full BigQuery table name."""
        if not cls.GCP_PROJECT or not cls.BIGQUERY_DATASET:
            return None
        
        table_name = cls.BIGQUERY_TABLES.get(table_key)
        if not table_name:
            return None
        
        return f"{cls.GCP_PROJECT}.{cls.BIGQUERY_DATASET}.{table_name}"

# Error Reporting
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting if enabled."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
    
    try:
        from google.cloud import error_reporting
        error_client = error_reporting.Client(project=Config.GCP_PROJECT)
        error_client.report_exception()
    except Exception as e:
        logger.error(f"Failed to report error: {e}")

# GCP Client Initialization
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
    
    publisher = service_manager.get_client('publisher')
    subscriber = service_manager.get_client('subscriber')
    
    if publisher and subscriber:
        return publisher, subscriber
    
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

# Module initialization check
if __name__ == "__main__":
    logger.info("Testing configuration module...")
    Config.init_app()
    print(f"Environment: {Config.ENVIRONMENT}")
    print(f"GCP Project: {Config.GCP_PROJECT}")
    print(f"API Key: {Config.API_KEY[:4]}...{Config.API_KEY[-4:] if len(Config.API_KEY) > 8 else ''}")
    print(f"Feeds configured: {len(Config.FEEDS)}")
    print(f"Service Status: {Config.get_service_manager().get_status()}")
