"""
Optimized configuration module for Threat Intelligence Platform.
Handles configuration management for production deployment with improved service management.
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

# Centralized Service Manager with timeout handling
class ServiceManager:
    """Centralized service management and monitoring with timeout and recovery logic."""
    _instance = None
    _lock = threading.Lock()
    INITIALIZATION_TIMEOUT = 300  # 5 minutes
    
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
        self._service_start_times = {}
        self._lock = threading.Lock()
        
        # Initialize start times
        current_time = time.time()
        for service in self._services:
            self._service_start_times[service] = current_time
        
        # Start background monitoring
        self._start_background_monitor()
    
    def update_status(self, service: str, status: ServiceStatus, error: str = None):
        """Update service status with proper logging."""
        with self._lock:
            old_status = self._services.get(service)
            self._services[service] = status
            
            if error:
                self._errors[service] = error
                logger.error(f"Service {service} error: {error}")
            elif service in self._errors:
                del self._errors[service]
            
            # Log status changes
            if old_status != status:
                logger.info(f"Service {service} status changed: {old_status.value if old_status else 'None'} -> {status.value}")
    
    def get_status(self) -> Dict:
        """Get overall system status with timeout handling."""
        with self._lock:
            # Check for services stuck in initializing
            current_time = time.time()
            for service, status in list(self._services.items()):
                if status == ServiceStatus.INITIALIZING:
                    start_time = self._service_start_times.get(service, current_time)
                    if current_time - start_time > self.INITIALIZATION_TIMEOUT:
                        logger.warning(f"Service {service} stuck initializing for {int(current_time - start_time)}s, marking as degraded")
                        self._services[service] = ServiceStatus.DEGRADED
                        self._errors[service] = f"Initialization timeout after {int(current_time - start_time)}s"
            
            return {
                'services': {k: v.value for k, v in self._services.items()},
                'errors': dict(self._errors),
                'overall': self._calculate_overall_status().value,
                'timestamp': datetime.utcnow().isoformat(),
                'initialization_timeout': self.INITIALIZATION_TIMEOUT
            }
    
    def _calculate_overall_status(self) -> ServiceStatus:
        """Calculate overall system status with improved logic."""
        # Core services that must be ready for system to be operational
        critical_services = ['config', 'bigquery', 'storage', 'ingestion', 'app']
        
        # Services that can be in degraded mode without affecting core functionality
        optional_services = ['ai_models', 'pubsub', 'analysis']
        
        # Check critical services
        critical_statuses = [self._services[service] for service in critical_services if service in self._services]
        optional_statuses = [self._services[service] for service in optional_services if service in self._services]
        
        # If any critical service is in error, system is in error
        if any(s == ServiceStatus.ERROR for s in critical_statuses):
            return ServiceStatus.ERROR
        
        # If all critical services are ready, check overall system state
        if all(s == ServiceStatus.READY for s in critical_statuses):
            # If optional services have issues, system is degraded but functional
            if any(s in [ServiceStatus.ERROR, ServiceStatus.DEGRADED] for s in optional_statuses):
                return ServiceStatus.DEGRADED
            # If optional services are still initializing, that's ok
            elif any(s == ServiceStatus.INITIALIZING for s in optional_statuses):
                return ServiceStatus.READY  # Core system is ready
            else:
                return ServiceStatus.READY
        
        # If any critical service is degraded, system is degraded
        if any(s == ServiceStatus.DEGRADED for s in critical_statuses):
            return ServiceStatus.DEGRADED
        
        # Otherwise, system is still initializing
        return ServiceStatus.INITIALIZING
    
    def get_client(self, client_type: str):
        """Get a client instance with error handling."""
        with self._lock:
            return self._clients.get(client_type)
    
    def set_client(self, client_type: str, client):
        """Set a client instance with validation."""
        if client is None:
            logger.warning(f"Attempting to set None client for {client_type}")
            return
            
        with self._lock:
            self._clients[client_type] = client
            logger.info(f"Registered {client_type} client")
    
    def get_cache(self, key: str):
        """Get cached value."""
        with self._lock:
            return self._cache.get(key)
    
    def set_cache(self, key: str, value: Any):
        """Set cached value."""
        with self._lock:
            self._cache[key] = value
    
    def _start_background_monitor(self):
        """Start background service monitoring."""
        def monitor_services():
            while True:
                try:
                    with self._lock:
                        # Check for services that might need recovery
                        current_time = time.time()
                        for service, status in list(self._services.items()):
                            if status == ServiceStatus.ERROR:
                                # Check if we should attempt recovery
                                error_time = self._service_start_times.get(f"{service}_error", 0)
                                if current_time - error_time > 60:  # Retry after 1 minute
                                    logger.info(f"Attempting to recover service {service}")
                                    self._services[service] = ServiceStatus.INITIALIZING
                                    self._service_start_times[service] = current_time
                                    if service in self._errors:
                                        del self._errors[service]
                    
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    logger.error(f"Error in service monitor: {e}")
                    time.sleep(60)  # Wait longer on error
        
        monitor_thread = threading.Thread(target=monitor_services, daemon=True)
        monitor_thread.start()
        logger.info("Started background service monitor")

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
        except Exception as e:
            logger.debug(f"Error getting default credentials: {e}")
    except ImportError:
        logger.debug("google-auth not available")
    
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
        """Initialize the application configuration with improved error handling."""
        service_manager = cls.get_service_manager()
        service_manager.update_status('config', ServiceStatus.INITIALIZING)
        
        try:
            start_time = time.time()
            logger.info(f"Initializing {cls.ENVIRONMENT} configuration")
            
            # Configure logging first
            cls.configure_logging()
            
            # Load API key from environment or Secret Manager
            cls._load_api_key()
            
            # Load feed configuration
            cls._load_feed_config()
            
            # Validate configuration
            cls.validate_configuration()
            
            initialization_time = time.time() - start_time
            service_manager.update_status('config', ServiceStatus.READY)
            logger.info(f"Configuration initialized successfully in {initialization_time:.2f}s - Environment: {cls.ENVIRONMENT}")
            
        except Exception as e:
            logger.error(f"Configuration initialization failed: {str(e)}")
            service_manager.update_status('config', ServiceStatus.ERROR, str(e))
            raise
    
    @classmethod
    def _load_api_key(cls):
        """Load API key from environment or Secret Manager with retry logic."""
        # Try environment variable first
        api_key = os.environ.get('API_KEY')
        
        if api_key and api_key != 'default-api-key':
            cls.API_KEY = api_key.strip()
            logger.info(f"Loaded API key from environment: {cls.API_KEY[:4]}...{cls.API_KEY[-4:]}")
            return
        
        # Try Secret Manager if available
        if cls.GCP_PROJECT:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    from google.cloud import secretmanager
                    client = secretmanager.SecretManagerServiceClient()
                    secret_name = f"projects/{cls.GCP_PROJECT}/secrets/api-keys/versions/latest"
                    
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
                    logger.warning(f"Attempt {attempt + 1} failed to access Secret Manager: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        logger.warning(f"Could not access secret {secret_name} after {max_retries} attempts")
        
        # Use default if nothing else works
        cls.API_KEY = 'default-api-key'
        logger.warning("Using default API key")
    
    @classmethod
    def _load_feed_config(cls):
        """Load feed configuration with proper fallbacks and retry logic."""
        # Try environment variable first
        env_feeds = os.environ.get('FEED_CONFIG')
        if env_feeds:
            try:
                feed_config = json.loads(env_feeds)
                cls.FEEDS = feed_config.get('feeds', DEFAULT_FEED_CONFIGS)
                logger.info(f"Loaded {len(cls.FEEDS)} feeds from environment")
                return
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in FEED_CONFIG environment variable: {e}")
        
        # Try Secret Manager for feed config
        if cls.GCP_PROJECT:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    from google.cloud import secretmanager
                    client = secretmanager.SecretManagerServiceClient()
                    secret_name = f"projects/{cls.GCP_PROJECT}/secrets/feed-config/versions/latest"
                    
                    response = client.access_secret_version(request={"name": secret_name})
                    secret_value = response.payload.data.decode("UTF-8")
                    
                    # Debug logging
                    logger.debug(f"Raw secret value: {secret_value[:100]}...")
                    
                    feed_config = json.loads(secret_value)
                    cls.FEEDS = feed_config.get('feeds', DEFAULT_FEED_CONFIGS)
                    
                    # Ensure we have feeds
                    if not cls.FEEDS:
                        logger.warning("No feeds found in Secret Manager config, using defaults")
                        cls.FEEDS = DEFAULT_FEED_CONFIGS
                    
                    logger.info(f"Loaded {len(cls.FEEDS)} feeds from Secret Manager")
                    return
                except Exception as e:
                    logger.warning(f"Attempt {attempt + 1} failed to access feed config: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        logger.warning(f"Could not access feed config after {max_retries} attempts")
        
        # Always use default feeds as fallback
        cls.FEEDS = DEFAULT_FEED_CONFIGS
        logger.warning(f"Using default feed configuration with {len(cls.FEEDS)} feeds")
    
    @classmethod
    def configure_logging(cls):
        """Configure logging based on settings with improved formatting."""
        log_level = getattr(logging, cls.LOG_LEVEL.upper(), logging.INFO)
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler with improved formatting
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
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
        """Validate configuration values - improved validation with automatic fixes."""
        warnings = []
        errors = []
        fixes_applied = []
        
        if cls.ENVIRONMENT == 'production':
            if cls.API_KEY == 'default-api-key':
                warnings.append("Production environment using default API key!")
        
        if not cls.GCP_PROJECT:
            warnings.append("GCP_PROJECT not set - some GCP services may fail")
        
        if not cls.GCS_BUCKET:
            warnings.append("GCS_BUCKET not set - data storage may fail")
            # Auto-fix: generate bucket name
            if cls.GCP_PROJECT:
                cls.GCS_BUCKET = f"{cls.GCP_PROJECT}-threat-data"
                fixes_applied.append(f"Auto-generated GCS_BUCKET: {cls.GCS_BUCKET}")
        
        if not cls.BIGQUERY_DATASET:
            warnings.append("BIGQUERY_DATASET not set - data storage may fail")
        
        if not cls.FEEDS:
            errors.append("No feeds configured - using defaults")
            cls.FEEDS = DEFAULT_FEED_CONFIGS
            fixes_applied.append("Applied default feed configuration")
        
        # Log all findings
        for warning in warnings:
            logger.warning(warning)
        
        for error in errors:
            logger.error(error)
        
        for fix in fixes_applied:
            logger.info(f"Auto-fix applied: {fix}")
        
        # Allow startup even with errors to show error messages
        return True
    
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

# Error Reporting with retry logic
def report_error(exception: Exception):
    """Report an error to Cloud Error Reporting if enabled."""
    if not Config.ENABLE_ERROR_REPORTING:
        return
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            from google.cloud import error_reporting
            error_client = error_reporting.Client(project=Config.GCP_PROJECT)
            error_client.report_exception()
            logger.debug("Error reported to Cloud Error Reporting")
            return
        except Exception as e:
            logger.error(f"Failed to report error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)

# GCP Client Initialization with timeout and retry logic
def initialize_bigquery():
    """Initialize and return a BigQuery client with proper error handling."""
    service_manager = Config.get_service_manager()
    
    # Check if already initialized
    existing_client = service_manager.get_client('bigquery')
    if existing_client:
        return existing_client
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            from google.cloud import bigquery
            client = bigquery.Client(project=Config.GCP_PROJECT, location=Config.BIGQUERY_LOCATION)
            
            # Test the connection
            client.query("SELECT 1").result()
            
            service_manager.set_client('bigquery', client)
            service_manager.update_status('bigquery', ServiceStatus.READY)
            logger.info("BigQuery client initialized successfully")
            return client
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed to initialize BigQuery client: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                service_manager.update_status('bigquery', ServiceStatus.ERROR, str(e))
    
    return None

def initialize_storage():
    """Initialize and return a Cloud Storage client with proper error handling."""
    service_manager = Config.get_service_manager()
    
    existing_client = service_manager.get_client('storage')
    if existing_client:
        return existing_client
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            from google.cloud import storage
            client = storage.Client(project=Config.GCP_PROJECT)
            
            # Test the connection by listing buckets
            list(client.list_buckets(max_results=1))
            
            service_manager.set_client('storage', client)
            service_manager.update_status('storage', ServiceStatus.READY)
            logger.info("Storage client initialized successfully")
            return client
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed to initialize Storage client: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                service_manager.update_status('storage', ServiceStatus.ERROR, str(e))
    
    return None

def initialize_pubsub():
    """Initialize and return PubSub publisher and subscriber clients with proper error handling."""
    service_manager = Config.get_service_manager()
    
    publisher = service_manager.get_client('publisher')
    subscriber = service_manager.get_client('subscriber')
    
    if publisher and subscriber:
        return publisher, subscriber
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            from google.cloud import pubsub_v1
            publisher = pubsub_v1.PublisherClient()
            subscriber = pubsub_v1.SubscriberClient()
            
            # Test the connection by listing topics
            project_path = f"projects/{Config.GCP_PROJECT}"
            list(publisher.list_topics(request={"project": project_path}, max_results=1))
            
            service_manager.set_client('publisher', publisher)
            service_manager.set_client('subscriber', subscriber)
            service_manager.update_status('pubsub', ServiceStatus.READY)
            logger.info("PubSub clients initialized successfully")
            
            return publisher, subscriber
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed to initialize PubSub clients: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                service_manager.update_status('pubsub', ServiceStatus.ERROR, str(e))
    
    return None, None
