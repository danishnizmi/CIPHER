"""
Configuration module for Threat Intelligence Platform.
Loads environment variables from GCP Secret Manager or environment.
Provides automatic setup of required resources and credentials.
"""

import os
import base64
import json
import logging
import uuid
import hashlib
import datetime
import traceback
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
PROJECT_ID = os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID")
REGION = os.environ.get("GCP_REGION", "us-central1")
SERVICE_ACCOUNT = os.environ.get("SERVICE_ACCOUNT")

# Default environment type
ENV = os.environ.get("ENVIRONMENT", "development")

# Secret names
SECRET_NAMES = [
    "api-keys",
    "database-credentials",
    "feed-config",
    "auth-config"
]

# Configuration cache
_config_cache = {}

# Detect build mode vs runtime mode
# During container build, set CONTAINER_BUILD=true in Dockerfile
IS_BUILD_MODE = os.environ.get("CONTAINER_BUILD", "false").lower() == "true"

# Import Secret Manager with improved error handling
SECRET_MANAGER_AVAILABLE = False
try:
    # Skip authentication attempt during container build
    if IS_BUILD_MODE:
        logger.info("Container build mode detected, skipping Secret Manager authentication")
    else:
        from google.cloud import secretmanager
        
        # Test authentication by creating a client (doesn't make any API calls yet)
        client = secretmanager.SecretManagerServiceClient()
        SECRET_MANAGER_AVAILABLE = True
        logger.info("Google Cloud Secret Manager is available")
except ImportError as e:
    logger.warning(f"Google Cloud Secret Manager not imported: {str(e)}. Try installing with pip install google-cloud-secretmanager")
except Exception as e:
    logger.warning(f"Google Cloud Secret Manager is not available: {str(e)}")
    logger.warning(traceback.format_exc())

# GCP Services availability flags
BIGQUERY_AVAILABLE = False
STORAGE_AVAILABLE = False
PUBSUB_AVAILABLE = False
VERTEXAI_AVAILABLE = False

# Import GCP services with error handling
try:
    from google.cloud import bigquery
    BIGQUERY_AVAILABLE = True
    logger.info("BigQuery module is available")
except ImportError as e:
    logger.warning(f"BigQuery module not imported: {str(e)}. Try installing with pip install google-cloud-bigquery")
except Exception as e:
    logger.warning(f"BigQuery could not be initialized: {str(e)}")

try:
    from google.cloud import storage
    STORAGE_AVAILABLE = True
    logger.info("Storage module is available")
except ImportError as e:
    logger.warning(f"Storage module not imported: {str(e)}. Try installing with pip install google-cloud-storage")
except Exception as e:
    logger.warning(f"Storage could not be initialized: {str(e)}")

try:
    from google.cloud import pubsub_v1
    PUBSUB_AVAILABLE = True
    logger.info("Pub/Sub module is available")
except ImportError as e:
    logger.warning(f"Pub/Sub module not imported: {str(e)}. Try installing with pip install google-cloud-pubsub")
except Exception as e:
    logger.warning(f"Pub/Sub could not be initialized: {str(e)}")

try:
    import vertexai
    VERTEXAI_AVAILABLE = True
    logger.info("Vertex AI module is available")
except ImportError as e:
    logger.warning(f"Vertex AI module not imported: {str(e)}. Try installing with pip install vertexai")
except Exception as e:
    logger.warning(f"Vertex AI could not be initialized: {str(e)}")


def load_secret(secret_name: str) -> Optional[Dict[str, Any]]:
    """Load a secret from Secret Manager or environment variables"""
    # First check environment variables as a fallback
    env_var_name = f"{secret_name.upper().replace('-', '_')}"
    if env_var_name in os.environ:
        try:
            return json.loads(os.environ[env_var_name])
        except json.JSONDecodeError:
            return {"value": os.environ[env_var_name]}
    
    # Then try Secret Manager if available
    if not SECRET_MANAGER_AVAILABLE:
        logger.warning(f"Secret Manager not available, could not load {secret_name}")
        return None
    
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"
        
        # Log the secret access attempt (without the secret name for security)
        logger.info(f"Accessing secret from project {PROJECT_ID}")
        
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")
        
        # Try to parse as JSON
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            # Return as string if not valid JSON
            return {"value": payload}
            
    except Exception as e:
        logger.warning(f"Error loading secret {secret_name}: {str(e)}")
        logger.warning(traceback.format_exc())
        
        return None


def create_or_update_secret(secret_name: str, secret_data: Dict[str, Any]) -> bool:
    """Create or update a secret in Secret Manager"""
    # If Secret Manager is not available, set as environment variable
    if not SECRET_MANAGER_AVAILABLE:
        env_var_name = f"{secret_name.upper().replace('-', '_')}"
        os.environ[env_var_name] = json.dumps(secret_data)
        logger.info(f"Set environment variable {env_var_name} (Secret Manager not available)")
        return True
    
    try:
        client = secretmanager.SecretManagerServiceClient()
        parent = f"projects/{PROJECT_ID}"
        secret_id = secret_name
        
        # Check if secret exists
        try:
            secret_path = f"{parent}/secrets/{secret_id}"
            client.get_secret(request={"name": secret_path})
            secret_exists = True
            logger.info(f"Secret {secret_name} already exists")
        except Exception:
            secret_exists = False
            logger.info(f"Secret {secret_name} doesn't exist, creating new")
        
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
                logger.info(f"Created new secret: {secret_name}")
            except Exception as create_error:
                logger.error(f"Error creating secret {secret_name}: {str(create_error)}")
                logger.error(traceback.format_exc())
        
        # Add new version
        payload = json.dumps(secret_data).encode("UTF-8")
        secret_path = f"{parent}/secrets/{secret_id}"
        
        try:
            client.add_secret_version(
                request={"parent": secret_path, "payload": {"data": payload}}
            )
            logger.info(f"Updated secret: {secret_name}")
            return True
        except Exception as version_error:
            logger.error(f"Error adding version to secret {secret_name}: {str(version_error)}")
            logger.error(traceback.format_exc())
            return False
    
    except Exception as e:
        logger.error(f"Failed to update secret {secret_name}: {str(e)}")
        logger.error(traceback.format_exc())
        return False


def auto_detect_project_id() -> str:
    """Auto-detect GCP Project ID from metadata server or instance"""
    if PROJECT_ID:
        return PROJECT_ID
    
    # Try to get from metadata server
    try:
        import requests
        metadata_url = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        headers = {"Metadata-Flavor": "Google"}
        response = requests.get(metadata_url, headers=headers, timeout=2)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        logger.debug(f"Error fetching project ID from metadata server: {str(e)}")
    
    # Try to get from Application Default Credentials
    try:
        import google.auth
        credentials, project_id = google.auth.default()
        if project_id:
            return project_id
    except Exception as e:
        logger.debug(f"Error fetching project ID from google.auth: {str(e)}")
    
    # Generate a unique project ID for development
    if ENV == "development":
        logger.warning("Generating development project ID")
        return f"dev-threat-intel-{str(uuid.uuid4())[:8]}"
    
    # Default to the hardcoded value
    logger.warning("Could not detect GCP Project ID, using default")
    return "primal-chariot-382610"


def get_database_configuration() -> Dict[str, Any]:
    """Determine appropriate database configuration based on environment"""
    # Default to BigQuery for data storage
    db_name = f"threat_intelligence_{ENV.lower()}"
    
    # Check if Cloud SQL is available
    cloud_sql_available = False
    if PROJECT_ID and ENV != "development":
        try:
            from google.cloud import sql_admin_v1
            cloud_sql_available = True
        except ImportError:
            cloud_sql_available = False
    
    # Generate configuration based on environment
    if cloud_sql_available:
        # Use Cloud SQL with IAM authentication
        region = REGION
        instance = f"{PROJECT_ID}:{region}:threat-intelligence-db"
        
        return {
            "DATABASE_TYPE": "cloud_sql",
            "DATABASE_NAME": db_name,
            "DATABASE_INSTANCE": instance,
            "USE_IAM_AUTH": "true",
            "DATABASE_USER": "threat_app_user",
            "DATABASE_HOST": f"/cloudsql/{instance}",
            "DATABASE_PORT": "5432"
        }
    else:
        # Use BigQuery as primary data store
        return {
            "DATABASE_TYPE": "bigquery",
            "DATABASE_NAME": "threat_intelligence",
            "BIGQUERY_DATASET": os.environ.get("BIGQUERY_DATASET", "threat_intelligence"),
            "USE_APPLICATION_DEFAULT": "true"
        }


def get_feed_configurations() -> Dict[str, Dict[str, Any]]:
    """Get the feed configurations with sensible defaults"""
    return {
        "alienvault": {
            "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "auth_header": "X-OTX-API-KEY",
            "auth_key": "",
            "active": True,
            "table_id": "alienvault_pulses"
        },
        "misp": {
            "url": "",  # Empty by default, user needs to provide
            "auth_header": "Authorization",
            "auth_key": "",
            "active": False,  # Inactive by default since URL is empty
            "table_id": "misp_events"
        },
        "threatfox": {
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "auth_header": "",
            "auth_key": "",
            "active": True,
            "table_id": "threatfox_iocs"
        },
        "phishtank": {
            "url": "https://data.phishtank.com/data/online-valid.json",
            "table_id": "phishtank_urls",
            "active": True
        },
        "urlhaus": {
            "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            "table_id": "urlhaus_malware",
            "active": True
        },
        "feodotracker": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "table_id": "feodotracker_c2",
            "active": True
        },
        "sslbl": {
            "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.json",
            "table_id": "sslbl_certificates",
            "active": True
        }
    }


def get_auth_config() -> Dict[str, Any]:
    """Get authentication configuration with sensible defaults"""
    # Generate a random secret key for sessions
    secret_key = str(uuid.uuid4())
    
    # Default admin password (should be changed on first login)
    default_password = hashlib.sha256("changeme".encode()).hexdigest()
    
    return {
        "FLASK_SECRET_KEY": secret_key,
        "REQUIRE_AUTH": ENV != "development",
        "ALLOW_REGISTRATION": ENV == "development",
        "SESSION_TIMEOUT": 3600,  # 1 hour
        "USERS": {
            "admin": {
                "password": default_password,
                "role": "admin",
                "created_at": datetime.datetime.now().isoformat(),
                "last_login": None
            }
        }
    }


def get_api_keys_config() -> Dict[str, Any]:
    """Get API keys configuration with sensible defaults"""
    # Generate a random API key for internal use
    api_key = base64.b64encode(os.urandom(24)).decode('utf-8')
    
    return {
        "API_KEY": api_key,
        "VIRUSTOTAL_API_KEY": "",
        "ALIENVAULT_API_KEY": "",
        "MISP_API_KEY": "",
        "MANDIANT_API_KEY": ""
    }


def get_config() -> Dict[str, Any]:
    """Get the complete configuration"""
    global _config_cache
    
    # Return cached config if available
    if _config_cache:
        return _config_cache
    
    # Auto-detect and set project ID
    try:
        detected_project_id = auto_detect_project_id()
        if detected_project_id != PROJECT_ID and PROJECT_ID is None:
            os.environ["GCP_PROJECT"] = detected_project_id
        
        # Start with environment variables
        config = {
            "PROJECT_ID": detected_project_id,
            "REGION": REGION,
            "ENVIRONMENT": ENV,
            "API_URL": os.environ.get("API_URL", f"https://api-{ENV}.{detected_project_id}.cloudfunctions.net"),
            "BIGQUERY_DATASET": os.environ.get("BIGQUERY_DATASET", "threat_intelligence"),
            "GCS_BUCKET": os.environ.get("GCS_BUCKET", f"{detected_project_id}-threat-data"),
            "PUBSUB_TOPIC": os.environ.get("PUBSUB_TOPIC", "threat-data-ingestion"),
            "BIGQUERY_AVAILABLE": BIGQUERY_AVAILABLE,
            "STORAGE_AVAILABLE": STORAGE_AVAILABLE,
            "PUBSUB_AVAILABLE": PUBSUB_AVAILABLE,
            "VERTEXAI_AVAILABLE": VERTEXAI_AVAILABLE
        }
        
        # Load secrets with error handling
        for secret_name in SECRET_NAMES:
            try:
                secret_data = load_secret(secret_name)
                if secret_data:
                    # Flatten the secrets into the config
                    for key, value in secret_data.items():
                        config[key] = value
            except Exception as e:
                logger.warning(f"Error loading secret {secret_name}: {str(e)}")
                logger.warning(traceback.format_exc())
        
        # Cache and return
        _config_cache = config
        return config
        
    except Exception as e:
        logger.error(f"Error getting configuration: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return basic config if there was an error
        return {
            "PROJECT_ID": PROJECT_ID or "primal-chariot-382610",
            "REGION": REGION,
            "ENVIRONMENT": ENV,
            "API_URL": os.environ.get("API_URL", ""),
            "BIGQUERY_DATASET": os.environ.get("BIGQUERY_DATASET", "threat_intelligence"),
            "GCS_BUCKET": os.environ.get("GCS_BUCKET", ""),
            "PUBSUB_TOPIC": os.environ.get("PUBSUB_TOPIC", "threat-data-ingestion"),
            "BIGQUERY_AVAILABLE": BIGQUERY_AVAILABLE,
            "STORAGE_AVAILABLE": STORAGE_AVAILABLE,
            "PUBSUB_AVAILABLE": PUBSUB_AVAILABLE,
            "VERTEXAI_AVAILABLE": VERTEXAI_AVAILABLE
        }


def get(key: str, default: Any = None) -> Any:
    """Get a specific configuration value"""
    try:
        config = get_config()
        return config.get(key, default)
    except Exception as e:
        logger.error(f"Error getting config value for {key}: {str(e)}")
        return default


def update_api_key(service: str, key: str) -> bool:
    """Update an API key for a specific service"""
    try:
        api_keys = get_config().get("api-keys", {})
        if not api_keys:
            api_keys = get_api_keys_config()
        
        if service.upper() + "_API_KEY" in api_keys:
            api_keys[service.upper() + "_API_KEY"] = key
            result = create_or_update_secret("api-keys", api_keys)
            
            # Clear the cache to force a reload
            global _config_cache
            _config_cache = {}
            
            return result
        
        return False
    except Exception as e:
        logger.error(f"Error updating API key for {service}: {str(e)}")
        return False


def update_feed_config(feed_name: str, config_update: Dict[str, Any]) -> bool:
    """Update configuration for a specific feed"""
    try:
        feed_config = get_config().get("FEED_CONFIG", {})
        if not feed_config:
            feed_config = {"FEED_CONFIG": get_feed_configurations()}
        
        if feed_name in feed_config.get("FEED_CONFIG", {}):
            for key, value in config_update.items():
                feed_config["FEED_CONFIG"][feed_name][key] = value
            
            result = create_or_update_secret("feed-config", feed_config)
            
            # Clear the cache to force a reload
            global _config_cache
            _config_cache = {}
            
            return result
        
        return False
    except Exception as e:
        logger.error(f"Error updating feed config for {feed_name}: {str(e)}")
        return False


def add_user(username: str, password: str, role: str = "readonly") -> bool:
    """Add a new user to the auth configuration"""
    try:
        auth_config = get_config().get("auth-config", {})
        if not auth_config:
            auth_config = get_auth_config()
        
        users = auth_config.get("USERS", {})
        
        # Check if user already exists
        if username in users:
            return False
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Add the user
        users[username] = {
            "password": hashed_password,
            "role": role,
            "created_at": datetime.datetime.now().isoformat(),
            "last_login": None
        }
        
        auth_config["USERS"] = users
        result = create_or_update_secret("auth-config", auth_config)
        
        # Clear the cache to force a reload
        global _config_cache
        _config_cache = {}
        
        return result
    except Exception as e:
        logger.error(f"Error adding user {username}: {str(e)}")
        return False


def update_user(username: str, updates: Dict[str, Any]) -> bool:
    """Update a user in the auth configuration"""
    try:
        auth_config = get_config().get("auth-config", {})
        if not auth_config:
            auth_config = get_auth_config()
        
        users = auth_config.get("USERS", {})
        
        # Check if user exists
        if username not in users:
            return False
        
        # Update the user
        for key, value in updates.items():
            if key == "password":
                # Hash the password
                value = hashlib.sha256(value.encode()).hexdigest()
            
            users[username][key] = value
        
        auth_config["USERS"] = users
        result = create_or_update_secret("auth-config", auth_config)
        
        # Clear the cache to force a reload
        global _config_cache
        _config_cache = {}
        
        return result
    except Exception as e:
        logger.error(f"Error updating user {username}: {str(e)}")
        return False


def init_app_config():
    """Initialize all configuration from GCP Secret Manager and environment variables"""
    try:
        # Get the configuration
        config = get_config()
        logger.info(f"Configuration loaded for environment: {config['ENVIRONMENT']}")
        logger.info(f"Using project: {config['PROJECT_ID']}")
        
        # Set missing environment variables from config
        for key, value in config.items():
            if isinstance(value, str) and not os.environ.get(key):
                os.environ[key] = value
        
        # Skip trying to access additional secrets during build mode
        if IS_BUILD_MODE:
            logger.info("Build mode: skipping additional Secret Manager operations")
            return config
        
        # Check if key secrets exist and create them if not
        try:
            # Create default API keys if missing
            if not config.get("API_KEY"):
                logger.warning("API_KEY missing, setting defaults")
                api_keys_data = get_api_keys_config()
                create_or_update_secret("api-keys", api_keys_data)
                
                # Update config with the generated keys
                for key, value in api_keys_data.items():
                    config[key] = value
            
            # Create default feed configurations if missing
            if not config.get("FEED_CONFIG"):
                logger.warning("Feed configuration missing, setting defaults")
                feed_config = {"FEED_CONFIG": get_feed_configurations()}
                create_or_update_secret("feed-config", feed_config)
                
                # Update config with the generated feed config
                config["FEED_CONFIG"] = feed_config["FEED_CONFIG"]
            
            # Create default auth config if missing
            if not config.get("FLASK_SECRET_KEY"):
                logger.warning("Auth configuration missing, setting defaults")
                auth_config = get_auth_config()
                create_or_update_secret("auth-config", auth_config)
                
                # Update config with the generated auth config
                for key, value in auth_config.items():
                    config[key] = value
            
            # Create default database credentials if missing
            if not config.get("DATABASE_TYPE"):
                logger.warning("Database credentials missing, setting defaults")
                db_credentials = get_database_configuration()
                create_or_update_secret("database-credentials", db_credentials)
                
                # Update config with the generated database credentials
                for key, value in db_credentials.items():
                    config[key] = value
            
            # Initialize BigQuery dataset if needed
            if BIGQUERY_AVAILABLE and config.get("DATABASE_TYPE") == "bigquery":
                try:
                    # Initialize BigQuery dataset
                    bq_client = bigquery.Client(project=config["PROJECT_ID"])
                    dataset_id = config.get("BIGQUERY_DATASET", "threat_intelligence")
                    dataset_ref = bq_client.dataset(dataset_id)
                    
                    try:
                        # Check if dataset exists
                        bq_client.get_dataset(dataset_ref)
                        logger.info(f"BigQuery dataset {dataset_id} already exists")
                    except Exception:
                        # Create dataset if it doesn't exist
                        dataset = bigquery.Dataset(dataset_ref)
                        dataset.location = "US"
                        bq_client.create_dataset(dataset)
                        logger.info(f"Created BigQuery dataset {dataset_id}")
                except Exception as e:
                    logger.warning(f"Error initializing BigQuery dataset: {str(e)}")
            
            # Initialize GCS bucket if needed
            if STORAGE_AVAILABLE:
                try:
                    # Initialize GCS bucket
                    storage_client = storage.Client(project=config["PROJECT_ID"])
                    bucket_name = config.get("GCS_BUCKET")
                    
                    if bucket_name:
                        try:
                            # Check if bucket exists
                            storage_client.get_bucket(bucket_name)
                            logger.info(f"GCS bucket {bucket_name} already exists")
                        except Exception:
                            # Create bucket if it doesn't exist
                            bucket = storage_client.create_bucket(bucket_name, location="us-central1")
                            logger.info(f"Created GCS bucket {bucket_name}")
                except Exception as e:
                    logger.warning(f"Error initializing GCS bucket: {str(e)}")
            
            # Initialize Pub/Sub topics if needed
            if PUBSUB_AVAILABLE:
                try:
                    # Initialize Pub/Sub topics
                    publisher = pubsub_v1.PublisherClient()
                    
                    # Create ingestion topic if it doesn't exist
                    ingestion_topic = config.get("PUBSUB_TOPIC", "threat-data-ingestion")
                    topic_path = publisher.topic_path(config["PROJECT_ID"], ingestion_topic)
                    
                    try:
                        publisher.get_topic(request={"topic": topic_path})
                        logger.info(f"Pub/Sub topic {ingestion_topic} already exists")
                    except Exception:
                        publisher.create_topic(request={"name": topic_path})
                        logger.info(f"Created Pub/Sub topic {ingestion_topic}")
                    
                    # Create analysis topic if it doesn't exist
                    analysis_topic = "threat-analysis-events"
                    analysis_topic_path = publisher.topic_path(config["PROJECT_ID"], analysis_topic)
                    
                    try:
                        publisher.get_topic(request={"topic": analysis_topic_path})
                        logger.info(f"Pub/Sub topic {analysis_topic} already exists")
                    except Exception:
                        publisher.create_topic(request={"name": analysis_topic_path})
                        logger.info(f"Created Pub/Sub topic {analysis_topic}")
                except Exception as e:
                    logger.warning(f"Error initializing Pub/Sub topics: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating required resources: {str(e)}")
            logger.error(traceback.format_exc())
        
        # Clear cache and reload config
        global _config_cache
        _config_cache = {}
        updated_config = get_config()
        
        return updated_config
    except Exception as e:
        logger.error(f"Error initializing app config: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return basic config in case of errors
        return {
            "PROJECT_ID": PROJECT_ID or "primal-chariot-382610",
            "ENVIRONMENT": ENV,
            "REGION": REGION
        }


# Expose key configuration variables
try:
    project_id = auto_detect_project_id()
    region = REGION
    environment = ENV
    bigquery_dataset = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
    gcs_bucket = os.environ.get("GCS_BUCKET", f"{project_id}-threat-data")
    api_url = os.environ.get("API_URL", f"https://api-{ENV}.{project_id}.cloudfunctions.net")
    api_key = None  # Will be loaded from get()
    feed_configs = {}  # Will be loaded from get()

    # Initialize if this module is imported directly
    if __name__ != "__main__":
        # Only initialize if not already initialized
        if not _config_cache:
            init_app_config()
            # Update module-level variables
            api_key = get("API_KEY")
            feed_configs = get("FEED_CONFIG", {})
except Exception as e:
    logger.error(f"Error initializing module variables: {str(e)}")
    logger.error(traceback.format_exc())
