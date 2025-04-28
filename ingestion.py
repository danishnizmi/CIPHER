"""
Threat Intelligence Platform - Enhanced Ingestion Module
Handles collection of threat data from open-source feeds and loads it into BigQuery.
Optimized for GCP services with improved reliability and performance.
"""

import os
import json
import logging
import csv
import time
import base64
from io import StringIO, BytesIO
import zipfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Iterator
from collections import defaultdict
from functools import wraps
import re
import hashlib

import requests
from google.cloud import bigquery
from google.cloud import storage
from google.cloud import pubsub_v1
from google.api_core import retry, exceptions
from google.api_core.retry import Retry
from google.cloud.exceptions import NotFound

# Import config module
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from config module
PROJECT_ID = config.project_id
BUCKET_NAME = config.gcs_bucket
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-data-ingestion")
ENVIRONMENT = config.environment

# Global clients
_clients = {}

# Rate limiting management
_last_request_time = defaultdict(float)
_rate_limit_delays = {
    "phishtank.com": 60,       # 60 seconds due to rate limit issues
    "data.phishtank.com": 60,  
    "urlhaus.abuse.ch": 10,   
    "threatfox.abuse.ch": 10, 
    "default": 5              
}

# BigQuery specific configuration
BQ_INSERT_BATCH_SIZE = 500  # Number of rows to insert in a single batch
BQ_MAX_RETRIES = 5         # Maximum number of retries for BigQuery operations
BQ_RETRY_DELAY = 1.5       # Base delay factor for exponential backoff

# GCP service availability flag
GCP_SERVICES_AVAILABLE = False
try:
    from google.cloud import bigquery, storage, pubsub_v1, secretmanager
    from google.api_core import retry, exceptions
    import google.auth
    GCP_SERVICES_AVAILABLE = True
    logger.info("GCP libraries successfully imported for ingestion module")
except ImportError:
    logger.warning("GCP libraries not available for ingestion module - will operate in degraded mode")

# Enhanced Open Source Feed Definitions with direct links
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "opensrc_url": "https://threatfox.abuse.ch/export/json/recent/",
        "fallback_url": "https://threatfox.abuse.ch/export/csv/recent/", 
        "table_id": "threatfox_iocs",
        "format": "json",
        "auth_required": False,
        "description": "ThreatFox IOCs - Malware indicators database",
        "json_mapping": {
            "path_options": [
                "data.iocs",   # Standard path
                "data",        # Alternative path
                ""             # Root level
            ],
            "id_fields": ["id", "ioc_id"]  # Fields that might contain unique IDs
        }
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "fallback_url": "https://data.phishtank.com/data/online-valid.csv",
        "table_id": "phishtank_urls",
        "format": "json",
        "auth_required": False,
        "rate_limit": 60,
        "description": "PhishTank - Community-verified phishing URLs"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "fallback_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv",
        "skip_lines": 8,  # Skip header info/comments
        "description": "URLhaus - Database of malicious URLs"
    },
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "fallback_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "table_id": "feodotracker_c2",
        "format": "json",
        "auth_required": False,
        "description": "Feodo Tracker - Botnet C2 IP Blocklist"
    },
    "cisa_known": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "table_id": "cisa_vulnerabilities",
        "format": "json",
        "json_root": "vulnerabilities",
        "auth_required": False,
        "description": "CISA Known Exploited Vulnerabilities Catalog"
    },
    "tor_exit": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "table_id": "tor_exit_nodes",
        "format": "text",
        "auth_required": False,
        "description": "Tor Exit Node List"
    },
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "table_id": "alienvault_otx",
        "format": "json",
        "auth_required": True,
        "auth_header": "X-OTX-API-KEY",
        "description": "AlienVault OTX - Open Threat Exchange"
    },
    "misp_feed": {
        "url": "https://raw.githubusercontent.com/MISP/MISP-STIX-Converter/main/examples/threat_report.json",
        "table_id": "misp_threats",
        "format": "json",
        "auth_required": False,
        "description": "MISP - Malware Information Sharing Platform"
    }
}

# Create a dummy client for graceful degradation
class DummyClient:
    """Dummy client to use when a service is unavailable"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        
    def __getattr__(self, name):
        def dummy_method(*args, **kwargs):
            logger.warning(f"{self.service_name} not available, {name} called but will return None")
            return None
        return dummy_method

def get_client(client_type: str):
    """Get or initialize a Google Cloud client with proper retry settings"""
    global _clients
    
    # Return cached client if available
    if client_type in _clients and _clients[client_type] is not None:
        return _clients[client_type]
    
    if not GCP_SERVICES_AVAILABLE and client_type not in ['bigquery']:
        # BigQuery can still work in some cases without full GCP integration
        logger.warning(f"GCP services not available, cannot create {client_type} client")
        return DummyClient(client_type)
    
    try:
        if client_type == 'bigquery':
            # Configure custom retry for BigQuery
            custom_retry = retry.Retry(
                initial=1.0,       # Initial backoff in seconds
                maximum=60.0,      # Maximum backoff
                multiplier=2.0,    # Multiplier for exponential backoff
                predicate=retry.if_transient_error,  # Retry on transient errors
                deadline=300.0     # Total deadline in seconds
            )
            
            # Create client
            client = bigquery.Client(project=PROJECT_ID)
            
            # Configure retry for operations client
            if hasattr(client, '_transport') and hasattr(client._transport, '_operations_client'):
                if hasattr(client._transport._operations_client, '_transport') and \
                   hasattr(client._transport._operations_client._transport, '_operations_stub'):
                    client._transport._operations_client._transport._operations_stub._interceptors.append(
                        retry.retry_interceptor(custom_retry)
                    )
            
            _clients[client_type] = client
            logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
            
        elif client_type == 'storage':
            _clients[client_type] = storage.Client(project=PROJECT_ID)
            logger.info(f"Storage client initialized for project {PROJECT_ID}")
            
        elif client_type == 'pubsub':
            # Configure custom retry for Pub/Sub
            custom_retry = retry.Retry(
                initial=1.0,
                maximum=30.0,
                multiplier=1.5,
                predicate=retry.if_transient_error,
                deadline=120.0
            )
            
            _clients[client_type] = pubsub_v1.PublisherClient()
            logger.info("Pub/Sub publisher initialized")
            
        elif client_type == 'secretmanager':
            _clients[client_type] = secretmanager.SecretManagerServiceClient()
            logger.info("Secret Manager client initialized")
            
        else:
            logger.error(f"Unknown client type: {client_type}")
            return DummyClient(client_type)
            
        return _clients[client_type]
        
    except Exception as e:
        logger.error(f"Failed to initialize {client_type} client: {str(e)}")
        _clients[client_type] = DummyClient(client_type)
        return _clients[client_type]

def exponential_backoff_retry(max_retries: int = 5, base_delay: float = 1.0):
    """Decorator for exponential backoff retries on functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise
                    
                    wait_time = base_delay * (2 ** (retries - 1))
                    logger.warning(f"Retry {retries}/{max_retries} after error: {str(e)}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
        return wrapper
    return decorator

def _rate_limited_request(url, timeout=30, max_retries=3, headers=None, api_key=None, auth_header=None):
    """Make a rate-limited request with respect to API limits and authentication"""
    domain = url.split('/')[2]
    
    # Determine delay based on domain
    delay = _rate_limit_delays.get(domain, _rate_limit_delays['default'])
    
    # Set default headers if none provided
    if headers is None:
        headers = {
            'User-Agent': 'ThreatIntelligencePlatform/1.0 (Research)',
            'Accept': 'application/json, text/plain, */*'
        }
    
    # Add authentication if provided
    if api_key and auth_header:
        headers[auth_header] = api_key
    
    for retry in range(max_retries):
        # Check if we need to wait
        time_since_last = time.time() - _last_request_time.get(domain, 0)
        if time_since_last < delay:
            wait_time = delay - time_since_last
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s before requesting from {domain}")
            time.sleep(wait_time)
        
        # Make request and record time
        try:
            logger.info(f"Requesting URL: {url}")
            response = requests.get(url, timeout=timeout, headers=headers)
            _last_request_time[domain] = time.time()
            
            # Log response details
            logger.info(f"Response status: {response.status_code}, size: {len(response.content)} bytes")
            
            # Handle rate limit responses
            if response.status_code == 429:
                logger.warning(f"Rate limit hit for {domain}. Response: {response.text[:100]}")
                # Increase delay for this domain for future requests
                _rate_limit_delays[domain] = min(_rate_limit_delays[domain] * 2, 300)  # Max 5 minutes
                
                # Apply backoff
                if retry < max_retries - 1:
                    wait_time = (2 ** retry) * 60  # Exponential backoff
                    logger.info(f"Backing off for {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                else:
                    raise requests.RequestException(f"Rate limit exceeded for {domain} after {max_retries} retries")
            
            # Check for other error codes
            if response.status_code >= 400:
                logger.warning(f"HTTP error {response.status_code} from {domain}: {response.text[:100]}")
                if retry < max_retries - 1:
                    wait_time = (2 ** retry) * 10
                    logger.info(f"HTTP error, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            return response
            
        except requests.RequestException as e:
            # Apply backoff for network errors
            if retry < max_retries - 1:
                wait_time = (2 ** retry) * 10  # Exponential backoff
                logger.info(f"Request error: {str(e)}. Backing off for {wait_time}s before retry")
                time.sleep(wait_time)
            else:
                raise
    
    # Should not reach here, but just in case
    raise requests.RequestException(f"Failed to make request to {url} after {max_retries} retries")

def ensure_resources(force_create=False) -> bool:
    """Ensure BigQuery datasets and tables exist with proper ACLs and metadata"""
    client = get_client('bigquery')
    if isinstance(client, DummyClient):
        return False
    
    try:
        # Create dataset if it doesn't exist
        try:
            dataset = client.get_dataset(DATASET_ID)
            logger.info(f"Dataset {DATASET_ID} already exists")
        except NotFound:
            logger.info(f"Dataset {DATASET_ID} not found, creating it")
            dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
            dataset.location = "US"
            
            # Add metadata
            dataset.description = "Threat Intelligence Platform Dataset"
            dataset.labels = {
                "env": ENVIRONMENT,
                "department": "security",
                "application": "threat-intelligence"
            }
            
            dataset = client.create_dataset(dataset, exists_ok=True)
            logger.info(f"Created dataset {DATASET_ID}")
            
            # Ensure service account has proper access
            service_account = f"cloud-build-service@{PROJECT_ID}.iam.gserviceaccount.com"
            dataset_access_entry = bigquery.AccessEntry(
                role="roles/bigquery.dataEditor",
                entity_type="userByEmail", 
                entity_id=service_account
            )
            entries = list(dataset.access_entries)
            entries.append(dataset_access_entry)
            dataset.access_entries = entries
            client.update_dataset(dataset, ["access_entries"])
            logger.info(f"Updated dataset permissions for {service_account}")
        
        # Create GCS bucket if needed
        storage_client = get_client('storage')
        if not isinstance(storage_client, DummyClient):
            try:
                bucket = storage_client.get_bucket(BUCKET_NAME)
                logger.info(f"GCS bucket {BUCKET_NAME} already exists")
            except NotFound:
                logger.info(f"GCS bucket {BUCKET_NAME} not found, creating it")
                bucket = storage_client.create_bucket(BUCKET_NAME, location="us-central1")
                logger.info(f"Created GCS bucket {BUCKET_NAME}")
        
        # Define standard fields all tables should have
        standard_fields = [
            bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
            bigquery.SchemaField("_ingestion_id", "STRING"),
            bigquery.SchemaField("_source", "STRING"),
            bigquery.SchemaField("_feed_type", "STRING")
        ]
        
        # Create tables if they don't exist
        for feed_name, feed_config in FEED_SOURCES.items():
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                if not force_create:
                    table = client.get_table(full_table_id)
                    logger.info(f"Table {table_id} already exists")
                    
                    # Check if standard fields exist
                    existing_fields = {field.name for field in table.schema}
                    missing_fields = []
                    for field in standard_fields:
                        if field.name not in existing_fields:
                            missing_fields.append(field)
                    
                    if missing_fields:
                        # Update schema with missing fields
                        new_schema = list(table.schema) + missing_fields
                        table.schema = new_schema
                        client.update_table(table, ["schema"])
                        logger.info(f"Added missing standard fields to {table_id}: {[f.name for f in missing_fields]}")
                else:
                    # Force table creation for testing
                    raise NotFound("Forcing table creation")
            except NotFound:
                # Create with enhanced schema based on feed type
                schema = standard_fields.copy()
                
                # Add feed-specific fields
                feed_format = feed_config.get("format")
                if feed_format == "json":
                    if feed_name == "threatfox":
                        schema.extend([
                            bigquery.SchemaField("id", "STRING"),
                            bigquery.SchemaField("ioc_type", "STRING"),
                            bigquery.SchemaField("ioc_value", "STRING"),
                            bigquery.SchemaField("threat_type", "STRING"),
                            bigquery.SchemaField("malware", "STRING"),
                            bigquery.SchemaField("confidence_level", "INTEGER"),
                            bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
                            bigquery.SchemaField("first_seen", "TIMESTAMP")
                        ])
                    elif feed_name == "phishtank":
                        schema.extend([
                            bigquery.SchemaField("url", "STRING"),
                            bigquery.SchemaField("phish_id", "STRING"),
                            bigquery.SchemaField("submission_time", "TIMESTAMP"),
                            bigquery.SchemaField("verified", "BOOLEAN"),
                            bigquery.SchemaField("verification_time", "TIMESTAMP"),
                            bigquery.SchemaField("target", "STRING")
                        ])
                
                # Create the table with schema
                table = bigquery.Table(full_table_id, schema=schema)
                
                # Add table description and expiration
                table.description = feed_config.get("description", "Threat Intelligence Feed")
                if ENVIRONMENT != "production":
                    # Set 90-day expiration for non-production environments
                    expiration_ms = 90 * 24 * 60 * 60 * 1000  # 90 days in milliseconds
                    table.expires = datetime.now() + timedelta(days=90)
                
                # Add clustering/partitioning for large tables
                if feed_name in ["threatfox", "phishtank", "urlhaus"]:
                    table.time_partitioning = bigquery.TimePartitioning(
                        type_=bigquery.TimePartitioningType.DAY,
                        field="_ingestion_timestamp"
                    )
                    if feed_name == "threatfox":
                        table.clustering_fields = ["ioc_type", "threat_type"]
                    elif feed_name == "phishtank":
                        table.clustering_fields = ["target", "verified"]
                
                # Create the table
                table = client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id} with enhanced schema and settings")
        
        # Create an additional threat_analysis table for later use
        try:
            analysis_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
            client.get_table(analysis_table_id)
            logger.info("Analysis table already exists")
        except NotFound:
            # Create analysis table with enhanced schema
            schema = [
                bigquery.SchemaField("source_id", "STRING"),
                bigquery.SchemaField("source_type", "STRING"),
                bigquery.SchemaField("iocs", "STRING"),
                bigquery.SchemaField("vertex_analysis", "STRING"),
                bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("analysis_id", "STRING"),
                bigquery.SchemaField("analysis_version", "STRING"),
                bigquery.SchemaField("severity", "STRING"),
                bigquery.SchemaField("confidence", "STRING"),
                bigquery.SchemaField("threat_actors", "STRING", mode="REPEATED"),
                bigquery.SchemaField("target_sectors", "STRING", mode="REPEATED"),
                bigquery.SchemaField("target_regions", "STRING", mode="REPEATED"),
                bigquery.SchemaField("malware_families", "STRING", mode="REPEATED"),
                bigquery.SchemaField("techniques", "STRING", mode="REPEATED")
            ]
            
            table = bigquery.Table(analysis_table_id, schema=schema)
            table.description = "Threat Intelligence Analysis Results"
            
            # Add partitioning and clustering
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="analysis_timestamp"
            )
            table.clustering_fields = ["source_type", "severity"]
            
            client.create_table(table, exists_ok=True)
            logger.info("Created analysis table with enhanced schema")
        
        # Create threat_campaigns table
        try:
            campaigns_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
            client.get_table(campaigns_table_id)
            logger.info("Campaigns table already exists")
        except NotFound:
            # Create campaigns table
            schema = [
                bigquery.SchemaField("campaign_id", "STRING"),
                bigquery.SchemaField("campaign_name", "STRING"),
                bigquery.SchemaField("threat_actor", "STRING"),
                bigquery.SchemaField("malware", "STRING"),
                bigquery.SchemaField("techniques", "STRING"),
                bigquery.SchemaField("targets", "STRING"),
                bigquery.SchemaField("severity", "STRING"),
                bigquery.SchemaField("sources", "STRING"),
                bigquery.SchemaField("iocs", "STRING"),
                bigquery.SchemaField("source_count", "INTEGER"),
                bigquery.SchemaField("ioc_count", "INTEGER"),
                bigquery.SchemaField("first_seen", "TIMESTAMP"),
                bigquery.SchemaField("last_seen", "TIMESTAMP"),
                bigquery.SchemaField("detection_timestamp", "TIMESTAMP")
            ]
            
            table = bigquery.Table(campaigns_table_id, schema=schema)
            table.description = "Detected Threat Campaigns"
            
            client.create_table(table, exists_ok=True)
            logger.info("Created campaigns table")
        
        # Ensure PubSub topic exists
        pubsub_client = get_client('pubsub')
        if not isinstance(pubsub_client, DummyClient):
            topic_path = pubsub_client.topic_path(PROJECT_ID, PUBSUB_TOPIC)
            try:
                pubsub_client.get_topic(request={"topic": topic_path})
                logger.info(f"PubSub topic {PUBSUB_TOPIC} already exists")
            except Exception:
                pubsub_client.create_topic(request={"name": topic_path})
                logger.info(f"Created PubSub topic {PUBSUB_TOPIC}")
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring resources: {str(e)}")
        return False

def _get_api_keys() -> Dict[str, str]:
    """Get API keys for authenticated feeds from Secret Manager or config"""
    api_keys = {}
    
    # Try to get from config cache first
    api_keys_config = config.get_cached_config('api-keys')
    
    if not api_keys_config:
        logger.warning("No API keys configuration found")
        return api_keys
    
    # Extract keys for each feed that needs authentication
    for feed_name, feed_config in FEED_SOURCES.items():
        if feed_config.get("auth_required", False):
            key_name = f"{feed_name}_api_key"
            api_keys[feed_name] = api_keys_config.get(key_name)
            
            if not api_keys.get(feed_name):
                # Try alternate key name format
                alternate_key = feed_name.replace("_", "-") + "-api-key"
                api_keys[feed_name] = api_keys_config.get(alternate_key)
    
    return api_keys

def publish_event(topic: str, data: Dict[str, Any]) -> bool:
    """Publish event to Pub/Sub topic with retry logic"""
    pubsub_client = get_client('pubsub')
    if isinstance(pubsub_client, DummyClient):
        logger.warning(f"Pub/Sub client not available, cannot publish to {topic}")
        return False
    
    try:
        topic_path = pubsub_client.topic_path(PROJECT_ID, topic)
        json_data = json.dumps(data).encode("utf-8")
        
        # Publish with retry
        for attempt in range(3):
            try:
                future = pubsub_client.publish(topic_path, data=json_data)
                message_id = future.result(timeout=30)
                logger.info(f"Published event {message_id} to {topic}")
                return True
            except Exception as e:
                if attempt == 2:  # Last attempt
                    raise
                logger.warning(f"Publish attempt {attempt+1} failed: {str(e)}, retrying...")
                time.sleep(1.5 ** attempt)
        
        return False
    except Exception as e:
        logger.error(f"Error publishing message to {topic}: {str(e)}")
        return False

class ThreatDataIngestion:
    """Enhanced threat data ingestion class with improved reliability and performance"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        self.ready = ensure_resources(force_create=False)
        self.feed_stats = {}
    
    def process_all_feeds(self) -> List[Dict]:
        """Process all configured feeds with enhanced reliability"""
        if not self.ready:
            # Try to initialize resources again
            logger.warning("Ingestion engine not properly initialized, retrying initialization")
            self.ready = ensure_resources(force_create=True)
            if not self.ready:
                logger.error("Failed to initialize resources, aborting ingestion")
                return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        logger.info(f"Processing {len(FEED_SOURCES)} feeds")
        
        # Get API keys for authenticated feeds
        api_keys = _get_api_keys()
        
        # Process feeds in order of reliability (most reliable first)
        feed_order = ["cisa_known", "tor_exit", "feodotracker", "urlhaus", "phishtank", "threatfox", "alienvault_otx", "misp_feed"]
        
        # Add any feeds not in the ordered list
        for feed_name in FEED_SOURCES:
            if feed_name not in feed_order:
                feed_order.append(feed_name)
        
        for feed_name in feed_order:
            if feed_name not in FEED_SOURCES:
                continue
                
            try:
                logger.info(f"Starting ingestion for feed: {feed_name}")
                
                # Check if feed requires authentication
                feed_config = FEED_SOURCES[feed_name]
                if feed_config.get("auth_required", False):
                    api_key = api_keys.get(feed_name)
                    if not api_key:
                        logger.warning(f"Missing API key for {feed_name}, skipping")
                        results.append({
                            "feed_name": feed_name,
                            "status": "error",
                            "message": "Missing API key",
                            "record_count": 0,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        continue
                
                # Process the feed
                result = self.process_feed(feed_name)
                results.append(result)
                
                # Add a small delay between feeds to avoid overwhelming systems
                time.sleep(2)
            except Exception as e:
                logger.error(f"Unexpected error processing feed {feed_name}: {str(e)}")
                results.append(self._error_result(feed_name, f"Unexpected error: {str(e)}"))
        
        # Log a summary
        success_count = sum(1 for r in results if r.get("status") == "success")
        total_records = sum(r.get("record_count", 0) for r in results)
        
        logger.info(f"Completed processing {len(results)} feeds: {success_count} successful, {total_records} total records")
        
        # Save the latest feed statistics
        self.feed_stats = {
            "last_run": datetime.utcnow().isoformat(),
            "feeds_processed": len(results),
            "successful_feeds": success_count,
            "total_records": total_records,
            "details": results
        }
        
        # Store stats in GCS for persistence
        self._store_stats()
        
        return results
    
    def _store_stats(self) -> bool:
        """Store feed statistics in GCS for persistence"""
        storage_client = get_client('storage')
        if isinstance(storage_client, DummyClient) or not self.feed_stats:
            return False
        
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            stats_blob = bucket.blob("stats/feed_stats_latest.json")
            
            # Store with timestamp
            stats_data = json.dumps(self.feed_stats)
            stats_blob.upload_from_string(stats_data, content_type="application/json")
            
            # Also store a timestamped version for history
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            history_blob = bucket.blob(f"stats/feed_stats_{timestamp}.json")
            history_blob.upload_from_string(stats_data, content_type="application/json")
            
            logger.info("Successfully stored feed statistics in GCS")
            return True
        except Exception as e:
            logger.error(f"Failed to store stats in GCS: {str(e)}")
            return False
    
    def process_feed(self, feed_name: str) -> Dict[str, Any]:
        """Process a feed and return results with enhanced reliability"""
        start_time = datetime.now()
        
        # Generate a unique ingestion ID
        ingestion_id = f"{feed_name}_{start_time.strftime('%Y%m%d%H%M%S')}_{hashlib.md5(feed_name.encode()).hexdigest()[:8]}"
        
        # Validate state and feed
        if not self.ready:
            return self._error_result(feed_name, "Processor not properly initialized")
            
        if feed_name not in FEED_SOURCES:
            return self._error_result(feed_name, "Unknown feed")
            
        feed_config = FEED_SOURCES[feed_name]
        
        try:
            # Get API key if needed
            api_key = None
            auth_header = None
            if feed_config.get("auth_required", False):
                api_keys = _get_api_keys()
                api_key = api_keys.get(feed_name)
                auth_header = feed_config.get("auth_header")
                
                if not api_key:
                    return self._error_result(feed_name, "Missing API key for authenticated feed")
            
            # Get feed data
            data, error = self._fetch_feed_data(feed_name, api_key, auth_header)
            
            if error:
                logger.warning(f"Primary feed fetch failed: {error}")
                # Try fallback URL if available
                if "fallback_url" in feed_config and feed_config["fallback_url"] != feed_config["url"]:
                    logger.info(f"Trying fallback URL for {feed_name}")
                    # Store original URL
                    original_url = feed_config["url"]
                    try:
                        # Use fallback URL
                        feed_config["url"] = feed_config["fallback_url"]
                        # If fallback is CSV but format is JSON, adjust format
                        original_format = feed_config.get("format")
                        if original_format == "json" and feed_config["fallback_url"].endswith(".csv"):
                            feed_config["format"] = "csv"
                            
                        data, fallback_error = self._fetch_feed_data(feed_name, api_key, auth_header)
                        
                        # Restore original format
                        feed_config["format"] = original_format
                        # Restore original URL
                        feed_config["url"] = original_url
                        
                        if fallback_error:
                            return self._error_result(feed_name, f"Primary and fallback fetch failed: {error}, {fallback_error}")
                    except Exception as e:
                        # Restore original URL
                        feed_config["url"] = original_url
                        return self._error_result(feed_name, f"Fallback error: {str(e)}")
                else:
                    return self._error_result(feed_name, f"Fetch error: {error}")
                
            if not data:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No data collected",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Process records
            records = self._process_records(data, feed_name, feed_config, ingestion_id)
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records extracted",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Upload to BigQuery
            record_count = self._upload_to_bigquery(records, feed_name, feed_config)
            
            if record_count == 0:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records uploaded",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Publish event
            try:
                self._publish_event(feed_name, record_count, ingestion_id)
            except Exception as e:
                logger.warning(f"Failed to publish event for {feed_name}: {e}")
            
            # Return success result
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "feed_type": feed_config.get("description", "Unknown feed"),
                "record_format": feed_config.get("format", "unknown"),
                "status": "success",
                "record_count": record_count,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat(),
                "ingestion_id": ingestion_id
            }
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            return self._error_result(feed_name, str(e), start_time, ingestion_id)
    
    def _error_result(self, feed_name: str, message: str, start_time=None, ingestion_id=None) -> Dict[str, Any]:
        """Create standardized error result"""
        duration = (datetime.now() - start_time).total_seconds() if start_time else 0
        if not ingestion_id:
            ingestion_id = f"{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}_error"
            
        return {
            "feed_name": feed_name,
            "status": "error",
            "message": message,
            "record_count": 0,
            "duration_seconds": duration,
            "timestamp": datetime.utcnow().isoformat(),
            "ingestion_id": ingestion_id
        }
    
    def _fetch_feed_data(self, feed_name: str, api_key=None, auth_header=None) -> Tuple[Any, Optional[str]]:
        """Fetch data from a feed source with enhanced error handling"""
        feed_config = FEED_SOURCES[feed_name]
        url = feed_config["url"]
        
        logger.info(f"Fetching data from {feed_name} ({url})")
        
        try:
            # Handle compressed data
            if feed_config.get("zip_compressed"):
                try:
                    logger.info(f"Fetching compressed data from {url}")
                    response = _rate_limited_request(url, timeout=30, api_key=api_key, auth_header=auth_header)
                    response.raise_for_status()
                    
                    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
                        # Get first file in the ZIP (or the specified one)
                        target_file = feed_config.get("zip_file_name")
                        if not target_file:
                            target_file = zip_file.namelist()[0]
                        
                        with zip_file.open(target_file) as file:
                            content = file.read().decode('utf-8', errors='ignore')
                            return content, None
                except Exception as e:
                    logger.error(f"Error processing compressed data: {str(e)}")
                    return None, f"Error: {str(e)}"
            
            # Make the standard request
            response = _rate_limited_request(url, timeout=30, api_key=api_key, auth_header=auth_header)
            response.raise_for_status()
            
            # Return data based on format
            feed_format = feed_config.get("format", "json")
            
            if feed_format == "json":
                try:
                    data = response.json()
                    
                    # Handle nested data
                    if "json_root" in feed_config:
                        root_field = feed_config["json_root"]
                        if root_field in data:
                            data = data[root_field]
                    
                    # Special handling for ThreatFox recursive exploration
                    if feed_name == "threatfox":
                        data = self._extract_threatfox_data(data)
                    
                    return data, None
                except json.JSONDecodeError as e:
                    # Better error handling for JSON parsing errors
                    logger.error(f"JSON decode error for {feed_name}: {str(e)}")
                    logger.info(f"Content sample: {response.text[:200]}...")
                    return None, f"JSON decode error: {str(e)}"
                
            elif feed_format == "csv":
                return response.text, None
                
            elif feed_format == "text":
                return response.text, None
                
            return None, f"Unsupported format: {feed_format}"
            
        except requests.RequestException as e:
            logger.error(f"Request error fetching {feed_name}: {str(e)}")
            return None, f"Request error: {str(e)}"
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {feed_name}: {str(e)}")
            return None, f"JSON decode error: {str(e)}"
        except Exception as e:
            logger.error(f"Error fetching {feed_name}: {str(e)}")
            return None, f"Error: {str(e)}"
    
    def _extract_threatfox_data(self, data: Any) -> List[Dict[str, Any]]:
        """Robustly extract ThreatFox data using recursive exploration"""
        # Define the possible paths in the ThreatFox response
        mapping = FEED_SOURCES["threatfox"].get("json_mapping", {})
        path_options = mapping.get("path_options", ["data.iocs", "data", ""])
        
        # Try each path option
        for path in path_options:
            if not path:  # Root level
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    # Try to find IOC arrays
                    for key, value in data.items():
                        if key == "iocs" and isinstance(value, list):
                            return value
                        elif key == "data" and isinstance(value, dict) and "iocs" in value:
                            return value["iocs"]
            else:  # Nested path
                current_data = data
                path_parts = path.split(".")
                valid_path = True
                
                # Traverse the path
                for part in path_parts:
                    if isinstance(current_data, dict) and part in current_data:
                        current_data = current_data[part]
                    else:
                        valid_path = False
                        break
                
                if valid_path and isinstance(current_data, list):
                    return current_data
        
        # If we got here, try to flatten the structure
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], dict):
                # Extract IOC data
                if "iocs" in data["data"] and isinstance(data["data"]["iocs"], list):
                    return data["data"]["iocs"]
                
                # ThreatFox format with numeric IDs as keys
                flattened = []
                for key, value in data.items():
                    if key.isdigit() and isinstance(value, list):
                        flattened.extend(value)
                    elif key.isdigit() and isinstance(value, dict) and "ioc_value" in value:
                        flattened.append(value)
                
                if flattened:
                    return flattened
        
        # No standard format found, return the original data
        if isinstance(data, list):
            return data
        else:
            # Return as a single-item list for consistent processing
            return [data]
    
    def _process_records(self, data: Any, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process feed data into standardized records with enhanced type handling"""
        feed_format = feed_config.get("format", "json")
        
        # Initialize an empty result list
        records = []
        
        # Process based on format
        if feed_format == "json":
            records = self._process_json_data(data, feed_name, feed_config, ingestion_id)
        elif feed_format == "csv":
            records = self._process_csv_data(data, feed_name, feed_config, ingestion_id)
        elif feed_format == "text":
            records = self._process_text_data(data, feed_name, feed_config, ingestion_id)
        else:
            logger.error(f"Unsupported format: {feed_format}")
            return []
        
        # Ensure all required metadata fields are present in every record
        timestamp = datetime.utcnow().isoformat()
        for record in records:
            # Add/normalize metadata fields for consistency
            record["_ingestion_timestamp"] = record.get("_ingestion_timestamp", timestamp)
            record["_ingestion_id"] = record.get("_ingestion_id", ingestion_id)
            record["_source"] = record.get("_source", feed_name)
            record["_feed_type"] = record.get("_feed_type", feed_config.get("description", "Threat Intelligence Feed"))
        
        return records
    
    def _process_json_data(self, data: Any, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process JSON feed data with enhanced format handling"""
        records = []
        timestamp = datetime.utcnow().isoformat()
        
        # Log the structure of the data
        logger.info(f"Processing JSON data for {feed_name}")
        if isinstance(data, dict):
            logger.info(f"Top-level keys: {list(data.keys())}")
        elif isinstance(data, list):
            logger.info(f"Data is a list with {len(data)} items")
        else:
            logger.info(f"Data is of type {type(data)}")
        
        # Ensure data is a list
        if not isinstance(data, list):
            # Special handling for some feeds like PhishTank 
            if feed_name == "phishtank" and isinstance(data, dict):
                data = list(data.values())[0] if data else []
            # Handle ThreatFox format with multiple key-value pairs - fallback
            elif feed_name == "threatfox" and isinstance(data, dict):
                # ThreatFox format may have IOCs at the top level or in a field
                iocs = data.get("data", {}).get("iocs", [])
                if iocs:
                    data = iocs
                else:
                    # For the export format, data might be directly at the top level
                    # Format looks like {"1511419": [{"ioc_value": "..."}, ...]} with multiple IDs
                    flattened_data = []
                    for key, value in data.items():
                        if isinstance(value, list):
                            flattened_data.extend(value)
                        elif isinstance(value, dict) and "ioc_value" in value:
                            flattened_data.append(value)
                    
                    if flattened_data:
                        data = flattened_data
                    elif "data" in data and isinstance(data["data"], dict):
                        # Another possible structure
                        data = [data["data"]]
                    else:
                        data = [data]
            # Handle CISA format
            elif feed_name == "cisa_known" and isinstance(data, dict):
                if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                    data = data["vulnerabilities"]
                else:
                    data = [data]
            else:
                data = [data]
        
        # Process each record
        for item in data:
            if not isinstance(item, dict):
                # Skip non-dict items
                continue
            
            # Add standard metadata fields
            record = item.copy()
            record["_ingestion_timestamp"] = timestamp
            record["_ingestion_id"] = ingestion_id
            record["_source"] = feed_name
            record["_feed_type"] = feed_config.get("description", "Threat Intelligence Feed")
            
            # Type conversion for known fields
            if feed_name == "threatfox":
                # Convert confidence level to integer if present
                if "confidence_level" in record and record["confidence_level"] is not None:
                    try:
                        record["confidence_level"] = int(record["confidence_level"])
                    except (ValueError, TypeError):
                        pass
                
                # Convert first_seen to timestamp if present
                if "first_seen" in record and record["first_seen"] is not None:
                    try:
                        # ThreatFox uses Unix timestamps
                        first_seen = int(record["first_seen"])
                        record["first_seen"] = datetime.fromtimestamp(first_seen).isoformat()
                    except (ValueError, TypeError):
                        pass
                
                # Convert tags to array if it's a string
                if "tags" in record and isinstance(record["tags"], str):
                    record["tags"] = [tag.strip() for tag in record["tags"].split(",")]
            
            records.append(record)
        
        logger.info(f"Processed {len(records)} records from {feed_name} JSON")
        return records
    
    def _process_csv_data(self, data: str, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process CSV feed data with proper dialect detection"""
        try:
            # Handle skip lines if specified
            skip_lines = feed_config.get("skip_lines", 0)
            comment_char = feed_config.get("comment_char", "#")
            
            # Split into lines for preprocessing
            lines = data.split('\n')
            
            # Filter out comment lines and find header
            content_lines = []
            header_found = False
            
            # Different strategies for finding header and content
            if skip_lines > 0:
                # Skip a specific number of lines from the top
                if skip_lines >= len(lines):
                    logger.warning(f"CSV has fewer lines ({len(lines)}) than skip_lines ({skip_lines})")
                    return []
                
                # Find the first non-empty line after skip_lines as the header
                for i in range(skip_lines, len(lines)):
                    line = lines[i].strip()
                    if line and not line.startswith(comment_char):
                        content_lines = lines[i:]
                        break
            else:
                # Dynamically find the header by skipping comment lines
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith(comment_char):
                        continue
                    
                    if not header_found:
                        # First non-comment line is assumed to be the header
                        header_found = True
                    
                    content_lines.append(line)
            
            if not content_lines:
                logger.warning(f"No content found in CSV data for {feed_name}")
                return []
            
            # Rejoin the content lines for CSV parsing
            filtered_data = '\n'.join(content_lines)
            
            # Use csv.Sniffer to detect the dialect
            try:
                sample = filtered_data[:min(1024, len(filtered_data))]  # Use a sample for sniffing
                dialect = csv.Sniffer().sniff(sample)
                reader = csv.DictReader(StringIO(filtered_data), dialect=dialect)
            except Exception as e:
                logger.warning(f"Could not sniff CSV dialect: {e}, falling back to default")
                reader = csv.DictReader(StringIO(filtered_data))
            
            # Print headers to debug
            logger.info(f"CSV Headers for {feed_name}: {reader.fieldnames}")
            
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in reader:
                # Skip empty rows
                if not any(value.strip() for value in row.values() if value):
                    continue
                
                # Clean up the record
                record = {}
                for key, value in row.items():
                    if key:  # Skip None keys
                        # Handle None values
                        clean_value = value.strip() if value else value
                        record[key] = clean_value
                
                # Add standard metadata fields
                record["_ingestion_timestamp"] = timestamp
                record["_ingestion_id"] = ingestion_id
                record["_source"] = feed_name
                record["_feed_type"] = feed_config.get("description", "Threat Intelligence Feed")
                
                records.append(record)
            
            logger.info(f"Parsed {len(records)} records from {feed_name} CSV")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing CSV data for {feed_name}: {str(e)}")
            # Log sample of the data to assist with debugging
            if data:
                logger.error(f"First 200 chars of data: {data[:200]}")
            return []
    
    def _process_text_data(self, data: str, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process text-based feeds with enhanced metadata"""
        try:
            lines = data.strip().split('\n')
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            # Get comment character from config or default to #
            comment_char = feed_config.get("comment_char", "#")
            
            # Generic text processing
            for i, line in enumerate(lines):
                # Skip empty lines or comments
                if not line or line.strip().startswith(comment_char):
                    continue
                
                # Extract metadata from comments
                metadata = {}
                if i > 0 and lines[i-1].startswith(comment_char):
                    # Try to extract key-value pairs from comment line
                    comment_line = lines[i-1].lstrip(comment_char).strip()
                    for kv_pair in comment_line.split(','):
                        if ':' in kv_pair:
                            k, v = kv_pair.split(':', 1)
                            metadata[k.strip()] = v.strip()
                
                content = line.strip()
                
                # Determine content type based on pattern matching
                content_type = "unknown"
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', content):
                    content_type = "ip"
                elif re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', content):
                    content_type = "domain"
                
                record = {
                    "line_number": i + 1,
                    "content": content,
                    "content_type": content_type,
                    "_ingestion_timestamp": timestamp,
                    "_ingestion_id": ingestion_id,
                    "_source": feed_name,
                    "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
                }
                
                # Add any extracted metadata
                record.update(metadata)
                
                records.append(record)
            
            logger.info(f"Processed {len(records)} records from {feed_name} text data")
            return records
        except Exception as e:
            logger.error(f"Error processing text data for {feed_name}: {str(e)}")
            return []
    
    def _infer_schema_type(self, value: Any) -> str:
        """Infer BigQuery schema type from a Python value"""
        if value is None:
            return "STRING"
        elif isinstance(value, bool):
            return "BOOLEAN"
        elif isinstance(value, int):
            return "INTEGER"
        elif isinstance(value, float):
            return "FLOAT"
        elif isinstance(value, (datetime, str)) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', str(value)):
            return "TIMESTAMP"
        elif isinstance(value, list):
            if value:
                # For arrays, determine element type from first item
                element_type = self._infer_schema_type(value[0])
                return element_type
            return "STRING"
        else:
            return "STRING"
    
    def _get_schema_for_records(self, records: List[Dict]) -> List[bigquery.SchemaField]:
        """Dynamically generate schema from records with required metadata fields"""
        if not records:
            return []
        
        # Add required metadata fields that should always be present
        required_fields = {
            "_ingestion_timestamp": "TIMESTAMP",
            "_ingestion_id": "STRING",
            "_source": "STRING",
            "_feed_type": "STRING"
        }
        
        # Get a list of all fields from all records
        field_types = required_fields.copy()
        
        # Process each record
        for record in records:
            for field_name, value in record.items():
                if field_name not in field_types:
                    field_types[field_name] = self._infer_schema_type(value)
        
        # Create schema fields
        schema = []
        for field_name, field_type in field_types.items():
            mode = "NULLABLE"
            
            # Check if it's an array type
            if field_type.endswith("_ARRAY"):
                field_type = field_type[:-6]
                mode = "REPEATED"
            
            schema.append(bigquery.SchemaField(field_name, field_type, mode=mode))
        
        return schema
    
    def _update_table_schema(self, client, full_table_id: str, missing_fields: set) -> bool:
        """Update table schema to add new fields with better error handling"""
        try:
            # Get current table
            table = client.get_table(full_table_id)
            current_schema = table.schema
            
            # Create a map of existing field names
            existing_fields = {field.name: field for field in current_schema}
            
            # Create new schema fields
            new_schema_fields = []
            for field_name in missing_fields:
                if field_name not in existing_fields:
                    # Special handling for known fields
                    field_type = "STRING"  # Default type
                    
                    if field_name == "_ingestion_timestamp":
                        field_type = "TIMESTAMP"
                    elif field_name == "_ingestion_id":
                        field_type = "STRING"
                    elif field_name == "_source":
                        field_type = "STRING"
                    elif field_name == "_feed_type":
                        field_type = "STRING"
                    
                    new_schema_fields.append(
                        bigquery.SchemaField(field_name, field_type)
                    )
            
            if not new_schema_fields:
                return False  # No new fields to add
            
            # Update schema
            updated_schema = list(current_schema) + new_schema_fields
            table.schema = updated_schema
            
            # Update the table with the new schema
            client.update_table(table, ["schema"])
            logger.info(f"Updated schema for {full_table_id} with fields: {', '.join(f.name for f in new_schema_fields)}")
            return True
        except Exception as e:
            logger.error(f"Schema update error: {str(e)}")
            return False
    
    def _upload_to_bigquery(self, records: List[Dict], feed_name: str, feed_config: Dict) -> int:
        """Upload records to BigQuery with automatic table creation and batch processing"""
        if not records:
            logger.warning(f"No records to upload for {feed_name}")
            return 0
        
        client = get_client('bigquery')
        if isinstance(client, DummyClient):
            logger.error("BigQuery client not initialized")
            return 0
        
        table_id = feed_config["table_id"]
        full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
        processed_count = 0
        
        try:
            # Get table if it exists
            try:
                table = client.get_table(full_table_id)
                table_exists = True
            except NotFound:
                table_exists = False
                logger.info(f"Table {full_table_id} not found, will create it")
            
            # Create table if it doesn't exist
            if not table_exists:
                schema = self._get_schema_for_records(records)
                if not schema:
                    # Define standard fields all tables should have
                    schema = [
                        bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                        bigquery.SchemaField("_ingestion_id", "STRING"),
                        bigquery.SchemaField("_source", "STRING"),
                        bigquery.SchemaField("_feed_type", "STRING")
                    ]
                
                table = bigquery.Table(full_table_id, schema=schema)
                table.description = feed_config.get("description", "Threat Intelligence Feed")
                
                table = client.create_table(table, exists_ok=True)
                logger.info(f"Created table {full_table_id} with {len(schema)} fields")
            
            # Process records in batches to avoid memory issues
            total_records = len(records)
            record_batches = [records[i:i + BQ_INSERT_BATCH_SIZE] for i in range(0, total_records, BQ_INSERT_BATCH_SIZE)]
            
            logger.info(f"Uploading {total_records} records in {len(record_batches)} batches")
            
            for batch_index, batch in enumerate(record_batches):
                # Process each batch with retries
                for retry_attempt in range(BQ_MAX_RETRIES):
                    try:
                        # Clean records for JSON serialization
                        rows_to_insert = []
                        for record in batch:
                            # Convert non-serializable objects to strings
                            processed_record = {}
                            for key, value in record.items():
                                if isinstance(value, datetime):
                                    processed_record[key] = value.isoformat()
                                elif isinstance(value, (dict, list)):
                                    processed_record[key] = json.dumps(value)
                                else:
                                    processed_record[key] = value
                            
                            rows_to_insert.append(processed_record)
                        
                        # Insert batch
                        errors = client.insert_rows_json(full_table_id, rows_to_insert)
                        
                        if not errors:
                            # Successful insertion
                            processed_count += len(batch)
                            logger.info(f"Batch {batch_index+1}/{len(record_batches)} uploaded successfully ({len(batch)} records)")
                            break
                        
                        # Handle schema evolution for errors
                        if "no such field" in str(errors):
                            logger.warning(f"Schema mismatch errors: {errors}")
                            
                            # Extract field names that need to be added
                            missing_fields = set()
                            for error_item in errors:
                                for error in error_item.get('errors', []):
                                    error_msg = error.get('message', '')
                                    if 'no such field' in error_msg:
                                        field_name = error.get('location', '').strip()
                                        if field_name:
                                            missing_fields.add(field_name)
                            
                            if missing_fields:
                                logger.info(f"Attempting to add missing fields: {missing_fields}")
                                success = self._update_table_schema(client, full_table_id, missing_fields)
                                
                                if success:
                                    logger.info("Schema updated, retrying insertion")
                                    continue  # Try insert again with updated schema
                        
                        # Apply backoff delay for other errors
                        if retry_attempt < BQ_MAX_RETRIES - 1:
                            delay = BQ_RETRY_DELAY * (2 ** retry_attempt)
                            logger.warning(f"Insertion errors, retry {retry_attempt+1}/{BQ_MAX_RETRIES} in {delay:.2f}s: {errors[:2]}")
                            time.sleep(delay)
                        else:
                            logger.error(f"Failed to insert batch after {BQ_MAX_RETRIES} retries: {errors}")
                    
                    except Exception as e:
                        if retry_attempt < BQ_MAX_RETRIES - 1:
                            delay = BQ_RETRY_DELAY * (2 ** retry_attempt)
                            logger.warning(f"Error inserting batch: {str(e)}, retry {retry_attempt+1}/{BQ_MAX_RETRIES} in {delay:.2f}s")
                            time.sleep(delay)
                        else:
                            logger.error(f"Failed to insert batch after {BQ_MAX_RETRIES} retries: {str(e)}")
            
            logger.info(f"Successfully uploaded {processed_count} of {total_records} records to {full_table_id}")
            return processed_count
            
        except Exception as e:
            logger.error(f"Error uploading to BigQuery: {str(e)}")
            return processed_count
    
    def _publish_event(self, feed_name: str, count: int, ingestion_id: str) -> bool:
        """Publish event to Pub/Sub to trigger analysis with enhanced retry"""
        # Prepare message
        message = {
            "feed_name": feed_name,
            "record_count": count,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "ingestion_complete",
            "ingestion_id": ingestion_id,
            "project_id": PROJECT_ID,
            "dataset_id": DATASET_ID
        }
        
        return publish_event(PUBSUB_TOPIC, message)
    
    def analyze_csv_file(self, csv_content: str, feed_name: str = "csv_upload") -> Dict[str, Any]:
        """Analyze an uploaded CSV file to extract threat intelligence"""
        if not csv_content:
            return {"error": "Empty CSV data"}
            
        try:
            # Generate a unique ingestion ID
            ingestion_id = f"upload_{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # First, determine the CSV dialect using sniffer
            try:
                sample = csv_content[:min(10000, len(csv_content))]  # Use a sample for sniffing
                dialect = csv.Sniffer().sniff(sample)
                has_header = csv.Sniffer().has_header(sample)
            except Exception as e:
                logger.warning(f"Could not detect CSV dialect: {e}, using default")
                dialect = csv.excel
                has_header = True
            
            # Parse CSV
            csv_io = StringIO(csv_content)
            csv_reader = csv.reader(csv_io, dialect=dialect)
            
            # Get headers
            headers = next(csv_reader) if has_header else [f"column_{i+1}" for i in range(len(next(csv_reader)))]
            
            # Reset and skip the header row
            csv_io.seek(0)
            if has_header:
                next(csv_reader)
            
            # Process the rows
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in csv_reader:
                if not row or all(not cell.strip() for cell in row):
                    continue  # Skip empty rows
                
                record = {
                    headers[i]: value for i, value in enumerate(row) if i < len(headers)
                }
                
                # Add metadata
                record["_ingestion_timestamp"] = timestamp
                record["_ingestion_id"] = ingestion_id
                record["_source"] = "csv_upload"
                record["_feed_type"] = f"Uploaded CSV: {feed_name}"
                
                records.append(record)
            
            # Upload to BigQuery with custom table name for the upload
            table_id = f"upload_{feed_name.lower().replace(' ', '_').replace('-', '_')}"
            
            # Configure as a temporary feed
            temp_feed_config = {
                "table_id": table_id,
                "format": "csv",
                "description": f"Uploaded CSV: {feed_name}"
            }
            
            # Upload to BigQuery
            record_count = self._upload_to_bigquery(records, feed_name, temp_feed_config)
            
            # Return result
            result = {
                "analysis_id": ingestion_id,
                "feed_name": feed_name,
                "table_id": table_id,
                "record_count": record_count,
                "column_count": len(headers),
                "headers": headers,
                "has_header": has_header,
                "dialect": {
                    "delimiter": dialect.delimiter,
                    "quotechar": dialect.quotechar,
                    "doublequote": dialect.doublequote,
                    "escapechar": dialect.escapechar or ""
                },
                "sample_records": records[:5] if records else [],
                "timestamp": timestamp
            }
            
            # Trigger analysis job if records were uploaded
            if record_count > 0:
                message = {
                    "file_type": "csv",
                    "feed_name": feed_name,
                    "timestamp": timestamp,
                    "event_type": "csv_upload",
                    "analysis_id": ingestion_id,
                    "record_count": record_count
                }
                publish_event(PUBSUB_TOPIC, message)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing CSV file: {e}")
            return {"error": f"Analysis failed: {e}"}

# HTTP endpoint for triggering data ingestion
def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion with enhanced options"""
    logger.info("Ingestion endpoint called")
    
    # Parse request
    try:
        request_json = request.get_json(silent=True)
    except Exception as e:
        logger.error(f"Error parsing request: {str(e)}")
        request_json = {"process_all": True}  # Default to process all if error
    
    # Initialize ingestion engine
    try:
        ingestion = ThreatDataIngestion()
    except Exception as e:
        logger.error(f"Error initializing ingestion engine: {str(e)}")
        return {"error": f"Failed to initialize: {str(e)}"}, 500
    
    if request_json:
        # Check for statistics request
        if request_json.get("get_stats"):
            stats = ingestion.feed_stats if hasattr(ingestion, 'feed_stats') else {"status": "Stats function not available"}
            return stats
        
        # Check for CSV upload
        if request_json.get("file_type") == "csv" and "content" in request_json:
            feed_name = request_json.get("feed_name", "csv_upload")
            content = request_json["content"]
            
            # Handle base64 encoded content
            if request_json.get("encoding") == "base64":
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except Exception as e:
                    return {"error": f"Failed to decode base64 content: {str(e)}"}, 400
            
            return ingestion.analyze_csv_file(content, feed_name)
        
        # Check for specific feed
        feed_name = request_json.get("feed_name")
        if feed_name:
            if feed_name == "all":
                # Process all feeds
                results = ingestion.process_all_feeds()
                return {"results": results, "count": len(results)}
            elif feed_name not in FEED_SOURCES:
                return {"error": f"Unknown feed: {feed_name}"}, 400
            
            try:
                result = ingestion.process_feed(feed_name)
                return result
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                return {"error": f"Processing error: {str(e)}"}, 500
    
    # Default to processing all feeds
    try:
        results = ingestion.process_all_feeds()
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Error processing all feeds: {str(e)}")
        return {"error": f"Processing error: {str(e)}"}, 500

if __name__ == "__main__":
    # Process all feeds when run directly
    ingestion = ThreatDataIngestion()
    results = ingestion.process_all_feeds()
    
    # Print results
    for result in results:
        print(f"{result.get('feed_name')}: {result.get('status')} ({result.get('record_count')} records)")
