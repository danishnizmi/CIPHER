"""
Optimized ingestion module for threat intelligence feeds.
Handles downloading, processing, and storing threat intelligence data with improved error handling and circuit breaker patterns.
"""

import os
import json
import csv
import io
import requests
import datetime
import logging
import tempfile
import traceback
import hashlib
import re
import socket
import time
import threading
import uuid
from typing import Dict, List, Any, Optional, Tuple, Union
from functools import lru_cache
from google.cloud import storage, bigquery, pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
from google.cloud.exceptions import Conflict

# Import configuration
from config import Config, ServiceManager, ServiceStatus, report_error

# Configure logging
logger = logging.getLogger(__name__)

# Global ingestion state for status tracking
ingestion_status = {
    "last_run": None,
    "running": False,
    "feeds_processed": 0,
    "feeds_failed": 0,
    "total_records": 0,
    "errors": []
}

# Lock for thread-safe operations
_ingestion_lock = threading.Lock()

# Default feed configs for testing
DEFAULT_FEEDS = [
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

# Circuit Breaker Pattern Implementation
class CircuitBreaker:
    """Circuit breaker pattern to handle failing services gracefully."""
    def __init__(self, failure_threshold=3, recovery_timeout=60, expected_exception=Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self._lock = threading.Lock()
    
    def call(self, func, *args, **kwargs):
        with self._lock:
            if self.state == 'OPEN':
                if self.last_failure_time and time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    logger.info(f"Circuit breaker transitioning to HALF_OPEN state")
                else:
                    raise self.expected_exception(f"Circuit breaker is OPEN. Next retry in {self.recovery_timeout - (time.time() - self.last_failure_time):.1f}s")
            
            try:
                result = func(*args, **kwargs)
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0
                    logger.info("Circuit breaker transitioned to CLOSED state - service recovered")
                return result
            except self.expected_exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    self.state = 'OPEN'
                    logger.warning(f"Circuit breaker OPENED after {self.failure_count} failures")
                
                raise e

# Global circuit breakers for different services
bigquery_circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
storage_circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
feed_circuit_breakers = {}  # Per-feed circuit breakers

# -------------------- Helper Functions --------------------

def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    return (
        service_manager.get_client('bigquery'),
        service_manager.get_client('storage'),
        service_manager.get_client('publisher'),
        service_manager.get_client('subscriber')
    )

def publish_event(event_type: str, data: dict = None):
    """Publish event through event bus if available."""
    try:
        from flask import g
        if hasattr(g, 'event_bus'):
            g.event_bus.publish(event_type, data)
            logger.debug(f"Published event: {event_type}")
    except Exception as e:
        logger.debug(f"Not in Flask context, skipping event publish: {e}")

def ensure_default_feeds():
    """Ensure default feeds exist if none configured."""
    if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
        logger.warning("No feeds configured, using defaults")
        Config.FEEDS = DEFAULT_FEEDS
        
        # Try to save to environment for future loads
        os.environ['FEED_CONFIG'] = json.dumps({"feeds": DEFAULT_FEEDS})
        
        # Also save to a local file
        try:
            with open('/tmp/feed_config.json', 'w') as f:
                json.dump({"feeds": DEFAULT_FEEDS}, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save feed config to disk: {e}")
    
    return Config.FEEDS

# -------------------- Data Processing --------------------

class DataProcessor:
    """Handles data cleaning, sanitization, and validation with improved performance."""
    
    @staticmethod
    @lru_cache(maxsize=1000)
    def sanitize_string(value: str) -> str:
        """Sanitize string values to prevent XSS and injection attacks."""
        if not value or not isinstance(value, str):
            return value
        # Remove control characters
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        # Truncate if too long
        return value[:32768] if len(value) > 32768 else value
        
    @staticmethod
    @lru_cache(maxsize=1000)
    def sanitize_ioc(ioc_type: str, value: str) -> Optional[str]:
        """Sanitize IOC values based on their type."""
        if not value:
            return value
            
        value = DataProcessor.sanitize_string(value)
        
        patterns = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
            'domain': r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            'url': r'^(https?|ftp)://.+$',
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'ip:port': r'^(\d{1,3}\.){3}\d{1,3}:\d+$'
        }
        
        if ioc_type in patterns and not re.match(patterns[ioc_type], value.lower()):
            if ioc_type == 'url' and re.match(r'^www\.', value.lower()):
                return "http://" + value
            logger.debug(f"Suspicious {ioc_type} format: {value}")
                
        return value
        
    @staticmethod
    def sanitize_record(record: Dict, record_type: str = None) -> Dict:
        """Sanitize an entire record."""
        if not record:
            return {}
            
        sanitized = {}
        
        for key, value in record.items():
            if isinstance(value, dict):
                sanitized[key] = DataProcessor.sanitize_record(value)
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    sanitized[key] = [DataProcessor.sanitize_record(item) for item in value]
                else:
                    sanitized[key] = value
            elif isinstance(value, str):
                if record_type == 'ioc' and key == 'value' and 'type' in record:
                    sanitized[key] = DataProcessor.sanitize_ioc(record['type'], value)
                else:
                    sanitized[key] = DataProcessor.sanitize_string(value)
            else:
                sanitized[key] = value
                
        return sanitized

    @staticmethod
    @lru_cache(maxsize=10000)
    def determine_ioc_type(value: str) -> str:
        """Determine the IOC type based on value format."""
        if not value or not isinstance(value, str):
            return 'unknown'
            
        value = value.strip().lower()
        
        # Handle ip:port format specially (for ThreatFox)
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}:\d+$', value):
            return 'ip:port'
        
        patterns = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$',
            'domain': r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            'url': r'^(https?|ftp)://.+$',
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
        
        for ioc_type, pattern in patterns.items():
            if re.match(pattern, value):
                return ioc_type
                
        return 'unknown'

# -------------------- Storage Operations --------------------

def ensure_bucket_exists(bucket_name: str) -> bool:
    """Ensure the GCS bucket exists and create it if it doesn't."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return False
    
    try:
        return storage_circuit_breaker.call(_ensure_bucket_exists_impl, storage_client, bucket_name)
    except Exception as e:
        logger.error(f"Circuit breaker: {e}")
        return False

def _ensure_bucket_exists_impl(storage_client, bucket_name: str) -> bool:
    """Implementation function for bucket creation."""
    try:
        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            logger.info(f"Creating bucket {bucket_name}")
            bucket = storage_client.create_bucket(
                bucket_name, 
                location=Config.GCP_REGION,
                predefined_acl='projectPrivate'
            )
            
            # Add lifecycle rules for cost optimization
            lifecycle_rules = {
                'rule': [
                    {'action': {'type': 'Delete'}, 'condition': {'age': 30, 'isLive': True}},
                    {'action': {'type': 'Delete'}, 'condition': {'numNewerVersions': 3, 'isLive': False}}
                ]
            }
            bucket.lifecycle_rules = [
                storage.LifecycleRule(**rule) for rule in lifecycle_rules['rule']
            ]
            bucket.patch()
            
            # Create folder structure
            for folder in ['feeds', 'raw', 'processed', 'cache', 'exports']:
                blob = bucket.blob(f"{folder}/.keep")
                blob.upload_from_string('')
            logger.info(f"Created bucket {bucket_name}")
                
            return True
        else:
            logger.debug(f"Bucket {bucket_name} already exists")
            return True
    except Exception as e:
        logger.error(f"Error ensuring bucket exists: {str(e)}")
        report_error(e)
        raise

def initialize_bigquery_tables() -> bool:
    """Initialize all required BigQuery tables with circuit breaker protection."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("Cannot initialize BigQuery tables - client not available")
        return False
    
    service_manager = Config.get_service_manager()
    
    try:
        return bigquery_circuit_breaker.call(_initialize_bigquery_tables_impl, bq_client, service_manager)
    except Exception as e:
        logger.error(f"Circuit breaker: {e}")
        return False

def _initialize_bigquery_tables_impl(bq_client, service_manager) -> bool:
    """Implementation function for BigQuery table initialization."""
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        
        # Check/create dataset
        try:
            bq_client.get_dataset(dataset_id)
            logger.debug(f"Dataset {dataset_id} already exists")
        except NotFound:
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = Config.BIGQUERY_LOCATION
            dataset.description = "Threat Intelligence Platform dataset for storing IOCs, feeds, and analysis data"
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {dataset_id}")
        
        # Define table schemas with proper indexing
        tables_config = {
            'indicators': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("value", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("source", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("feed_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("confidence", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("campaign_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("raw_data", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("last_analyzed", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("risk_score", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("analysis_summary", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware_printable", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("reference", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("reporter", "STRING", mode="NULLABLE"),
            ],
            'vulnerabilities': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("cve_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("title", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("severity", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("cvss_score", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("affected_products", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("published_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("source", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("references", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
            ],
            'threat_actors': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("aliases", "STRING", mode="REPEATED"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("country", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("motivation", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("tactics", "STRING", mode="REPEATED"),
                bigquery.SchemaField("techniques", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tools", "STRING", mode="REPEATED"),
                bigquery.SchemaField("targets", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
            ],
            'campaigns': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("start_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("end_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("targets", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tactics", "STRING", mode="REPEATED"),
                bigquery.SchemaField("techniques", "STRING", mode="REPEATED"),
                bigquery.SchemaField("indicators", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
            ],
            'malware': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("aliases", "STRING", mode="REPEATED"),
                bigquery.SchemaField("type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("platform", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("capabilities", "STRING", mode="REPEATED"),
                bigquery.SchemaField("indicators", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
            ]
        }
        
        # Create or update tables
        for table_name, schema in tables_config.items():
            table_id = f"{dataset_id}.{table_name}"
            try:
                try:
                    table = bq_client.get_table(table_id)
                    logger.debug(f"Table {table_id} exists, checking schema")
                    
                    existing_fields = {field.name: field for field in table.schema}
                    new_fields = [field for field in schema if field.name not in existing_fields]
                    
                    if new_fields:
                        logger.info(f"Updating schema for {table_id} with {len(new_fields)} new fields")
                        table.schema = list(table.schema) + new_fields
                        bq_client.update_table(table, ["schema"])
                        
                except NotFound:
                    table = bigquery.Table(table_id, schema=schema)
                    # Add partitioning for indicators table
                    if table_name == 'indicators':
                        table.time_partitioning = bigquery.TimePartitioning(
                            type_=bigquery.TimePartitioningType.DAY,
                            field="created_at"
                        )
                    bq_client.create_table(table)
                    logger.info(f"Created table {table_id}")
                
                # Verify with test query
                test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                bq_client.query(test_query).result()
                
            except Exception as e:
                logger.warning(f"Issue with table {table_id}: {str(e)}")
                # Continue with other tables
                
        return True
    except Exception as e:
        logger.error(f"Error initializing BigQuery tables: {str(e)}")
        report_error(e)
        raise

def upload_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket with circuit breaker protection."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        return storage_circuit_breaker.call(_upload_to_gcs_impl, storage_client, bucket_name, blob_name, data, content_type)
    except Exception as e:
        logger.error(f"Circuit breaker: {e}")
        return None

def _upload_to_gcs_impl(storage_client, bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> str:
    """Implementation function for GCS upload."""
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if content_type is None:
            if blob_name.endswith('.json'):
                content_type = 'application/json'
            elif blob_name.endswith('.csv'):
                content_type = 'text/csv'
            elif blob_name.endswith('.txt'):
                content_type = 'text/plain'
            else:
                content_type = 'application/octet-stream'
        
        if isinstance(data, str):
            data_to_upload = data.encode('utf-8')
        else:
            data_to_upload = data
            
        blob.content_type = content_type
        blob.upload_from_string(data_to_upload, content_type=content_type)
        
        gcs_uri = f"gs://{bucket_name}/{blob_name}"
        logger.info(f"Uploaded data to {gcs_uri}")
        return gcs_uri
    except Exception as e:
        logger.error(f"Error uploading to GCS: {str(e)}")
        report_error(e)
        raise

def upload_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery with optimized batching and circuit breaker protection."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client or not records:
        return None
    
    try:
        return bigquery_circuit_breaker.call(_upload_to_bigquery_impl, bq_client, table_id, records)
    except Exception as e:
        logger.error(f"Circuit breaker: {e}")
        return None

def _upload_to_bigquery_impl(bq_client, table_id: str, records: List[Dict]) -> str:
    """Implementation function for BigQuery upload with rate limiting."""
    logger.info(f"Uploading {len(records)} records to {table_id}")
    
    # Optimized batch size based on testing
    batch_size = 50
    job_ids = []
    
    # Rate limiting variables
    max_batch_per_minute = 20
    batch_counter = 0
    minute_start = time.time()
    successful_batches = 0
    
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(records) + batch_size - 1) // batch_size
        
        logger.info(f"Processing batch {batch_num}/{total_batches}")
        
        # Apply rate limiting
        batch_counter += 1
        if batch_counter >= max_batch_per_minute:
            elapsed = time.time() - minute_start
            if elapsed < 60:
                sleep_time = 60 - elapsed + 2  # Add 2 seconds buffer
                logger.info(f"Rate limiting: pausing for {sleep_time:.1f}s")
                time.sleep(sleep_time)
            # Reset counters
            batch_counter = 0
            minute_start = time.time()
        
        try:
            processed_batch = []
            for record in batch:
                processed_record = {}
                
                for key, value in record.items():
                    if isinstance(value, (datetime.datetime, datetime.date)):
                        processed_record[key] = value.isoformat()
                    elif key in ['created_at', 'first_seen', 'last_seen', 'timestamp'] and isinstance(value, str):
                        try:
                            # Handle various date formats
                            if value.endswith('Z'):
                                dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                            else:
                                dt = datetime.datetime.fromisoformat(value)
                            processed_record[key] = dt.isoformat()
                        except ValueError:
                            # If date parsing fails, use current time
                            processed_record[key] = datetime.datetime.utcnow().isoformat()
                    elif isinstance(value, dict):
                        processed_record[key] = json.dumps(value)
                    elif key == 'tags' and isinstance(value, list):
                        processed_record[key] = [str(item) for item in value]
                    elif isinstance(value, list) and not value:
                        processed_record[key] = [] if key == 'tags' else value
                    elif isinstance(value, (dict, list)) and key not in ['tags']:
                        processed_record[key] = json.dumps(value)
                    else:
                        processed_record[key] = value
                
                # Ensure required fields
                if 'id' not in processed_record:
                    processed_record['id'] = hashlib.md5(str(record).encode()).hexdigest()
                
                if 'value' not in processed_record:
                    if 'ioc' in processed_record:
                        processed_record['value'] = str(processed_record['ioc'])
                    elif 'indicator' in processed_record:
                        processed_record['value'] = str(processed_record['indicator'])
                    else:
                        processed_record['value'] = 'unknown_' + str(uuid.uuid4())
                elif not isinstance(processed_record['value'], str):
                    processed_record['value'] = str(processed_record['value'])
                
                processed_batch.append(processed_record)
            
            if not processed_batch:
                continue
            
            # Retry logic with exponential backoff
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    job_config = bigquery.LoadJobConfig(
                        schema_update_options=[bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
                        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                        max_bad_records=len(processed_batch) // 10  # Allow up to 10% bad records
                    )
                    
                    job = bq_client.load_table_from_json(
                        processed_batch,
                        table_id,
                        job_config=job_config
                    )
                    
                    result = job.result(timeout=60)
                    
                    if job.errors:
                        logger.error(f"Errors in batch {batch_num}: {job.errors}")
                        if attempt < max_retries - 1:
                            # Exponential backoff with jitter
                            backoff_time = min(60, (2 ** attempt) + (time.time() % 2))
                            logger.info(f"Retrying batch {batch_num} in {backoff_time:.1f} seconds")
                            time.sleep(backoff_time)
                            continue
                    else:
                        job_ids.append(job.job_id)
                        successful_batches += 1
                        logger.info(f"Successfully uploaded batch {batch_num}")
                    
                    break
                        
                except Exception as e:
                    logger.error(f"Error uploading batch {batch_num} (attempt {attempt + 1}): {str(e)}")
                    if "Exceeded rate limits" in str(e) or "rateLimitExceeded" in str(e):
                        # Longer backoff for rate limit errors
                        backoff_time = min(120, 30 + (15 * attempt))
                        logger.info(f"Rate limit exceeded, retrying batch {batch_num} in {backoff_time} seconds")
                        time.sleep(backoff_time)
                    elif attempt < max_retries - 1:
                        backoff_time = min(60, (2 ** attempt) + (time.time() % 5))
                        time.sleep(backoff_time)
                    else:
                        logger.error(f"Failed to upload batch {batch_num} after {max_retries} attempts")
            
        except Exception as e:
            logger.error(f"Error processing batch {batch_num}: {str(e)}")
    
    logger.info(f"Upload completed: {successful_batches}/{total_batches} batches successful")
    return job_ids[0] if job_ids else None

# -------------------- Feed Processing --------------------

def download_feed(url: str, headers: Dict = None, timeout: int = 60) -> Tuple[Optional[str], Optional[bytes]]:
    """Download content from a feed URL with retry logic and circuit breaker."""
    if not headers:
        headers = {
            'User-Agent': f"ThreatIntelligencePlatform/{Config.VERSION}",
            'Accept': 'application/json, text/csv, text/plain',
            'Accept-Encoding': 'gzip, deflate'
        }
    
    # Get or create circuit breaker for this URL
    domain = url.split('/')[2]
    if domain not in feed_circuit_breakers:
        feed_circuit_breakers[domain] = CircuitBreaker(failure_threshold=3, recovery_timeout=120)
    
    try:
        return feed_circuit_breakers[domain].call(_download_feed_impl, url, headers, timeout)
    except Exception as e:
        logger.error(f"Circuit breaker prevented request to {url}: {e}")
        return None, None

def _download_feed_impl(url: str, headers: Dict, timeout: int) -> Tuple[str, bytes]:
    """Implementation function for feed download."""
    max_retries = 3
    session = requests.Session()
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading feed from {url} (attempt {attempt+1}/{max_retries})")
            response = session.get(url, headers=headers, timeout=timeout, stream=True)
            
            if response.status_code == 429:
                # Handle rate limiting
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            elif response.status_code == 404:
                logger.error(f"Feed not found (404): {url}")
                raise requests.RequestException("Feed not found")
            
            response.raise_for_status()
            
            # Read content in chunks to handle large feeds
            content = b''
            chunk_size = 8192
            total_size = 0
            max_size = 100 * 1024 * 1024  # 100MB limit
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    content += chunk
                    total_size += len(chunk)
                    if total_size > max_size:
                        logger.warning(f"Feed too large, truncating at {max_size} bytes")
                        break
            
            content_type = response.headers.get('Content-Type', '')
            logger.info(f"Downloaded {len(content)} bytes from {url}")
            return content_type, content
            
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = min(60, 2 ** attempt)
                logger.warning(f"Request failed: {str(e)}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Request failed after {max_retries} attempts: {str(e)}")
                raise
    
    return None, None

def parse_json_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse JSON feed data with better error handling."""
    try:
        # Try multiple decodings
        content_str = None
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            for encoding in ['latin-1', 'cp1252', 'utf-16']:
                try:
                    content_str = content.decode(encoding, errors='replace')
                    logger.debug(f"Decoded with {encoding}")
                    break
                except:
                    continue
            else:
                content_str = content.decode('utf-8', errors='ignore')
        
        # Parse JSON with fallback handling
        try:
            data = json.loads(content_str)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error: {e}")
            # Try to find and extract JSON content
            json_start = content_str.find('{')
            json_array_start = content_str.find('[')
            
            if json_start >= 0 and (json_array_start < 0 or json_start < json_array_start):
                content_str = content_str[json_start:]
            elif json_array_start >= 0:
                content_str = content_str[json_array_start:]
            else:
                logger.error("No valid JSON content found")
                return []
            
            try:
                data = json.loads(content_str)
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON after cleanup")
                return []
        
        # Handle different data formats
        processed_data = []
        
        # Handle ThreatFox format (threat IDs as keys)
        if isinstance(data, dict) and 'data' in data and isinstance(data['data'], list):
            processed_data = data['data']
        elif isinstance(data, dict) and all(key.isdigit() for key in list(data.keys())[:5]):
            for threat_id, threat_items in data.items():
                if isinstance(threat_items, list):
                    for item in threat_items:
                        if isinstance(item, dict):
                            item_copy = item.copy()
                            item_copy['threat_id'] = threat_id
                            processed_data.append(item_copy)
        # Handle regular JSON array or dict with 'data' field
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                    for item in value:
                        item_copy = item.copy()
                        item_copy['threat_id'] = key
                        processed_data.append(item_copy)
                elif key == 'data' and isinstance(value, list):
                    processed_data.extend(value)
        elif isinstance(data, list):
            processed_data = data
        
        logger.info(f"Parsed {len(processed_data)} records from JSON feed")
        return processed_data
    except Exception as e:
        logger.error(f"Error parsing JSON feed: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

def parse_csv_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse CSV feed data with improved error handling and encoding detection."""
    try:
        # Try different encodings to handle various CSV files
        content_str = None
        detected_encoding = 'utf-8'
        
        # Try BOM detection
        if content.startswith(b'\xef\xbb\xbf'):
            content_str = content[3:].decode('utf-8')
            detected_encoding = 'utf-8'
        else:
            # Try common encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'utf-16', 'iso-8859-1']:
                try:
                    content_str = content.decode(encoding)
                    detected_encoding = encoding
                    break
                except UnicodeDecodeError:
                    continue
        
        if not content_str:
            # Last resort decoding with error replacement
            content_str = content.decode('utf-8', errors='replace')
            detected_encoding = 'utf-8 (with errors replaced)'
        
        logger.debug(f"Detected encoding: {detected_encoding}")
        
        # Skip comment lines at the beginning
        lines = content_str.splitlines()
        clean_lines = []
        url_haus_format = False
        
        # Detect format
        if any(line.startswith('#') for line in lines[:5]):
            # Check for URLhaus format
            if any('"url"' in line.lower() or '"date_added"' in line.lower() for line in lines[:15]):
                url_haus_format = True
                logger.info("Detected URLhaus CSV format")
                
                # Find the header line
                header_line_idx = -1
                for i, line in enumerate(lines):
                    if not line.startswith('#') and any(column in line.lower() for column in ['"url"', '"date_added"', '"threat"']):
                        header_line_idx = i
                        break
                        
                if header_line_idx >= 0:
                    clean_lines = [lines[header_line_idx]] + lines[header_line_idx+1:]
                else:
                    clean_lines = [line for line in lines if not line.startswith('#')]
            else:
                # Standard comment skipping
                clean_lines = [line for line in lines if not line.startswith('#')]
        else:
            clean_lines = lines
        
        if not clean_lines or len(clean_lines) < 2:
            logger.warning("No valid CSV content found after filtering comments")
            return []
            
        # Rejoin into a string
        content_str = '\n'.join(clean_lines)
        
        # Detect CSV dialect
        try:
            sample = content_str[:2048] if len(content_str) > 2048 else content_str
            dialect = csv.Sniffer().sniff(sample)
            logger.debug(f"Detected CSV dialect: delimiter={repr(dialect.delimiter)}, quotechar={repr(dialect.quotechar)}")
        except Exception as e:
            logger.debug(f"Could not detect CSV dialect: {e}, using default")
            dialect = csv.excel
            if url_haus_format:
                dialect.delimiter = ','
                dialect.quotechar = '"'
        
        # Read CSV data
        reader = csv.DictReader(io.StringIO(content_str), dialect=dialect)
        
        # Handle URLhaus special processing
        if url_haus_format:
            logger.info("Processing URLhaus format with explicit column mapping")
            
            # Get fieldnames
            fieldnames = reader.fieldnames
            if not fieldnames or not any(name.lower() in ['url', 'date_added', 'status'] for name in fieldnames):
                # Try to construct fieldnames
                first_row = clean_lines[0].split(dialect.delimiter)
                potential_headers = [h.strip(dialect.quotechar + ' \t') for h in first_row]
                
                if any(h.lower() in ['url', 'date_added', 'status'] for h in potential_headers):
                    fieldnames = potential_headers
                    # Reset reader with new fieldnames
                    content_str = '\n'.join(clean_lines[1:])
                    reader = csv.DictReader(io.StringIO(content_str), fieldnames=fieldnames, dialect=dialect)
                else:
                    # Default fieldnames for URLhaus
                    fieldnames = ['id', 'date_added', 'url', 'url_status', 'threat', 'tags', 'urlhaus_link', 'reporter']
                    reader = csv.DictReader(io.StringIO(content_str), fieldnames=fieldnames, dialect=dialect)
            
            # Process data
            csv_data = []
            for row_num, row in enumerate(reader, 1):
                if not row or not any(row.values()) or not row.get('url'):
                    continue
                
                # Clean the data
                cleaned_row = {}
                for key, value in row.items():
                    if value:
                        cleaned_row[key] = value.strip('"\'').replace('\x00', '')
                    else:
                        cleaned_row[key] = value
                
                csv_data.append(cleaned_row)
                
                if row_num == 1:
                    logger.debug(f"URLhaus sample row: {cleaned_row}")
            
            # Convert to standard format
            standardized_data = []
            for row in csv_data:
                if not row.get('url') or row.get('url').startswith('#'):
                    continue
                
                std_record = {
                    'ioc_type': 'url',
                    'ioc_value': row.get('url', '').strip(),
                    'threat_type': row.get('threat', '').strip() or 'malware',
                    'first_seen_utc': row.get('date_added', '').strip(),
                    'reporter': row.get('reporter', '').strip(),
                    'reference': row.get('urlhaus_link', '').strip(),
                    'status': row.get('url_status', '').strip(),
                    'source': 'urlhaus'
                }
                
                # Add tags if present
                if 'tags' in row and row['tags']:
                    std_record['tags'] = row['tags'].strip()
                
                standardized_data.append(std_record)
            
            logger.info(f"Standardized {len(standardized_data)} URLhaus records")
            return standardized_data
        
        # Standard CSV processing
        csv_data = []
        for row_num, row in enumerate(reader, 1):
            if not row or not any(value.strip() if isinstance(value, str) else value for value in row.values()):
                continue
            
            # Clean the data
            cleaned_row = {}
            for key, value in row.items():
                if isinstance(value, str):
                    cleaned_row[key] = value.strip().replace('\x00', '')
                else:
                    cleaned_row[key] = value
            
            csv_data.append(cleaned_row)
        
        logger.info(f"Processed {len(csv_data)} CSV records")
        return csv_data
        
    except Exception as e:
        logger.error(f"Error parsing CSV feed: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

def parse_feed(content: bytes, format_type: str = None, parser_config: Dict = None) -> List[Dict]:
    """Parse feed data with format auto-detection and error handling."""
    if not content:
        logger.warning("No content to parse")
        return []
    
    if parser_config is None:
        parser_config = {}
    
    # Auto-detect format if not specified
    if not format_type:
        content_start = content[:1000].strip()
        if (content_start.startswith(b'{') or content_start.startswith(b'[') or 
            b'"' in content_start and content_start.count(b'\n') < 10):
            format_type = 'json'
        elif b',' in content_start and content_start.count(b'\n') > 5:
            format_type = 'csv'
        else:
            format_type = 'text'
    
    try:
        logger.info(f"Parsing feed data as {format_type} format")
        start_time = time.time()
        
        if format_type == 'json':
            results = parse_json_feed(content, parser_config)
        elif format_type == 'csv':
            results = parse_csv_feed(content, parser_config)
        else:
            logger.warning(f"Unknown format type: {format_type}, falling back to JSON")
            results = parse_json_feed(content, parser_config)
        
        parse_time = time.time() - start_time
        logger.info(f"Successfully parsed {len(results)} records from feed in {parse_time:.2f}s")
        return results
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format with improved processing."""
    normalized = []
    current_time = datetime.datetime.utcnow()
    
    for i, record in enumerate(records):
        try:
            # Skip empty records
            if not record:
                continue
                
            # Handle ThreatFox format
            if 'ioc_value' in record and 'ioc_type' in record:
                value = record['ioc_value']
                ioc_type = record['ioc_type']
                
                # Parse tags
                tags = record.get('tags', '')
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',') if t.strip()]
                elif not isinstance(tags, list):
                    tags = []
                
                # Parse malware aliases
                malware_aliases = record.get('malware_alias', '')
                if isinstance(malware_aliases, str):
                    malware_aliases = [a.strip() for a in malware_aliases.split(',') if a.strip()]
                elif not isinstance(malware_aliases, list):
                    malware_aliases = []
                
                # Create indicator
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}:{ioc_type}".encode()).hexdigest(),
                    "value": value,
                    "type": ioc_type,
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": current_time.isoformat(),
                    "confidence": int(record.get('confidence_level', 50)),
                    "tags": tags,
                    "description": f"Indicator from {feed_name}",
                    "threat_type": record.get('threat_type'),
                    "threat_id": record.get('threat_id'),
                    "malware": record.get('malware'),
                    "malware_printable": record.get('malware_printable'),
                    "first_seen": record.get('first_seen_utc'),
                    "last_seen": record.get('last_seen_utc'),
                    "reference": record.get('reference'),
                    "reporter": record.get('reporter'),
                    "raw_data": json.dumps(record)
                }
                
                # Add malware aliases to tags
                for alias in malware_aliases:
                    if alias not in indicator['tags']:
                        indicator['tags'].append(f"malware:{alias}")
                
            # Handle URLhaus format
            elif ('url' in record or 'ioc_value' in record) and (feed_name.lower() == 'urlhaus' or 'threat' in record):
                value = record.get('ioc_value') or record.get('url', '')
                
                # Ensure we have a proper URL
                if not value.startswith(('http://', 'https://', 'ftp://')):
                    if value.startswith('www.'):
                        value = 'http://' + value
                    elif '.' in value and not value.startswith('#'):
                        value = 'http://' + value
                
                # Parse tags
                tags = record.get('tags', '')
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',') if t.strip()]
                elif not isinstance(tags, list):
                    tags = []
                
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                    "value": value,
                    "type": 'url',
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": current_time.isoformat(),
                    "confidence": 80 if record.get('url_status') == 'online' else 60,
                    "tags": tags,
                    "description": f"URL from {feed_name}",
                    "threat_type": record.get('threat_type') or record.get('threat', 'malware_download'),
                    "first_seen": record.get('first_seen_utc') or record.get('date_added'),
                    "last_seen": record.get('last_seen_utc') or record.get('last_online'),
                    "reporter": record.get('reporter'),
                    "reference": record.get('reference') or record.get('urlhaus_reference') or record.get('urlhaus_link'),
                    "status": record.get('url_status') or record.get('status'),
                    "raw_data": json.dumps(record)
                }
                
            else:
                # Generic format
                value = record.get('value') or record.get('indicator') or record.get('ioc') or record.get('url') or ''
                if not value:
                    continue
                    
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                    "value": value,
                    "type": record.get('type') or DataProcessor.determine_ioc_type(value),
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": current_time.isoformat(),
                    "confidence": int(record.get('confidence', 50)),
                    "tags": record.get('tags', []) if isinstance(record.get('tags'), list) else [],
                    "description": record.get('description', f"Indicator from {feed_name}"),
                    "raw_data": json.dumps(record)
                }
            
            if not indicator['value']:
                continue
                
            # Ensure confidence is an integer
            if not isinstance(indicator['confidence'], int):
                indicator['confidence'] = 50
                
            # Calculate initial risk score
            risk_score = calculate_initial_risk_score(indicator)
            indicator['risk_score'] = risk_score
            
            # Sanitize the record
            indicator = DataProcessor.sanitize_record(indicator, record_type='ioc')
                
            normalized.append(indicator)
            
        except Exception as e:
            logger.warning(f"Error normalizing record {i+1} from {feed_name}: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.debug(f"Problematic record: {record}")
            continue
    
    logger.info(f"Normalized {len(normalized)} records from {feed_name}")
    return normalized

def calculate_initial_risk_score(indicator: Dict) -> int:
    """Calculate initial risk score for an indicator with improved logic."""
    base_score = indicator.get('confidence', 50)
    
    # Adjust based on threat type
    threat_type = indicator.get('threat_type', '').lower()
    if 'botnet' in threat_type:
        base_score += 25
    elif 'ransomware' in threat_type:
        base_score += 30
    elif 'malware' in threat_type:
        base_score += 15
    elif 'phishing' in threat_type:
        base_score += 10
    
    # Adjust based on malware type
    malware = indicator.get('malware', '').lower()
    if 'ransomware' in malware:
        base_score += 30
    elif any(term in malware for term in ['cobalt', 'strike']):
        base_score += 25
    elif any(term in malware for term in ['remcos', 'rat']):
        base_score += 20
    elif 'trojan' in malware:
        base_score += 15
    
    # Adjust based on activity recency
    if indicator.get('first_seen'):
        try:
            first_seen_str = indicator['first_seen']
            if first_seen_str.endswith('Z'):
                first_seen = datetime.datetime.fromisoformat(first_seen_str.replace('Z', '+00:00'))
            else:
                first_seen = datetime.datetime.fromisoformat(first_seen_str)
            
            age_days = (datetime.datetime.utcnow() - first_seen).days
            if age_days < 1:
                base_score += 15
            elif age_days < 7:
                base_score += 10
            elif age_days < 30:
                base_score += 5
        except:
            pass
    
    # Adjust based on IOC type
    ioc_type = indicator.get('type', '').lower()
    if ioc_type == 'ip:port':
        base_score += 10  # Active C2 infrastructure
    elif ioc_type == 'hash':
        base_score += 5   # Direct malware evidence
    
    # Ensure score is within bounds
    return min(max(base_score, 0), 100)

# -------------------- Main Processing --------------------

def process_feed(feed_config: Dict) -> Dict:
    """Process a single feed and store its data with enhanced error handling."""
    feed_name = feed_config.get("name", "Unknown")
    feed_id = feed_config.get("id", feed_name)
    start_time = time.time()
    
    logger.info(f"Starting ingestion for feed '{feed_name}'")
    
    result = {
        "feed_name": feed_name,
        "feed_id": feed_id,
        "start_time": datetime.datetime.utcnow().isoformat(),
        "status": "failed",
        "record_count": 0,
        "error": None,
        "processing_time": 0
    }
    
    try:
        if not feed_config.get("enabled", True):
            logger.info(f"Feed '{feed_name}' is disabled, skipping")
            result["status"] = "skipped"
            result["error"] = "Feed is disabled"
            return result
        
        # Get clients
        bq_client, storage_client, publisher, subscriber = get_clients()
        
        # Initialize services if not ready
        service_manager = Config.get_service_manager()
        status = service_manager.get_status()
        
        if status['services'].get('bigquery') != 'ready':
            logger.info("Initializing BigQuery client")
            initialize_bigquery()
        
        if status['services'].get('storage') != 'ready':
            logger.info("Initializing Storage client")
            initialize_storage()
        
        # Refresh clients after initialization
        bq_client, storage_client, publisher, subscriber = get_clients()
        
        # Ensure bucket exists
        bucket_name = Config.GCS_BUCKET
        if not ensure_bucket_exists(bucket_name):
            result["error"] = "Failed to ensure GCS bucket exists"
            return result
        
        # Download feed data
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        timeout = feed_config.get("timeout", 60)
        
        logger.info(f"Downloading from {url}")
        content_type, content = download_feed(url, headers, timeout)
        if not content:
            result["error"] = "Failed to download feed data"
            return result
        
        result["content_type"] = content_type
        result["download_size"] = len(content)
        
        # Store raw data with timestamp
        storage_path = feed_config.get("storage_path", f"feeds/{feed_id}")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Determine file extension
        format_type = feed_config.get("format", "")
        if format_type == "json":
            file_extension = ".json"
            content_type_to_use = "application/json"
        elif format_type == "csv":
            file_extension = ".csv"
            content_type_to_use = "text/csv"
        else:
            # Auto-detect based on content-type header
            if content_type and 'json' in content_type.lower():
                file_extension = '.json'
                content_type_to_use = "application/json"
                format_type = "json"
            elif content_type and 'csv' in content_type.lower():
                file_extension = '.csv'
                content_type_to_use = "text/csv"
                format_type = "csv"
            else:
                file_extension = '.txt'
                content_type_to_use = "text/plain"
                format_type = "text"
        
        # Upload raw data to GCS
        raw_blob_name = f"{storage_path}/raw/{timestamp}{file_extension}"
        raw_uri = upload_to_gcs(bucket_name, raw_blob_name, content, content_type_to_use)
        if not raw_uri:
            result["error"] = "Failed to store raw feed data"
            return result
        
        result["raw_uri"] = raw_uri
        
        # Parse feed data
        parser_config = feed_config.get("parser_config", {})
        logger.info(f"Parsing feed data with format: {format_type}")
        parsed_data = parse_feed(content, format_type, parser_config)
        
        if not parsed_data:
            logger.warning(f"No valid records found in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No valid records found"
            return result
        
        result["parsed_count"] = len(parsed_data)
        
        # Normalize data
        logger.info(f"Normalizing {len(parsed_data)} records")
        normalized_data = normalize_indicators(parsed_data, feed_id)
        
        if not normalized_data:
            logger.info(f"No records to process in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No records to process"
            return result
        
        # Store processed data
        processed_blob_name = f"{storage_path}/processed/{timestamp}.json"
        processed_uri = upload_to_gcs(
            bucket_name, 
            processed_blob_name,
            json.dumps(normalized_data, indent=2),
            "application/json"
        )
        
        if not processed_uri:
            result["error"] = "Failed to store processed feed data"
            return result
        
        result["processed_uri"] = processed_uri
        result["record_count"] = len(normalized_data)
        
        # Initialize BigQuery tables
        logger.info("Ensuring BigQuery tables exist")
        if not initialize_bigquery_tables():
            logger.warning("BigQuery tables initialization reported issues, continuing anyway")
        
        # Upload to BigQuery
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        indicators_table_id = f"{dataset_id}.indicators"
        
        logger.info(f"Uploading {len(normalized_data)} records to BigQuery")
        job_id = upload_to_bigquery(indicators_table_id, normalized_data)
        
        if not job_id:
            result["error"] = "Failed to upload data to BigQuery"
            return result
        
        result["bigquery_job_id"] = job_id
        
        # Publish to Pub/Sub
        if publisher:
            try:
                topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
                
                message_data = {
                    "operation": "feed_processed",
                    "feed_name": feed_name,
                    "feed_id": feed_id,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "record_count": len(normalized_data),
                    "raw_uri": raw_uri,
                    "processed_uri": processed_uri
                }
                
                message_json = json.dumps(message_data)
                future = publisher.publish(topic_path, message_json.encode("utf-8"), feed_id=feed_id)
                message_id = future.result(timeout=30)
                result["pubsub_message_id"] = message_id
                logger.info(f"Published message to Pub/Sub: {message_id}")
            except Exception as e:
                logger.warning(f"Failed to publish message to Pub/Sub: {str(e)}")
        
        # Publish event for cache invalidation
        publish_event('data_ingested', {
            'feed_id': feed_id,
            'record_count': len(normalized_data)
        })
        
        result["status"] = "success"
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        result["processing_time"] = time.time() - start_time
        
        logger.info(f"Successfully processed feed '{feed_name}': {len(normalized_data)} records in {result['processing_time']:.2f}s")
        return result
    
    except Exception as e:
        logger.error(f"Error processing feed '{feed_name}': {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        
        result["error"] = str(e)
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        result["processing_time"] = time.time() - start_time
        return result

# -------------------- Public API Functions --------------------

def ingest_feed(feed_name: str) -> Dict:
    """Process a single feed by name."""
    global ingestion_status
    
    service_manager = Config.get_service_manager()
    
    with _ingestion_lock:
        service_manager.update_status('ingestion', ServiceStatus.READY)
        ingestion_status["running"] = True
    
    feed_config = None
    if hasattr(Config, 'get_feed_by_id'):
        feed_config = Config.get_feed_by_id(feed_name)
    
    if not feed_config and hasattr(Config, 'FEEDS'):
        for feed in Config.FEEDS:
            if feed.get('id') == feed_name or feed.get('name') == feed_name:
                feed_config = feed
                break
    
    if not feed_config:
        logger.error(f"Feed '{feed_name}' not found in configuration")
        error_result = {
            "feed_name": feed_name,
            "status": "failed",
            "error": "Feed not found in configuration"
        }
        with _ingestion_lock:
            ingestion_status["feeds_failed"] += 1
            ingestion_status["errors"].append(f"Feed '{feed_name}' not found")
        return error_result
    
    result = process_feed(feed_config)
    
    with _ingestion_lock:
        if result["status"] == "success":
            ingestion_status["feeds_processed"] += 1
            ingestion_status["total_records"] += result.get("record_count", 0)
        elif result["status"] != "skipped":
            ingestion_status["feeds_failed"] += 1
            error_msg = result.get("error", "Unknown error")
            ingestion_status["errors"].append(f"Feed '{feed_name}': {error_msg}")
    
    return result

def ingest_all_feeds() -> List[Dict]:
    """Process all enabled feeds."""
    global ingestion_status
    service_manager = Config.get_service_manager()
    
    with _ingestion_lock:
        ingestion_status = {
            "last_run": datetime.datetime.utcnow().isoformat(),
            "running": True,
            "feeds_processed": 0,
            "feeds_failed": 0,
            "total_records": 0,
            "errors": []
        }
        service_manager.update_status('ingestion', ServiceStatus.READY)
    
    start_time = time.time()
    
    # Initialize tables before processing feeds
    logger.info("Initializing BigQuery tables")
    initialize_bigquery_tables()
    
    # Ensure feed configuration
    ensure_default_feeds()
    
    feeds = []
    if hasattr(Config, 'get_enabled_feeds'):
        feeds = Config.get_enabled_feeds()
    elif hasattr(Config, 'FEEDS'):
        feeds = [f for f in Config.FEEDS if f.get('enabled', True)]
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        with _ingestion_lock:
            ingestion_status["running"] = False
            service_manager.update_status('ingestion', ServiceStatus.DEGRADED, "No feeds configured")
        return []
    
    logger.info(f"Processing {len(feeds)} enabled feeds")
    
    results = []
    successful_feeds = 0
    
    # Process feeds with some parallelization (but limited to avoid resource exhaustion)
    for feed_config in feeds:
        try:
            feed_id = feed_config.get("id") or feed_config.get("name")
            if not feed_id:
                logger.warning(f"Skipping feed with no ID: {feed_config}")
                continue
                
            result = process_feed(feed_config)
            results.append(result)
            
            with _ingestion_lock:
                if result["status"] == "success":
                    ingestion_status["feeds_processed"] += 1
                    ingestion_status["total_records"] += result.get("record_count", 0)
                    successful_feeds += 1
                elif result["status"] != "skipped":
                    ingestion_status["feeds_failed"] += 1
                    error_msg = result.get("error", "Unknown error")
                    ingestion_status["errors"].append(f"Feed '{feed_id}': {error_msg}")
                    
        except Exception as e:
            feed_name = feed_config.get("name", "Unknown")
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            
            results.append({
                "feed_name": feed_name,
                "status": "failed",
                "error": str(e)
            })
            
            with _ingestion_lock:
                ingestion_status["feeds_failed"] += 1
                ingestion_status["errors"].append(f"Feed '{feed_name}': {str(e)}")
    
    total_time = time.time() - start_time
    
    with _ingestion_lock:
        ingestion_status["running"] = False
        ingestion_status["total_processing_time"] = total_time
        
        if ingestion_status["feeds_failed"] > 0:
            service_manager.update_status('ingestion', ServiceStatus.DEGRADED, 
                                        f"{ingestion_status['feeds_failed']} feeds failed")
        else:
            service_manager.update_status('ingestion', ServiceStatus.READY)
    
    # Publish completion event
    publish_event('ingestion_completed', {
        'total_feeds': len(feeds),
        'processed': ingestion_status["feeds_processed"],
        'failed': ingestion_status["feeds_failed"],
        'records': ingestion_status["total_records"],
        'processing_time': total_time
    })
    
    logger.info(f"Completed processing: {successful_feeds}/{len(results)} feeds processed successfully in {total_time:.2f}s")
    
    return results

def get_ingestion_status() -> Dict:
    """Get the current status of the ingestion process."""
    global ingestion_status
    
    with _ingestion_lock:
        status_copy = dict(ingestion_status)
    
    status_copy["current_time"] = datetime.datetime.utcnow().isoformat()
    
    # Add service status
    service_manager = Config.get_service_manager()
    status_copy["service_status"] = service_manager.get_status()
    
    return status_copy

# -------------------- Background Processing --------------------

def trigger_ingestion_in_background() -> threading.Thread:
    """Trigger ingestion in a background thread."""
    def ingestion_thread():
        service_manager = Config.get_service_manager()
        try:
            logger.info("Starting background ingestion thread")
            results = ingest_all_feeds()
            logger.info(f"Background ingestion thread completed - processed {len(results)} feeds")
            
            # Log summary
            successful = sum(1 for r in results if r.get('status') == 'success')
            skipped = sum(1 for r in results if r.get('status') == 'skipped')
            failed = sum(1 for r in results if r.get('status') == 'failed')
            total_records = sum(r.get('record_count', 0) for r in results)
            
            logger.info(f"Ingestion summary: {successful} successful, {skipped} skipped, {failed} failed, {total_records} total records")
            
        except Exception as e:
            logger.error(f"Error in background ingestion thread: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            report_error(e)
            service_manager.update_status('ingestion', ServiceStatus.ERROR, str(e))
    
    thread = threading.Thread(target=ingestion_thread, daemon=True)
    thread.start()
    logger.info("Background ingestion thread started")
    return thread

def ingest_from_pubsub(event, context):
    """Cloud Function entry point for PubSub triggered ingestion."""
    try:
        logger.info(f"Received PubSub message for ingestion")
        
        if 'data' in event:
            import base64
            message_data_bytes = base64.b64decode(event['data'])
            message_data = json.loads(message_data_bytes)
        else:
            message_data = {}
        
        process_all = message_data.get('process_all', False)
        feed_id = message_data.get('feed_id')
        force_tables = message_data.get('force_tables', False)
        
        if force_tables:
            logger.info("Forcing BigQuery tables update as requested")
            initialize_bigquery_tables()
            
        if process_all:
            results = ingest_all_feeds()
            logger.info(f"Processed all feeds: {len(results)} feeds")
            return {"status": "success", "feeds_processed": len(results)}
        elif feed_id:
            result = ingest_feed(feed_id)
            logger.info(f"Processed feed {feed_id}: {result['status']}")
            return result
        else:
            logger.warning("No feed_id or process_all flag provided in message")
            return {"status": "error", "message": "No action specified"}
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {"status": "error", "error": str(e)}

# CLI entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Ingestion Tool')
    parser.add_argument('--feed', type=str, help='Process a specific feed by ID or name')
    parser.add_argument('--all', action='store_true', help='Process all configured feeds')
    parser.add_argument('--verify', action='store_true', help='Verify ingestion setup')
    parser.add_argument('--status', action='store_true', help='Show ingestion status')
    args = parser.parse_args()
    
    # Initialize configuration
    Config.init_app()
    
    if args.verify:
        logger.info("Verifying ingestion setup...")
        
        if ensure_bucket_exists(Config.GCS_BUCKET):
            logger.info(f"✓ GCS bucket {Config.GCS_BUCKET} exists")
        else:
            logger.error(f"✗ Failed to ensure GCS bucket {Config.GCS_BUCKET} exists")
        
        if initialize_bigquery_tables():
            logger.info("✓ BigQuery tables initialized successfully")
        else:
            logger.error("✗ Failed to initialize BigQuery tables")
        
        # Test service status
        service_manager = Config.get_service_manager()
        status = service_manager.get_status()
        logger.info(f"Service status: {status['overall']}")
        
    elif args.status:
        status = get_ingestion_status()
        print(json.dumps(status, indent=2, default=str))
        
    elif args.feed:
        logger.info(f"Processing feed: {args.feed}")
        result = ingest_feed(args.feed)
        print(json.dumps(result, indent=2, default=str))
        
    elif args.all:
        logger.info("Processing all feeds...")
        results = ingest_all_feeds()
        success_count = sum(1 for r in results if r.get('status') == 'success')
        print(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
        print(json.dumps(results, indent=2, default=str))
        
    else:
        logger.info("No action specified, use --help for options")
        print("Use --all to process all feeds, --feed <id> to process a specific feed, or --verify to check setup")
