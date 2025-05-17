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
import time
import threading
import uuid
from typing import Dict, List, Any, Optional, Tuple, Union
from functools import lru_cache
from google.cloud import storage, bigquery, pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
from google.cloud.exceptions import Conflict
import tldextract

# Import optimized configuration and utilities
from config import (
    Config, ServiceManager, ServiceStatus, report_error,
    Utils, CircuitBreaker, CacheManager, shared_cache
)

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

# Per-feed circuit breakers
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
        # Get DEFAULT_FEED_CONFIGS from Config if available
        if hasattr(Config, 'DEFAULT_FEED_CONFIGS'):
            Config.FEEDS = Config.DEFAULT_FEED_CONFIGS
        else:
            # Define basic default feeds if nothing else is available
            Config.FEEDS = [
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
    
    return Config.FEEDS

# -------------------- Storage Operations --------------------

def ensure_bucket_exists(bucket_name: str) -> bool:
    """Ensure the GCS bucket exists and create it if it doesn't."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        # Try to initialize storage client directly as fallback
        try:
            from google.cloud import storage
            storage_client = storage.Client(project=Config.GCP_PROJECT)
        except Exception as e:
            logger.error(f"Failed to initialize storage client: {e}")
            return False
    
    # Get or create circuit breaker for this operation
    if 'storage_bucket' not in feed_circuit_breakers:
        feed_circuit_breakers['storage_bucket'] = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            bucket = storage_client.bucket(bucket_name)
            if not bucket.exists():
                logger.info(f"Creating bucket {bucket_name}")
                try:
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
                except Exception as bucket_error:
                    logger.error(f"Error creating bucket: {str(bucket_error)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        return False
            else:
                logger.debug(f"Bucket {bucket_name} already exists")
                return True
                
        except Exception as e:
            logger.error(f"Error checking bucket exists (attempt {attempt+1}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                return False
    
    return False

def initialize_bigquery_tables() -> bool:
    """Initialize all required BigQuery tables with circuit breaker protection."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("Cannot initialize BigQuery tables - client not available")
        # Try to initialize BigQuery client directly as fallback
        try:
            from google.cloud import bigquery
            bq_client = bigquery.Client(project=Config.GCP_PROJECT)
        except Exception as e:
            logger.error(f"Failed to initialize BigQuery client: {e}")
            return False
    
    service_manager = Config.get_service_manager()
    
    # Get or create circuit breaker for this operation
    if 'bigquery_tables' not in feed_circuit_breakers:
        feed_circuit_breakers['bigquery_tables'] = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
            
            # Check/create dataset
            try:
                bq_client.get_dataset(dataset_id)
                logger.debug(f"Dataset {dataset_id} already exists")
            except NotFound:
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = getattr(Config, 'BIGQUERY_LOCATION', 'US')
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
            logger.error(f"Error initializing BigQuery tables (attempt {attempt+1}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                return False
    
    return False

def upload_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket with retry logic."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    max_retries = 3
    for attempt in range(max_retries):
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
            logger.error(f"Error uploading to GCS (attempt {attempt+1}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                return None
    
    return None

def upload_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery with optimized batching and retry logic."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client or not records:
        return None
    
    # Optimized batch size based on testing
    batch_size = 50
    job_ids = []
    
    # Rate limiting variables
    max_batch_per_minute = 10  # Reduced from 20 to avoid rate limits
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
                elif isinstance(value, (dict, list)) and key not in ['tags']:
                    processed_record[key] = json.dumps(value)
                else:
                    processed_record[key] = value
            
            # Ensure required fields
            if 'id' not in processed_record:
                processed_record['id'] = Utils.generate_id("record", str(uuid.uuid4()))
            
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
    
    logger.info(f"Upload completed: {successful_batches}/{total_batches} batches successful")
    return job_ids[0] if job_ids else None

# -------------------- Feed Processing --------------------

def download_feed(url: str, headers: Dict = None, timeout: int = 60) -> Tuple[Optional[str], Optional[bytes]]:
    """Download content from a feed URL with retry logic."""
    if not headers:
        headers = {
            'User-Agent': f"ThreatIntelligencePlatform/{Config.VERSION}",
            'Accept': 'application/json, text/csv, text/plain',
            'Accept-Encoding': 'gzip, deflate'
        }
    
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
                break
            
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
    
    return None, None

def parse_feed(content: bytes, format_type: str = None, parser_config: Dict = None) -> List[Dict]:
    """Parse feed data with auto-detection."""
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
        
        # Convert to string with various encodings
        content_str = None
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
            try:
                content_str = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        
        if not content_str:
            content_str = content.decode('utf-8', errors='replace')
        
        # Process based on format
        if format_type == 'json':
            try:
                data = json.loads(content_str)
                
                # Handle different JSON structures
                if isinstance(data, dict) and 'data' in data and isinstance(data['data'], list):
                    result = data['data']
                elif isinstance(data, list):
                    result = data
                else:
                    # Try to extract array from complex JSON
                    for key, value in data.items():
                        if isinstance(value, list) and len(value) > 0:
                            result = value
                            break
                    else:
                        result = [data]  # Default to wrapped object
                        
                logger.info(f"Parsed {len(result)} records from JSON feed")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error: {e}")
                return []
                
        elif format_type == 'csv':
            try:
                # Skip comment lines
                lines = content_str.splitlines()
                clean_lines = [line for line in lines if not line.startswith('#')]
                
                if not clean_lines:
                    return []
                
                # Detect delimiter
                sniffer = csv.Sniffer()
                dialect = sniffer.sniff(clean_lines[0] + '\n' + clean_lines[min(1, len(clean_lines)-1)])
                
                # Parse CSV
                reader = csv.DictReader(clean_lines, dialect=dialect)
                result = list(reader)
                
                logger.info(f"Parsed {len(result)} records from CSV feed")
                return result
            except Exception as e:
                logger.error(f"CSV parsing error: {e}")
                return []
        else:
            logger.warning(f"Unsupported format: {format_type}")
            return []
            
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format."""
    normalized = []
    current_time = datetime.datetime.utcnow()
    
    for record in records:
        try:
            # Skip empty records
            if not record:
                continue
            
            # Extract key fields with fallbacks
            value = (record.get('ioc_value') or record.get('value') or 
                     record.get('indicator') or record.get('ioc') or 
                     record.get('url', ''))
                     
            if not value:
                continue
                
            # Determine indicator type
            ioc_type = (record.get('ioc_type') or record.get('type') or
                        ('url' if value.startswith(('http://', 'https://')) else 
                        'domain' if Utils.is_valid_domain(value) else
                        'ip' if Utils.is_valid_ip(value) else
                        'unknown'))
            
            # Build normalized record
            indicator = {
                "id": Utils.generate_id(f"{feed_name}:{value}:{ioc_type}", ""),
                "value": value,
                "type": ioc_type,
                "source": feed_name,
                "feed_id": feed_name,
                "created_at": current_time.isoformat(),
                "confidence": int(record.get('confidence_level', 50)),
                "description": record.get('description', f"Indicator from {feed_name}")
            }
            
            # Add optional fields if present
            for field in ['threat_type', 'threat_id', 'malware', 'first_seen', 'last_seen',
                         'reference', 'reporter']:
                if field in record and record[field]:
                    indicator[field] = record[field]
            
            # Process tags
            tags = record.get('tags', [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]
            
            if tags:
                indicator['tags'] = tags
            
            # Calculate initial risk score - simple version
            risk_score = indicator.get('confidence', 50)
            if 'malware' in str(record).lower():
                risk_score += 10
            if 'ransomware' in str(record).lower():
                risk_score += 20
                
            indicator['risk_score'] = min(100, max(0, risk_score))
            
            # Store raw data for reference
            indicator['raw_data'] = json.dumps(record)
                
            normalized.append(indicator)
            
        except Exception as e:
            logger.warning(f"Error normalizing record from {feed_name}: {str(e)}")
            continue
    
    logger.info(f"Normalized {len(normalized)} records from {feed_name}")
    return normalized

# -------------------- Main Processing --------------------

def process_feed(feed_config: Dict) -> Dict:
    """Process a single feed and store its data."""
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
        
        # Determine file extension and content type
        format_type = feed_config.get("format", "")
        if not format_type:
            # Auto-detect from content type
            if content_type and 'json' in content_type.lower():
                format_type = 'json'
                file_extension = '.json'
                content_type_to_use = "application/json"
            elif content_type and 'csv' in content_type.lower():
                format_type = 'csv'
                file_extension = '.csv'
                content_type_to_use = "text/csv"
            else:
                format_type = 'text'
                file_extension = '.txt'
                content_type_to_use = "text/plain"
        else:
            # Use specified format
            if format_type == 'json':
                file_extension = '.json'
                content_type_to_use = "application/json"
            elif format_type == 'csv':
                file_extension = '.csv'
                content_type_to_use = "text/csv"
            else:
                file_extension = '.txt'
                content_type_to_use = "text/plain"
        
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
        
        # Publish to Pub/Sub if available
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
    
    # Process feeds sequentially for reliability
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
            service_manager.update_status('ingestion', ServiceStatus.INITIALIZING)
            
            # Ensure GCP resources exist first
            bucket_exists = ensure_bucket_exists(Config.GCS_BUCKET)
            tables_exist = initialize_bigquery_tables()
            
            if not bucket_exists or not tables_exist:
                logger.warning("Some resources failed to initialize, ingestion may be incomplete")
                service_manager.update_status('ingestion', ServiceStatus.DEGRADED, 
                                            "Resource initialization incomplete")
            
            # Run actual ingestion
            results = ingest_all_feeds()
            
            # Log summary
            successful = sum(1 for r in results if r.get('status') == 'success')
            skipped = sum(1 for r in results if r.get('status') == 'skipped')
            failed = sum(1 for r in results if r.get('status') == 'failed')
            total_records = sum(r.get('record_count', 0) for r in results)
            
            logger.info(f"Ingestion summary: {successful} successful, {skipped} skipped, {failed} failed, {total_records} total records")
            
            # Update service status based on results
            if failed > 0:
                service_manager.update_status('ingestion', ServiceStatus.DEGRADED, 
                                            f"{failed}/{len(results)} feeds failed")
            else:
                service_manager.update_status('ingestion', ServiceStatus.READY)
                
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
        
    else:
        logger.info("No action specified, use --help for options")
        print("Use --all to process all feeds, --feed <id> to process a specific feed, or --verify to check setup")
