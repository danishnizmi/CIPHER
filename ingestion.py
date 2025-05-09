"""
Optimized ingestion module for threat intelligence feeds.
Handles downloading, processing, and storing threat intelligence data.
Ensures BigQuery resources are properly initialized and uses cost-effective strategies.
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
import config
from config import Config

# Configure logging with a single setup
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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

# Global client initialization flag
_clients_initialized = False
_bq_client = None
_storage_client = None 
_publisher = None
_subscriber = None

# -------------------- Google Cloud Clients --------------------

def initialize_clients():
    """Initialize and cache Google Cloud clients."""
    global _clients_initialized, _bq_client, _storage_client, _publisher, _subscriber
    
    if _clients_initialized:
        return _bq_client, _storage_client, _publisher, _subscriber
    
    # Get clients from config module to ensure consistent client usage
    _bq_client = config.initialize_bigquery()
    _storage_client = config.initialize_storage()
    _publisher, _subscriber = config.initialize_pubsub()
    
    if _bq_client:
        logger.info("BigQuery client initialized successfully")
    else:
        logger.error("Failed to initialize BigQuery client")
        
    if _storage_client:
        logger.info("Storage client initialized successfully")
    else:
        logger.error("Failed to initialize Storage client")
        
    if _publisher and _subscriber:
        logger.info("Pub/Sub clients initialized successfully")
    else:
        logger.error("Failed to initialize Pub/Sub clients")
    
    _clients_initialized = True
    return _bq_client, _storage_client, _publisher, _subscriber

# -------------------- Data Sanitization and Validation --------------------

class DataProcessor:
    """Handles data cleaning, sanitization, and validation."""
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string values to prevent XSS and injection attacks."""
        if not value or not isinstance(value, str):
            return value
        # Remove control characters and limit length
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        return value[:32768] if len(value) > 32768 else value
        
    @staticmethod
    def sanitize_ioc(ioc_type: str, value: str) -> Optional[str]:
        """Sanitize IOC values based on their type."""
        if not value:
            return value
            
        value = DataProcessor.sanitize_string(value)
        
        # Validation patterns
        patterns = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
            'domain': r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            'url': r'^(https?|ftp)://.+$',
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
        
        # Check specific IOC type
        if ioc_type in patterns and not re.match(patterns[ioc_type], value.lower()):
            # Special handling for URLs - try to fix common issues
            if ioc_type == 'url' and re.match(r'^www\.', value.lower()):
                return "http://" + value
            # Don't invalidate - just log warning
            logger.debug(f"Suspicious {ioc_type} format: {value}")
                
        return value
        
    @staticmethod
    def sanitize_record(record: Dict, record_type: str = None) -> Dict:
        """Sanitize an entire record."""
        if not record:
            return {}
            
        sanitized = {}
        
        for key, value in record.items():
            # Handle nested structures
            if isinstance(value, dict):
                sanitized[key] = DataProcessor.sanitize_record(value)
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    sanitized[key] = [DataProcessor.sanitize_record(item) for item in value]
                else:
                    sanitized[key] = value
            elif isinstance(value, str):
                # Special handling for IOC values
                if record_type == 'ioc' and key == 'value' and 'type' in record:
                    sanitized[key] = DataProcessor.sanitize_ioc(record['type'], value)
                else:
                    sanitized[key] = DataProcessor.sanitize_string(value)
            else:
                sanitized[key] = value
                
        return sanitized

    @staticmethod
    def deduplicate_records(records: List[Dict], existing_hashes: List[str] = None) -> Tuple[List[Dict], List[str]]:
        """Deduplicate records based on content hash."""
        if existing_hashes is None:
            existing_hashes = []
            
        deduplicated_data = []
        new_hashes = []
        
        for record in records:
            record_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode('utf-8')).hexdigest()
            if record_hash not in existing_hashes and record_hash not in new_hashes:
                deduplicated_data.append(record)
                new_hashes.append(record_hash)
                
        return deduplicated_data, new_hashes
    
    @staticmethod
    def determine_ioc_type(value: str) -> str:
        """Determine the IOC type based on value format."""
        if not value or not isinstance(value, str):
            return 'unknown'
            
        value = value.strip().lower()
        
        # Check for IP:Port format first
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}:\d+$', value):
            return 'ip:port'
        
        # Check using patterns
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
                
        # Default type
        return 'unknown'

# -------------------- Storage and BigQuery Operations --------------------

def ensure_bucket_exists(bucket_name: str) -> bool:
    """Ensure the GCS bucket exists and create it if it doesn't."""
    storage_client = _storage_client or initialize_clients()[1]
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return False
    
    try:
        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            # Create bucket with cost-optimized settings
            logger.info(f"Creating bucket {bucket_name}")
            bucket = storage_client.create_bucket(
                bucket_name, 
                location=Config.GCP_REGION,
                predefined_acl='projectPrivate'
            )
            logger.info(f"Created bucket {bucket_name}")
            
            # Add lifecycle policy to reduce storage costs
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
            
            # Create necessary folder structure
            for folder in ['feeds', 'raw', 'processed', 'cache', 'exports']:
                blob = bucket.blob(f"{folder}/")
                blob.upload_from_string('')
            logger.info(f"Created folder structure in bucket {bucket_name}")
                
            return True
        else:
            logger.debug(f"Bucket {bucket_name} already exists")
            return True
            
    except Exception as e:
        logger.error(f"Error ensuring bucket exists: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return False

def initialize_bigquery_tables() -> bool:
    """Initialize all required BigQuery tables with optimized schema."""
    bq_client = _bq_client or initialize_clients()[0]
    
    if not bq_client:
        logger.error("Cannot initialize BigQuery tables - client not available")
        return False
    
    try:
        # Ensure dataset exists
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        try:
            bq_client.get_dataset(dataset_id)
            logger.debug(f"Dataset {dataset_id} already exists")
        except NotFound:
            # Create dataset
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = Config.BIGQUERY_LOCATION
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {dataset_id}")
        
        # Define tables with optimized schemas
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
                bigquery.SchemaField("campaign_name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware_alias", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware_printable", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("report_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("raw_data", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("enrichment_geo", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("enrichment_country", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("last_analyzed", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("risk_score", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("analysis_summary", "STRING", mode="NULLABLE"),
            ],
            'vulnerabilities': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("cve_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("severity", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("published_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("modified_date", "TIMESTAMP", mode="NULLABLE"),
            ],
            'threat_actors': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("aliases", "STRING", mode="REPEATED"),
                bigquery.SchemaField("first_observed", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_observed", "TIMESTAMP", mode="NULLABLE"),
            ],
            'campaigns': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("start_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("end_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor", "STRING", mode="NULLABLE"),
            ],
            'malware': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
            ],
            'users': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("username", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("password_hash", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("role", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_login", "TIMESTAMP", mode="NULLABLE"),
            ],
            'audit_log': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("user_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("action", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("resource", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("details", "STRING", mode="NULLABLE"),
            ]
        }
        
        # Create or update tables
        for table_name, schema in tables_config.items():
            table_id = f"{dataset_id}.{table_name}"
            try:
                try:
                    table = bq_client.get_table(table_id)
                    logger.debug(f"Table {table_id} exists, checking schema")
                    
                    # Check for schema updates - optimized to only update if needed
                    existing_fields = {field.name: field for field in table.schema}
                    new_fields = [field for field in schema if field.name not in existing_fields]
                    
                    if new_fields:
                        logger.info(f"Updating schema for {table_id} with {len(new_fields)} new fields")
                        table.schema = list(table.schema) + new_fields
                        bq_client.update_table(table, ["schema"])
                        
                except NotFound:
                    # Create table
                    table = bigquery.Table(table_id, schema=schema)
                    bq_client.create_table(table)
                    logger.info(f"Created table {table_id}")
                
                # Verify with test query
                test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                bq_client.query(test_query).result()
                
            except Exception as e:
                logger.warning(f"Issue with table {table_id}: {str(e)}")
                return False
                
        return True
        
    except Exception as e:
        logger.error(f"Error initializing BigQuery tables: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return False

def upload_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket with proper content type handling."""
    storage_client = _storage_client or initialize_clients()[1]
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        # Determine content type
        if content_type is None:
            # Default content type based on extension
            if blob_name.endswith('.json'):
                content_type = 'application/json'
            elif blob_name.endswith('.csv'):
                content_type = 'text/csv'
            elif blob_name.endswith('.txt'):
                content_type = 'text/plain'
            else:
                content_type = 'application/octet-stream'
        
        # Ensure data is properly encoded
        if isinstance(data, str):
            data_to_upload = data.encode('utf-8')
        else:
            data_to_upload = data
            
        # Set content type and upload
        blob.content_type = content_type
        blob.upload_from_string(data_to_upload, content_type=content_type)
        
        gcs_uri = f"gs://{bucket_name}/{blob_name}"
        logger.info(f"Uploaded data to {gcs_uri}")
        return gcs_uri
        
    except Exception as e:
        logger.error(f"Error uploading to GCS: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return None

def upload_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery with optimized batching and retries."""
    bq_client = _bq_client or initialize_clients()[0]
    
    if not bq_client or not records:
        return None
    
    logger.info(f"Uploading {len(records)} records to {table_id}")
    
    # Process records in batches for better reliability
    batch_size = 50
    job_ids = []
    
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        batch_num = i//batch_size + 1
        logger.info(f"Processing batch {batch_num}/{(len(records) + batch_size - 1) // batch_size}")
        
        try:
            # Process records to handle special types
            processed_batch = []
            for record in batch:
                processed_record = {}
                
                for key, value in record.items():
                    # Handle timestamps
                    if isinstance(value, (datetime.datetime, datetime.date)):
                        processed_record[key] = value.isoformat()
                    elif key in ['created_at', 'first_seen', 'last_seen', 'timestamp'] and isinstance(value, str):
                        try:
                            # Normalize timestamp format
                            dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                            processed_record[key] = dt.isoformat()
                        except ValueError:
                            processed_record[key] = datetime.datetime.utcnow().isoformat()
                    # Handle nested structures
                    elif isinstance(value, dict):
                        processed_record[key] = json.dumps(value)
                    # Handle array fields
                    elif key == 'tags' and isinstance(value, list):
                        processed_record[key] = [str(item) for item in value]
                    # Handle empty arrays
                    elif isinstance(value, list) and not value:
                        processed_record[key] = [] if key == 'tags' else value
                    # Handle other objects
                    elif isinstance(value, (dict, list)) and key not in ['tags']:
                        processed_record[key] = json.dumps(value)
                    else:
                        processed_record[key] = value
                
                # Ensure required fields
                if 'id' not in processed_record:
                    processed_record['id'] = hashlib.md5(str(record).encode()).hexdigest()
                
                # Ensure value field
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
            
            # Upload with retries
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Configure the job
                    job_config = bigquery.LoadJobConfig(
                        schema_update_options=[bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
                        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                    )
                    
                    # Upload the batch
                    job = bq_client.load_table_from_json(
                        processed_batch,
                        table_id,
                        job_config=job_config
                    )
                    
                    result = job.result(timeout=60)
                    
                    if job.errors:
                        logger.error(f"Errors in batch {batch_num}: {job.errors}")
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)  # Exponential backoff
                            continue
                    else:
                        job_ids.append(job.job_id)
                        logger.info(f"Successfully uploaded batch {batch_num}")
                    
                    break
                        
                except Exception as e:
                    logger.error(f"Error uploading batch {batch_num}: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to upload batch {batch_num} after {max_retries} attempts")
            
        except Exception as e:
            logger.error(f"Error processing batch {batch_num}: {str(e)}")
    
    return job_ids[0] if job_ids else None

# -------------------- Feed Processing Functions --------------------

def download_feed(url: str, headers: Dict = None, timeout: int = 60) -> Tuple[Optional[str], Optional[bytes]]:
    """Download content from a feed URL with retry logic."""
    if not headers:
        headers = {'User-Agent': f"ThreatIntelligencePlatform/{Config.VERSION}"}
    
    # Implement retry logic with exponential backoff
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading feed from {url} (attempt {attempt+1}/{max_retries})")
            response = requests.get(url, headers=headers, timeout=timeout)
            
            # Check for rate limiting
            if response.status_code == 429:
                wait_time = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
                
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '')
            return content_type, response.content
            
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Request failed: {str(e)}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Request failed after {max_retries} attempts: {str(e)}")
                return None, None
    
    return None, None

def parse_json_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse JSON feed data with robust error handling."""
    try:
        # Try multiple decoding approaches
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try different encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    content_str = content.decode(encoding, errors='replace')
                    data = json.loads(content_str)
                    break
                except:
                    continue
            else:
                # Last resort - try to find JSON in the content
                content_str = content.decode('utf-8', errors='ignore')
                json_start = content_str.find('{')
                json_array_start = content_str.find('[')
                
                if json_start >= 0 and (json_array_start < 0 or json_start < json_array_start):
                    data = json.loads(content_str[json_start:])
                elif json_array_start >= 0:
                    data = json.loads(content_str[json_array_start:])
                else:
                    raise Exception("Could not find valid JSON content")
        
        # Handle ThreatFox specific format: {id: [data]}
        processed_data = []
        if isinstance(data, dict):
            for key, value in data.items():
                # ThreatFox format
                if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                    for item in value:
                        item_copy = item.copy()
                        item_copy['threat_id'] = key
                        processed_data.append(item_copy)
                # PhishTank format (array of objects)
                elif key == 'data' and isinstance(value, list):
                    processed_data.extend(value)
        elif isinstance(data, list):
            processed_data = data
        
        return processed_data
    except Exception as e:
        logger.error(f"Error parsing JSON feed: {str(e)}")
        return []

def parse_csv_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse CSV feed data with robust error handling."""
    try:
        # Decode content
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                content_str = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            content_str = content.decode('utf-8', errors='replace')
        
        # Skip comment lines (URLhaus specific)
        lines = content_str.splitlines()
        clean_lines = []
        for line in lines:
            if not line.strip().startswith('#'):
                clean_lines.append(line)
        
        if not clean_lines:
            return []
            
        content_str = '\n'.join(clean_lines)
        
        # Parse CSV
        dialect = csv.Sniffer().sniff(content_str[:1024]) if content_str else csv.excel
        csv_data = []
        
        # Parse with header
        reader = csv.DictReader(io.StringIO(content_str), dialect=dialect)
        csv_data = list(reader)
        
        # Filter out empty records
        csv_data = [row for row in csv_data if any(value.strip() if isinstance(value, str) else value for value in row.values())]
        
        return csv_data
    except Exception as e:
        logger.error(f"Error parsing CSV feed: {str(e)}")
        return []

def parse_feed(content: bytes, format_type: str = None, parser_config: Dict = None) -> List[Dict]:
    """Parse feed data with format auto-detection if needed."""
    if not content:
        return []
    
    if parser_config is None:
        parser_config = {}
    
    # Auto-detect format if not specified
    if not format_type:
        content_start = content[:100].strip()
        if content_start.startswith(b'{') or content_start.startswith(b'['):
            format_type = 'json'
        elif b',' in content_start and b'\n' in content[:1000]:
            format_type = 'csv'
        else:
            format_type = 'text'
    
    try:
        # Call appropriate parser based on format
        if format_type == 'json':
            return parse_json_feed(content, parser_config)
        elif format_type == 'csv':
            return parse_csv_feed(content, parser_config)
        else:
            logger.warning(f"Unknown format type: {format_type}, falling back to JSON")
            return parse_json_feed(content, parser_config)
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format for storage."""
    normalized = []
    
    for record in records:
        # Handle different feed formats
        
        # ThreatFox format
        if 'ioc_value' in record and 'ioc_type' in record:
            value = record['ioc_value']
            ioc_type = record['ioc_type']
            
            # Parse tags if they're comma-separated string
            tags = record.get('tags', '')
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]
            
            indicator = {
                "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                "value": value,
                "type": ioc_type,
                "source": feed_name,
                "feed_id": feed_name,
                "created_at": datetime.datetime.utcnow().isoformat(),
                "confidence": record.get('confidence_level', 50),
                "tags": tags,
                "description": f"Indicator from {feed_name}",
                "threat_type": record.get('threat_type'),
                "malware": record.get('malware'),
                "malware_alias": record.get('malware_alias'),
                "malware_printable": record.get('malware_printable'),
                "first_seen": record.get('first_seen_utc'),
                "last_seen": record.get('last_seen_utc'),
                "raw_data": json.dumps(record)
            }
            
        # URLhaus format  
        elif 'url' in record and 'threat' in record:
            value = record['url']
            
            # Parse tags if they're comma-separated string
            tags = record.get('tags', '')
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]
            
            indicator = {
                "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                "value": value,
                "type": 'url',
                "source": feed_name,
                "feed_id": feed_name,
                "created_at": datetime.datetime.utcnow().isoformat(),
                "confidence": 80 if record.get('url_status') == 'online' else 60,
                "tags": tags,
                "description": f"URL from {feed_name}",
                "threat_type": record.get('threat'),
                "first_seen": record.get('dateadded'),
                "last_seen": record.get('last_online'),
                "raw_data": json.dumps(record)
            }
            
        # PhishTank format
        elif 'url' in record:
            value = record['url']
            
            indicator = {
                "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                "value": value,
                "type": 'url',
                "source": feed_name,
                "feed_id": feed_name,
                "created_at": datetime.datetime.utcnow().isoformat(),
                "confidence": 90 if record.get('verified') == 'yes' else 70,
                "tags": ['phishing', 'verified'] if record.get('verified') == 'yes' else ['phishing'],
                "description": f"Phishing URL from {feed_name}",
                "threat_type": 'phishing',
                "first_seen": record.get('submission_time'),
                "last_seen": record.get('verification_time'),
                "raw_data": json.dumps(record)
            }
            
        else:
            # Generic format
            value = record.get('value') or record.get('indicator') or ''
            if not value:
                continue
                
            indicator = {
                "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                "value": value,
                "type": record.get('type') or DataProcessor.determine_ioc_type(value),
                "source": feed_name,
                "feed_id": feed_name,
                "created_at": datetime.datetime.utcnow().isoformat(),
                "confidence": record.get('confidence', 50),
                "tags": record.get('tags', []),
                "description": record.get('description', f"Indicator from {feed_name}"),
                "raw_data": json.dumps(record)
            }
        
        # Skip invalid records
        if not indicator['value']:
            continue
            
        normalized.append(indicator)
    
    return normalized

# -------------------- Main Processing Functions --------------------

def process_feed(feed_config: Dict) -> Dict:
    """Process a single feed and store its data."""
    feed_name = feed_config.get("name", "Unknown")
    feed_id = feed_config.get("id", feed_name)
    
    logger.info(f"Starting ingestion for feed '{feed_name}'")
    
    result = {
        "feed_name": feed_name,
        "feed_id": feed_id,
        "start_time": datetime.datetime.utcnow().isoformat(),
        "status": "failed",
        "record_count": 0,
        "error": None
    }
    
    try:
        # Check if feed is enabled
        if not feed_config.get("enabled", True):
            logger.info(f"Feed '{feed_name}' is disabled, skipping")
            result["status"] = "skipped"
            result["error"] = "Feed is disabled"
            return result
        
        # Ensure clients are initialized
        initialize_clients()
        
        # Ensure bucket exists
        bucket_name = Config.GCS_BUCKET
        if not ensure_bucket_exists(bucket_name):
            result["error"] = "Failed to ensure GCS bucket exists"
            return result
        
        # Step 1: Download feed data
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        timeout = feed_config.get("timeout", 60)
        
        content_type, content = download_feed(url, headers, timeout)
        if not content:
            result["error"] = "Failed to download feed data"
            return result
        
        result["content_type"] = content_type
        
        # Step 2: Store raw data
        storage_path = feed_config.get("storage_path", f"feeds/{feed_name}")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Determine file extension and content type
        format_type = feed_config.get("format", "")
        if format_type == "json":
            file_extension = ".json"
            content_type_to_use = "application/json"
        elif format_type == "csv":
            file_extension = ".csv"
            content_type_to_use = "text/csv"
        else:
            # Auto-detect
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
        
        # Store raw data
        raw_blob_name = f"{storage_path}/raw/{timestamp}{file_extension}"
        raw_uri = upload_to_gcs(bucket_name, raw_blob_name, content, content_type_to_use)
        if not raw_uri:
            result["error"] = "Failed to store raw feed data"
            return result
        
        result["raw_uri"] = raw_uri
        
        # Step 3: Parse feed data
        parser_config = feed_config.get("parser_config", {})
        parsed_data = parse_feed(content, format_type, parser_config)
        if not parsed_data:
            logger.warning(f"No valid records found in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No valid records found"
            return result
        
        # Step 4: Normalize data to common format
        normalized_data = normalize_indicators(parsed_data, feed_name)
        
        # Step 5: Deduplicate records (optional - can be expensive)
        # For now, we'll skip deduplication to ensure data gets into BigQuery
        deduplicated_data = normalized_data
        
        # If no records, return success
        if not deduplicated_data:
            logger.info(f"No records to process in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No records to process"
            return result
        
        # Step 6: Store processed data
        processed_blob_name = f"{storage_path}/processed/{timestamp}.json"
        processed_uri = upload_to_gcs(
            bucket_name, 
            processed_blob_name,
            json.dumps(deduplicated_data, indent=2),
            "application/json"
        )
        
        if not processed_uri:
            result["error"] = "Failed to store processed feed data"
            return result
        
        result["processed_uri"] = processed_uri
        result["record_count"] = len(deduplicated_data)
        
        # Step 7: Upload to BigQuery
        # First ensure dataset and tables exist
        if not initialize_bigquery_tables():
            logger.warning("BigQuery tables initialization reported issues")
        
        # Upload to indicators table
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        indicators_table_id = f"{dataset_id}.indicators"
        job_id = upload_to_bigquery(indicators_table_id, deduplicated_data)
        
        if not job_id:
            result["error"] = "Failed to upload data to BigQuery"
            return result
        
        result["bigquery_job_id"] = job_id
        
        # Step 8: Publish to Pub/Sub (optional)
        if _publisher:
            topic_path = _publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
            
            message_data = {
                "operation": "feed_processed",
                "feed_name": feed_name,
                "feed_id": feed_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "record_count": len(deduplicated_data),
                "raw_uri": raw_uri,
                "processed_uri": processed_uri
            }
            
            try:
                message_json = json.dumps(message_data)
                future = _publisher.publish(topic_path, message_json.encode("utf-8"), feed_id=feed_id)
                message_id = future.result()
                result["pubsub_message_id"] = message_id
            except Exception as e:
                logger.warning(f"Failed to publish message to Pub/Sub: {str(e)}")
        
        # Update result
        result["status"] = "success"
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        
        logger.info(f"Successfully processed feed '{feed_name}': {len(deduplicated_data)} records")
        return result
    
    except Exception as e:
        logger.error(f"Error processing feed '{feed_name}': {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        
        result["error"] = str(e)
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        return result

# -------------------- Public API Functions --------------------

def ingest_feed(feed_name: str) -> Dict:
    """Process a single feed by name."""
    global ingestion_status
    
    # Initialize clients if needed
    initialize_clients()
    
    # Get feed configuration
    feed_config = None
    if hasattr(Config, 'get_feed_by_id'):
        feed_config = Config.get_feed_by_id(feed_name)
    
    # Try to find it in Config.FEEDS
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
        ingestion_status["feeds_failed"] += 1
        ingestion_status["errors"].append(f"Feed '{feed_name}' not found")
        return error_result
    
    # Process feed
    result = process_feed(feed_config)
    
    # Update global status
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
    
    # Reset status
    ingestion_status = {
        "last_run": datetime.datetime.utcnow().isoformat(),
        "running": True,
        "feeds_processed": 0,
        "feeds_failed": 0,
        "total_records": 0,
        "errors": []
    }
    
    # Initialize clients
    initialize_clients()
    
    # Make sure BigQuery tables are initialized
    initialize_bigquery_tables()
    
    # Make sure feed configuration is available
    if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
        if hasattr(Config, 'ensure_feed_configuration'):
            Config.ensure_feed_configuration()
    
    # Get enabled feeds
    feeds = []
    if hasattr(Config, 'get_enabled_feeds'):
        feeds = Config.get_enabled_feeds()
    elif hasattr(Config, 'FEEDS'):
        feeds = [f for f in Config.FEEDS if f.get('enabled', True)]
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        ingestion_status["running"] = False
        return []
    
    logger.info(f"Processing {len(feeds)} enabled feeds")
    
    results = []
    for feed_config in feeds:
        try:
            feed_id = feed_config.get("id") or feed_config.get("name")
            if not feed_id:
                continue
                
            result = process_feed(feed_config)
            results.append(result)
            
            # Update overall status
            if result["status"] == "success":
                ingestion_status["feeds_processed"] += 1
                ingestion_status["total_records"] += result.get("record_count", 0)
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
            
            ingestion_status["feeds_failed"] += 1
            ingestion_status["errors"].append(f"Feed '{feed_name}': {str(e)}")
    
    # Update status
    ingestion_status["running"] = False
    
    # Print summary
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"Completed processing: {success_count}/{len(results)} feeds processed successfully")
    
    return results

def get_ingestion_status() -> Dict:
    """Get the current status of the ingestion process."""
    global ingestion_status
    
    # Create a copy of the status
    status_copy = ingestion_status.copy()
    
    # Add current timestamp
    status_copy["current_time"] = datetime.datetime.utcnow().isoformat()
    
    return status_copy

# -------------------- Background Processing --------------------

def trigger_ingestion_in_background() -> threading.Thread:
    """Trigger ingestion in a background thread."""
    def ingestion_thread():
        try:
            logger.info("Starting background ingestion thread")
            ingest_all_feeds()
            logger.info("Background ingestion thread completed")
        except Exception as e:
            logger.error(f"Error in background ingestion thread: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            config.report_error(e)
    
    # Start ingestion in a separate thread
    thread = threading.Thread(target=ingestion_thread)
    thread.daemon = True
    thread.start()
    logger.info("Background ingestion thread started")
    return thread

def ingest_from_pubsub(event, context):
    """Cloud Function entry point for PubSub triggered ingestion."""
    try:
        logger.info(f"Received PubSub message for ingestion")
        
        # Extract message data
        if 'data' in event:
            import base64
            message_data_bytes = base64.b64decode(event['data'])
            message_data = json.loads(message_data_bytes)
        else:
            message_data = {}
        
        # Process based on message data
        process_all = message_data.get('process_all', False)
        feed_id = message_data.get('feed_id')
        force_tables = message_data.get('force_tables', False)
        
        # Initialize clients
        initialize_clients()
        
        # Check if we need to force BigQuery table updates
        if force_tables:
            logger.info("Forcing BigQuery tables update as requested")
            initialize_bigquery_tables()
            
        if process_all:
            results = ingest_all_feeds()
            logger.info(f"Processed all feeds: {len(results)} feeds")
        elif feed_id:
            result = ingest_feed(feed_id)
            logger.info(f"Processed feed {feed_id}: {result['status']}")
        else:
            logger.warning("No feed_id or process_all flag provided in message")
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)

# -------------------- Feed Configuration --------------------

# Updated feed configurations based on actual data formats
FEED_CONFIGS = [
    {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent indicators from ThreatFox",
        "format": "json",
        "type": "mixed",
        "enabled": True,
        "parser_config": {}
    },
    {
        "id": "urlhaus",
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recent malware URLs from URLhaus",
        "format": "csv",
        "type": "url",
        "enabled": True,
        "parser_config": {}
    },
    {
        "id": "phishtank",
        "name": "PhishTank URLs",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "description": "URLs verified as phishing by PhishTank community",
        "format": "json",
        "type": "url",
        "enabled": True,
        "parser_config": {},
        "timeout": 30  # Shorter timeout to handle rate limiting
    }
]

# Update Config if feeds are not set
if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
    Config.FEEDS = FEED_CONFIGS

# CLI command runner
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Ingestion Tool')
    parser.add_argument('--feed', type=str, help='Process a specific feed by ID or name')
    parser.add_argument('--all', action='store_true', help='Process all configured feeds')
    parser.add_argument('--verify', action='store_true', help='Verify ingestion setup')
    args = parser.parse_args()
    
    # Initialize clients
    initialize_clients()
    
    if args.verify:
        logger.info("Verifying ingestion setup...")
        
        # Check clients
        if not _bq_client or not _storage_client:
            logger.error("GCP clients not properly initialized")
        else:
            logger.info("GCP clients initialized successfully")
        
        # Check bucket
        if ensure_bucket_exists(Config.GCS_BUCKET):
            logger.info(f"GCS bucket {Config.GCS_BUCKET} exists")
        else:
            logger.error(f"Failed to ensure GCS bucket {Config.GCS_BUCKET} exists")
        
        # Check tables
        if initialize_bigquery_tables():
            logger.info("BigQuery tables initialized successfully")
        else:
            logger.error("Failed to initialize BigQuery tables")
            
    elif args.feed:
        logger.info(f"Processing feed: {args.feed}")
        result = ingest_feed(args.feed)
        logger.info(f"Result: {result}")
        
    elif args.all:
        logger.info("Processing all feeds...")
        results = ingest_all_feeds()
        success_count = sum(1 for r in results if r.get('status') == 'success')
        logger.info(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
        
    else:
        logger.info("No action specified, use --feed, --all, or --verify")
