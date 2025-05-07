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

# -------------------- Google Cloud Clients --------------------

def initialize_clients():
    """Initialize and cache Google Cloud clients."""
    # Get clients from config module to ensure consistent client usage
    bq_client = config.initialize_bigquery()
    storage_client = config.initialize_storage()
    publisher, subscriber = config.initialize_pubsub()
    
    if bq_client:
        logger.info("BigQuery client initialized successfully")
    else:
        logger.error("Failed to initialize BigQuery client")
        
    if storage_client:
        logger.info("Storage client initialized successfully")
    else:
        logger.error("Failed to initialize Storage client")
        
    if publisher and subscriber:
        logger.info("Pub/Sub clients initialized successfully")
    else:
        logger.error("Failed to initialize Pub/Sub clients")
        
    return bq_client, storage_client, publisher, subscriber

# Initialize Google Cloud clients globally
bq_client, storage_client, publisher, subscriber = initialize_clients()

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
            return None
                
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
    if not storage_client:
        logger.error("Storage client not initialized")
        return False
    
    try:
        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            # Create bucket with cost-optimized settings
            storage_client.create_bucket(
                bucket, 
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
            bucket.lifecycle_rules = lifecycle_rules
            bucket.patch()
            
            # Create necessary folder structure
            for folder in ['feeds', 'raw', 'processed', 'cache', 'exports']:
                bucket.blob(f"{folder}/").upload_from_string('')
                
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

def force_update_bigquery_tables() -> bool:
    """Force update tables by dropping and recreating when needed."""
    if not bq_client:
        logger.error("Cannot update BigQuery tables - client not available")
        return False
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        tables_to_check = ['indicators', 'vulnerabilities', 'threat_actors', 'campaigns', 'malware', 'users', 'audit_log']
        
        # Check each table
        for table_name in tables_to_check:
            table_id = f"{dataset_id}.{table_name}"
            try:
                # Try to query the table to see if it works
                test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                try:
                    bq_client.query(test_query).result()
                    logger.info(f"Table {table_id} is accessible")
                except Exception:
                    # Delete and recreate problematic table
                    logger.warning(f"Table {table_id} has issues, deleting for recreation")
                    try:
                        bq_client.delete_table(table_id)
                        logger.info(f"Deleted table {table_id}")
                    except Exception as e:
                        logger.warning(f"Error deleting table {table_id}: {str(e)}")
            except NotFound:
                logger.info(f"Table {table_id} not found, will be created")
        
        # Reinitialize all tables
        return initialize_bigquery_tables()
        
    except Exception as e:
        logger.error(f"Error in force_update_bigquery_tables: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return False

def upload_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket with proper content type handling."""
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

def get_cached_hashes(feed_name: str) -> List[str]:
    """Get cached hashes from GCS for deduplication."""
    if not storage_client:
        return []
    
    bucket_name = Config.GCS_BUCKET
    blob_name = f"cache/feed_hashes_{feed_name}.json"
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if blob.exists():
            content = blob.download_as_text()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return []
        
        return []
    except Exception as e:
        logger.warning(f"Error getting cached hashes: {str(e)}")
        return []

def store_cached_hashes(feed_name: str, hashes: List[str]) -> bool:
    """Store cached hashes to GCS with a limit to control costs."""
    if not storage_client:
        return False
    
    bucket_name = Config.GCS_BUCKET
    blob_name = f"cache/feed_hashes_{feed_name}.json"
    
    try:
        # Limit hash count for cost control
        if len(hashes) > 10000:
            hashes = hashes[-10000:]
            
        # Upload to GCS
        return upload_to_gcs(bucket_name, blob_name, json.dumps(hashes), 'application/json') is not None
    except Exception as e:
        logger.warning(f"Error storing cached hashes: {str(e)}")
        return False

def upload_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery with optimized batching and retries."""
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
    
    # Implement retry logic
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading feed from {url} (attempt {attempt+1}/{max_retries})")
            response = requests.get(url, headers=headers, timeout=timeout)
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
        elif format_type == 'text':
            return parse_text_feed(content, parser_config)
        else:
            logger.warning(f"Unknown format type: {format_type}, falling back to JSON")
            return parse_json_feed(content, parser_config)
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return []

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
        
        # Handle nested structures
        root_element = parser_config.get("root_element")
        if root_element and isinstance(data, dict) and root_element in data:
            data = data[root_element]
            
        # Normalize to list format
        if not isinstance(data, list):
            if isinstance(data, dict):
                # Process dictionary data
                processed_data = []
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            item_copy = item.copy() if isinstance(item, dict) else {"value": item}
                            item_copy["threat_id"] = key
                            processed_data.append(item_copy)
                    elif key not in ['meta', 'info']:
                        processed_data.append({"value": str(value), "type": "unknown", "key": key})
                
                data = processed_data if processed_data else [data]
            else:
                data = [{"value": data}]
        
        # Filter and clean up records
        cleaned_data = []
        for item in data:
            if isinstance(item, dict) and item:
                cleaned_data.append(item)
            elif item is not None:
                cleaned_data.append({"value": str(item)})
        
        return cleaned_data
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
        
        # Skip header lines if specified
        skip_lines = parser_config.get("skip_lines", 0)
        if skip_lines > 0:
            lines = content_str.splitlines()
            if len(lines) > skip_lines:
                content_str = '\n'.join(lines[skip_lines:])
        
        # Skip comment lines
        content_str = '\n'.join([line for line in content_str.splitlines() if not line.strip().startswith('#')])
        
        # Get configuration
        field_names = parser_config.get("field_names", [])
        has_header = parser_config.get("has_header", True)
        value_field = parser_config.get("value_field", "value")
        type_field = parser_config.get("type_field", "type")
        
        # Parse CSV
        try:
            dialect = csv.Sniffer().sniff(content_str[:1024]) if content_str else csv.excel
        except:
            dialect = csv.excel
            
        csv_data = []
        
        if has_header and not field_names:
            # Parse with header
            reader = csv.DictReader(io.StringIO(content_str), dialect=dialect)
            csv_data = list(reader)
        elif field_names:
            # Parse with provided field names
            reader = csv.DictReader(io.StringIO(content_str), fieldnames=field_names, dialect=dialect)
            csv_data = list(reader)
        else:
            # Fallback parsing
            lines = content_str.splitlines()
            # Detect delimiter
            delimiters = [',', '\t', ';', '|']
            delimiter = max(delimiters, key=lambda d: lines[0].count(d) if lines else 0)
            
            for line in lines:
                if not line.strip():
                    continue
                    
                values = line.split(delimiter)
                row = {f"column{i+1}": val.strip() for i, val in enumerate(values)}
                csv_data.append(row)
        
        # Filter out empty records
        csv_data = [row for row in csv_data if any(value.strip() if isinstance(value, str) else value for value in row.values())]
        
        # Determine IOC types
        for row in csv_data:
            # Copy the value field if needed
            if value_field in row and value_field != "value":
                row["value"] = row[value_field]
            
            # Determine IOC type
            if type_field in row and type_field != "type":
                value = str(row.get("value", ""))
                type_hint = str(row.get(type_field, "")).lower()
                
                if "url" in type_hint or value.startswith(("http://", "https://")):
                    row["type"] = "url"
                elif "ip" in type_hint:
                    row["type"] = "ip"
                elif "domain" in type_hint:
                    row["type"] = "domain"
                elif "hash" in type_hint or len(value) == 32:
                    row["type"] = "md5"
                elif len(value) == 40:
                    row["type"] = "sha1"
                elif len(value) == 64:
                    row["type"] = "sha256"
                else:
                    row["type"] = DataProcessor.determine_ioc_type(value)
            else:
                # Default type detection
                row["type"] = DataProcessor.determine_ioc_type(str(row.get("value", "")))
        
        return csv_data
    except Exception as e:
        logger.error(f"Error parsing CSV feed: {str(e)}")
        return []

def parse_text_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse plain text feed data (usually line-by-line)."""
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
        
        lines = [line.strip() for line in content_str.splitlines() if line.strip()]
        
        # Skip lines if specified
        skip_lines = parser_config.get("skip_lines", 0)
        if skip_lines > 0 and len(lines) > skip_lines:
            lines = lines[skip_lines:]
        
        # Skip comments
        if parser_config.get("skip_comments", True):
            lines = [line for line in lines if not line.startswith('#')]
            
        # Create records
        data = []
        field_name = parser_config.get("value_field_name", "value")
        
        for line in lines:
            record = {field_name: line}
            
            # Extract data with regex if provided
            line_regex = parser_config.get("line_regex")
            if line_regex:
                try:
                    match = re.search(line_regex, line)
                    if match:
                        record.update(match.groupdict())
                except re.error:
                    pass
            
            # Determine IOC type
            if 'type' not in record:
                record['type'] = DataProcessor.determine_ioc_type(line)
            
            data.append(record)
            
        return data
    except Exception as e:
        logger.error(f"Error parsing text feed: {str(e)}")
        return []

def apply_transformations(records: List[Dict], parser_config: Dict) -> List[Dict]:
    """Apply transformations to normalize and enrich records."""
    if not records:
        return []
    
    # Get configuration
    transformations = parser_config.get("transformations", {})
    array_fields = parser_config.get("array_fields", [])
    date_fields = parser_config.get("date_fields", [])
    int_fields = parser_config.get("int_fields", [])
    float_fields = parser_config.get("float_fields", [])
    bool_fields = parser_config.get("bool_fields", [])
    
    transformed_records = []
    for record in records:
        transformed = record.copy()
        
        # Apply custom transformations
        for field, transform_func in transformations.items():
            if field in transformed and callable(transform_func):
                try:
                    transformed[field] = transform_func(transformed[field])
                except Exception:
                    pass
        
        # Convert array fields
        for field in array_fields:
            if field in transformed and not isinstance(transformed[field], list):
                if isinstance(transformed[field], str):
                    transformed[field] = transformed[field].split(",") if transformed[field] else []
                else:
                    transformed[field] = [transformed[field]] if transformed[field] else []
        
        # Convert numeric fields
        for field in int_fields:
            if field in transformed and transformed[field] not in (None, ""):
                try:
                    transformed[field] = int(float(transformed[field]))
                except (ValueError, TypeError):
                    pass
                    
        for field in float_fields:
            if field in transformed and transformed[field] not in (None, ""):
                try:
                    transformed[field] = float(transformed[field])
                except (ValueError, TypeError):
                    pass
        
        # Convert boolean fields
        for field in bool_fields:
            if field in transformed and isinstance(transformed[field], str):
                transformed[field] = transformed[field].lower() in ("yes", "true", "1", "t", "y")
        
        # Add ingestion timestamp
        transformed["ingestion_timestamp"] = datetime.datetime.utcnow().isoformat()
        
        transformed_records.append(transformed)
    
    return transformed_records

def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format for storage."""
    normalized = []
    
    for record in records:
        # Skip records without value
        if 'value' not in record:
            continue
        
        # Ensure value is a string
        value = str(record['value'])
        
        # Skip empty or comment values
        if not value or value.startswith('#'):
            continue
            
        # Create normalized record
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
        
        # Copy additional fields
        for field in ['first_seen', 'last_seen', 'malware_type', 'threat_type']:
            if field in record:
                indicator[field] = record[field]
        
        normalized.append(indicator)
    
    return normalized

def get_parser_config(feed_name: str) -> Dict:
    """Get parser configuration for a specific feed."""
    # Try to get from Config
    feed_config = None
    if hasattr(Config, 'get_feed_by_id'):
        feed_config = Config.get_feed_by_id(feed_name)
    
    if feed_config and "parser_config" in feed_config:
        return feed_config["parser_config"]
    
    # Find feed in Config.FEEDS
    if hasattr(Config, 'FEEDS'):
        for feed in Config.FEEDS:
            if feed.get('id') == feed_name or feed.get('name') == feed_name:
                if "parser_config" in feed:
                    return feed["parser_config"]
    
    # Default config
    return {
        "transformations": {},
        "array_fields": [],
        "date_fields": ["timestamp", "created_at", "updated_at", "first_seen", "last_seen"],
        "int_fields": ["count", "port"],
        "float_fields": ["score", "confidence"],
        "bool_fields": ["active", "malicious", "enabled"]
    }

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
        parser_config = get_parser_config(feed_name)
        parsed_data = parse_feed(content, format_type, parser_config)
        if not parsed_data:
            logger.warning(f"No valid records found in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No valid records found"
            return result
        
        # Step 4: Apply transformations
        transformed_data = apply_transformations(parsed_data, parser_config)
        
        # Step 5: Normalize data to common format
        normalized_data = normalize_indicators(transformed_data, feed_name)
        
        # Step 6: Deduplicate records
        existing_hashes = get_cached_hashes(feed_name)
        deduplicated_data, new_hashes = DataProcessor.deduplicate_records(normalized_data, existing_hashes)
        
        # Store new hashes
        store_cached_hashes(feed_name, existing_hashes + new_hashes)
        
        # If no new records, return success
        if not deduplicated_data:
            logger.info(f"No new records in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No new records after deduplication"
            return result
        
        # Step 7: Store processed data
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
        
        # Step 8: Upload to BigQuery
        # First ensure dataset and tables exist
        if not initialize_bigquery_tables():
            logger.warning("BigQuery tables initialization reported issues")
        
        # Upload to indicators table
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        indicators_table_id = f"{dataset_id}.indicators"
        job_id = upload_to_bigquery(indicators_table_id, deduplicated_data)
        
        if not job_id:
            # Try force update and retry
            logger.warning("Failed to upload data, attempting to force update tables")
            force_update_bigquery_tables()
            job_id = upload_to_bigquery(indicators_table_id, deduplicated_data)
            
            if not job_id:
                result["error"] = "Failed to upload data to BigQuery"
                return result
        
        result["bigquery_job_id"] = job_id
        
        # Step 9: Publish to Pub/Sub
        if publisher:
            topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
            
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
                future = publisher.publish(topic_path, message_json.encode("utf-8"), feed_id=feed_id)
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

def trigger_ingestion_in_background() -> threading.Thread:
    """Trigger ingestion in a background thread."""
    def ingestion_thread():
        try:
            logger.info("Starting background ingestion thread")
            # First ensure BigQuery tables are properly initialized
            if not initialize_bigquery_tables():
                logger.warning("BigQuery tables initialization reported issues")
                # Try force updating tables
                if force_update_bigquery_tables():
                    logger.info("Successfully forced BigQuery tables update")
                else:
                    logger.error("Failed to update BigQuery tables, ingestion may have issues")
            
            # Proceed with ingestion
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
        
        # Check if we need to force BigQuery table updates
        if force_tables:
            logger.info("Forcing BigQuery tables update as requested")
            force_update_bigquery_tables()
            
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

# -------------------- Default Feeds --------------------

# Define default feeds
DEFAULT_FEED_CONFIGS = [
    {
        "id": "phishtank",
        "name": "PhishTank URLs",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "description": "URLs verified as phishing by PhishTank community",
        "format": "json",
        "type": "url",
        "enabled": True,
        "parser_config": {
            "root_element": "data",
            "value_field": "url",
            "transformations": {
                "type": lambda record: "url"
            }
        }
    },
    {
        "id": "urlhaus",
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recent malware URLs from URLhaus",
        "format": "csv",
        "type": "url",
        "enabled": True,
        "parser_config": {
            "skip_lines": 8,
            "has_header": True,
            "value_field": "url",
            "type_field": "threat"
        }
    },
    {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent indicators from ThreatFox",
        "format": "json",
        "type": "mixed",
        "enabled": True,
        "parser_config": {
            "field_mappings": {
                "ioc_value": "value",
                "ioc_type": "type",
                "threat_type": "description",
                "malware": "malware_type",
                "first_seen_utc": "first_seen",
                "tags": "tags",
                "confidence_level": "confidence"
            },
            "array_fields": ["tags"]
        }
    }
]

# Add default feeds to config if no feeds are configured
if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
    logger.info("No feeds configured, adding default feeds")
    Config.FEEDS = DEFAULT_FEED_CONFIGS

# Automatically trigger ingestion on module load for production environment
if __name__ != "__main__" and Config.ENVIRONMENT == 'production' and getattr(Config, 'AUTO_INGEST', False):
    # Wait a bit for app startup
    logger.info("Auto-ingestion enabled - will start ingestion after app startup")
    
    def delayed_start():
        time.sleep(10)  # Wait for app startup
        # First ensure BigQuery tables
        initialize_bigquery_tables()
        # Then start ingestion
        trigger_ingestion_in_background()
        
    startup_thread = threading.Thread(target=delayed_start)
    startup_thread.daemon = True
    startup_thread.start()

# CLI command runner
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Ingestion Tool')
    parser.add_argument('--feed', type=str, help='Process a specific feed by ID or name')
    parser.add_argument('--all', action='store_true', help='Process all configured feeds')
    parser.add_argument('--force-tables', action='store_true', help='Force recreation of BigQuery tables')
    parser.add_argument('--verify', action='store_true', help='Verify ingestion setup')
    args = parser.parse_args()
    
    if args.force_tables:
        logger.info("Forcing recreation of BigQuery tables...")
        if force_update_bigquery_tables():
            logger.info("Successfully recreated BigQuery tables")
        else:
            logger.error("Failed to recreate BigQuery tables")
    
    if args.verify:
        logger.info("Verifying ingestion setup...")
        if not bq_client or not storage_client:
            logger.error("GCP clients not properly initialized")
        else:
            logger.info("GCP clients initialized successfully")
            
        if ensure_bucket_exists(Config.GCS_BUCKET):
            logger.info(f"GCS bucket {Config.GCS_BUCKET} exists")
        else:
            logger.error(f"Failed to ensure GCS bucket {Config.GCS_BUCKET} exists")
            
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
        logger.info("No action specified, use --feed, --all, --force-tables, or --verify")
