"""
Ingestion module for threat intelligence feeds.
Handles downloading, processing, and storing threat intelligence data.
Also ensures BigQuery resources are properly initialized.
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
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
from google.cloud.exceptions import Conflict

# Import configuration
import config
from config import Config

# Configure logging
log_level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO'))
logging.basicConfig(
    level=log_level,
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
    """Initialize and return Google Cloud clients."""
    # Initialize BigQuery
    try:
        bq_client = config.initialize_bigquery()
        if bq_client:
            logger.info("BigQuery client initialized successfully")
        else:
            logger.error("Failed to initialize BigQuery client")
    except Exception as e:
        logger.error(f"Error initializing BigQuery client: {str(e)}")
        bq_client = None

    # Initialize Storage
    try:
        storage_client = config.initialize_storage()
        if storage_client:
            logger.info("Storage client initialized successfully")
        else:
            logger.error("Failed to initialize Storage client")
    except Exception as e:
        logger.error(f"Error initializing Storage client: {str(e)}")
        storage_client = None

    # Initialize Pub/Sub
    try:
        publisher, subscriber = config.initialize_pubsub()
        if publisher and subscriber:
            logger.info("Pub/Sub clients initialized successfully")
        else:
            logger.error("Failed to initialize Pub/Sub clients")
    except Exception as e:
        logger.error(f"Error initializing Pub/Sub clients: {str(e)}")
        publisher, subscriber = None, None

    return bq_client, storage_client, publisher, subscriber

# Initialize Google Cloud clients globally
bq_client, storage_client, publisher, subscriber = initialize_clients()

# -------------------- Data Sanitization --------------------

class DataSanitizer:
    """Handles data cleaning and sanitization before storage."""
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string values to prevent XSS and injection attacks."""
        if not value or not isinstance(value, str):
            return value
            
        # Remove control characters
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        
        # Limit string length to prevent abuse
        max_length = 32768  # 32KB
        if len(value) > max_length:
            return value[:max_length]
            
        return value
        
    @staticmethod
    def sanitize_ioc(ioc_type: str, value: str) -> Optional[str]:
        """Sanitize IOC values based on their type."""
        if not value:
            return value
            
        value = DataSanitizer.sanitize_string(value)
        
        if ioc_type == 'ip':
            # Ensure valid IP format
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, value):
                return None
                
        elif ioc_type == 'domain':
            # Ensure valid domain format
            domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
            if not re.match(domain_pattern, value.lower()):
                return None
                
        elif ioc_type == 'url':
            # Ensure valid URL format - more lenient to catch more URLs
            url_pattern = r'^(https?|ftp)://.+$'
            if not re.match(url_pattern, value.lower()):
                # Try to fix common URL format issues
                if re.match(r'^www\.', value.lower()):
                    return "http://" + value
                return None
                
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            # Ensure valid hash format
            hash_patterns = {
                'md5': r'^[a-f0-9]{32}$',
                'sha1': r'^[a-f0-9]{40}$',
                'sha256': r'^[a-f0-9]{64}$'
            }
            if not re.match(hash_patterns.get(ioc_type, r'.*'), value.lower()):
                return None
                
        return value
        
    @staticmethod
    def sanitize_record(record: Dict, record_type: str = None) -> Dict:
        """Sanitize an entire record."""
        if not record:
            return {}
            
        sanitized = {}
        
        for key, value in record.items():
            # Handle nested dictionaries
            if isinstance(value, dict):
                sanitized[key] = DataSanitizer.sanitize_record(value)
                
            # Handle lists
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    # List of dictionaries
                    sanitized[key] = [DataSanitizer.sanitize_record(item) for item in value]
                else:
                    # List of primitives
                    sanitized[key] = value
                    
            # Handle strings
            elif isinstance(value, str):
                # Special handling for IOC values
                if record_type == 'ioc' and key == 'value' and 'type' in record:
                    sanitized[key] = DataSanitizer.sanitize_ioc(record['type'], value)
                else:
                    sanitized[key] = DataSanitizer.sanitize_string(value)
                    
            # Pass through other types
            else:
                sanitized[key] = value
                
        return sanitized

# -------------------- Deduplication and Retry Handling --------------------

class DeduplicationHandler:
    """Handles deduplication of incoming data."""
    
    @staticmethod
    def generate_hash(data: Any) -> str:
        """Generate a hash from data for deduplication."""
        hasher = hashlib.sha256()
        
        if isinstance(data, dict):
            # Sort keys for consistent hashing
            data_str = json.dumps(data, sort_keys=True)
        elif isinstance(data, str):
            data_str = data
        else:
            data_str = str(data)
            
        hasher.update(data_str.encode('utf-8'))
        return hasher.hexdigest()
        
    @staticmethod
    def is_duplicate(record: Dict, existing_hashes: List[str]) -> bool:
        """Check if a record is a duplicate based on its hash."""
        record_hash = DeduplicationHandler.generate_hash(record)
        return record_hash in existing_hashes


class RetryHandler:
    """Handles retries for failed operations."""
    
    @staticmethod
    def with_retries(func):
        """Decorator to add retry logic to a function."""
        def wrapper(*args, max_retries=3, backoff_factor=1.5, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    wait_time = backoff_factor ** attempt
                    logger.warning(f"Attempt {attempt+1}/{max_retries} failed: {str(e)}")
                    logger.warning(f"Retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
            
            # All retries failed
            logger.error(f"All {max_retries} retry attempts failed")
            raise last_exception
            
        return wrapper

# -------------------- Storage and BigQuery Operations --------------------

def ensure_bucket_exists(bucket_name: str) -> bool:
    """Ensure the GCS bucket exists and create it if it doesn't."""
    if not storage_client:
        logger.error("Storage client not initialized")
        return False
    
    try:
        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            logger.info(f"Creating bucket {bucket_name}...")
            storage_client.create_bucket(
                bucket, 
                location=Config.GCP_REGION,
                predefined_acl='projectPrivate'
            )
            logger.info(f"Created new bucket: {bucket_name}")
            
            # Create necessary folder structure
            folders = ['feeds', 'raw', 'processed', 'cache', 'exports']
            for folder in folders:
                blob = bucket.blob(f"{folder}/")
                blob.upload_from_string('')
                
            return True
        else:
            logger.debug(f"Bucket {bucket_name} already exists")
            return True
            
    except Exception as e:
        logger.error(f"Error ensuring bucket exists: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return False


def ensure_dataset_exists(dataset_id: str) -> bool:
    """Ensure the BigQuery dataset exists and create it if it doesn't."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        try:
            bq_client.get_dataset(dataset_id)
            logger.debug(f"Dataset {dataset_id} already exists")
            return True
        except NotFound:
            # Create dataset
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = Config.BIGQUERY_LOCATION
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {dataset_id}")
            return True
    except Exception as e:
        logger.error(f"Error ensuring dataset exists: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return False


def ensure_table_exists(table_id: str, schema: List[bigquery.SchemaField], force_update: bool = False) -> bool:
    """Ensure the BigQuery table exists and create it if it doesn't with better error handling."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        try:
            table = bq_client.get_table(table_id)
            logger.debug(f"Table {table_id} already exists")
            
            # Check if schema needs update or force updating
            if force_update:
                logger.info(f"Forcing schema update for table {table_id}")
                table.schema = schema
                try:
                    bq_client.update_table(table, ["schema"])
                    logger.info(f"Updated schema for table {table_id}")
                except Exception as update_error:
                    logger.warning(f"Could not update schema for existing table: {str(update_error)}")
            else:
                # Check for missing fields
                existing_schema = {field.name: field for field in table.schema}
                new_schema_fields = [field for field in schema if field.name not in existing_schema]
                
                if new_schema_fields:
                    logger.info(f"Updating table {table_id} schema with {len(new_schema_fields)} new fields")
                    updated_schema = list(table.schema) + new_schema_fields
                    table.schema = updated_schema
                    bq_client.update_table(table, ["schema"])
                    logger.info(f"Updated schema for table {table_id}")
            
            # Test query to verify table is accessible
            test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
            bq_client.query(test_query).result()
            
            return True
            
        except NotFound:
            # Create table
            logger.info(f"Table {table_id} not found, creating new table")
            table = bigquery.Table(table_id, schema=schema)
            created_table = bq_client.create_table(table)
            logger.info(f"Created table {table_id}")
            
            # Verify table creation with test query
            test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
            bq_client.query(test_query).result()
            logger.info(f"Verified table {table_id} is accessible")
            
            return True
    except Conflict:
        # Table might have been created by another process
        logger.warning(f"Conflict creating table {table_id}, it may already exist")
        return True
    except Exception as e:
        logger.error(f"Error ensuring table exists: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return False


def initialize_bigquery_tables():
    """Initialize all required BigQuery tables and datasets with improved error handling."""
    if not bq_client:
        logger.error("Cannot initialize BigQuery tables - client not available")
        return False
    
    try:
        # First ensure the dataset exists
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        logger.info(f"Ensuring dataset exists: {dataset_id}")
        
        if not ensure_dataset_exists(dataset_id):
            logger.error(f"Failed to create dataset {dataset_id}")
            return False
        
        # Define indicators table schema
        indicators_schema = [
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
        ]
        
        # Create all required tables
        table_configs = {
            'indicators': indicators_schema,
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
        
        all_created = True
        for table_name, schema in table_configs.items():
            table_id = f"{dataset_id}.{table_name}"
            logger.info(f"Ensuring table exists: {table_id}")
            if not ensure_table_exists(table_id, schema):
                logger.error(f"Failed to create table {table_name}")
                all_created = False
            else:
                # Verify table was actually created by checking if we can query it
                try:
                    test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                    bq_client.query(test_query).result()
                    logger.info(f"Successfully verified table {table_name} exists and is queryable")
                except Exception as e:
                    logger.error(f"Table {table_name} created but not queryable: {str(e)}")
                    if Config.ENVIRONMENT != 'production':
                        logger.error(traceback.format_exc())
                    all_created = False
        
        return all_created
    
    except Exception as e:
        logger.error(f"Error initializing BigQuery tables: {str(e)}")
        logger.error(traceback.format_exc())
        config.report_error(e)
        return False


def force_update_bigquery_tables() -> bool:
    """Force update of all BigQuery tables (call this when table issues are suspected)."""
    if not bq_client:
        logger.error("Cannot update BigQuery tables - client not available")
        return False
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        logger.info(f"Force updating tables in dataset {dataset_id}")
        
        # First drop any tables that exist with problems
        tables_to_force = ['indicators', 'vulnerabilities', 'threat_actors', 'campaigns', 'malware', 'users', 'audit_log']
        
        for table_name in tables_to_force:
            table_id = f"{dataset_id}.{table_name}"
            try:
                logger.info(f"Checking table {table_id} for force update")
                bq_client.get_table(table_id)
                
                # Try to query the table
                try:
                    test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                    bq_client.query(test_query).result()
                    logger.info(f"Table {table_id} passed validation, no need to recreate")
                except Exception as e:
                    # Table exists but has issues, delete and recreate
                    logger.warning(f"Table {table_id} has issues, deleting for recreation: {str(e)}")
                    bq_client.delete_table(table_id)
                    logger.info(f"Deleted table {table_id} for recreation")
            except NotFound:
                # Table doesn't exist, will be created below
                logger.info(f"Table {table_id} not found, will be created")
        
        # Now reinitialize all tables
        result = initialize_bigquery_tables()
        
        if result:
            logger.info("Successfully forced update of all BigQuery tables")
        else:
            logger.error("Failed to force update all BigQuery tables")
        
        return result
    
    except Exception as e:
        logger.error(f"Error in force_update_bigquery_tables: {str(e)}")
        logger.error(traceback.format_exc())
        config.report_error(e)
        return False


def upload_blob_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket and return its URI.
    
    Fixed version to ensure content types match between metadata and the upload.
    """
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        # Determine the proper content type based on data and extension
        if content_type is None:
            # Default content type based on file extension
            if blob_name.endswith('.json'):
                content_type = 'application/json'
            elif blob_name.endswith('.csv'):
                content_type = 'text/csv'
            elif blob_name.endswith('.txt'):
                content_type = 'text/plain'
            else:
                # Default to binary data
                content_type = 'application/octet-stream'
        
        # Ensure the data matches the content type
        if isinstance(data, str):
            # For JSON content type, ensure data is valid JSON
            if content_type == 'application/json' and not blob_name.endswith('.json'):
                try:
                    # Verify it's valid JSON by parsing it
                    json.loads(data)
                except json.JSONDecodeError:
                    # If not valid JSON, use a different content type
                    content_type = 'text/plain'
            
            # Convert string to properly encoded bytes
            data_to_upload = data.encode('utf-8')
        else:
            data_to_upload = data
            
        # Set content type on the blob
        blob.content_type = content_type
            
        # Upload data - FIXED: Now explicitly passes content_type to avoid mismatch
        blob.upload_from_string(
            data_to_upload,
            content_type=content_type  # Use same content type for both metadata and upload
        )
        
        gcs_uri = f"gs://{bucket_name}/{blob_name}"
        logger.info(f"Uploaded data to {gcs_uri} with content type {content_type}")
        return gcs_uri
    
    except Exception as e:
        logger.error(f"Error uploading data to GCS: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return None


def download_blob_from_gcs(bucket_name: str, blob_name: str) -> Optional[bytes]:
    """Download data from GCS bucket."""
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if not blob.exists():
            logger.warning(f"Blob {blob_name} does not exist in bucket {bucket_name}")
            return None
            
        # Download data
        return blob.download_as_bytes()
    
    except Exception as e:
        logger.error(f"Error downloading data from GCS: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        return None


def upload_records_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery table with enhanced error handling and retries."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return None
    
    if not records:
        logger.warning(f"No records to upload to {table_id}")
        return None
    
    # Process records in smaller batches for better reliability
    batch_size = 50  # Smaller batch size for better reliability
    success_count = 0
    error_count = 0
    job_ids = []
    
    # Log more details about the records
    logger.info(f"Preparing to upload {len(records)} records to {table_id}")
    
    try:
        # Log sample record for debugging
        if records:
            sample_record = records[0]
            logger.info(f"Sample record: {json.dumps(sample_record, default=str)[:500]}...")
    except Exception as e:
        logger.warning(f"Could not log sample record: {str(e)}")
    
    # Split records into batches
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        batch_num = i//batch_size + 1
        logger.info(f"Processing batch {batch_num}/{(len(records) + batch_size - 1) // batch_size} ({len(batch)} records)")
        
        try:
            # Prepare processed batch with proper handling of field types
            processed_batch = []
            record_errors = []
            
            for record in batch:
                try:
                    processed_record = {}
                    
                    # Process each field with special handling for timestamps and schema compatibility
                    for key, value in record.items():
                        # Handle datetime objects
                        if isinstance(value, (datetime.datetime, datetime.date)):
                            processed_record[key] = value.isoformat()
                        
                        # Handle string timestamps
                        elif key in ['created_at', 'first_seen', 'last_seen', 'timestamp'] and isinstance(value, str):
                            try:
                                # Try to parse and normalize the timestamp format
                                dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                                processed_record[key] = dt.isoformat()
                            except ValueError:
                                # If can't parse, use current time
                                processed_record[key] = datetime.datetime.utcnow().isoformat()
                                logger.warning(f"Invalid datetime format for {key}: {value}, using current time")
                        
                        # Handle nested dicts by converting to JSON strings
                        elif isinstance(value, dict):
                            processed_record[key] = json.dumps(value)
                            
                        # Handle tags/array fields
                        elif key == 'tags' and isinstance(value, list):
                            # Ensure all items are strings
                            processed_record[key] = [str(item) for item in value]
                        
                        # Handle empty arrays
                        elif isinstance(value, list) and not value:
                            if key == 'tags':
                                processed_record[key] = []
                            else:
                                processed_record[key] = value
                        
                        # Handle JSON objects stored as strings
                        elif isinstance(value, (dict, list)) and key not in ['tags']:
                            processed_record[key] = json.dumps(value)
                        
                        # All other values pass through
                        else:
                            processed_record[key] = value
                    
                    # Ensure required fields
                    if 'id' not in processed_record:
                        processed_record['id'] = hashlib.md5(str(record).encode()).hexdigest()
                    
                    # Ensure value field exists and is a string
                    if 'value' not in processed_record:
                        if 'ioc' in processed_record:
                            processed_record['value'] = str(processed_record['ioc'])
                        elif 'indicator' in processed_record:
                            processed_record['value'] = str(processed_record['indicator'])
                        else:
                            processed_record['value'] = 'unknown_' + str(uuid.uuid4())
                            logger.warning(f"Added default value field to record: {processed_record['value']}")
                    elif not isinstance(processed_record['value'], str):
                        processed_record['value'] = str(processed_record['value'])
                    
                    # Add record to batch
                    processed_batch.append(processed_record)
                except Exception as record_err:
                    record_errors.append(str(record_err))
                    logger.error(f"Error processing record: {str(record_err)}")
            
            if record_errors:
                logger.warning(f"Encountered {len(record_errors)} errors while processing records. First error: {record_errors[0]}")
            
            if not processed_batch:
                logger.error("No valid records to upload after processing")
                error_count += 1
                continue
            
            # Upload to BigQuery with multiple retry attempts
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    # Configure the job
                    job_config = bigquery.LoadJobConfig(
                        schema_update_options=[
                            bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
                        ],
                        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                    )
                    
                    # Upload the records directly
                    job = bq_client.load_table_from_json(
                        processed_batch,
                        table_id,
                        job_config=job_config
                    )
                    
                    # Wait for job to complete with timeout
                    result = job.result(timeout=120)  # 2 minute timeout
                    
                    if job.errors:
                        logger.error(f"Errors in batch {batch_num}: {job.errors}")
                        if attempt < max_retries - 1:
                            wait_time = 2 ** attempt  # Exponential backoff
                            logger.info(f"Retrying batch in {wait_time} seconds...")
                            time.sleep(wait_time)
                            continue
                        else:
                            error_count += 1
                    else:
                        job_ids.append(job.job_id)
                        success_count += 1
                        logger.info(f"Successfully uploaded batch {batch_num} ({len(processed_batch)} records) to {table_id}")
                    
                    # Break retry loop on success
                    break
                        
                except Exception as e:
                    logger.error(f"Error uploading batch {batch_num} to BigQuery: {str(e)}")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.info(f"Retrying batch in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"Failed to upload batch {batch_num} after {max_retries} attempts")
                        error_count += 1
            
        except Exception as e:
            logger.error(f"Unexpected error processing batch {batch_num}: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            error_count += 1
    
    # Report results
    total_batches = (len(records) + batch_size - 1) // batch_size
    logger.info(f"BigQuery upload complete: {success_count}/{total_batches} batches successful")
    
    if success_count > 0:
        return job_ids[0]  # Return first job ID on success
    else:
        return None


def infer_schema_from_record(record: Dict) -> List[bigquery.SchemaField]:
    """Infer BigQuery schema from a sample record."""
    schema = []
    
    for key, value in record.items():
        # Skip internal fields that shouldn't be stored
        if key.startswith('_'):
            continue
            
        field_type = "STRING"  # Default type
        field_mode = "NULLABLE"
        fields = None
        
        # Determine field type and mode
        if value is None:
            field_type = "STRING"
            
        elif isinstance(value, bool):
            field_type = "BOOLEAN"
            
        elif isinstance(value, int):
            field_type = "INTEGER"
            
        elif isinstance(value, float):
            field_type = "FLOAT"
            
        elif isinstance(value, dict):
            # For nested fields, recursively infer the schema
            field_type = "RECORD"
            fields = infer_schema_from_record(value)
            
        elif isinstance(value, list):
            field_mode = "REPEATED"
            
            if value and all(isinstance(item, dict) for item in value):
                # List of records
                field_type = "RECORD"
                fields = infer_schema_from_record(value[0])
                
            elif value and all(isinstance(item, bool) for item in value):
                field_type = "BOOLEAN"
                
            elif value and all(isinstance(item, int) for item in value):
                field_type = "INTEGER"
                
            elif value and all(isinstance(item, float) for item in value):
                field_type = "FLOAT"
                
            else:
                # Default to string for mixed types or empty lists
                field_type = "STRING"
                
        elif isinstance(value, str):
            # Try to detect timestamp format
            if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$', value):
                field_type = "TIMESTAMP"
            else:
                field_type = "STRING"
                
        # Create and add the schema field
        schema.append(bigquery.SchemaField(
            name=key,
            field_type=field_type,
            mode=field_mode,
            fields=fields
        ))
            
    return schema

# -------------------- Feed Processing Functions --------------------

def get_parser_config(feed_name: str) -> Dict:
    """Get feed parser configuration based on feed name."""
    # First try to get from config module
    feed_config = Config.get_feed_by_id(feed_name)
    
    if feed_config and "parser_config" in feed_config:
        return feed_config["parser_config"]
        
    # Default parser configuration
    return {
        "transformations": {},
        "array_fields": [],
        "date_fields": ["timestamp", "created_at", "updated_at", "first_seen", "last_seen"],
        "int_fields": ["count", "port"],
        "float_fields": ["score", "confidence"],
        "bool_fields": ["active", "malicious", "enabled"]
    }


@RetryHandler.with_retries
def download_feed_data(url: str, headers: Dict = None, timeout: int = 60) -> Tuple[str, bytes]:
    """Download content from a feed URL."""
    if not headers:
        headers = {}
        
    # Add User-Agent if not provided
    if 'User-Agent' not in headers:
        headers['User-Agent'] = f"ThreatIntelligencePlatform/{Config.VERSION}"
        
    try:
        logger.info(f"Downloading feed from {url}")
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '')
        
        return content_type, response.content
    
    except requests.RequestException as e:
        logger.error(f"Request exception downloading feed from {url}: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise
    except Exception as e:
        logger.error(f"Error downloading feed from {url}: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise


def parse_feed_data(content: bytes, format_type: str, parser_config: Dict) -> List[Dict]:
    """Parse raw feed data based on format type and parser configuration."""
    try:
        if format_type == "json":
            return parse_json_feed(content, parser_config)
        elif format_type == "csv":
            return parse_csv_feed(content, parser_config)
        elif format_type == "text":
            return parse_text_feed(content, parser_config)
        else:
            # Auto-detect format
            logger.warning(f"Unknown format type: {format_type}, attempting auto-detection")
            
            # Try to detect format from content
            try:
                # Check if content looks like JSON
                content_start = content[:100].strip()
                if content_start.startswith(b'{') or content_start.startswith(b'['):
                    logger.info("Content appears to be JSON, parsing as JSON")
                    return parse_json_feed(content, parser_config)
                
                # Check if content looks like CSV
                if b',' in content_start and b'\n' in content[:1000]:
                    logger.info("Content appears to be CSV, parsing as CSV")
                    return parse_csv_feed(content, parser_config)
                
                # Default to text
                logger.info("Content format not detected, parsing as text")
                return parse_text_feed(content, parser_config)
            except Exception as detect_error:
                logger.warning(f"Auto-detection failed: {str(detect_error)}")
                
                # Try each format in order
                try:
                    return parse_json_feed(content, parser_config)
                except Exception:
                    try:
                        return parse_csv_feed(content, parser_config)
                    except Exception:
                        return parse_text_feed(content, parser_config)
    
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise


def parse_json_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse JSON formatted content with improved error handling."""
    try:
        # Try different decoding approaches
        try:
            # First try direct JSON decoding
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try decoding with utf-8 first
            try:
                content_str = content.decode('utf-8', errors='replace')
                data = json.loads(content_str)
            except json.JSONDecodeError:
                # Try with different encodings
                for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        content_str = content.decode(encoding, errors='replace')
                        data = json.loads(content_str)
                        logger.info(f"Successfully decoded JSON with {encoding} encoding")
                        break
                    except json.JSONDecodeError:
                        continue
                else:
                    # If all decodings fail, try a more lenient approach
                    content_str = content.decode('utf-8', errors='ignore')
                    
                    # Look for JSON start/end markers
                    json_start = content_str.find('{')
                    json_array_start = content_str.find('[')
                    
                    if json_start >= 0 and (json_array_start < 0 or json_start < json_array_start):
                        # Try to find matching closing brace
                        data = json.loads(content_str[json_start:])
                    elif json_array_start >= 0:
                        # Try to find matching closing bracket
                        data = json.loads(content_str[json_array_start:])
                    else:
                        raise Exception("Could not find valid JSON content")
        
        # Handle case where the data is nested under a root element
        root_element = parser_config.get("root_element")
        if root_element and isinstance(data, dict) and root_element in data:
            data = data[root_element]
            
        # If data is not a list, convert it to one
        if not isinstance(data, list):
            # Check if it's a dict with lists as values
            if isinstance(data, dict):
                processed_data = []
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            # Add the key as an ID field
                            item_copy = item.copy() if isinstance(item, dict) else {"value": item}
                            item_copy["threat_id"] = key
                            processed_data.append(item_copy)
                    else:
                        # For non-list values, special handling
                        if key != 'meta' and key != 'info':  # Skip meta information
                            processed_data.append({"value": str(value), "type": "unknown", "key": key})
                
                if processed_data:
                    data = processed_data
                else:
                    # If no usable data found, wrap the original dict
                    data = [data]
            else:
                # Wrap in list if it's a primitive value
                data = [{"value": data}]
        
        # Clean up the records
        cleaned_data = []
        for item in data:
            if isinstance(item, dict):
                # Only include valid records with minimally required data
                if item:  # Non-empty dict
                    cleaned_data.append(item)
            elif item is not None:
                # Convert non-dict items to dicts
                cleaned_data.append({"value": str(item)})
        
        return cleaned_data
    except Exception as e:
        logger.error(f"Error parsing JSON feed: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise Exception(f"Failed to parse JSON data: {str(e)}")


def parse_csv_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse CSV formatted content with improved error handling."""
    try:
        # Try to decode with different encodings
        content_str = None
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
            try:
                content_str = content.decode(encoding, errors='replace')
                break
            except UnicodeDecodeError:
                continue
        
        if content_str is None:
            # If all specific encodings fail, use utf-8 with replace error handler
            content_str = content.decode('utf-8', errors='replace')
        
        # Skip header lines if specified
        skip_lines = parser_config.get("skip_lines", 0)
        if skip_lines > 0:
            lines = content_str.splitlines()
            if len(lines) > skip_lines:
                content_str = '\n'.join(lines[skip_lines:])
        
        # Parse with different CSV dialects if needed
        csv_data = None
        dialects = [csv.excel, csv.unix_dialect, csv.excel_tab]
        
        if parser_config.get("has_header", True):
            # Try with header
            for dialect in dialects:
                try:
                    csv_reader = csv.DictReader(io.StringIO(content_str), dialect=dialect)
                    csv_data = list(csv_reader)
                    if csv_data:
                        break
                except Exception:
                    continue
        
        # If no data with header, try without header
        if not csv_data:
            # For CSV without headers, use field names from config or generate them
            field_names = parser_config.get("field_names", [])
            if not field_names:
                # Generate field names as column1, column2, etc.
                try:
                    sniffer = csv.Sniffer()
                    dialect = sniffer.sniff(content_str[:1024])
                    first_row = next(csv.reader(io.StringIO(content_str), dialect))
                    field_names = [f"column{i+1}" for i in range(len(first_row))]
                except Exception:
                    # If sniffer fails, make a best guess
                    first_line = content_str.split('\n')[0]
                    if ',' in first_line:
                        field_names = [f"column{i+1}" for i in range(first_line.count(',') + 1)]
                    elif '\t' in first_line:
                        field_names = [f"column{i+1}" for i in range(first_line.count('\t') + 1)]
                    else:
                        field_names = ["value"]
            
            for dialect in dialects:
                try:
                    csv_reader = csv.DictReader(io.StringIO(content_str), fieldnames=field_names, dialect=dialect)
                    csv_data = list(csv_reader)
                    if csv_data:
                        break
                except Exception:
                    continue
        
        # If we still have no data, use a fallback approach
        if not csv_data:
            logger.warning("Standard CSV parsing failed, using fallback row splitting")
            data = []
            lines = content_str.splitlines()
            
            # Try to determine delimiter
            delimiters = [',', '\t', ';', '|']
            delimiter = ','  # Default
            
            # Count occurrences of each delimiter in first line
            if lines:
                first_line = lines[0]
                counts = {d: first_line.count(d) for d in delimiters}
                if counts:
                    delimiter = max(counts.keys(), key=lambda k: counts[k])
            
            # Parse with simple delimiter splitting
            if parser_config.get("has_header", True) and lines:
                header = [h.strip() for h in lines[0].split(delimiter)]
                
                for line in lines[1:]:
                    if not line.strip():
                        continue
                        
                    values = line.split(delimiter)
                    row = {}
                    
                    # Map values to header names
                    for i, val in enumerate(values):
                        if i < len(header):
                            row[header[i]] = val.strip()
                        else:
                            row[f"column{i+1}"] = val.strip()
                    
                    data.append(row)
                    
                csv_data = data
            else:
                # No header, use column names
                for line in lines:
                    if not line.strip():
                        continue
                        
                    values = line.split(delimiter)
                    row = {}
                    
                    for i, val in enumerate(values):
                        row[f"column{i+1}"] = val.strip()
                    
                    data.append(row)
                    
                csv_data = data
        
        # Filter out empty records
        if csv_data:
            csv_data = [row for row in csv_data if any(value.strip() if isinstance(value, str) else value for value in row.values())]
        
        # Add 'value' field if missing for compatibility
        for row in csv_data:
            # Try to identify a suitable value field based on common naming patterns
            if 'value' not in row:
                for key in ['ioc', 'indicator', 'ip', 'domain', 'url', 'hash', 'md5', 'sha1', 'sha256']:
                    if key in row and row[key]:
                        row['value'] = row[key]
                        break
                else:
                    # If no suitable field found, use the first non-empty field
                    for key, val in row.items():
                        if val and isinstance(val, str) and val.strip():
                            row['value'] = val
                            break
        
        return csv_data
    except Exception as e:
        logger.error(f"Error parsing CSV data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise Exception(f"Failed to parse CSV data: {str(e)}")


def parse_text_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse plain text content (usually line by line)."""
    try:
        # Try various encodings
        content_str = None
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
            try:
                content_str = content.decode(encoding, errors='replace')
                break
            except UnicodeDecodeError:
                continue
        
        if content_str is None:
            # If all specific encodings fail, use utf-8 with replace error handler
            content_str = content.decode('utf-8', errors='replace')
        
        lines = [line.strip() for line in content_str.splitlines() if line.strip()]
        
        # Skip lines if specified
        skip_lines = parser_config.get("skip_lines", 0)
        if skip_lines > 0 and len(lines) > skip_lines:
            lines = lines[skip_lines:]
            
        # Create record for each line
        data = []
        field_name = parser_config.get("value_field_name", "value")
        
        for line in lines:
            # Skip comments if configured
            if parser_config.get("skip_comments", False) and line.startswith('#'):
                continue
                
            record = {field_name: line}
            
            # Extract data using regex if provided
            line_regex = parser_config.get("line_regex")
            if line_regex:
                try:
                    match = re.search(line_regex, line)
                    if match:
                        record.update(match.groupdict())
                except re.error:
                    logger.warning(f"Invalid regex pattern: {line_regex}")
            
            # Try to determine IOC type based on content
            if 'type' not in record:
                record['type'] = determine_ioc_type(line)
            
            data.append(record)
            
        return data
    except Exception as e:
        logger.error(f"Error parsing text data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        raise Exception(f"Failed to parse text data: {str(e)}")


def apply_transformations(records: List[Dict], parser_config: Dict) -> List[Dict]:
    """Apply transformations to parsed records based on parser configuration."""
    if not records:
        return []
        
    transformations = parser_config.get("transformations", {})
    array_fields = parser_config.get("array_fields", [])
    date_fields = parser_config.get("date_fields", [])
    int_fields = parser_config.get("int_fields", [])
    float_fields = parser_config.get("float_fields", [])
    bool_fields = parser_config.get("bool_fields", [])
    
    # Process each record
    transformed_records = []
    for record in records:
        transformed_record = record.copy()
        
        # Apply explicit transformations
        for field, transform_func in transformations.items():
            if field in transformed_record and callable(transform_func):
                try:
                    transformed_record[field] = transform_func(transformed_record[field])
                except Exception as e:
                    logger.warning(f"Error applying transformation to field '{field}': {str(e)}")
                
        # Convert array fields
        for field in array_fields:
            if field in transformed_record and not isinstance(transformed_record[field], list):
                if isinstance(transformed_record[field], str):
                    transformed_record[field] = transformed_record[field].split(",") if transformed_record[field] else []
                else:
                    transformed_record[field] = [transformed_record[field]] if transformed_record[field] else []
                    
        # Convert date fields
        for field in date_fields:
            if field in transformed_record and transformed_record[field]:
                # Keep the original format but ensure it's a string
                transformed_record[field] = str(transformed_record[field])
                
        # Convert numeric fields
        for field in int_fields:
            if field in transformed_record and transformed_record[field] not in (None, ""):
                try:
                    transformed_record[field] = int(float(transformed_record[field]))
                except (ValueError, TypeError):
                    pass
                    
        for field in float_fields:
            if field in transformed_record and transformed_record[field] not in (None, ""):
                try:
                    transformed_record[field] = float(transformed_record[field])
                except (ValueError, TypeError):
                    pass
                    
        # Convert boolean fields
        for field in bool_fields:
            if field in transformed_record:
                if isinstance(transformed_record[field], str):
                    transformed_record[field] = transformed_record[field].lower() in ("yes", "true", "1", "t", "y")
                    
        # Add ingestion timestamp
        transformed_record["ingestion_timestamp"] = datetime.datetime.utcnow().isoformat()
        
        # Add record to transformed records
        transformed_records.append(transformed_record)
    
    return transformed_records


def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format for storage."""
    normalized = []
    
    for record in records:
        # Check if record has the minimum required fields
        if 'value' not in record:
            continue
        
        # Ensure value is a string
        value = str(record['value'])
        
        # Create normalized indicator record
        indicator = {
            "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
            "value": value,
            "type": record.get('type') or determine_ioc_type(value),
            "source": feed_name,
            "feed_id": feed_name,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "confidence": record.get('confidence', 50),
            "tags": record.get('tags', []),
            "description": record.get('description', f"Indicator from {feed_name}"),
            "raw_data": json.dumps(record)
        }
        
        # Copy additional fields if they exist
        for field in ['first_seen', 'last_seen', 'malware_type', 'threat_type']:
            if field in record:
                indicator[field] = record[field]
        
        normalized.append(indicator)
    
    return normalized


def determine_ioc_type(value: str) -> str:
    """Determine the IOC type based on value format with improved pattern matching."""
    if not value or not isinstance(value, str):
        return 'unknown'
        
    value = value.strip()
    
    # IP address pattern - more comprehensive
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$'
    if re.match(ip_pattern, value):
        return 'ip'
    
    # Domain pattern - more lenient
    domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if re.match(domain_pattern, value.lower()):
        return 'domain'
    
    # URL pattern - more inclusive
    url_pattern = r'^(https?|ftp)://.+$'
    if re.search(url_pattern, value.lower()):
        return 'url'
    
    # Hash patterns
    md5_pattern = r'^[a-f0-9]{32}$'
    sha1_pattern = r'^[a-f0-9]{40}$'
    sha256_pattern = r'^[a-f0-9]{64}$'
    
    if re.match(md5_pattern, value.lower()):
        return 'md5'
    if re.match(sha1_pattern, value.lower()):
        return 'sha1'
    if re.match(sha256_pattern, value.lower()):
        return 'sha256'
    
    # Email pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, value):
        return 'email'
    
    # Filename pattern
    filename_pattern = r'\.(exe|dll|bat|ps1|vbs|js|py|sh|pl|jar)$'
    if re.search(filename_pattern, value.lower()):
        return 'filename'
    
    # Default if no pattern matches
    return 'unknown'


def get_cached_hashes(feed_name: str) -> List[str]:
    """Get cached hashes from GCS for deduplication."""
    if not storage_client:
        return []
    
    cache_key = f"feed_hashes_{feed_name}"
    bucket_name = Config.GCS_BUCKET
    blob_name = f"cache/{cache_key}.json"
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if blob.exists():
            content = blob.download_as_text()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in cached hashes for {feed_name}")
                return []
        
        return []
    except Exception as e:
        logger.warning(f"Error getting cached hashes: {str(e)}")
        return []


def store_cached_hashes(feed_name: str, hashes: List[str]) -> bool:
    """Store cached hashes to GCS for deduplication."""
    if not storage_client:
        return False
    
    cache_key = f"feed_hashes_{feed_name}"
    bucket_name = Config.GCS_BUCKET
    blob_name = f"cache/{cache_key}.json"
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        # Only store up to 10000 hashes to avoid excessive storage use
        if len(hashes) > 10000:
            hashes = hashes[-10000:]
            
        # Fixed: Explicitly match content type with upload for consistency
        json_content = json.dumps(hashes)
        blob.upload_from_string(json_content, content_type="application/json")
        return True
    except Exception as e:
        logger.warning(f"Error storing cached hashes: {str(e)}")
        return False

# -------------------- Diagnostic Functions --------------------

def diagnose_bigquery_issues():
    """Diagnose common BigQuery issues that might prevent data ingestion."""
    if not bq_client:
        logger.error("BigQuery client not initialized - Check service account permissions")
        return False
    
    try:
        # Test basic query capability
        logger.info("Testing BigQuery connectivity...")
        test_query = "SELECT 1 as test"
        query_job = bq_client.query(test_query)
        results = list(query_job.result())
        if results and len(results) > 0:
            logger.info("✅ BigQuery connectivity test passed")
        else:
            logger.error("❌ BigQuery query returned no results")
            return False
        
        # Check if dataset exists
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        logger.info(f"Checking if dataset {dataset_id} exists...")
        try:
            bq_client.get_dataset(dataset_id)
            logger.info(f"✅ Dataset {dataset_id} exists")
        except Exception as e:
            logger.error(f"❌ Dataset {dataset_id} doesn't exist: {str(e)}")
            logger.info("Attempting to create dataset...")
            if not ensure_dataset_exists(dataset_id):
                logger.error("Failed to create dataset")
                return False
        
        # Check if indicators table exists and is accessible
        table_id = f"{dataset_id}.indicators"
        logger.info(f"Checking if table {table_id} exists and is accessible...")
        try:
            bq_client.get_table(table_id)
            # Verify the table with a query
            test_query = f"SELECT COUNT(*) FROM `{table_id}`"
            query_job = bq_client.query(test_query)
            results = list(query_job.result())
            logger.info(f"✅ Table {table_id} exists and is accessible - contains {results[0][0]} rows")
        except Exception as e:
            logger.error(f"❌ Issue with table {table_id}: {str(e)}")
            logger.info("Attempting to recreate table...")
            if not initialize_bigquery_tables():
                logger.error("Failed to initialize tables")
                return False
        
        return True
    except Exception as e:
        logger.error(f"Error while diagnosing BigQuery issues: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return False


def diagnose_feed_issues():
    """Diagnose issues with feed configuration and connectivity."""
    logger.info("Diagnosing feed configuration and connectivity...")
    
    # Check feed configuration
    if not Config.FEEDS or len(Config.FEEDS) == 0:
        logger.error("❌ No feeds configured")
        # Load default feeds
        Config.FEEDS = DEFAULT_FEED_CONFIGS
        logger.info("Loaded default feeds")
    
    # Test connectivity to each feed
    successful_feeds = 0
    failed_feeds = 0
    
    for feed in Config.FEEDS:
        if not feed.get("enabled", True):
            logger.info(f"Feed {feed.get('name')} is disabled, skipping")
            continue
            
        url = feed.get("url")
        if not url:
            logger.warning(f"Feed {feed.get('name')} has no URL, skipping")
            continue
            
        try:
            logger.info(f"Testing connectivity to {url}...")
            # Use requests directly with a short timeout for testing
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                successful_feeds += 1
                logger.info(f"✅ Successfully connected to {feed.get('name')} ({url})")
                
                # Output sample of response content for debugging
                content_preview = response.content[:200]
                logger.info(f"Content preview: {content_preview}")
            else:
                failed_feeds += 1
                logger.warning(f"❌ Feed {feed.get('name')} returned status code {response.status_code}")
        except Exception as e:
            failed_feeds += 1
            logger.error(f"❌ Failed to connect to feed {feed.get('name')} ({url}): {str(e)}")
    
    logger.info(f"Feed connectivity test results: {successful_feeds} successful, {failed_feeds} failed")
    return successful_feeds > 0


def fix_and_force_ingestion():
    """Fix common issues and force ingestion of feed data."""
    logger.info("Starting comprehensive ingestion repair process...")
    
    # Step 1: Diagnose and fix BigQuery issues
    logger.info("Step 1/4: Diagnosing BigQuery issues...")
    if not diagnose_bigquery_issues():
        logger.warning("BigQuery issues found, attempting to continue...")
        # Force table recreation as a last resort
        force_update_bigquery_tables()
    
    # Step 2: Diagnose and fix feed issues
    logger.info("Step 2/4: Diagnosing feed issues...")
    if not diagnose_feed_issues():
        logger.warning("Feed connectivity issues found, attempting to continue with available feeds...")
    
    # Step 3: Force ingestion with detailed logging
    logger.info("Step 3/4: Running forced ingestion with detailed logging...")
    
    # Temporarily increase log level
    current_log_level = logger.level
    logger.setLevel(logging.DEBUG)
    
    # Set processing flags to capture more details
    os.environ['DEBUG'] = 'true'
    
    try:
        # Run ingestion with forced parameters
        result = ingest_all_feeds()
        
        # Log results
        success_count = sum(1 for r in result if r.get('status') == 'success')
        logger.info(f"Ingestion results: {success_count}/{len(result)} feeds processed successfully")
        
        # Log detailed information about failures
        for feed_result in result:
            if feed_result.get('status') != 'success':
                feed_name = feed_result.get('feed_name', 'Unknown')
                error = feed_result.get('error', 'Unknown error')
                logger.error(f"Failed to process feed {feed_name}: {error}")
    except Exception as e:
        logger.error(f"Error during forced ingestion: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
    finally:
        # Restore log level
        logger.setLevel(current_log_level)
    
    # Step 4: Verify results
    logger.info("Step 4/4: Verifying ingestion results...")
    verify_ingestion_results()
    
    logger.info("Ingestion repair process completed")
    return True


def verify_ingestion_results():
    """Verify that data was successfully ingested into BigQuery."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        # Check indicators table
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.indicators"
        
        # Count records
        query = f"SELECT COUNT(*) as count FROM `{table_id}`"
        query_job = bq_client.query(query)
        results = list(query_job.result())
        
        if results and len(results) > 0:
            count = results[0]['count']
            logger.info(f"Found {count} records in the indicators table")
            
            if count > 0:
                # Sample some records
                sample_query = f"SELECT * FROM `{table_id}` LIMIT 3"
                sample_job = bq_client.query(sample_query)
                samples = list(sample_job.result())
                
                logger.info(f"Sample record fields: {[field.name for field in sample_job.schema]}")
                logger.info(f"Sample record count: {len(samples)}")
                
                # Log a few key fields from the first record
                if samples:
                    first_record = dict(samples[0])
                    logger.info(f"First record ID: {first_record.get('id')}")
                    logger.info(f"First record type: {first_record.get('type')}")
                    logger.info(f"First record value: {first_record.get('value')}")
                
                return True
            else:
                logger.warning("No records found in the indicators table after ingestion")
                return False
        else:
            logger.error("Failed to query record count")
            return False
    except Exception as e:
        logger.error(f"Error verifying ingestion results: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return False

# -------------------- Main Feed Processing Function --------------------

def process_feed(feed_config: Dict) -> Dict:
    """Process a single feed and store its data."""
    feed_name = feed_config["name"]
    feed_id = feed_config.get("id", feed_name)
    start_time = datetime.datetime.utcnow()
    
    logger.info(f"Starting ingestion process for feed '{feed_name}'")
    
    result = {
        "feed_name": feed_name,
        "feed_id": feed_id,
        "start_time": start_time.isoformat(),
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
        
        # Step 1: Ensure bucket exists
        bucket_name = Config.GCS_BUCKET
        if not ensure_bucket_exists(bucket_name):
            result["error"] = "Failed to ensure GCS bucket exists"
            return result
        
        # Step 2: Download feed data
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        timeout = feed_config.get("timeout", 60)
        
        try:
            content_type, content = download_feed_data(url, headers, timeout)
            result["content_type"] = content_type
        except Exception as e:
            result["error"] = f"Download failed: {str(e)}"
            return result
        
        # Step 3: Store raw feed data
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
        elif format_type == "text":
            file_extension = ".txt"
            content_type_to_use = "text/plain"
        else:
            # Determine from content type
            if 'json' in content_type.lower():
                file_extension = '.json'
                content_type_to_use = "application/json"
            elif 'csv' in content_type.lower():
                file_extension = '.csv'
                content_type_to_use = "text/csv"
            elif 'text/plain' in content_type.lower():
                file_extension = '.txt'
                content_type_to_use = "text/plain"
            else:
                file_extension = '.dat'
                content_type_to_use = "application/octet-stream"
        
        # Store raw data - ensure correct content type
        raw_blob_name = f"{storage_path}/raw/{timestamp}{file_extension}"
        raw_uri = upload_blob_to_gcs(bucket_name, raw_blob_name, content, content_type_to_use)
        if not raw_uri:
            result["error"] = "Failed to store raw feed data"
            return result
        
        result["raw_uri"] = raw_uri
        
        # Step 4: Parse feed data
        parser_config = get_parser_config(feed_name)
        try:
            parsed_data = parse_feed_data(content, format_type, parser_config)
            if not parsed_data:
                logger.warning(f"No valid records found in feed '{feed_name}'")
                result["status"] = "success"  # Still considered success, just empty
                result["warning"] = "No valid records found"
                return result
            
            # Log summary of parsed data
            logger.info(f"Successfully parsed {len(parsed_data)} records from {feed_name}")
            
        except Exception as e:
            result["error"] = f"Parsing failed: {str(e)}"
            return result
        
        # Step 5: Apply transformations
        transformed_data = apply_transformations(parsed_data, parser_config)
        
        # Step 6: Normalize data to common format
        normalized_data = normalize_indicators(transformed_data, feed_name)
        logger.info(f"Normalized {len(normalized_data)} indicators from {feed_name}")
        
        # Step 7: Deduplicate records
        existing_hashes = get_cached_hashes(feed_name)
        
        deduplicated_data = []
        new_hashes = []
        
        for record in normalized_data:
            record_hash = DeduplicationHandler.generate_hash(record)
            if record_hash not in existing_hashes and record_hash not in new_hashes:
                deduplicated_data.append(record)
                new_hashes.append(record_hash)
        
        # Store hashes for future deduplication - with fixed content type
        store_cached_hashes(feed_name, existing_hashes + new_hashes)
        
        # If no records after deduplication, return success with warning
        if not deduplicated_data:
            logger.info(f"No new records found in feed '{feed_name}' after deduplication")
            result["status"] = "success"
            result["warning"] = "No new records after deduplication"
            return result
        
        # Step 8: Store processed data - with fixed content type
        processed_blob_name = f"{storage_path}/processed/{timestamp}.json"
        processed_data_json = json.dumps(deduplicated_data, indent=2)
        processed_uri = upload_blob_to_gcs(
            bucket_name, 
            processed_blob_name,
            processed_data_json,
            "application/json"  # Explicitly set to JSON content type
        )
        
        if not processed_uri:
            result["error"] = "Failed to store processed feed data"
            return result
        
        result["processed_uri"] = processed_uri
        result["record_count"] = len(deduplicated_data)
        
        # Step 9: First ensure BigQuery tables exist
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        if not ensure_dataset_exists(dataset_id):
            result["error"] = "Failed to ensure BigQuery dataset exists"
            return result
        
        if not initialize_bigquery_tables():
            logger.warning("BigQuery tables initialization reported issues, attempting to continue")
        
        # Step 10: Upload to main indicators table
        indicators_table_id = f"{dataset_id}.indicators"
        job_id = upload_records_to_bigquery(indicators_table_id, deduplicated_data)
        
        if not job_id:
            # Try force-updating tables and retry upload
            logger.warning("Failed to upload data to main indicators table, attempting to force update tables")
            force_update_bigquery_tables()
            job_id = upload_records_to_bigquery(indicators_table_id, deduplicated_data)
            
            if not job_id:
                result["error"] = "Failed to upload data to BigQuery even after table force update"
                return result
        
        result["bigquery_job_id"] = job_id
        
        # Step 11: Also create a feed-specific table for reference (optional)
        feed_table_name = re.sub(r'[^a-zA-Z0-9_]', '_', feed_name.lower())
        feed_table_id = f"{dataset_id}.{feed_table_name}"
        
        # Infer schema from first record
        if deduplicated_data:
            try:
                schema = infer_schema_from_record(deduplicated_data[0])
                
                # Ensure feed-specific table exists
                if ensure_table_exists(feed_table_id, schema):
                    feed_job_id = upload_records_to_bigquery(feed_table_id, deduplicated_data)
                    if feed_job_id:
                        result["feed_table_job_id"] = feed_job_id
                        logger.info(f"Also uploaded data to feed-specific table {feed_table_id}")
                else:
                    logger.warning(f"Failed to create feed-specific table {feed_table_id}")
            except Exception as feed_table_error:
                logger.warning(f"Error with feed-specific table: {str(feed_table_error)}")
                # Continue with main process - this is optional
        
        # Step 12: Publish to Pub/Sub if publisher is available
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
                future = publisher.publish(
                    topic_path, 
                    message_json.encode("utf-8"),
                    feed_id=feed_id
                )
                message_id = future.result()
                result["pubsub_message_id"] = message_id
            except Exception as e:
                logger.warning(f"Failed to publish message to Pub/Sub: {str(e)}")
        
        # Update result
        result["status"] = "success"
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        result["duration_seconds"] = (datetime.datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Successfully processed feed '{feed_name}': {len(deduplicated_data)} records")
        return result
    
    except Exception as e:
        logger.error(f"Unhandled error processing feed '{feed_name}': {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        config.report_error(e)
        
        result["error"] = str(e)
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        result["duration_seconds"] = (datetime.datetime.utcnow() - start_time).total_seconds()
        return result

# -------------------- Public API Functions --------------------

def ingest_feed(feed_name: str) -> Dict:
    """Process a single feed by name."""
    global ingestion_status
    
    # Get feed configuration
    feed_config = Config.get_feed_by_id(feed_name)
    
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


def ingest_feeds_by_schedule(schedule: str) -> List[Dict]:
    """Process all feeds with a specific schedule."""
    global ingestion_status
    
    # Update status
    ingestion_status["running"] = True
    ingestion_status["last_run"] = datetime.datetime.utcnow().isoformat()
    
    # Define a getter for feeds by schedule if it doesn't exist
    if not hasattr(Config, 'get_feeds_by_schedule'):
        # Default implementation
        def get_feeds_by_schedule(sched):
            return [f for f in Config.FEEDS if f.get('schedule') == sched]
        feeds = get_feeds_by_schedule(schedule)
    else:
        # Use implementation from Config
        feeds = Config.get_feeds_by_schedule(schedule)
    
    if not feeds:
        logger.info(f"No feeds configured for schedule '{schedule}'")
        ingestion_status["running"] = False
        return []
    
    logger.info(f"Processing {len(feeds)} feeds for schedule '{schedule}'")
    
    results = []
    for feed_config in feeds:
        try:
            feed_id = feed_config.get("id") or feed_config.get("name")
            if not feed_id:
                continue
            
            result = ingest_feed(feed_id)
            results.append(result)
        except Exception as e:
            feed_name = feed_config.get("name", "Unknown")
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            
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
    logger.info(f"Schedule '{schedule}' completed: {success_count}/{len(results)} feeds processed successfully")
    
    return results


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
    
    # Ensure BigQuery resources are initialized
    if not initialize_bigquery_tables():
        logger.warning("Failed to initialize BigQuery tables completely, will attempt to continue")
        # Try force update as well
        if not force_update_bigquery_tables():
            logger.error("Failed to force update BigQuery tables, ingestion may have issues")
    
    # Make sure feed configuration is initialized
    if not Config.FEEDS or len(Config.FEEDS) == 0:
        Config.ensure_feed_configuration()

    # Define a getter for enabled feeds if it doesn't exist
    if not hasattr(Config, 'get_enabled_feeds'):
        # Default implementation - consider all feeds enabled unless explicitly disabled
        feeds = [f for f in Config.FEEDS if f.get('enabled', True)]
    else:
        # Use implementation from Config
        feeds = Config.get_enabled_feeds()
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        ingestion_status["running"] = False
        return []
    
    logger.info(f"Processing all {len(feeds)} enabled feeds")
    
    results = []
    for feed_config in feeds:
        try:
            feed_id = feed_config.get("id") or feed_config.get("name")
            if not feed_id:
                continue
            
            result = ingest_feed(feed_id)
            results.append(result)
        except Exception as e:
            feed_name = feed_config.get("name", "Unknown")
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            config.report_error(e)
            
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
    success_count = sum(1 for r in results if r.get("status") == "success")
    logger.info(f"All feeds processed: {success_count}/{len(results)} feeds processed successfully")
    
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
        logger.info(f"Received PubSub message: {event}")
        
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

# Define some hardcoded default feed configurations for testing and development
DEFAULT_FEED_CONFIGS = [
    {
        "id": "phishtank",
        "name": "PhishTank URLs",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "description": "URLs verified as phishing by PhishTank community",
        "format": "json",
        "type": "url",
        "update_frequency": "daily",
        "parser_config": {
            "root_element": "data",
            "transformations": {}
        },
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
        "parser_config": {
            "skip_lines": 8,
            "has_header": True,
            "transformations": {}
        },
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
        "parser_config": {
            "root_element": "data",
            "transformations": {}
        },
        "enabled": True
    }
]

# Add default feeds to config if no feeds are configured
if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
    logger.info("No feeds configured, adding default feeds")
    Config.FEEDS = DEFAULT_FEED_CONFIGS

# Automatically trigger ingestion on module load for production environment
if __name__ != "__main__" and Config.ENVIRONMENT == 'production' and Config.AUTO_INGEST:
    # Wait a bit to ensure the app has started
    logger.info("Auto-ingestion enabled - will start ingestion after app startup")
    
    def delayed_start():
        time.sleep(10)  # Wait 10 seconds for app startup
        # First ensure BigQuery tables
        initialize_bigquery_tables()
        # Then start ingestion
        trigger_ingestion_in_background()
        
    startup_thread = threading.Thread(target=delayed_start)
    startup_thread.daemon = True
    startup_thread.start()

# Initialize database tables on module import
if initialize_bigquery_tables():
    logger.info("BigQuery tables initialized successfully")
    
    # Test BigQuery connectivity to verify it's working
    try:
        # Simple test query
        test_query = "SELECT 1 as test"
        query_job = bq_client.query(test_query)
        results = list(query_job.result())
        if results and len(results) > 0:
            logger.info("BigQuery connectivity test passed")
        else:
            logger.warning("BigQuery connectivity test returned no results, there may be issues")
    except Exception as e:
        logger.warning(f"BigQuery connectivity test failed: {str(e)}")
else:
    logger.warning("Some BigQuery tables could not be initialized, will retry when needed")
    # Force update to fix any issues
    if force_update_bigquery_tables():
        logger.info("Successfully forced update of BigQuery tables")
    else:
        logger.error("Failed to force update BigQuery tables, ingestion may have issues")

# CLI command runner
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Ingestion Tool')
    parser.add_argument('--diagnose', action='store_true', help='Run diagnostics on BigQuery and feed configuration')
    parser.add_argument('--fix', action='store_true', help='Fix issues and force ingestion')
    parser.add_argument('--feed', type=str, help='Process a specific feed by ID or name')
    parser.add_argument('--verify', action='store_true', help='Verify ingestion results')
    parser.add_argument('--force-tables', action='store_true', help='Force recreation of BigQuery tables')
    args = parser.parse_args()
    
    if args.diagnose:
        logger.info("Running diagnostics...")
        diagnose_bigquery_issues()
        diagnose_feed_issues()
        
    elif args.fix:
        logger.info("Running fix and force ingestion...")
        fix_and_force_ingestion()
        
    elif args.feed:
        logger.info(f"Processing specific feed: {args.feed}")
        result = ingest_feed(args.feed)
        logger.info(f"Result: {result}")
        
    elif args.verify:
        logger.info("Verifying ingestion results...")
        verify_ingestion_results()
        
    elif args.force_tables:
        logger.info("Forcing recreation of BigQuery tables...")
        force_update_bigquery_tables()
        
    else:
        logger.info("Running standard ingestion...")
        results = ingest_all_feeds()
        success_count = sum(1 for r in results if r.get('status') == 'success')
        logger.info(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
