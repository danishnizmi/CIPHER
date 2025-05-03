"""
Ingestion module for threat intelligence feeds.
Handles downloading, processing, and storing threat intelligence data.
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
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
from google.cloud.exceptions import Conflict

import config

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
            # Ensure valid URL format
            url_pattern = r'^(http|https|ftp)://[^\s/$.?#].[^\s]*$'
            if not re.match(url_pattern, value.lower()):
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

class FeedIngestion:
    """Class to handle the ingestion of threat intelligence feeds."""
    
    def __init__(self):
        """Initialize the FeedIngestion class with GCP clients."""
        self.storage_client = None
        self.bigquery_client = None
        self.publisher = None
        self.bucket_name = None
        self.topic_path = None
        
        try:
            # Initialize clients
            self.storage_client = storage.Client(project=config.Config.GCP_PROJECT)
            self.bigquery_client = bigquery.Client(project=config.Config.GCP_PROJECT)
            self.publisher = pubsub_v1.PublisherClient()
            self.bucket_name = config.Config.GCS_BUCKET
            
            # Ensure bucket exists
            self._ensure_bucket_exists()
            
            # Topic path for PubSub
            if config.Config.PUBSUB_TOPIC:
                self.topic_path = self.publisher.topic_path(
                    config.Config.GCP_PROJECT, config.Config.PUBSUB_TOPIC
                )
                
            logger.info("FeedIngestion initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing FeedIngestion: {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
                
    def _ensure_bucket_exists(self):
        """Create the GCS bucket if it doesn't exist."""
        if not self.storage_client or not self.bucket_name:
            logger.error("Storage client or bucket name not initialized")
            return
            
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            if not bucket.exists():
                self.storage_client.create_bucket(
                    bucket, 
                    location=config.Config.GCP_REGION,
                    predefined_acl='projectPrivate'
                )
                logger.info(f"Created new bucket: {self.bucket_name}")
                
                # Create necessary folder structure
                folders = ['feeds', 'raw', 'processed', 'cache', 'exports']
                for folder in folders:
                    blob = bucket.blob(f"{folder}/")
                    blob.upload_from_string('')
                    
        except GoogleAPIError as e:
            logger.error(f"Google API error ensuring bucket exists: {str(e)}")
        except Exception as e:
            logger.error(f"Error ensuring bucket exists: {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            
    @RetryHandler.with_retries        
    def download_feed(self, feed_config: Dict) -> Tuple[str, bytes, Dict]:
        """
        Download content from the feed URL.
        
        Args:
            feed_config: Feed configuration dictionary
            
        Returns:
            Tuple of (content_type, content_bytes, response_metadata)
        """
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        
        try:
            logger.info(f"Downloading feed '{feed_config['name']}' from {url}")
            
            # Add User-Agent if not provided
            if 'User-Agent' not in headers:
                headers['User-Agent'] = f"ThreatIntelligencePlatform/{config.Config.VERSION}"
                
            # Set timeout to avoid hanging
            timeout = feed_config.get("timeout", 60)
            
            # Make the request
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '')
            
            # Create response metadata for tracking
            response_metadata = {
                "url": url,
                "status_code": response.status_code,
                "content_type": content_type,
                "content_length": len(response.content),
                "headers": dict(response.headers),
                "download_time": datetime.datetime.utcnow().isoformat()
            }
            
            return content_type, response.content, response_metadata
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception downloading feed from {url}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error downloading feed from {url}: {str(e)}")
            raise
            
    def store_raw_feed(self, feed_config: Dict, content: bytes, content_type: str) -> str:
        """
        Store the raw feed content in Google Cloud Storage.
        
        Args:
            feed_config: Feed configuration dictionary
            content: Raw content bytes
            content_type: MIME type of the content
            
        Returns:
            GCS URI of the stored file
        """
        if not self.storage_client or not self.bucket_name:
            raise Exception("Storage client not initialized")
            
        feed_name = feed_config["name"]
        storage_path = feed_config.get("storage_path", f"feeds/{feed_name}")
        
        # Generate a timestamp for the filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Determine file extension based on format or content type
        format_type = feed_config.get("format", "")
        if format_type == "json":
            file_extension = ".json"
        elif format_type == "csv":
            file_extension = ".csv"
        elif format_type == "text":
            file_extension = ".txt"
        else:
            # Fallback to content type
            if 'json' in content_type.lower():
                file_extension = '.json'
            elif 'csv' in content_type.lower():
                file_extension = '.csv'
            elif 'text/plain' in content_type.lower():
                file_extension = '.txt'
            else:
                file_extension = '.dat'
                
        # Create the blob name
        blob_name = f"{storage_path}/raw/{timestamp}{file_extension}"
        
        try:
            # Get the bucket
            bucket = self.storage_client.bucket(self.bucket_name)
            
            # Create the blob and upload
            blob = bucket.blob(blob_name)
            blob.upload_from_string(content, content_type=content_type)
            
            gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
            logger.info(f"Stored raw feed '{feed_name}' at {gcs_uri}")
            
            return gcs_uri
            
        except GoogleAPIError as e:
            logger.error(f"Google API error storing raw feed '{feed_name}': {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error storing raw feed '{feed_name}': {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            raise
            
    def parse_feed(self, feed_config: Dict, content: bytes) -> List[Dict]:
        """
        Parse the feed content with enhanced validation and sanitization.
        
        Args:
            feed_config: Feed configuration dictionary
            content: Raw content bytes
            
        Returns:
            List of parsed and sanitized items as dictionaries
        """
        feed_name = feed_config["name"]
        format_type = feed_config.get("format", "").lower()
        parser_config = get_parser_config(feed_name)
        
        logger.info(f"Parsing feed '{feed_name}' with format '{format_type}'")
        
        try:
            # Parse data based on format type
            if format_type == "json":
                data = self._parse_json(content, parser_config)
            elif format_type == "csv":
                data = self._parse_csv(content, parser_config)
            elif format_type == "text":
                data = self._parse_text(content, parser_config)
            else:
                # Auto-detect format
                logger.warning(f"Unknown format type for feed '{feed_name}': {format_type}, attempting auto-detection")
                try:
                    data = self._parse_json(content, parser_config)
                except Exception:
                    try:
                        data = self._parse_csv(content, parser_config)
                    except Exception:
                        data = self._parse_text(content, parser_config)
                        
            # Early validation: remove empty records or records without required fields
            required_fields = feed_config.get("required_fields", [])
            if required_fields:
                data = [item for item in data if all(field in item for field in required_fields)]
                
            # Apply transformations from parser config
            data = self._apply_transformations(data, parser_config)
            
            # Sanitize data
            record_type = feed_config.get("record_type")
            sanitized_data = [DataSanitizer.sanitize_record(item, record_type) for item in data]
            
            # Filter out None/empty values that might have been sanitized away
            sanitized_data = [item for item in sanitized_data if item]
            
            # Deduplicate records if enabled
            if feed_config.get("enable_deduplication", True):
                # Get existing hashes from the last run if available
                feed_hash_key = f"feed_hashes_{feed_name}"
                existing_hashes = self._get_cached_hashes(feed_hash_key)
                
                # Filter out duplicates
                unique_data = []
                new_hashes = []
                
                for item in sanitized_data:
                    item_hash = DeduplicationHandler.generate_hash(item)
                    if item_hash not in existing_hashes and item_hash not in new_hashes:
                        unique_data.append(item)
                        new_hashes.append(item_hash)
                        
                # Store new hashes for next run
                self._store_cached_hashes(feed_hash_key, new_hashes)
                
                logger.info(f"Deduplicated {len(sanitized_data) - len(unique_data)} records")
                return unique_data
                
            return sanitized_data
            
        except Exception as e:
            logger.error(f"Error parsing feed '{feed_name}': {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            raise

    def _parse_json(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse JSON formatted content."""
        try:
            data = json.loads(content)
            
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
                            # It's a single item, wrap in a list
                            data = [data]
                    
                    if processed_data:
                        data = processed_data
                else:
                    # Wrap in list if it's a primitive value
                    data = [{"value": data}]
            
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON data: {str(e)}")
            raise Exception(f"Failed to parse JSON data: {str(e)}")
        
    def _parse_csv(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse CSV formatted content."""
        try:
            content_str = content.decode('utf-8', errors='replace')
            
            # Skip header lines if specified
            skip_lines = parser_config.get("skip_lines", 0)
            if skip_lines > 0:
                lines = content_str.splitlines()
                if len(lines) > skip_lines:
                    content_str = '\n'.join(lines[skip_lines:])
                    
            # Parse CSV with DictReader or regular reader based on config
            if parser_config.get("has_header", True):
                csv_reader = csv.DictReader(io.StringIO(content_str))
                data = list(csv_reader)
            else:
                # For CSV without headers, use field names from config or generate them
                field_names = parser_config.get("field_names", [])
                if not field_names:
                    # Generate field names as column1, column2, etc.
                    first_row = next(csv.reader(io.StringIO(content_str)))
                    field_names = [f"column{i+1}" for i in range(len(first_row))]
                    # Reset the reader
                    content_str = content.decode('utf-8', errors='replace')
                
                csv_reader = csv.DictReader(io.StringIO(content_str), fieldnames=field_names)
                data = list(csv_reader)
            
            return data
        except Exception as e:
            logger.error(f"Error parsing CSV data: {str(e)}")
            raise Exception(f"Failed to parse CSV data: {str(e)}")
        
    def _parse_text(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse plain text content (usually line by line)."""
        try:
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
                
                # Apply custom line parsing if provided
                line_parser = parser_config.get("line_parser")
                if line_parser and callable(line_parser):
                    try:
                        parsed = line_parser(line)
                        if parsed and isinstance(parsed, dict):
                            record.update(parsed)
                    except Exception as e:
                        logger.warning(f"Error with custom line parser: {str(e)}")
                
                data.append(record)
                
            return data
        except Exception as e:
            logger.error(f"Error parsing text data: {str(e)}")
            raise Exception(f"Failed to parse text data: {str(e)}")
            
    def _apply_transformations(self, data: List[Dict], parser_config: Dict) -> List[Dict]:
        """Apply transformations from parser config to the parsed data."""
        if not data:
            return []
            
        transformations = parser_config.get("transformations", {})
        array_fields = parser_config.get("array_fields", [])
        date_fields = parser_config.get("date_fields", [])
        int_fields = parser_config.get("int_fields", [])
        float_fields = parser_config.get("float_fields", [])
        bool_fields = parser_config.get("bool_fields", [])
        
        # Process each item
        for item in data:
            # Apply explicit transformations
            for field, transform_func in transformations.items():
                if field in item and callable(transform_func):
                    try:
                        item[field] = transform_func(item[field])
                    except Exception as e:
                        logger.warning(f"Error applying transformation to field '{field}': {str(e)}")
                    
            # Convert array fields
            for field in array_fields:
                if field in item and not isinstance(item[field], list):
                    if isinstance(item[field], str):
                        item[field] = item[field].split(",") if item[field] else []
                    else:
                        item[field] = [item[field]] if item[field] else []
                        
            # Convert date fields
            for field in date_fields:
                if field in item and item[field]:
                    # Keep the original format but ensure it's a string
                    item[field] = str(item[field])
                    
            # Convert numeric fields
            for field in int_fields:
                if field in item and item[field] not in (None, ""):
                    try:
                        item[field] = int(float(item[field]))
                    except (ValueError, TypeError):
                        pass
                        
            for field in float_fields:
                if field in item and item[field] not in (None, ""):
                    try:
                        item[field] = float(item[field])
                    except (ValueError, TypeError):
                        pass
                        
            # Convert boolean fields
            for field in bool_fields:
                if field in item:
                    if isinstance(item[field], str):
                        item[field] = item[field].lower() in ("yes", "true", "1", "t", "y")
                        
            # Add ingestion timestamp
            item["ingestion_timestamp"] = datetime.datetime.utcnow().isoformat()
            
        return data

    def _get_cached_hashes(self, key: str) -> List[str]:
        """Get cached hashes from GCS."""
        if not self.storage_client or not self.bucket_name:
            return []
            
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            blob = bucket.blob(f"cache/{key}.json")
            
            if blob.exists():
                content = blob.download_as_text()
                return json.loads(content)
            
            return []
            
        except Exception as e:
            logger.warning(f"Error getting cached hashes: {str(e)}")
            return []
            
    def _store_cached_hashes(self, key: str, hashes: List[str]) -> None:
        """Store cached hashes to GCS."""
        if not self.storage_client or not self.bucket_name:
            return
            
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            blob = bucket.blob(f"cache/{key}.json")
            
            # Only store up to 10000 hashes to avoid excessive storage use
            if len(hashes) > 10000:
                hashes = hashes[-10000:]
                
            blob.upload_from_string(json.dumps(hashes), content_type="application/json")
            
        except Exception as e:
            logger.warning(f"Error storing cached hashes: {str(e)}")
        
    def store_processed_feed(self, feed_config: Dict, data: List[Dict]) -> str:
        """
        Store the processed feed data in Google Cloud Storage as JSON.
        
        Args:
            feed_config: Feed configuration dictionary
            data: Processed data as list of dictionaries
            
        Returns:
            GCS URI of the stored file
        """
        if not self.storage_client or not self.bucket_name:
            raise Exception("Storage client not initialized")
            
        if not data:
            logger.warning(f"No data to store for feed '{feed_config['name']}'")
            return ""
            
        feed_name = feed_config["name"]
        storage_path = feed_config.get("storage_path", f"feeds/{feed_name}")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create the blob name
        blob_name = f"{storage_path}/processed/{timestamp}.json"
        
        try:
            # Get the bucket
            bucket = self.storage_client.bucket(self.bucket_name)
            
            # Create the blob and upload
            blob = bucket.blob(blob_name)
            
            # Convert to JSON with date handling
            def json_serializer(obj):
                if isinstance(obj, (datetime.datetime, datetime.date)):
                    return obj.isoformat()
                raise TypeError(f"Type {type(obj)} not serializable")
                
            blob.upload_from_string(
                json.dumps(data, default=json_serializer, indent=2),
                content_type='application/json'
            )
            
            gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
            logger.info(f"Stored processed feed '{feed_name}' at {gcs_uri} ({len(data)} records)")
            
            return gcs_uri
            
        except GoogleAPIError as e:
            logger.error(f"Google API error storing processed feed '{feed_name}': {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error storing processed feed '{feed_name}': {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            raise
            
    def _infer_schema(self, sample: Dict) -> List[bigquery.SchemaField]:
        """
        Enhanced BigQuery schema inference with better type handling.
        
        Args:
            sample: A sample dictionary to infer the schema from
            
        Returns:
            List of BigQuery SchemaField objects
        """
        schema = []
        
        for key, value in sample.items():
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
                fields = self._infer_schema(value)
                
            elif isinstance(value, list):
                field_mode = "REPEATED"
                
                if value and all(isinstance(item, dict) for item in value):
                    # List of records
                    field_type = "RECORD"
                    fields = self._infer_schema(value[0])
                    
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
        
    def upload_to_bigquery(self, feed_config: Dict, data: List[Dict]) -> Tuple[bool, str]:
        """
        Upload the processed data to BigQuery with improved error handling.
        
        Args:
            feed_config: Feed configuration dictionary
            data: Processed data as list of dictionaries
            
        Returns:
            Tuple of (success, job_id or error message)
        """
        if not self.bigquery_client:
            logger.error("BigQuery client not initialized")
            return False, "BigQuery client not initialized"
            
        if not data:
            logger.warning(f"No data to upload to BigQuery for feed '{feed_config['name']}'")
            return False, "No data to upload"
            
        feed_name = feed_config["name"]
        table_id = feed_config.get("bq_table")
        
        if not table_id:
            table_id = f"{config.Config.GCP_PROJECT}.{config.Config.BIGQUERY_DATASET}.{feed_name.replace('-', '_')}"
            
        try:
            # Check if dataset exists, if not create it
            dataset_id = f"{config.Config.GCP_PROJECT}.{config.Config.BIGQUERY_DATASET}"
            try:
                self.bigquery_client.get_dataset(dataset_id)
                logger.debug(f"Dataset {dataset_id} exists")
            except NotFound:
                # Create dataset
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = config.Config.BIGQUERY_LOCATION
                self.bigquery_client.create_dataset(dataset)
                logger.info(f"Created dataset {dataset_id}")
                
            # Check if table exists, if not create it
            try:
                self.bigquery_client.get_table(table_id)
                logger.debug(f"Table {table_id} exists")
            except NotFound:
                # Create table with schema inference
                if not data:
                    return False, "No data to infer schema from"
                    
                # Infer schema from the first item
                schema = self._infer_schema(data[0])
                
                # Create table
                table = bigquery.Table(table_id, schema=schema)
                self.bigquery_client.create_table(table)
                logger.info(f"Created table {table_id}")
                
            # Prepare data
            processed_data = []
            for item in data:
                # Convert any non-serializable items to strings
                cleaned_item = {}
                for key, value in item.items():
                    if isinstance(value, (datetime.datetime, datetime.date)):
                        cleaned_item[key] = value.isoformat()
                    else:
                        cleaned_item[key] = value
                processed_data.append(cleaned_item)
                
            # Write data to a temporary file
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
                for item in processed_data:
                    temp_file.write(json.dumps(item) + "\n")
                
                temp_file_name = temp_file.name
                
            # Configure the load job
            job_config = bigquery.LoadJobConfig(
                source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                schema_update_options=[
                    bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
                ],
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                autodetect=True,
            )
            
            # Load the data
            with open(temp_file_name, "rb") as source_file:
                job = self.bigquery_client.load_table_from_file(
                    source_file, 
                    table_id, 
                    job_config=job_config
                )
                
            # Wait for the job to complete
            job.result()
            
            # Clean up the temporary file
            os.unlink(temp_file_name)
            
            logger.info(f"Uploaded {len(data)} records to BigQuery table {table_id}")
            return True, job.job_id
            
        except Exception as e:
            logger.error(f"Error uploading to BigQuery: {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            return False, str(e)
            
    def publish_to_pubsub(self, feed_name: str, message: Dict) -> Optional[str]:
        """
        Publish a message to PubSub topic.
        
        Args:
            feed_name: Name of the feed
            message: Message data to publish
            
        Returns:
            Message ID if successful, None otherwise
        """
        if not self.publisher or not self.topic_path:
            logger.debug(f"PubSub topic not configured, skipping publish for feed '{feed_name}'")
            return None
            
        try:
            # Add feed name to the message
            message["feed_name"] = feed_name
            message["timestamp"] = datetime.datetime.utcnow().isoformat()
            
            # Convert message to JSON and encode
            data = json.dumps(message).encode("utf-8")
            
            # Publish the message
            future = self.publisher.publish(self.topic_path, data)
            message_id = future.result()
            
            logger.info(f"Published message to PubSub for feed '{feed_name}', ID: {message_id}")
            return message_id
            
        except Exception as e:
            logger.error(f"Error publishing to PubSub: {str(e)}")
            return None
            
    def process_feed(self, feed_config: Dict) -> Dict:
        """
        Process a feed with enhanced error handling and retries.
        
        Args:
            feed_config: Configuration for the feed
            
        Returns:
            Dictionary with processing results
        """
        feed_name = feed_config["name"]
        start_time = datetime.datetime.utcnow()
        
        logger.info(f"Starting ingestion process for feed '{feed_name}'")
        
        result = {
            "feed_name": feed_name,
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
                
            # Step 1: Download the feed with retries
            try:
                content_type, content, download_metadata = self.download_feed(feed_config)
                result["download_metadata"] = download_metadata
            except Exception as e:
                logger.error(f"Error downloading feed '{feed_name}': {str(e)}")
                result["error"] = f"Download failed: {str(e)}"
                return result
                
            # Step 2: Store the raw feed
            try:
                raw_uri = self.store_raw_feed(feed_config, content, content_type)
                result["raw_uri"] = raw_uri
            except Exception as e:
                logger.error(f"Error storing raw feed '{feed_name}': {str(e)}")
                result["error"] = f"Raw storage failed: {str(e)}"
                return result
                
            # Step 3: Parse the feed with validation and sanitization
            try:
                parsed_data = self.parse_feed(feed_config, content)
                result["record_count"] = len(parsed_data)
                
                if not parsed_data:
                    logger.warning(f"No valid records found in feed '{feed_name}'")
                    result["status"] = "success"  # Still considered success, just empty
                    result["warning"] = "No valid records found"
                    
                    # Update status and timing
                    end_time = datetime.datetime.utcnow()
                    result["end_time"] = end_time.isoformat()
                    result["duration_seconds"] = (end_time - start_time).total_seconds()
                    
                    # Publish status to PubSub
                    self.publish_to_pubsub(feed_name, {
                        "operation": "feed_ingestion",
                        "status": "success",
                        "warning": "No valid records found",
                        "record_count": 0,
                        "raw_uri": raw_uri
                    })
                    
                    return result
                    
            except Exception as e:
                logger.error(f"Error parsing feed '{feed_name}': {str(e)}")
                result["error"] = f"Parsing failed: {str(e)}"
                return result
                
            # Step 4: Store the processed feed
            try:
                processed_uri = self.store_processed_feed(feed_config, parsed_data)
                result["processed_uri"] = processed_uri
            except Exception as e:
                logger.error(f"Error storing processed feed '{feed_name}': {str(e)}")
                result["error"] = f"Processed storage failed: {str(e)}"
                return result
                
            # Step 5: Upload to BigQuery if configured
            if feed_config.get("bq_table") or feed_config.get("upload_to_bigquery", True):
                try:
                    bq_success, bq_result = self.upload_to_bigquery(feed_config, parsed_data)
                    result["bigquery_success"] = bq_success
                    
                    if bq_success:
                        result["bigquery_job_id"] = bq_result
                    else:
                        result["bigquery_error"] = bq_result
                        result["warning"] = f"BigQuery upload issues: {bq_result}"
                        
                except Exception as e:
                    logger.error(f"Error uploading to BigQuery: {str(e)}")
                    result["bigquery_success"] = False
                    result["bigquery_error"] = str(e)
                    result["warning"] = f"BigQuery upload failed: {str(e)}"
            
            # Update status and timing
            end_time = datetime.datetime.utcnow()
            result["end_time"] = end_time.isoformat()
            result["duration_seconds"] = (end_time - start_time).total_seconds()
            result["status"] = "success"
            
            # Publish result to PubSub
            message_id = self.publish_to_pubsub(feed_name, {
                "operation": "feed_ingestion",
                "status": "success",
                "record_count": len(parsed_data),
                "raw_uri": raw_uri,
                "processed_uri": processed_uri,
                "bigquery_success": result.get("bigquery_success", False)
            })
            
            if message_id:
                result["pubsub_message_id"] = message_id
                
            logger.info(f"Completed ingestion for feed '{feed_name}': {len(parsed_data)} records processed")
            return result
            
        except Exception as e:
            # Handle unhandled exceptions
            end_time = datetime.datetime.utcnow()
            result["end_time"] = end_time.isoformat()
            result["duration_seconds"] = (end_time - start_time).total_seconds()
            result["error"] = str(e)
            result["traceback"] = traceback.format_exc()
            
            # Publish error to PubSub
            self.publish_to_pubsub(feed_name, {
                "operation": "feed_ingestion",
                "status": "error",
                "error": str(e)
            })
            
            logger.error(f"Unhandled error processing feed '{feed_name}': {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            return result

# -------------------- Helper Functions --------------------

def get_parser_config(feed_name: str) -> Dict:
    """
    Get parser configuration for a feed.
    
    Args:
        feed_name: Name of the feed
        
    Returns:
        Parser configuration dictionary
    """
    # Try to get from config module
    feed_config = config.Config.get_feed_by_id(feed_name)
    
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

def ingest_feed(feed_name: str) -> Dict:
    """
    Ingest a specific feed by name.
    
    Args:
        feed_name: Name of the feed to ingest
        
    Returns:
        Processing result dictionary
    """
    global ingestion_status
    
    feed_config = config.Config.get_feed_by_id(feed_name)
    
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
        
    if not feed_config.get("enabled", True):
        logger.warning(f"Feed '{feed_name}' is disabled in configuration")
        skip_result = {
            "feed_name": feed_name,
            "status": "skipped",
            "error": "Feed is disabled in configuration"
        }
        return skip_result
        
    ingestion = FeedIngestion()
    try:
        result = ingestion.process_feed(feed_config)
        
        # Update global status
        if result["status"] == "success":
            ingestion_status["feeds_processed"] += 1
            ingestion_status["total_records"] += result.get("record_count", 0)
        else:
            ingestion_status["feeds_failed"] += 1
            error_msg = result.get("error", "Unknown error")
            ingestion_status["errors"].append(f"Feed '{feed_name}': {error_msg}")
            
        return result
    except Exception as e:
        logger.error(f"Unhandled exception in ingest_feed for '{feed_name}': {str(e)}")
        error_result = {
            "feed_name": feed_name,
            "status": "failed",
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        ingestion_status["feeds_failed"] += 1
        ingestion_status["errors"].append(f"Feed '{feed_name}': {str(e)}")
        return error_result

def ingest_feeds_by_schedule(schedule: str) -> List[Dict]:
    """
    Ingest all feeds configured for a specific schedule.
    
    Args:
        schedule: Schedule type (e.g., 'hourly', 'daily')
        
    Returns:
        List of processing result dictionaries
    """
    global ingestion_status
    
    # Update status
    ingestion_status["running"] = True
    ingestion_status["last_run"] = datetime.datetime.utcnow().isoformat()
    
    feeds = config.Config.get_feeds_by_schedule(schedule)
    
    if not feeds:
        logger.info(f"No feeds configured for schedule '{schedule}'")
        ingestion_status["running"] = False
        return []
        
    logger.info(f"Processing {len(feeds)} feeds for schedule '{schedule}'")
    
    results = []
    
    for feed_config in feeds:
        try:
            result = ingest_feed(feed_config.get("id") or feed_config.get("name"))
            results.append(result)
        except Exception as e:
            logger.error(f"Error processing feed '{feed_config.get('name')}': {str(e)}")
            results.append({
                "feed_name": feed_config.get("name"),
                "status": "failed",
                "error": str(e)
            })
            ingestion_status["feeds_failed"] += 1
            ingestion_status["errors"].append(f"Feed '{feed_config.get('name')}': {str(e)}")
        
    # Log summary
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"Schedule '{schedule}' completed: {success_count}/{len(results)} feeds processed successfully")
    
    # Update status
    ingestion_status["running"] = False
    
    return results

def ingest_all_feeds() -> List[Dict]:
    """
    Ingest all enabled feeds.
    
    Returns:
        List of processing result dictionaries
    """
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
    
    feeds = config.Config.get_enabled_feeds()
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        ingestion_status["running"] = False
        return []
        
    logger.info(f"Processing all {len(feeds)} enabled feeds")
    
    results = []
    
    for feed_config in feeds:
        try:
            feed_name = feed_config.get("id") or feed_config.get("name")
            if not feed_name:
                continue
                
            result = ingest_feed(feed_name)
            results.append(result)
        except Exception as e:
            feed_name = feed_config.get("id") or feed_config.get("name", "Unknown")
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            results.append({
                "feed_name": feed_name,
                "status": "failed",
                "error": str(e)
            })
            ingestion_status["feeds_failed"] += 1
            ingestion_status["errors"].append(f"Feed '{feed_name}': {str(e)}")
        
    # Log summary
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"All feeds processed: {success_count}/{len(results)} feeds processed successfully")
    
    # Update status
    ingestion_status["running"] = False
    
    return results

def generate_feed_hash(feed_name: str, data: Union[bytes, List[Dict]]) -> str:
    """
    Generate a hash of feed data for deduplication.
    
    Args:
        feed_name: Name of the feed
        data: Raw bytes or processed data
        
    Returns:
        SHA-256 hash as a hexadecimal string
    """
    hasher = hashlib.sha256()
    
    if isinstance(data, bytes):
        hasher.update(data)
    else:
        # For processed data, convert to a canonical JSON string
        hasher.update(json.dumps(data, sort_keys=True).encode("utf-8"))
        
    return hasher.hexdigest()

def get_ingestion_status() -> Dict:
    """
    Get the current status of the ingestion process.
    
    Returns:
        Status dictionary
    """
    global ingestion_status
    
    # Create a copy of the status to avoid modification issues
    status_copy = ingestion_status.copy()
    
    # Add current timestamp
    status_copy["current_time"] = datetime.datetime.utcnow().isoformat()
    
    return status_copy

def trigger_ingestion_in_background():
    """Trigger ingestion in a background thread."""
    def ingestion_thread():
        try:
            logger.info("Starting background ingestion thread")
            ingest_all_feeds()
            logger.info("Background ingestion thread completed")
        except Exception as e:
            logger.error(f"Error in background ingestion thread: {str(e)}")
            if config.Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
    
    # Start ingestion in a separate thread
    thread = threading.Thread(target=ingestion_thread)
    thread.daemon = True
    thread.start()
    logger.info("Background ingestion thread started")
    return thread

# Automatically trigger ingestion on module load for production environment
if config.Config.ENVIRONMENT == 'production' and not config.Config.DISABLE_AUTO_INGESTION:
    # Wait a bit to ensure the app has started
    logger.info("Auto-ingestion enabled - will start ingestion after app startup")
    
    def delayed_start():
        time.sleep(10)  # Wait 10 seconds for app startup
        trigger_ingestion_in_background()
        
    startup_thread = threading.Thread(target=delayed_start)
    startup_thread.daemon = True
    startup_thread.start()

if __name__ == "__main__":
    # When run as a script, ingest all feeds and print the results
    logger.info("Running ingestion.py as standalone script")
    results = ingest_all_feeds()
    
    # Print summary
    success_count = sum(1 for r in results if r.get("status") == "success")
    total_records = sum(r.get("record_count", 0) for r in results if r.get("status") == "success")
    
    print(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
    print(f"Total records ingested: {total_records}")
    
    # Print errors if any
    for result in results:
        if result.get("status") != "success":
            print(f"Feed '{result.get('feed_name')}' failed: {result.get('error', 'Unknown error')}")
