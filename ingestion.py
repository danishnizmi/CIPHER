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
from typing import Dict, List, Any, Optional, Tuple, Union
from google.cloud import storage
from google.cloud import bigquery
from google.cloud import pubsub_v1
from google.api_core.exceptions import NotFound

import config

# Configure logging
logger = logging.getLogger(__name__)

class FeedIngestion:
    """Class to handle the ingestion of threat intelligence feeds."""
    
    def __init__(self):
        """Initialize the FeedIngestion class with GCP clients."""
        self.storage_client = storage.Client(project=config.GCP_PROJECT)
        self.bigquery_client = bigquery.Client(project=config.GCP_PROJECT)
        self.publisher = pubsub_v1.PublisherClient()
        self.bucket_name = config.GCS_BUCKET
        
        # Ensure bucket exists
        self._ensure_bucket_exists()
        
        # Topic path for PubSub
        if config.PUBSUB_TOPIC:
            self.topic_path = self.publisher.topic_path(
                config.GCP_PROJECT, config.PUBSUB_TOPIC
            )
        else:
            self.topic_path = None
            
    def _ensure_bucket_exists(self):
        """Create the GCS bucket if it doesn't exist."""
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            if not bucket.exists():
                self.storage_client.create_bucket(
                    self.bucket_name, 
                    location=config.GCP_REGION
                )
                logger.info(f"Created new bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Error ensuring bucket exists: {str(e)}")
            raise
            
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
            
            response = requests.get(url, headers=headers, timeout=60)
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
            
        except Exception as e:
            logger.error(f"Error storing raw feed '{feed_name}': {str(e)}")
            raise
            
    def parse_feed(self, feed_config: Dict, content: bytes) -> List[Dict]:
        """
        Parse the feed content based on its format.
        
        Args:
            feed_config: Feed configuration dictionary
            content: Raw content bytes
            
        Returns:
            List of parsed items as dictionaries
        """
        feed_name = feed_config["name"]
        format_type = feed_config.get("format", "").lower()
        parser_config = config.get_parser_config(feed_name)
        
        logger.info(f"Parsing feed '{feed_name}' with format '{format_type}'")
        
        try:
            if format_type == "json":
                return self._parse_json(content, parser_config)
            elif format_type == "csv":
                return self._parse_csv(content, parser_config)
            elif format_type == "text":
                return self._parse_text(content, parser_config)
            else:
                logger.warning(f"Unknown format type for feed '{feed_name}': {format_type}")
                # Try to auto-detect format
                try:
                    return self._parse_json(content, parser_config)
                except:
                    try:
                        return self._parse_csv(content, parser_config)
                    except:
                        return self._parse_text(content, parser_config)
        except Exception as e:
            logger.error(f"Error parsing feed '{feed_name}': {str(e)}")
            raise
            
    def _parse_json(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse JSON formatted content."""
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
                            item_copy = item.copy()
                            item_copy["threat_id"] = key
                            processed_data.append(item_copy)
                    else:
                        # It's a single item, wrap in a list
                        data = [data]
                
                if processed_data:
                    data = processed_data
                    
        # Apply transformations from parser config
        return self._apply_transformations(data, parser_config)
        
    def _parse_csv(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse CSV formatted content."""
        content_str = content.decode('utf-8')
        
        # Skip header lines if specified
        skip_lines = parser_config.get("skip_lines", 0)
        if skip_lines > 0:
            lines = content_str.splitlines()
            if len(lines) > skip_lines:
                content_str = '\n'.join(lines[skip_lines:])
                
        # Parse CSV with DictReader
        csv_reader = csv.DictReader(io.StringIO(content_str))
        data = list(csv_reader)
        
        # Apply transformations from parser config
        return self._apply_transformations(data, parser_config)
        
    def _parse_text(self, content: bytes, parser_config: Dict) -> List[Dict]:
        """Parse plain text content (usually line by line)."""
        content_str = content.decode('utf-8')
        lines = [line.strip() for line in content_str.splitlines() if line.strip()]
        
        # Get transformations
        transformations = parser_config.get("transformations", {})
        
        # Convert each line to a dictionary
        data = []
        for line in lines:
            item = {}
            for field, transform in transformations.items():
                item[field] = transform(line)
            data.append(item)
            
        return data
        
    def _apply_transformations(self, data: List[Dict], parser_config: Dict) -> List[Dict]:
        """Apply transformations from parser config to the parsed data."""
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
                if field in item:
                    item[field] = transform_func(item[field])
                    
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
                        item[field] = int(item[field])
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
                        item[field] = item[field].lower() in ("yes", "true", "1")
                        
            # Add ingestion timestamp
            item["ingestion_timestamp"] = datetime.datetime.utcnow().isoformat()
            
        return data
        
    def store_processed_feed(self, feed_config: Dict, data: List[Dict]) -> str:
        """
        Store the processed feed data in Google Cloud Storage as JSON.
        
        Args:
            feed_config: Feed configuration dictionary
            data: Processed data as list of dictionaries
            
        Returns:
            GCS URI of the stored file
        """
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
            blob.upload_from_string(
                json.dumps(data, indent=2),
                content_type='application/json'
            )
            
            gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
            logger.info(f"Stored processed feed '{feed_name}' at {gcs_uri} ({len(data)} records)")
            
            return gcs_uri
            
        except Exception as e:
            logger.error(f"Error storing processed feed '{feed_name}': {str(e)}")
            raise
            
    def upload_to_bigquery(self, feed_config: Dict, data: List[Dict]) -> Tuple[bool, str]:
        """
        Upload the processed data to BigQuery.
        
        Args:
            feed_config: Feed configuration dictionary
            data: Processed data as list of dictionaries
            
        Returns:
            Tuple of (success, job_id or error message)
        """
        if not data:
            logger.warning(f"No data to upload to BigQuery for feed '{feed_config['name']}'")
            return False, "No data to upload"
            
        feed_name = feed_config["name"]
        table_id = feed_config.get("bq_table")
        
        if not table_id:
            table_id = f"{config.GCP_PROJECT}.{config.BIGQUERY_DATASET}.{feed_name}"
            
        try:
            # Check if table exists, if not create it
            try:
                self.bigquery_client.get_table(table_id)
                logger.debug(f"Table {table_id} exists")
            except NotFound:
                # Create dataset if it doesn't exist
                dataset_id = f"{config.GCP_PROJECT}.{config.BIGQUERY_DATASET}"
                try:
                    self.bigquery_client.get_dataset(dataset_id)
                except NotFound:
                    dataset = bigquery.Dataset(dataset_id)
                    dataset.location = config.BQ_LOCATION
                    self.bigquery_client.create_dataset(dataset)
                    logger.info(f"Created dataset {dataset_id}")
                
                # Infer schema from the first item
                schema = self._infer_schema(data[0])
                
                # Create table
                table = bigquery.Table(table_id, schema=schema)
                self.bigquery_client.create_table(table)
                logger.info(f"Created table {table_id}")
                
            # Write data to a temporary file
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
                for item in data:
                    # Convert any non-serializable items to strings
                    for key, value in item.items():
                        if isinstance(value, (datetime.datetime, datetime.date)):
                            item[key] = value.isoformat()
                    
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
            return False, str(e)
            
    def _infer_schema(self, sample: Dict) -> List[bigquery.SchemaField]:
        """
        Infer BigQuery schema from a sample dictionary.
        
        Args:
            sample: A sample dictionary to infer the schema from
            
        Returns:
            List of BigQuery SchemaField objects
        """
        schema = []
        
        for key, value in sample.items():
            field_type = "STRING"  # Default type
            
            if isinstance(value, bool):
                field_type = "BOOLEAN"
            elif isinstance(value, int):
                field_type = "INTEGER"
            elif isinstance(value, float):
                field_type = "FLOAT"
            elif isinstance(value, dict):
                # For nested fields, recursively infer the schema
                nested_schema = self._infer_schema(value)
                schema.append(bigquery.SchemaField(
                    key, "RECORD", fields=nested_schema
                ))
                continue
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    # List of records
                    nested_schema = self._infer_schema(value[0])
                    schema.append(bigquery.SchemaField(
                        key, "RECORD", mode="REPEATED", fields=nested_schema
                    ))
                elif value:
                    # List of simple types
                    if all(isinstance(item, bool) for item in value):
                        schema.append(bigquery.SchemaField(
                            key, "BOOLEAN", mode="REPEATED"
                        ))
                    elif all(isinstance(item, int) for item in value):
                        schema.append(bigquery.SchemaField(
                            key, "INTEGER", mode="REPEATED"
                        ))
                    elif all(isinstance(item, float) for item in value):
                        schema.append(bigquery.SchemaField(
                            key, "FLOAT", mode="REPEATED"
                        ))
                    else:
                        # Default to string for mixed types
                        schema.append(bigquery.SchemaField(
                            key, "STRING", mode="REPEATED"
                        ))
                else:
                    # Empty list, default to string
                    schema.append(bigquery.SchemaField(
                        key, "STRING", mode="REPEATED"
                    ))
                continue
                
            schema.append(bigquery.SchemaField(key, field_type))
            
        return schema
        
    def publish_to_pubsub(self, feed_name: str, message: Dict) -> Optional[str]:
        """
        Publish a message to PubSub topic.
        
        Args:
            feed_name: Name of the feed
            message: Message data to publish
            
        Returns:
            Message ID if successful, None otherwise
        """
        if not self.topic_path:
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
        Process a feed based on its configuration.
        
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
            # Step 1: Download the feed
            content_type, content, download_metadata = self.download_feed(feed_config)
            result["download_metadata"] = download_metadata
            
            # Step 2: Store the raw feed
            raw_uri = self.store_raw_feed(feed_config, content, content_type)
            result["raw_uri"] = raw_uri
            
            # Step 3: Parse the feed
            parsed_data = self.parse_feed(feed_config, content)
            result["record_count"] = len(parsed_data)
            
            # Step 4: Store the processed feed
            if parsed_data:
                processed_uri = self.store_processed_feed(feed_config, parsed_data)
                result["processed_uri"] = processed_uri
                
                # Step 5: Upload to BigQuery if configured
                if feed_config.get("bq_table"):
                    bq_success, bq_result = self.upload_to_bigquery(feed_config, parsed_data)
                    result["bigquery_success"] = bq_success
                    if bq_success:
                        result["bigquery_job_id"] = bq_result
                    else:
                        result["bigquery_error"] = bq_result
                
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
                "processed_uri": result.get("processed_uri", ""),
                "bigquery_success": result.get("bigquery_success", False)
            })
            
            if message_id:
                result["pubsub_message_id"] = message_id
                
            logger.info(f"Completed ingestion for feed '{feed_name}': {len(parsed_data)} records processed")
            return result
            
        except Exception as e:
            # Handle the error
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
            
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            return result

def ingest_feed(feed_name: str) -> Dict:
    """
    Ingest a specific feed by name.
    
    Args:
        feed_name: Name of the feed to ingest
        
    Returns:
        Processing result dictionary
    """
    feed_config = config.get_feed_config(feed_name)
    
    if not feed_config:
        logger.error(f"Feed '{feed_name}' not found in configuration")
        return {
            "feed_name": feed_name,
            "status": "failed",
            "error": "Feed not found in configuration"
        }
        
    if not feed_config.get("enabled", True):
        logger.warning(f"Feed '{feed_name}' is disabled in configuration")
        return {
            "feed_name": feed_name,
            "status": "skipped",
            "error": "Feed is disabled in configuration"
        }
        
    ingestion = FeedIngestion()
    return ingestion.process_feed(feed_config)

def ingest_feeds_by_schedule(schedule: str) -> List[Dict]:
    """
    Ingest all feeds configured for a specific schedule.
    
    Args:
        schedule: Schedule type (e.g., 'hourly', 'daily')
        
    Returns:
        List of processing result dictionaries
    """
    feeds = config.get_feeds_by_schedule(schedule)
    
    if not feeds:
        logger.info(f"No feeds configured for schedule '{schedule}'")
        return []
        
    logger.info(f"Processing {len(feeds)} feeds for schedule '{schedule}'")
    
    results = []
    ingestion = FeedIngestion()
    
    for feed_config in feeds:
        result = ingestion.process_feed(feed_config)
        results.append(result)
        
    # Log summary
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"Schedule '{schedule}' completed: {success_count}/{len(results)} feeds processed successfully")
    
    return results

def ingest_all_feeds() -> List[Dict]:
    """
    Ingest all enabled feeds.
    
    Returns:
        List of processing result dictionaries
    """
    feeds = config.get_enabled_feeds()
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        return []
        
    logger.info(f"Processing all {len(feeds)} enabled feeds")
    
    results = []
    ingestion = FeedIngestion()
    
    for feed_config in feeds:
        result = ingestion.process_feed(feed_config)
        results.append(result)
        
    # Log summary
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"All feeds processed: {success_count}/{len(results)} feeds processed successfully")
    
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

if __name__ == "__main__":
    # When run as a script, ingest all feeds
    results = ingest_all_feeds()
    
    # Print summary
    success_count = sum(1 for r in results if r["status"] == "success")
    print(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
    
    # Print errors if any
    for result in results:
        if result["status"] != "success":
            print(f"Feed '{result['feed_name']}' failed: {result.get('error', 'Unknown error')}")
