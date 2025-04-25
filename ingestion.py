"""
Threat Intelligence Platform - Simplified Ingestion Module
Handles collection of threat data from open-source feeds and loads it into BigQuery.
"""

import os
import json
import logging
import csv
import time
from io import StringIO, BytesIO
import zipfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple
from collections import defaultdict
from functools import wraps

import requests
from google.cloud import bigquery
from google.cloud import storage
from google.cloud import pubsub_v1

# Import config module
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = config.project_id
BUCKET_NAME = config.gcs_bucket
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-data-ingestion")

# Global clients
bq_client = None
storage_client = None
publisher = None

# Rate limiting management
_last_request_time = defaultdict(float)
_rate_limit_delays = {
    "phishtank.com": 300,  # 5 minutes between requests - PhishTank has strict limits
    "urlhaus.abuse.ch": 60,  # 1 minute
    "threatfox.abuse.ch": 60,  # 1 minute
    "default": 10  # Default 10 seconds for any other domain
}

# Basic Open Source Feed Definitions
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "table_id": "threatfox_iocs",
        "opensrc_url": "https://threatfox.abuse.ch/export/json/recent/",
        "format": "json",
        "auth_required": False,
        "description": "ThreatFox IOCs - Malware indicators database"
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "table_id": "phishtank_urls",
        "format": "json",
        "auth_required": False,
        "rate_limit": 300,  # 5 minutes
        "description": "PhishTank - Community-verified phishing URLs"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv",
        "skip_lines": 8,  # Skip header info/comments
        "description": "URLhaus - Database of malicious URLs"
    }
}

def get_client(client_type: str):
    """Get or initialize a Google Cloud client"""
    global bq_client, storage_client, publisher
    
    try:
        if client_type == 'bigquery':
            if bq_client is None:
                bq_client = bigquery.Client(project=PROJECT_ID)
                logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
            return bq_client
        elif client_type == 'storage':
            if storage_client is None:
                storage_client = storage.Client(project=PROJECT_ID)
                logger.info(f"Storage client initialized for project {PROJECT_ID}")
            return storage_client
        elif client_type == 'pubsub':
            if publisher is None:
                publisher = pubsub_v1.PublisherClient()
                logger.info("Pub/Sub publisher initialized")
            return publisher
        else:
            logger.error(f"Unknown client type: {client_type}")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize {client_type} client: {str(e)}")
        return None

def _rate_limited_request(url, timeout=30, max_retries=3):
    """Make a rate-limited request with respect to API limits"""
    domain = url.split('/')[2]
    
    # Determine delay based on domain
    delay = _rate_limit_delays.get(domain, _rate_limit_delays['default'])
    
    for retry in range(max_retries):
        # Check if we need to wait
        time_since_last = time.time() - _last_request_time.get(domain, 0)
        if time_since_last < delay:
            wait_time = delay - time_since_last
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s before requesting from {domain}")
            time.sleep(wait_time)
        
        # Make request and record time
        try:
            response = requests.get(url, timeout=timeout)
            _last_request_time[domain] = time.time()
            
            # Handle rate limit responses
            if response.status_code == 429:
                logger.warning(f"Rate limit hit for {domain}. Response: {response.text}")
                # Increase delay for this domain for future requests
                _rate_limit_delays[domain] = min(_rate_limit_delays[domain] * 2, 3600)  # Max 1 hour
                
                # Apply backoff
                if retry < max_retries - 1:
                    wait_time = (2 ** retry) * 60  # Exponential backoff
                    logger.info(f"Backing off for {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                else:
                    raise requests.RequestException(f"Rate limit exceeded for {domain} after {max_retries} retries")
            
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

def ensure_resources() -> bool:
    """Ensure BigQuery datasets and tables exist"""
    client = get_client('bigquery')
    if not client:
        return False
    
    try:
        # Create dataset if it doesn't exist
        try:
            client.get_dataset(DATASET_ID)
            logger.info(f"Dataset {DATASET_ID} already exists")
        except Exception:
            dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
            dataset.location = "US"
            client.create_dataset(dataset, exists_ok=True)
            logger.info(f"Created dataset {DATASET_ID}")
        
        # Create tables if they don't exist
        for feed_name, feed_config in FEED_SOURCES.items():
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                client.get_table(full_table_id)
                logger.info(f"Table {table_id} already exists")
            except Exception:
                # Create with minimal schema, BigQuery will auto-detect the rest
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring resources: {str(e)}")
        return False

class ThreatDataIngestion:
    """Simplified threat data ingestion class"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        self.ready = ensure_resources()
        self.feed_stats = {}
    
    def process_all_feeds(self) -> List[Dict]:
        """Process all configured feeds"""
        if not self.ready:
            logger.error("Ingestion engine not properly initialized")
            return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        logger.info(f"Processing {len(FEED_SOURCES)} feeds")
        
        for feed_name in FEED_SOURCES:
            try:
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
        
        return results
    
    def process_feed(self, feed_name: str) -> Dict[str, Any]:
        """Process a feed and return results"""
        start_time = datetime.now()
        
        # Validate state and feed
        if not self.ready:
            return self._error_result(feed_name, "Processor not properly initialized")
            
        if feed_name not in FEED_SOURCES:
            return self._error_result(feed_name, "Unknown feed")
            
        feed_config = FEED_SOURCES[feed_name]
        
        try:
            # Get feed data
            data, error = self._fetch_feed_data(feed_name)
            
            if error:
                return self._error_result(feed_name, f"Fetch error: {error}")
                
            if not data:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No data collected",
                    "record_count": 0
                }
            
            # Process records
            records = self._process_records(data, feed_name, feed_config)
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records extracted",
                    "record_count": 0
                }
            
            # Upload to BigQuery
            record_count = self._upload_to_bigquery(records, feed_name, feed_config)
            
            if record_count == 0:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records uploaded",
                    "record_count": 0
                }
            
            # Publish event
            self._publish_event(feed_name, record_count)
            
            # Return success result
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "feed_type": feed_config.get("description", "Unknown feed"),
                "record_format": feed_config.get("format", "unknown"),
                "status": "success",
                "record_count": record_count,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            return self._error_result(feed_name, str(e), start_time)
    
    def _error_result(self, feed_name: str, message: str, start_time=None) -> Dict[str, Any]:
        """Create standardized error result"""
        duration = (datetime.now() - start_time).total_seconds() if start_time else 0
        return {
            "feed_name": feed_name,
            "status": "error",
            "message": message,
            "record_count": 0,
            "duration_seconds": duration,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _fetch_feed_data(self, feed_name: str) -> Tuple[Any, Optional[str]]:
        """Fetch data from a feed source"""
        feed_config = FEED_SOURCES[feed_name]
        url = feed_config["url"]
        
        logger.info(f"Fetching data from {feed_name} ({url})")
        
        try:
            # Special handling for ThreatFox
            if feed_name == "threatfox":
                try:
                    # Use the direct export URL (more reliable than API)
                    url = feed_config.get("opensrc_url", feed_config["url"])
                    
                    logger.info(f"Fetching ThreatFox data from {url}")
                    response = _rate_limited_request(url, timeout=30)
                    response.raise_for_status()
                    
                    return response.json(), None
                except Exception as e:
                    logger.error(f"Error fetching ThreatFox data: {str(e)}")
                    return None, f"Error: {str(e)}"
            
            # Handle compressed data
            if feed_config.get("zip_compressed"):
                try:
                    logger.info(f"Fetching compressed data from {url}")
                    response = _rate_limited_request(url, timeout=30)
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
            response = _rate_limited_request(url, timeout=30)
            response.raise_for_status()
            
            # Return data based on format
            feed_format = feed_config.get("format", "json")
            
            if feed_format == "json":
                data = response.json()
                
                # Handle nested data
                if "json_root" in feed_config:
                    root_field = feed_config["json_root"]
                    if root_field in data:
                        data = data[root_field]
                
                return data, None
                
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
    
    def _process_records(self, data: Any, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Process feed data into standardized records"""
        feed_format = feed_config.get("format", "json")
        
        if feed_format == "json":
            return self._process_json_data(data, feed_name, feed_config)
        elif feed_format == "csv":
            return self._process_csv_data(data, feed_name, feed_config)
        elif feed_format == "text":
            return self._process_text_data(data, feed_name, feed_config)
        else:
            logger.error(f"Unsupported format: {feed_format}")
            return []
    
    def _process_json_data(self, data: Any, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Process JSON feed data"""
        records = []
        timestamp = datetime.utcnow().isoformat()
        
        # Ensure data is a list
        if not isinstance(data, list):
            # Special handling for some feeds like PhishTank 
            if feed_name == "phishtank" and isinstance(data, dict):
                data = list(data.values())[0] if data else []
            # Handle ThreatFox format with multiple key-value pairs
            elif feed_name == "threatfox" and isinstance(data, dict):
                # ThreatFox format may have IOCs at the top level or in a field
                iocs = data.get("data", {}).get("iocs", [])
                if iocs:
                    data = iocs
                else:
                    # For the export format, data might be directly at the top level
                    # Format looks like {"1511419": [{"ioc_value": "..."}, ...]} with multiple IDs
                    flattened_data = []
                    for ioc_list in data.values():
                        if isinstance(ioc_list, list):
                            flattened_data.extend(ioc_list)
                    data = flattened_data
            else:
                data = [data]
        
        # Process each record
        for item in data:
            if not isinstance(item, dict):
                continue
                
            # Add ingestion timestamp
            record = item.copy()
            record["_ingestion_timestamp"] = timestamp
            
            records.append(record)
        
        logger.info(f"Processed {len(records)} records from {feed_name} JSON")
        return records
    
    def _process_csv_data(self, data: str, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Process CSV feed data with better handling of headers and comments"""
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
            
            # Check for quoted content (common in URLhaus CSV)
            has_quotes = '"' in filtered_data
            
            # Parse CSV with appropriate dialect
            if has_quotes:
                # Use csv.Sniffer to detect the dialect if needed
                dialect = csv.excel
                reader = csv.DictReader(StringIO(filtered_data), dialect=dialect)
            else:
                reader = csv.DictReader(StringIO(filtered_data))
            
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
                
                # Add ingestion timestamp
                record["_ingestion_timestamp"] = timestamp
                
                records.append(record)
            
            logger.info(f"Parsed {len(records)} records from {feed_name} CSV")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing CSV data for {feed_name}: {str(e)}")
            # Log sample of the data to assist with debugging
            if data:
                logger.error(f"First 200 chars of data: {data[:200]}")
            return []
    
    def _process_text_data(self, data: str, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Process text-based feeds"""
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
                
                record = {
                    "line_number": i + 1,
                    "content": line.strip(),
                    "_ingestion_timestamp": timestamp
                }
                records.append(record)
            
            logger.info(f"Processed {len(records)} records from {feed_name} text data")
            return records
        except Exception as e:
            logger.error(f"Error processing text data for {feed_name}: {str(e)}")
            return []
    
    def _upload_to_bigquery(self, records: List[Dict], feed_name: str, feed_config: Dict) -> int:
        """Upload records to BigQuery with automatic table creation and retry logic"""
        if not records:
            logger.warning(f"No records to upload for {feed_name}")
            return 0
        
        client = get_client('bigquery')
        if not client:
            logger.error("BigQuery client not initialized")
            return 0
        
        table_id = feed_config["table_id"]
        full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
        
        try:
            # Configure load job with schema auto-detection
            job_config = bigquery.LoadJobConfig(
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                schema_update_options=[bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
                source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                autodetect=True
            )
            
            # Convert records to newline-delimited JSON
            json_data = "\n".join([json.dumps(record) for record in records])
            
            # Load the data
            load_job = client.load_table_from_string(
                json_data, full_table_id, job_config=job_config
            )
            
            # Wait for the job to complete
            load_job.result(timeout=120)
            
            logger.info(f"Loaded {len(records)} records to {full_table_id}")
            return len(records)
        except Exception as e:
            logger.error(f"Error loading data to BigQuery: {str(e)}")
            
            # Check if table exists, create if it doesn't
            try:
                client.get_table(full_table_id)
            except Exception:
                logger.info(f"Table {full_table_id} not found, creating it...")
                
                # Create with minimal schema, BigQuery will auto-detect the rest
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                
                # Try again after creating the table
                try:
                    job_config = bigquery.LoadJobConfig(
                        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                        schema_update_options=[bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
                        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                        autodetect=True
                    )
                    
                    json_data = "\n".join([json.dumps(record) for record in records])
                    load_job = client.load_table_from_string(
                        json_data, full_table_id, job_config=job_config
                    )
                    load_job.result(timeout=120)
                    
                    logger.info(f"Loaded {len(records)} records to newly created {full_table_id}")
                    return len(records)
                except Exception as retry_e:
                    logger.error(f"Error loading data to newly created table: {str(retry_e)}")
            
            # If we got here, both attempts failed
            return 0
    
    def _publish_event(self, feed_name: str, count: int) -> bool:
        """Publish event to Pub/Sub to trigger analysis"""
        client = get_client('pubsub')
        if not client:
            logger.error("Pub/Sub publisher not initialized")
            return False
        
        try:
            topic_path = client.topic_path(PROJECT_ID, PUBSUB_TOPIC)
            
            # Prepare message
            message = {
                "feed_name": feed_name,
                "record_count": count,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "ingestion_complete"
            }
            
            data = json.dumps(message).encode("utf-8")
            
            # Publish message
            future = client.publish(topic_path, data=data)
            message_id = future.result(timeout=30)
            
            logger.info(f"Published ingestion event {message_id} for {feed_name}")
            return True
        except Exception as e:
            logger.error(f"Error publishing message: {str(e)}")
            return False

    def get_feed_statistics(self) -> Dict:
        """Get statistics about ingested data"""
        client = get_client('bigquery')
        if not client:
            return {"error": "BigQuery client not initialized"}
        
        try:
            stats = {
                "feeds": [],
                "total_records": 0,
                "active_feeds": 0,
                "timestamp": datetime.utcnow().isoformat(),
                "last_ingestion_run": self.feed_stats.get("last_run", "Never")
            }
            
            # Query for all tables in the dataset
            query = f"""
            SELECT table_id 
            FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__` 
            ORDER BY table_id
            """
            
            query_job = client.query(query)
            tables = [row.table_id for row in query_job.result()]
            
            # Get stats for each table
            for table_id in tables:
                try:
                    # Find the feed name that corresponds to this table
                    feed_name = None
                    feed_config = None
                    for name, config in FEED_SOURCES.items():
                        if config.get("table_id") == table_id:
                            feed_name = name
                            feed_config = config
                            break
                    
                    if not feed_name:
                        # This may be a system table or custom table
                        if table_id.startswith(('threat_', 'system_')):
                            continue
                        feed_name = table_id
                    
                    # Query record counts
                    count_query = f"""
                    SELECT 
                        COUNT(*) as record_count,
                        MIN(_ingestion_timestamp) as earliest_record,
                        MAX(_ingestion_timestamp) as latest_record,
                        COUNT(DISTINCT CAST(_ingestion_timestamp AS DATE)) as update_days
                    FROM `{PROJECT_ID}.{DATASET_ID}.{table_id}`
                    """
                    
                    count_job = client.query(count_query)
                    result = list(count_job.result())[0]
                    
                    record_count = result.record_count
                    earliest = result.earliest_record.isoformat() if result.earliest_record else None
                    latest = result.latest_record.isoformat() if result.latest_record else None
                    update_days = result.update_days
                    
                    # Calculate growth rate (records per day)
                    growth_rate = 0
                    if update_days > 0:
                        growth_rate = record_count / update_days
                    
                    feed_stats = {
                        "feed_name": feed_name,
                        "table_id": table_id,
                        "record_count": record_count,
                        "earliest_record": earliest,
                        "latest_record": latest,
                        "update_days": update_days,
                        "growth_rate": growth_rate,
                        "description": feed_config.get("description") if feed_config else "Custom feed"
                    }
                    
                    stats["feeds"].append(feed_stats)
                    stats["total_records"] += record_count
                    
                    # Count as active if it has data
                    if record_count > 0:
                        stats["active_feeds"] += 1
                    
                except Exception as e:
                    logger.warning(f"Error getting stats for table {table_id}: {str(e)}")
                    # Include the table with error
                    stats["feeds"].append({
                        "feed_name": feed_name if feed_name else table_id,
                        "table_id": table_id,
                        "error": str(e),
                        "record_count": 0
                    })
            
            # Add detail from last ingestion run if available
            if self.feed_stats and "details" in self.feed_stats:
                for feed_stat in stats["feeds"]:
                    feed_name = feed_stat["feed_name"]
                    # Find matching details from last run
                    for detail in self.feed_stats["details"]:
                        if detail.get("feed_name") == feed_name:
                            feed_stat["last_ingestion"] = {
                                "status": detail.get("status"),
                                "record_count": detail.get("record_count", 0),
                                "timestamp": detail.get("timestamp"),
                                "duration_seconds": detail.get("duration_seconds", 0)
                            }
                            break
            
            return stats
        except Exception as e:
            logger.error(f"Error getting feed statistics: {str(e)}")
            return {"error": str(e)}

# HTTP endpoint for triggering data ingestion
def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion"""
    ingestion = ThreatDataIngestion()
    
    # Parse request
    request_json = request.get_json(silent=True)
    
    if request_json:
        # Check for statistics request
        if request_json.get("get_stats"):
            stats = ingestion.get_feed_statistics()
            return stats
        
        # Check for specific feed
        feed_name = request_json.get("feed_name")
        if feed_name:
            if feed_name not in FEED_SOURCES:
                return {"error": f"Unknown feed: {feed_name}"}, 400
            
            result = ingestion.process_feed(feed_name)
            return result
    
    # Default to processing all feeds
    results = ingestion.process_all_feeds()
    return {"results": results, "count": len(results)}

if __name__ == "__main__":
    # Process all feeds when run directly
    ingestion = ThreatDataIngestion()
    results = ingestion.process_all_feeds()
    
    # Print results
    for result in results:
        print(f"{result.get('feed_name')}: {result.get('status')} ({result.get('record_count')} records)")
