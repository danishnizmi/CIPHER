"""
Threat Intelligence Platform - Data Ingestion Module
Handles collection of threat data from various open-source feeds and loads it into BigQuery.
Enhanced with smarter feed detection, resilient error handling, and improved CSV processing.
"""

import os
import json
import logging
import hashlib
import csv
import time
from io import StringIO, BytesIO
import zipfile
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple

from google.cloud import storage
from google.cloud import pubsub_v1
from google.cloud import bigquery
from google.api_core import exceptions as gcp_exceptions
import requests

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

# Open source feed definitions with more detailed configuration
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "table_id": "threatfox_iocs",
        "opensrc_url": "https://threatfox.abuse.ch/export/json/recent/",
        "format": "json",
        "api_key_config": "threatfox_api_key", 
        "auth_required": False,
        "description": "ThreatFox IOCs - Malware indicators database"
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "table_id": "phishtank_urls",
        "format": "json",
        "auth_required": False,
        "description": "PhishTank - Community-verified phishing URLs"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv",
        "zip_compressed": True,
        "skip_lines": 8,  # Skip first 8 lines (comments)
        "description": "URLhaus - Database of malicious URLs"
    },
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "table_id": "feodotracker_c2",
        "format": "json",
        "auth_required": False,
        "description": "Feodo Tracker - Botnet C2 servers"
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "table_id": "cisa_vulnerabilities",
        "format": "json",
        "json_root": "vulnerabilities",  # The actual data is in this subfield
        "description": "CISA Known Exploited Vulnerabilities"
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "table_id": "tor_exit_nodes",
        "format": "text",
        "description": "Tor Exit Nodes - IP addresses of Tor exit nodes"
    },
    "misp_feed": {
        "url": "https://example.com/feed.json",  # Replace with actual MISP feed URL
        "table_id": "misp_events",
        "format": "json",
        "auth_type": "header",
        "auth_header": "Authorization",
        "auth_key_config": "misp_api_key",
        "enabled": False,  # Disabled by default (needs configuration)
        "description": "MISP - Open Source Threat Intelligence Platform"
    },
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "table_id": "alienvault_pulses",
        "format": "json",
        "auth_type": "header",
        "auth_header": "X-OTX-API-KEY",
        "auth_key_config": "alienvault_api_key",
        "enabled": False,  # Disabled by default (needs API key)
        "description": "AlienVault OTX - Open Threat Exchange"
    }
}

def initialize_clients():
    """Initialize GCP clients"""
    global bq_client, storage_client, publisher
    
    try:
        # Initialize BigQuery
        if not bq_client:
            bq_client = bigquery.Client(project=PROJECT_ID)
            logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
        
        # Initialize Cloud Storage
        if not storage_client:
            storage_client = storage.Client(project=PROJECT_ID)
            logger.info(f"Storage client initialized for project {PROJECT_ID}")
        
        # Initialize Pub/Sub
        if not publisher:
            publisher = pubsub_v1.PublisherClient()
            logger.info("Pub/Sub publisher initialized")
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize clients: {str(e)}")
        return False

def ensure_resources():
    """Ensure BigQuery datasets and tables exist"""
    if not bq_client:
        return False
    
    try:
        # Create dataset if it doesn't exist
        try:
            bq_client.get_dataset(DATASET_ID)
            logger.info(f"Dataset {DATASET_ID} already exists")
        except Exception:
            dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
            dataset.location = "US"
            bq_client.create_dataset(dataset, exists_ok=True)
            logger.info(f"Created dataset {DATASET_ID}")
        
        # Create tables if they don't exist
        for feed_name, feed_config in FEED_SOURCES.items():
            # Skip disabled feeds
            if not feed_config.get("enabled", True):
                continue
                
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                bq_client.get_table(full_table_id)
                logger.info(f"Table {table_id} already exists")
            except Exception:
                # Create with minimal schema, BigQuery will auto-detect the rest
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring resources: {str(e)}")
        return False

def get_feed_api_key(feed_config: Dict) -> Optional[str]:
    """Get API key for a feed from config or environment
    
    Args:
        feed_config: Feed configuration dictionary
        
    Returns:
        API key if available, None otherwise
    """
    if not feed_config.get("auth_required", False) and not feed_config.get("auth_key_config"):
        return None
        
    key_config_name = feed_config.get("auth_key_config")
    if not key_config_name:
        return None
        
    # Try to get from environment
    env_key = os.environ.get(key_config_name.upper())
    if env_key:
        return env_key
        
    # Try to get from config
    api_keys_config = config.get_cached_config('api-keys') or {}
    return api_keys_config.get(key_config_name)

class ThreatFeedIngestion:
    """Handles ingestion from open source threat feeds"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        self.ready = initialize_clients() and ensure_resources()
        self._feed_configs = {}  # Cache for feed configurations (including API keys)
    
    def fetch_feed_data(self, feed_name: str) -> List[Dict]:
        """Fetch data from a specific feed
        
        Args:
            feed_name: Name of the feed to fetch
            
        Returns:
            List of data records from the feed
        """
        if feed_name not in FEED_SOURCES:
            logger.error(f"Unknown feed: {feed_name}")
            return []
        
        feed_config = FEED_SOURCES[feed_name]
        
        # Skip disabled feeds
        if not feed_config.get("enabled", True):
            logger.warning(f"Feed {feed_name} is disabled, skipping")
            return []
        
        url = feed_config["url"]
        feed_format = feed_config.get("format", "json")
        
        logger.info(f"Fetching data from {feed_name} ({url})")
        
        try:
            # Build request parameters
            headers = {}
            params = {}
            
            # Handle authentication if required
            if feed_config.get("auth_required", False) or feed_config.get("auth_key_config"):
                api_key = get_feed_api_key(feed_config)
                if not api_key:
                    logger.warning(f"API key required for {feed_name} but none found")
                    return []
                
                # Add API key to headers or params based on config
                auth_type = feed_config.get("auth_type", "header")
                if auth_type == "header":
                    headers[feed_config.get("auth_header", "Authorization")] = api_key
                elif auth_type == "param":
                    params[feed_config.get("auth_param", "key")] = api_key
            
            # Special handling for different feed formats
            if feed_name == "threatfox":
                return self._fetch_threatfox_data(feed_config)
            elif feed_name == "urlhaus" and feed_config.get("zip_compressed"):
                return self._fetch_compressed_data(feed_config)
            elif feed_format == "text":
                return self._fetch_text_feed(feed_name, feed_config)
            
            # Handle standard JSON/CSV feeds
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            if feed_format == "json":
                data = response.json()
                
                # Handle JSON feeds with data in a subfield
                if "json_root" in feed_config:
                    root_field = feed_config["json_root"]
                    if root_field in data:
                        data = data[root_field]
                
                # Ensure the data is a list
                if not isinstance(data, list):
                    data = [data]
                
                # Add ingestion timestamp
                timestamp = datetime.utcnow().isoformat()
                for item in data:
                    if isinstance(item, dict):
                        item["_ingestion_timestamp"] = timestamp
                
                return data
            elif feed_format == "csv":
                # Parse CSV
                csv_data = response.text
                return self._parse_csv_data(csv_data, feed_config)
            
            logger.warning(f"Unsupported format for {feed_name}: {feed_format}")
            return []
        except Exception as e:
            logger.error(f"Error fetching {feed_name}: {str(e)}")
            return []
    
    def _fetch_threatfox_data(self, feed_config: Dict) -> List[Dict]:
        """Fetch ThreatFox data using their API or direct export URL
        
        Args:
            feed_config: ThreatFox feed configuration
            
        Returns:
            List of ThreatFox IOC records
        """
        try:
            # Use the direct export URL (more reliable than API)
            url = feed_config.get("opensrc_url", feed_config["url"])
            
            logger.info(f"Fetching ThreatFox data from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            records = []
            
            # Process the data based on format
            if isinstance(data, list):
                # Direct export format (list of IOCs)
                for item in data:
                    record = {
                        "ioc_id": item.get("id", ""),
                        "ioc": item.get("ioc", ""),
                        "threat_type": item.get("threat_type", ""),
                        "threat_type_desc": item.get("threat_type_desc", ""),
                        "ioc_type": item.get("ioc_type", ""),
                        "malware": item.get("malware", ""),
                        "malware_printable": item.get("malware_printable", ""),
                        "malware_alias": item.get("malware_alias", ""),
                        "confidence_level": item.get("confidence_level", ""),
                        "first_seen": item.get("first_seen", ""),
                        "last_seen": item.get("last_seen", ""),
                        "reference": item.get("reference", ""),
                        "reporter": item.get("reporter", ""),
                        "_ingestion_timestamp": datetime.utcnow().isoformat()
                    }
                    records.append(record)
            elif isinstance(data, dict) and "data" in data:
                # API response format (data field contains IOCs)
                iocs = data.get("data", [])
                for item in iocs:
                    record = {
                        "ioc_id": item.get("id", ""),
                        "ioc": item.get("ioc", ""),
                        "threat_type": item.get("threat_type", ""),
                        "threat_type_desc": item.get("threat_type_desc", ""),
                        "ioc_type": item.get("ioc_type", ""),
                        "malware": item.get("malware", ""),
                        "confidence_level": item.get("confidence_level", ""),
                        "first_seen": item.get("first_seen", ""),
                        "last_seen": item.get("last_seen", ""),
                        "_ingestion_timestamp": datetime.utcnow().isoformat()
                    }
                    records.append(record)
            
            logger.info(f"Processed {len(records)} ThreatFox records")
            return records
        except Exception as e:
            logger.error(f"Error fetching ThreatFox data: {str(e)}")
            return []
    
    def _fetch_compressed_data(self, feed_config: Dict) -> List[Dict]:
        """Fetch and decompress ZIP or GZip data
        
        Args:
            feed_config: Feed configuration with compression details
            
        Returns:
            List of processed records
        """
        try:
            url = feed_config["url"]
            format_type = feed_config.get("format", "csv")
            
            logger.info(f"Fetching compressed data from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Handle ZIP files
            if url.endswith('.zip') or feed_config.get("zip_compressed"):
                with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
                    # Get first file in the ZIP (or the specified one)
                    target_file = feed_config.get("zip_file_name")
                    if not target_file:
                        target_file = zip_file.namelist()[0]
                    
                    with zip_file.open(target_file) as file:
                        content = file.read().decode('utf-8', errors='ignore')
                        
                        if format_type == "csv":
                            return self._parse_csv_data(content, feed_config)
                        elif format_type == "json":
                            data = json.loads(content)
                            # Ensure it's a list of records
                            if not isinstance(data, list):
                                data = [data]
                            return data
                        else:
                            logger.warning(f"Unsupported format in compressed file: {format_type}")
                            return []
                            
            # Handle GZip files (if needed in the future)
            # For now, we just return an empty list
            logger.warning("Unsupported compression format")
            return []
            
        except Exception as e:
            logger.error(f"Error processing compressed data: {str(e)}")
            return []
    
    def _fetch_text_feed(self, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Fetch and parse text-based feeds (like Tor exit nodes)
        
        Args:
            feed_name: Name of the feed
            feed_config: Feed configuration
            
        Returns:
            List of processed records
        """
        try:
            url = feed_config["url"]
            
            logger.info(f"Fetching text feed from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            # Process based on feed type
            if feed_name == "tor_exit_nodes":
                for line in lines:
                    if line and not line.startswith('#'):
                        record = {
                            "ip_address": line.strip(),
                            "type": "tor_exit_node",
                            "_ingestion_timestamp": timestamp
                        }
                        records.append(record)
            else:
                # Generic text processing for other text feeds
                for i, line in enumerate(lines):
                    if line and not line.startswith('#'):
                        record = {
                            "line_number": i + 1,
                            "content": line.strip(),
                            "_ingestion_timestamp": timestamp
                        }
                        records.append(record)
            
            logger.info(f"Processed {len(records)} {feed_name} records")
            return records
        except Exception as e:
            logger.error(f"Error fetching {feed_name} data: {str(e)}")
            return []
    
    def _parse_csv_data(self, csv_content: str, feed_config: Dict) -> List[Dict]:
        """Parse CSV data with intelligent handling of different formats
        
        Args:
            csv_content: CSV data as string
            feed_config: Feed configuration with CSV options
            
        Returns:
            List of records from CSV
        """
        try:
            # Handle skip lines if specified
            skip_lines = feed_config.get("skip_lines", 0)
            if skip_lines > 0:
                lines = csv_content.split('\n')
                if len(lines) <= skip_lines:
                    logger.warning(f"CSV has fewer lines ({len(lines)}) than skip_lines ({skip_lines})")
                    return []
                
                csv_content = '\n'.join(lines[skip_lines:])
            
            # Parse CSV
            reader = csv.DictReader(StringIO(csv_content))
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in reader:
                # Create a record, retaining all columns
                record = {key: value for key, value in row.items() if key}
                
                # Add ingestion timestamp
                record["_ingestion_timestamp"] = timestamp
                
                # Process tags if they're comma-separated
                if "tags" in record and record["tags"]:
                    try:
                        record["tags"] = [tag.strip() for tag in record["tags"].split(",")]
                    except:
                        # Keep as string if splitting fails
                        pass
                        
                records.append(record)
            
            logger.info(f"Parsed {len(records)} records from CSV")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing CSV data: {str(e)}")
            return []
    
    def upload_to_bigquery(self, feed_name: str, records: List[Dict]) -> int:
        """Upload records to BigQuery
        
        Args:
            feed_name: Name of the feed (for table selection)
            records: List of records to upload
            
        Returns:
            Number of records uploaded
        """
        if not records:
            logger.warning(f"No records to upload for {feed_name}")
            return 0
        
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return 0
        
        feed_config = FEED_SOURCES.get(feed_name)
        if not feed_config:
            logger.error(f"Unknown feed: {feed_name}")
            return 0
        
        table_id = feed_config["table_id"]
        full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
        
        try:
            # Ensure all records have an ingestion timestamp
            timestamp = datetime.utcnow().isoformat()
            for record in records:
                if "_ingestion_timestamp" not in record:
                    record["_ingestion_timestamp"] = timestamp
            
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
            load_job = bq_client.load_table_from_string(
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
                bq_client.get_table(full_table_id)
            except Exception:
                logger.info(f"Table {full_table_id} not found, creating it...")
                
                # Create with minimal schema, BigQuery will auto-detect the rest
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                bq_client.create_table(table, exists_ok=True)
                
                # Try again after creating the table
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
                    load_job = bq_client.load_table_from_string(
                        json_data, full_table_id, job_config=job_config
                    )
                    
                    # Wait for the job to complete
                    load_job.result(timeout=120)
                    
                    logger.info(f"Loaded {len(records)} records to newly created {full_table_id}")
                    return len(records)
                except Exception as retry_e:
                    logger.error(f"Error loading data to newly created table: {str(retry_e)}")
            
            # If we got here, both attempts failed
            return 0
    
    def publish_ingestion_event(self, feed_name: str, count: int) -> bool:
        """Publish event to Pub/Sub to trigger analysis
        
        Args:
            feed_name: Name of the processed feed
            count: Number of records ingested
            
        Returns:
            True if event was published successfully, False otherwise
        """
        if not publisher:
            logger.error("Pub/Sub publisher not initialized")
            return False
        
        try:
            topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
            
            # Prepare message
            message = {
                "feed_name": feed_name,
                "record_count": count,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "ingestion_complete"
            }
            
            data = json.dumps(message).encode("utf-8")
            
            # Publish message
            future = publisher.publish(topic_path, data=data)
            message_id = future.result(timeout=30)
            
            logger.info(f"Published ingestion event {message_id} for {feed_name}")
            return True
        except Exception as e:
            logger.error(f"Error publishing message: {str(e)}")
            return False
    
    def process_feed(self, feed_name: str) -> Dict:
        """Process a single feed end-to-end
        
        Args:
            feed_name: Name of the feed to process
            
        Returns:
            Dictionary with processing results
        """
        start_time = datetime.now()
        
        if not self.ready:
            logger.error("Ingestion engine not properly initialized")
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": "Ingestion engine not properly initialized",
                "record_count": 0
            }
        
        if feed_name not in FEED_SOURCES:
            logger.error(f"Unknown feed: {feed_name}")
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": "Unknown feed",
                "record_count": 0
            }
        
        feed_config = FEED_SOURCES[feed_name]
        
        # Check if feed is enabled
        if not feed_config.get("enabled", True):
            logger.warning(f"Feed {feed_name} is disabled")
            return {
                "feed_name": feed_name,
                "status": "skipped",
                "message": "Feed is disabled",
                "record_count": 0
            }
        
        try:
            # Fetch data
            records = self.fetch_feed_data(feed_name)
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No data collected",
                    "record_count": 0
                }
            
            # Upload to BigQuery
            count = self.upload_to_bigquery(feed_name, records)
            
            # Publish event
            if count > 0:
                self.publish_ingestion_event(feed_name, count)
            
            # Return results
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "feed_type": feed_config.get("description", "Unknown feed"),
                "record_format": feed_config.get("format", "unknown"),
                "status": "success",
                "record_count": count,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": str(e),
                "record_count": 0,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def process_all_feeds(self) -> List[Dict]:
        """Process all configured feeds
        
        Returns:
            List of processing results for each feed
        """
        if not self.ready:
            logger.error("Ingestion engine not properly initialized")
            return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        active_feeds = [name for name, config in FEED_SOURCES.items() 
                        if config.get("enabled", True)]
        
        logger.info(f"Processing {len(active_feeds)} active feeds")
        
        for feed_name in active_feeds:
            result = self.process_feed(feed_name)
            results.append(result)
            
            # Add a small delay between feeds to avoid rate limits
            time.sleep(2)
        
        # Log a summary
        success_count = sum(1 for r in results if r.get("status") == "success")
        total_records = sum(r.get("record_count", 0) for r in results)
        
        logger.info(f"Completed processing {len(results)} feeds: {success_count} successful, {total_records} total records")
        return results
    
    def process_custom_feed(self, feed_data: Dict) -> Dict:
        """Process a custom feed from uploaded data
        
        Args:
            feed_data: Dictionary with feed configuration and content
            
        Returns:
            Processing results
        """
        feed_name = feed_data.get("feed_name", "custom_feed")
        feed_type = feed_data.get("feed_type", "csv")
        table_id = feed_data.get("table_id", f"custom_{int(time.time())}")
        content = feed_data.get("content")
        
        if not content:
            return {"status": "error", "message": "No content provided"}
        
        start_time = datetime.now()
        
        try:
            # Create a temporary feed config
            temp_feed_config = {
                "url": "custom_data",
                "table_id": table_id,
                "format": feed_type,
                "description": feed_data.get("description", "Custom uploaded feed")
            }
            
            # Parse the data based on type
            records = []
            
            if feed_type == "csv":
                records = self._parse_csv_data(content, temp_feed_config)
            elif feed_type == "json":
                try:
                    json_data = json.loads(content)
                    # Ensure it's a list
                    if isinstance(json_data, dict):
                        # Check for data in a common root field
                        for field in ["data", "results", "items", "records"]:
                            if field in json_data and isinstance(json_data[field], list):
                                json_data = json_data[field]
                                break
                        else:
                            # If no list field found, wrap the dict in a list
                            json_data = [json_data]
                    
                    # Add ingestion timestamp
                    timestamp = datetime.utcnow().isoformat()
                    for item in json_data:
                        if isinstance(item, dict):
                            item["_ingestion_timestamp"] = timestamp
                    
                    records = json_data
                except json.JSONDecodeError as e:
                    return {"status": "error", "message": f"Invalid JSON: {str(e)}"}
            elif feed_type == "text":
                lines = content.strip().split('\n')
                timestamp = datetime.utcnow().isoformat()
                
                for i, line in enumerate(lines):
                    if line and not line.startswith('#'):
                        record = {
                            "line_number": i + 1,
                            "content": line.strip(),
                            "_ingestion_timestamp": timestamp
                        }
                        records.append(record)
            else:
                return {"status": "error", "message": f"Unsupported feed type: {feed_type}"}
            
            if not records:
                return {
                    "status": "warning",
                    "message": "No records found in the provided content",
                    "record_count": 0
                }
            
            # Store a copy in Cloud Storage if appropriate
            if storage_client and BUCKET_NAME:
                try:
                    bucket = storage_client.bucket(BUCKET_NAME)
                    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    blob = bucket.blob(f"custom_feeds/{feed_name}_{timestamp_str}.{feed_type}")
                    blob.upload_from_string(content)
                    logger.info(f"Uploaded custom feed to GCS: {blob.name}")
                except Exception as e:
                    logger.warning(f"Failed to upload custom feed to storage: {str(e)}")
            
            # Upload to BigQuery
            FEED_SOURCES[feed_name] = temp_feed_config  # Temporarily add to config
            count = self.upload_to_bigquery(feed_name, records)
            del FEED_SOURCES[feed_name]  # Remove temporary config
            
            # Publish event to trigger analysis
            if count > 0:
                self.publish_ingestion_event(table_id, count)
            
            # Return results
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "table_id": table_id,
                "status": "success",
                "record_count": count,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error processing custom feed: {str(e)}")
            return {
                "status": "error",
                "message": str(e),
                "record_count": 0
            }
    
    def get_feed_statistics(self) -> Dict:
        """Get statistics about ingested data
        
        Returns:
            Statistics about feeds and record counts
        """
        if not bq_client:
            return {"error": "BigQuery client not initialized"}
        
        try:
            stats = {
                "feeds": [],
                "total_records": 0,
                "active_feeds": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Query for all tables in the dataset
            query = f"""
            SELECT table_id 
            FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__` 
            ORDER BY table_id
            """
            
            query_job = bq_client.query(query)
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
                        MAX(_ingestion_timestamp) as latest_record
                    FROM `{PROJECT_ID}.{DATASET_ID}.{table_id}`
                    """
                    
                    count_job = bq_client.query(count_query)
                    result = list(count_job.result())[0]
                    
                    record_count = result.record_count
                    earliest = result.earliest_record.isoformat() if result.earliest_record else None
                    latest = result.latest_record.isoformat() if result.latest_record else None
                    
                    feed_stats = {
                        "feed_name": feed_name,
                        "table_id": table_id,
                        "record_count": record_count,
                        "earliest_record": earliest,
                        "latest_record": latest,
                        "description": feed_config.get("description") if feed_config else "Custom feed"
                    }
                    
                    stats["feeds"].append(feed_stats)
                    stats["total_records"] += record_count
                    
                    # Count as active if it has data and is enabled in config
                    if record_count > 0 and (not feed_config or feed_config.get("enabled", True)):
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
            
            return stats
        except Exception as e:
            logger.error(f"Error getting feed statistics: {str(e)}")
            return {"error": str(e)}
    
    def check_feed_health(self) -> Dict[str, Any]:
        """Check health of all feeds
        
        Returns:
            Dictionary with health status for each feed
        """
        feed_health = {
            "status": "healthy",
            "feeds": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # First get statistics from BigQuery
        stats = self.get_feed_statistics()
        
        # Error in getting stats
        if "error" in stats:
            feed_health["status"] = "degraded"
            feed_health["error"] = stats["error"]
            return feed_health
        
        # Create a mapping of table_id to stats
        table_stats = {feed["table_id"]: feed for feed in stats.get("feeds", [])}
        
        # Check each configured feed
        for feed_name, feed_config in FEED_SOURCES.items():
            # Skip disabled feeds
            if not feed_config.get("enabled", True):
                feed_health["feeds"][feed_name] = {
                    "status": "disabled",
                    "table_id": feed_config.get("table_id"),
                    "message": "Feed is disabled in configuration"
                }
                continue
                
            table_id = feed_config.get("table_id")
            
            # Get stats for this feed
            feed_stats = table_stats.get(table_id, {})
            latest_record = feed_stats.get("latest_record")
            record_count = feed_stats.get("record_count", 0)
            
            feed_status = {
                "status": "healthy",
                "table_id": table_id,
                "record_count": record_count
            }
            
            # Check if the feed has data
            if record_count == 0:
                feed_status["status"] = "warning"
                feed_status["message"] = "No records found"
                
            # Check if the feed has recent data (updated in the last 7 days for daily feeds)
            elif latest_record:
                try:
                    latest_date = datetime.fromisoformat(latest_record.replace('Z', '+00:00'))
                    days_since_update = (datetime.utcnow() - latest_date).days
                    
                    feed_status["last_updated_days_ago"] = days_since_update
                    
                    # Daily feeds should have data in the last 2 days
                    if feed_config.get("frequency") == "daily" and days_since_update > 2:
                        feed_status["status"] = "warning"
                        feed_status["message"] = f"Data is {days_since_update} days old"
                    # Weekly feeds should have data in the last 8 days
                    elif feed_config.get("frequency") == "weekly" and days_since_update > 8:
                        feed_status["status"] = "warning"
                        feed_status["message"] = f"Data is {days_since_update} days old"
                    # Default: feeds should have data in the last 7 days
                    elif days_since_update > 7:
                        feed_status["status"] = "warning"
                        feed_status["message"] = f"Data is {days_since_update} days old"
                except Exception as e:
                    # Handle date parsing errors
                    feed_status["last_updated"] = latest_record
            
            # Add feed status
            feed_health["feeds"][feed_name] = feed_status
            
            # Update overall status if any feed is unhealthy
            if feed_status["status"] != "healthy" and feed_health["status"] == "healthy":
                feed_health["status"] = "degraded"
        
        # Summary stats
        feed_health["total_feeds"] = len(FEED_SOURCES)
        feed_health["active_feeds"] = stats.get("active_feeds", 0)
        feed_health["total_records"] = stats.get("total_records", 0)
        
        return feed_health

# HTTP handler for Cloud Functions
def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion"""
    ingestion = ThreatFeedIngestion()
    
    # Parse request
    request_json = request.get_json(silent=True)
    
    if request_json:
        # Check for statistics request
        if request_json.get("get_stats"):
            stats = ingestion.get_feed_statistics()
            return stats
            
        # Check for health check request
        if request_json.get("health_check"):
            health = ingestion.check_feed_health()
            return health
        
        # Check for custom feed processing
        if request_json.get("custom_feed"):
            result = ingestion.process_custom_feed(request_json)
            return result
        
        # Check for specific feed
        feed_name = request_json.get("feed_name")
        if feed_name:
            if feed_name not in FEED_SOURCES:
                return {"error": f"Unknown feed: {feed_name}"}, 400
            
            result = ingestion.process_feed(feed_name)
            return result
        
        # Check for process_all flag
        if request_json.get("process_all"):
            results = ingestion.process_all_feeds()
            return {"results": results, "count": len(results)}
    
    # Default to processing all feeds
    results = ingestion.process_all_feeds()
    return {"results": results, "count": len(results)}

# CLI entry point
if __name__ == "__main__":
    # Process all feeds
    ingestion = ThreatFeedIngestion()
    results = ingestion.process_all_feeds()
    
    # Print results
    for result in results:
        status = result.get("status", "unknown")
        feed = result.get("feed_name", "unknown")
        count = result.get("record_count", 0)
        print(f"{feed}: {status} ({count} records)")
    
    # Get statistics
    stats = ingestion.get_feed_statistics()
    print(f"\nTotal records ingested: {stats.get('total_records', 0)}")
    print(f"Active feeds: {stats.get('active_feeds', 0)}")
