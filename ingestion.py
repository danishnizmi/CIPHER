"""
Threat Intelligence Platform - Data Ingestion Module
Handles collection of threat data from various sources and loads it into GCP.
"""

import os
import json
import logging
import hashlib
import csv
from io import StringIO
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union

from google.cloud import storage
from google.cloud import pubsub_v1
from google.cloud import bigquery
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

# Initialize GCP clients
try:
    storage_client = storage.Client()
except Exception as e:
    logger.error(f"Failed to initialize storage client: {str(e)}")
    storage_client = None

try:
    bq_client = bigquery.Client()
except Exception as e:
    logger.error(f"Failed to initialize BigQuery client: {str(e)}")
    bq_client = None

try:
    publisher = pubsub_v1.PublisherClient()
except Exception as e:
    logger.error(f"Failed to initialize PubSub client: {str(e)}")
    publisher = None

# Get OSINT Feed Configuration from config module
def get_feed_config():
    """Get feed configuration with fallback"""
    feed_config = config.get_cached_config('feed-config')
    
    if 'feeds' in feed_config:
        # Convert list to dict structure using 'name' as key
        feed_dict = {}
        for feed in feed_config.get('feeds', []):
            if 'name' in feed:
                feed_dict[feed['name']] = feed
        
        if feed_dict:
            return feed_dict
    
    # Fallback configuration if not in config module
    return {
        "alienvault": {
            "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "auth_header": "X-OTX-API-KEY",
            "auth_key": os.environ.get("ALIENVAULT_API_KEY", ""),
            "table_id": "alienvault_pulses",
            "active": True
        },
        "misp": {
            "url": "https://your-misp-instance.com/events/restSearch",
            "auth_header": "Authorization",
            "auth_key": os.environ.get("MISP_API_KEY", ""),
            "table_id": "misp_events",
            "active": False
        },
        "threatfox": {
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "table_id": "threatfox_iocs",
            "active": True
        },
        "phishtank": {
            "url": "https://data.phishtank.com/data/online-valid.json",
            "table_id": "phishtank_urls",
            "active": True
        },
        "urlhaus": {
            "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            "table_id": "urlhaus_malware",
            "active": True
        },
        "feodotracker": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "table_id": "feodotracker_c2",
            "active": True
        },
        "sslbl": {
            "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.json",
            "table_id": "sslbl_certificates",
            "active": True
        }
    }

# Load feed configuration
FEED_CONFIG = get_feed_config()

class ThreatDataIngestion:
    """Main class for handling threat data ingestion"""
    
    def __init__(self):
        """Initialize ingestion resources"""
        self._ensure_resources_exist()
    
    def _ensure_resources_exist(self):
        """Ensure required GCP resources exist (bucket, dataset, tables)"""
        # Create GCS bucket if it doesn't exist
        if storage_client:
            try:
                storage_client.get_bucket(BUCKET_NAME)
                logger.info(f"Bucket {BUCKET_NAME} exists")
            except Exception as e:
                try:
                    bucket = storage_client.create_bucket(BUCKET_NAME, location="us-central1")
                    logger.info(f"Created bucket {bucket.name}")
                except Exception as create_e:
                    logger.error(f"Error creating bucket: {str(create_e)}")
        
        # Create BigQuery dataset if it doesn't exist
        if bq_client:
            try:
                bq_client.get_dataset(DATASET_ID)
                logger.info(f"Dataset {DATASET_ID} exists")
            except Exception as e:
                try:
                    dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
                    dataset.location = "US"
                    dataset = bq_client.create_dataset(dataset)
                    logger.info(f"Created dataset {DATASET_ID}")
                except Exception as create_e:
                    logger.error(f"Error creating dataset: {str(create_e)}")
        
        # Tables will be created on first insert with auto-detected schema
    
    def _get_feed_config(self, feed_name: str) -> Dict[str, Any]:
        """Get configuration for a specific feed with error handling"""
        if feed_name not in FEED_CONFIG:
            logger.error(f"Feed {feed_name} not found in configuration")
            raise ValueError(f"Unknown feed: {feed_name}")
        
        feed_config = FEED_CONFIG[feed_name]
        
        # Check if feed is active
        if not feed_config.get("active", True):
            logger.warning(f"Feed {feed_name} is not active")
            raise ValueError(f"Feed {feed_name} is not active")
        
        # Check for required URL
        if not feed_config.get("url"):
            logger.error(f"Feed {feed_name} has no URL configured")
            raise ValueError(f"Feed {feed_name} has no URL configured")
        
        return feed_config
    
    def process_feed_data(self, feed_name: str, data: Any) -> List[Dict[str, Any]]:
        """Process data from a specific feed into a standardized format"""
        processed_data = []
        
        # Handle different feed data structures
        if feed_name == "alienvault":
            # AlienVault returns a dict with a 'results' array
            if isinstance(data, dict) and "results" in data:
                feed_items = data["results"]
            else:
                feed_items = data if isinstance(data, list) else []
            
            # Process each pulse
            for pulse in feed_items:
                # Add ingestion timestamp
                pulse["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                processed_data.append(pulse)
        
        elif feed_name == "misp":
            # MISP returns a dict with a 'response' array
            if isinstance(data, dict) and "response" in data:
                feed_items = data["response"]
            else:
                feed_items = data if isinstance(data, list) else []
            
            # Process each event
            for event in feed_items:
                # Add ingestion timestamp
                event["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                processed_data.append(event)
        
        elif feed_name == "threatfox":
            # ThreatFox API returns a dict with a 'data' array
            if isinstance(data, dict):
                if "data" in data and isinstance(data["data"], list):
                    feed_items = data["data"]
                elif "query_status" in data:
                    # Handle ThreatFox search responses
                    if "data" in data and isinstance(data["data"], dict):
                        feed_items = [data["data"]]
                    else:
                        feed_items = []
                else:
                    feed_items = [data]
            else:
                feed_items = data if isinstance(data, list) else []
            
            # Process each IOC
            for ioc in feed_items:
                # Add ingestion timestamp
                ioc["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                processed_data.append(ioc)
        
        elif feed_name == "phishtank":
            # PhishTank returns a list of phishing URLs
            feed_items = data if isinstance(data, list) else []
            
            # Process each phishing entry
            for entry in feed_items:
                processed_entry = {
                    "url": entry.get("url"),
                    "phish_id": entry.get("phish_id"),
                    "verified": entry.get("verified"),
                    "verification_time": entry.get("verification_time"),
                    "target": entry.get("target"),
                    "details": entry.get("details"),
                    "_ingestion_timestamp": datetime.utcnow().isoformat()
                }
                processed_data.append(processed_entry)
        
        elif feed_name == "urlhaus":
            # URLhaus API returns a dict with a 'urls' array
            if isinstance(data, dict) and "urls" in data:
                feed_items = data["urls"]
            else:
                feed_items = data if isinstance(data, list) else []
            
            # Process each malicious URL
            for entry in feed_items:
                processed_entry = {
                    "url": entry.get("url"),
                    "status": entry.get("url_status"),
                    "date_added": entry.get("date_added"),
                    "threat": entry.get("threat"),
                    "tags": entry.get("tags"),
                    "malware_type": entry.get("malware"),
                    "_ingestion_timestamp": datetime.utcnow().isoformat()
                }
                processed_data.append(processed_entry)
        
        elif feed_name == "feodotracker":
            # Feodo Tracker returns a list of C2 servers
            feed_items = data if isinstance(data, list) else []
            
            # Process each C2 server
            for entry in feed_items:
                processed_entry = {
                    "ip_address": entry.get("ip_address"),
                    "port": entry.get("port"),
                    "status": entry.get("status"),
                    "hostname": entry.get("hostname"),
                    "first_seen": entry.get("first_seen"),
                    "last_online": entry.get("last_online"),
                    "malware": entry.get("malware"),
                    "_ingestion_timestamp": datetime.utcnow().isoformat()
                }
                processed_data.append(processed_entry)
        
        elif feed_name == "sslbl":
            # SSL Blacklist returns a list of malicious certificates
            feed_items = data if isinstance(data, list) else []
            
            # Process each certificate
            for entry in feed_items:
                processed_entry = {
                    "ssl_fingerprint": entry.get("sha1"),
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "malware": entry.get("subject"),
                    "_ingestion_timestamp": datetime.utcnow().isoformat()
                }
                processed_data.append(processed_entry)
        
        else:
            # Generic fallback for unknown feeds - just add timestamp
            if isinstance(data, list):
                for item in data:
                    item["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                    processed_data.append(item)
            elif isinstance(data, dict):
                data["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                processed_data.append(data)
        
        return processed_data
    
    def collect_feed_data(self, feed_name: str) -> List[Dict[str, Any]]:
        """Collect data from a specific feed"""
        feed_config = self._get_feed_config(feed_name)
        headers = {}
        
        # Set authentication headers if configured
        if "auth_header" in feed_config and "auth_key" in feed_config and feed_config["auth_key"]:
            headers[feed_config["auth_header"]] = feed_config["auth_key"]
        
        # Set user agent to avoid blocks
        headers["User-Agent"] = "ThreatIntelligencePlatform/1.0"
        
        # Prepare request
        request_data = None
        request_method = feed_config.get("method", "GET")
        
        # Special handling for ThreatFox API which requires POST with JSON
        if feed_name == "threatfox":
            request_method = "POST"
            request_data = {"query": "get_iocs", "days": 7}
        
        try:
            logger.info(f"Collecting data from {feed_name} feed at {feed_config['url']}")
            
            # Make the request with appropriate method and data
            if request_method.upper() == "POST":
                response = requests.post(
                    feed_config["url"], 
                    headers=headers, 
                    json=request_data,
                    timeout=30
                )
            else:
                response = requests.get(
                    feed_config["url"], 
                    headers=headers,
                    timeout=30
                )
            
            response.raise_for_status()
            
            # Determine content type
            content_type = response.headers.get('content-type', '').lower()
            
            # Handle different response formats
            if 'application/json' in content_type:
                data = response.json()
                logger.info(f"Received JSON data from {feed_name}")
            elif 'text/csv' in content_type:
                # Parse CSV data
                csv_data = []
                csv_reader = csv.DictReader(StringIO(response.text))
                for row in csv_reader:
                    csv_data.append(row)
                data = csv_data
                logger.info(f"Received CSV data from {feed_name} with {len(csv_data)} rows")
            else:
                # Try to parse as JSON anyway
                try:
                    data = response.json()
                    logger.info(f"Parsed response as JSON despite content-type: {content_type}")
                except json.JSONDecodeError:
                    # If it can't be parsed as JSON, store raw text
                    logger.warning(f"Could not parse {feed_name} response as JSON, storing as raw text")
                    data = [{"raw_content": response.text, "content_type": content_type}]
            
            # Process the data based on feed type
            processed_data = self.process_feed_data(feed_name, data)
            
            logger.info(f"Processed {len(processed_data)} items from {feed_name}")
            return processed_data
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error collecting data from {feed_name}: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text[:500]}...")
            return []
        except ValueError as e:
            logger.error(f"Error collecting data from {feed_name}: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error collecting data from {feed_name}: {str(e)}")
            return []
    
    def store_raw_data(self, feed_name: str, data: List[Dict[str, Any]]) -> str:
        """Store raw data in Cloud Storage"""
        if not data:
            logger.warning(f"No data to store for feed {feed_name}")
            return ""
        
        if not storage_client:
            logger.error("Storage client not initialized")
            return ""
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        blob_name = f"{feed_name}/{timestamp}.json"
        
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            blob = bucket.blob(blob_name)
            
            blob.upload_from_string(
                json.dumps(data, indent=2),
                content_type="application/json"
            )
            
            gcs_path = f"gs://{BUCKET_NAME}/{blob_name}"
            logger.info(f"Stored raw data in {gcs_path}")
            return gcs_path
        except Exception as e:
            logger.error(f"Error storing raw data for {feed_name}: {str(e)}")
            return ""
    
    def load_to_bigquery(self, feed_name: str, data: List[Dict[str, Any]]) -> int:
        """Load processed data to BigQuery"""
        if not data:
            logger.warning(f"No data to load to BigQuery for feed {feed_name}")
            return 0
            
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return 0
        
        feed_config = self._get_feed_config(feed_name)
        table_id = f"{PROJECT_ID}.{DATASET_ID}.{feed_config['table_id']}"
        
        # Ensure all items have ingestion timestamp
        for item in data:
            if "_ingestion_timestamp" not in item:
                item["_ingestion_timestamp"] = datetime.utcnow().isoformat()
        
        # Load data to BigQuery with auto schema detection
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            schema_update_options=[
                bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
            ],
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            autodetect=True
        )
        
        try:
            # Serialize each item to JSON and join with newlines
            json_data = "\n".join([json.dumps(item) for item in data])
            
            load_job = bq_client.load_table_from_string(
                json_data, table_id, job_config=job_config
            )
            load_job.result()  # Wait for job to complete
            
            logger.info(f"Loaded {len(data)} records to {table_id}")
            return len(data)
        except Exception as e:
            logger.error(f"Error loading data to BigQuery: {str(e)}")
            
            # Check if error is because table doesn't exist
            if "not found" in str(e).lower():
                try:
                    # Create empty table with just the timestamp field
                    schema = [
                        bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP")
                    ]
                    
                    table = bigquery.Table(table_id, schema=schema)
                    table = bq_client.create_table(table)
                    logger.info(f"Created table {table_id}")
                    
                    # Try loading again
                    json_data = "\n".join([json.dumps(item) for item in data])
                    load_job = bq_client.load_table_from_string(
                        json_data, table_id, job_config=job_config
                    )
                    load_job.result()
                    
                    logger.info(f"Loaded {len(data)} records to {table_id} after table creation")
                    return len(data)
                except Exception as create_error:
                    logger.error(f"Error creating table and loading data: {str(create_error)}")
            
            return 0
    
    def publish_ingestion_event(self, feed_name: str, count: int, gcs_path: str) -> None:
        """Publish ingestion event to Pub/Sub for downstream processing"""
        if not publisher:
            logger.error("PubSub publisher not initialized")
            return
            
        topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        
        message = {
            "feed_name": feed_name,
            "record_count": count,
            "raw_data_location": gcs_path,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed"
        }
        
        try:
            message_json = json.dumps(message)
            data = message_json.encode("utf-8")
            future = publisher.publish(topic_path, data=data)
            message_id = future.result()
            
            logger.info(f"Published ingestion event {message_id} to {topic_path}")
        except Exception as e:
            logger.error(f"Error publishing message to Pub/Sub: {str(e)}")
    
    def process_feed(self, feed_name: str) -> Dict[str, Any]:
        """Process a single feed end-to-end"""
        start_time = datetime.now()
        logger.info(f"Starting processing of feed: {feed_name}")
        
        try:
            # Collect data from feed
            data = self.collect_feed_data(feed_name)
            
            if not data:
                duration = (datetime.now() - start_time).total_seconds()
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": "No data collected",
                    "record_count": 0,
                    "duration_seconds": duration
                }
            
            # Store raw data
            gcs_path = self.store_raw_data(feed_name, data)
            
            # Load to BigQuery
            record_count = self.load_to_bigquery(feed_name, data)
            
            # Publish event
            if record_count > 0:
                self.publish_ingestion_event(feed_name, record_count, gcs_path)
            
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "status": "success",
                "record_count": record_count,
                "raw_data_location": gcs_path,
                "duration_seconds": duration
            }
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": str(e),
                "record_count": 0,
                "duration_seconds": duration
            }
    
    def process_all_feeds(self) -> List[Dict[str, Any]]:
        """Process all configured feeds"""
        results = []
        
        # Get list of active feeds
        active_feeds = [
            feed_name for feed_name, config in FEED_CONFIG.items() 
            if config.get("active", True)
        ]
        
        logger.info(f"Processing {len(active_feeds)} active feeds: {', '.join(active_feeds)}")
        
        for feed_name in active_feeds:
            try:
                result = self.process_feed(feed_name)
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                results.append({
                    "feed_name": feed_name,
                    "status": "error",
                    "message": str(e),
                    "record_count": 0
                })
        
        return results
    
    def get_feed_statistics(self) -> Dict[str, Any]:
        """Get statistics about all feeds"""
        stats = {
            "feeds": [],
            "total_records": 0,
            "active_feeds": 0,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return stats
            
        for feed_name, config in FEED_CONFIG.items():
            table_id = f"{PROJECT_ID}.{DATASET_ID}.{config['table_id']}"
            
            try:
                # Count records in the table
                query = f"""
                SELECT COUNT(*) as record_count,
                       MIN(_ingestion_timestamp) as earliest_record,
                       MAX(_ingestion_timestamp) as latest_record
                FROM `{table_id}`
                """
                
                query_job = bq_client.query(query)
                results = query_job.result()
                row = next(results)
                
                feed_stats = {
                    "feed_name": feed_name,
                    "table_id": config['table_id'],
                    "record_count": row.record_count,
                    "earliest_record": row.earliest_record.isoformat() if row.earliest_record else None,
                    "latest_record": row.latest_record.isoformat() if row.latest_record else None,
                    "active": config.get("active", True)
                }
                
                stats["feeds"].append(feed_stats)
                stats["total_records"] += row.record_count
                if config.get("active", True):
                    stats["active_feeds"] += 1
                
            except Exception as e:
                logger.warning(f"Error getting statistics for feed {feed_name}: {str(e)}")
                stats["feeds"].append({
                    "feed_name": feed_name,
                    "table_id": config['table_id'],
                    "record_count": 0,
                    "error": str(e),
                    "active": config.get("active", True)
                })
                if config.get("active", True):
                    stats["active_feeds"] += 1
        
        return stats


# Cloud Function entry point
def ingest_threat_data(request):
    """HTTP Cloud Function entry point"""
    ingestion = ThreatDataIngestion()
    
    # Check if specific feed is requested
    request_json = request.get_json(silent=True)
    
    if request_json:
        logger.info(f"Received request: {json.dumps(request_json)}")
        
        # Check for statistics request
        if request_json.get("get_stats"):
            stats = ingestion.get_feed_statistics()
            return stats
        
        # Check for specific feed
        feed_name = request_json.get("feed_name")
        if feed_name:
            if feed_name not in FEED_CONFIG:
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
    ingestion = ThreatDataIngestion()
    
    # Process all feeds
    results = ingestion.process_all_feeds()
    print(json.dumps(results, indent=2))
    
    # Get statistics
    stats = ingestion.get_feed_statistics()
    print("\nFeed Statistics:")
    print(json.dumps(stats, indent=2))
