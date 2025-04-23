"""
Threat Intelligence Platform - Data Ingestion Module
Handles collection of threat data from various open-source feeds and loads it into BigQuery.
"""

import os
import json
import logging
import hashlib
import csv
import time
from io import StringIO, BytesIO
import zipfile
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

# Open source feed definitions - simplified
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "table_id": "threatfox_iocs",
        "opensrc_url": "https://threatfox.abuse.ch/export/json/recent/",
        "format": "json"
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "table_id": "phishtank_urls",
        "format": "json"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv"
    },
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "table_id": "feodotracker_c2",
        "format": "json"
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "table_id": "cisa_vulnerabilities",
        "format": "json"
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "table_id": "tor_exit_nodes",
        "format": "text"
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

class ThreatFeedIngestion:
    """Handles ingestion from open source threat feeds"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        self.ready = initialize_clients() and ensure_resources()
    
    def fetch_feed_data(self, feed_name: str) -> List[Dict]:
        """Fetch data from a specific feed"""
        if feed_name not in FEED_SOURCES:
            logger.error(f"Unknown feed: {feed_name}")
            return []
        
        feed_config = FEED_SOURCES[feed_name]
        url = feed_config["url"]
        feed_format = feed_config.get("format", "json")
        
        logger.info(f"Fetching data from {feed_name} ({url})")
        
        try:
            # Special handling for URLhaus (needs to handle ZIP file)
            if feed_name == "urlhaus":
                return self._fetch_urlhaus_data(feed_config)
            
            # Handle text-based feeds (like Tor exit nodes)
            if feed_format == "text":
                return self._fetch_text_feed(feed_name, feed_config)
            
            # Handle standard JSON/CSV feeds
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            if feed_format == "json":
                data = response.json()
                # Handle different JSON structures
                if feed_name == "cisa_kev" and "vulnerabilities" in data:
                    return self._process_cisa_vulns(data["vulnerabilities"])
                elif feed_name == "threatfox":
                    # Make a special API request for ThreatFox
                    return self._fetch_threatfox_data(feed_config)
                else:
                    # For simple JSON arrays
                    return data if isinstance(data, list) else [data]
            elif feed_format == "csv":
                csv_data = response.text
                reader = csv.DictReader(StringIO(csv_data))
                return list(reader)
            
            logger.warning(f"Unsupported format for {feed_name}: {feed_format}")
            return []
        except Exception as e:
            logger.error(f"Error fetching {feed_name}: {str(e)}")
            return []
    
    def _fetch_urlhaus_data(self, feed_config: Dict) -> List[Dict]:
        """Fetch and parse URLhaus CSV data (ZIP file)"""
        try:
            response = requests.get(feed_config["url"], timeout=30)
            response.raise_for_status()
            
            # URLhaus CSV is ZIP compressed
            with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
                # There should be only one file in the ZIP
                csv_filename = zip_file.namelist()[0]
                with zip_file.open(csv_filename) as csv_file:
                    content = csv_file.read().decode('utf-8')
                    # Skip the first 8 lines (comments)
                    lines = content.split('\n')
                    csv_data = '\n'.join(lines[8:])
                    
                    # Parse CSV
                    reader = csv.DictReader(StringIO(csv_data))
                    records = []
                    
                    for row in reader:
                        if not row:
                            continue
                            
                        record = {
                            "id": row.get("# id", ""),
                            "dateadded": row.get("dateadded", ""),
                            "url": row.get("url", ""),
                            "url_status": row.get("url_status", ""),
                            "threat": row.get("threat", ""),
                            "tags": row.get("tags", "").split(",") if row.get("tags") else [],
                            "_ingestion_timestamp": datetime.utcnow().isoformat()
                        }
                        records.append(record)
                    
                    logger.info(f"Processed {len(records)} URLhaus records")
                    return records
        except Exception as e:
            logger.error(f"Error fetching URLhaus data: {str(e)}")
            return []
    
    def _fetch_text_feed(self, feed_name: str, feed_config: Dict) -> List[Dict]:
        """Fetch and parse text-based feeds (like Tor exit nodes)"""
        try:
            response = requests.get(feed_config["url"], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            records = []
            
            # Process based on feed type
            if feed_name == "tor_exit_nodes":
                for line in lines:
                    if line and not line.startswith('#'):
                        record = {
                            "ip_address": line.strip(),
                            "type": "tor_exit_node",
                            "_ingestion_timestamp": datetime.utcnow().isoformat()
                        }
                        records.append(record)
            
            logger.info(f"Processed {len(records)} {feed_name} records")
            return records
        except Exception as e:
            logger.error(f"Error fetching {feed_name} data: {str(e)}")
            return []
    
    def _fetch_threatfox_data(self, feed_config: Dict) -> List[Dict]:
        """Fetch ThreatFox data using their API"""
        try:
            # Use the direct export URL instead of the API
            response = requests.get(feed_config["opensrc_url"], timeout=30)
            response.raise_for_status()
            
            data = response.json()
            records = []
            
            # Process the data
            for item in data:
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
    
    def _process_cisa_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """Process CISA Known Exploited Vulnerabilities"""
        records = []
        for vuln in vulns:
            vuln["_ingestion_timestamp"] = datetime.utcnow().isoformat()
            records.append(vuln)
        
        logger.info(f"Processed {len(records)} CISA vulnerabilities")
        return records
    
    def upload_to_bigquery(self, feed_name: str, records: List[Dict]) -> int:
        """Upload records to BigQuery"""
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
            for record in records:
                if "_ingestion_timestamp" not in record:
                    record["_ingestion_timestamp"] = datetime.utcnow().isoformat()
            
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
            return 0
    
    def publish_ingestion_event(self, feed_name: str, count: int) -> bool:
        """Publish event to Pub/Sub to trigger analysis"""
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
        """Process a single feed end-to-end"""
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
                "status": "success",
                "record_count": count,
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
    
    def process_all_feeds(self) -> List[Dict]:
        """Process all configured feeds"""
        if not self.ready:
            logger.error("Ingestion engine not properly initialized")
            return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        for feed_name in FEED_SOURCES:
            result = self.process_feed(feed_name)
            results.append(result)
        
        logger.info(f"Completed processing {len(results)} feeds")
        return results
    
    def get_feed_statistics(self) -> Dict:
        """Get statistics about ingested data"""
        if not bq_client:
            return {"error": "BigQuery client not initialized"}
        
        try:
            stats = {
                "feeds": [],
                "total_records": 0,
                "active_feeds": len(FEED_SOURCES),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            for feed_name, feed_config in FEED_SOURCES.items():
                table_id = feed_config["table_id"]
                full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
                
                # Query record counts
                query = f"""
                SELECT 
                    COUNT(*) as record_count,
                    MIN(_ingestion_timestamp) as earliest_record,
                    MAX(_ingestion_timestamp) as latest_record
                FROM `{full_table_id}`
                """
                
                try:
                    query_job = bq_client.query(query)
                    results = list(query_job.result())
                    
                    if results:
                        row = results[0]
                        
                        feed_stats = {
                            "feed_name": feed_name,
                            "table_id": table_id,
                            "record_count": row.record_count,
                            "earliest_record": row.earliest_record.isoformat() if row.earliest_record else None,
                            "latest_record": row.latest_record.isoformat() if row.latest_record else None
                        }
                        
                        stats["feeds"].append(feed_stats)
                        stats["total_records"] += row.record_count
                except Exception as e:
                    logger.error(f"Error querying stats for {feed_name}: {str(e)}")
                    stats["feeds"].append({
                        "feed_name": feed_name,
                        "table_id": table_id,
                        "record_count": 0,
                        "error": str(e)
                    })
            
            return stats
        except Exception as e:
            logger.error(f"Error getting feed statistics: {str(e)}")
            return {"error": str(e)}

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
