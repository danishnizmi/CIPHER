"""
Threat Intelligence Platform - Data Ingestion Module
Handles collection of threat data from various sources and loads it into GCP.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from google.cloud import storage
from google.cloud import pubsub_v1
from google.cloud import bigquery
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
BUCKET_NAME = os.environ.get("GCS_BUCKET", f"{PROJECT_ID}-threat-data")
DATASET_ID = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
PUBSUB_TOPIC = os.environ.get("PUBSUB_TOPIC", "threat-data-ingestion")

# Initialize GCP clients
storage_client = storage.Client()
bq_client = bigquery.Client()
publisher = pubsub_v1.PublisherClient()

# OSINT Feed Configuration
FEED_CONFIG = {
    "alienvault": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "auth_header": "X-OTX-API-KEY",
        "auth_key": os.environ.get("ALIENVAULT_API_KEY", ""),
        "table_id": "alienvault_pulses"
    },
    "misp": {
        "url": "https://your-misp-instance.com/events/restSearch",
        "auth_header": "Authorization",
        "auth_key": os.environ.get("MISP_API_KEY", ""),
        "table_id": "misp_events"
    },
    "threatfox": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "table_id": "threatfox_iocs"
    }
}


class ThreatDataIngestion:
    """Main class for handling threat data ingestion"""
    
    def __init__(self):
        """Initialize ingestion resources"""
        self._ensure_resources_exist()
    
    def _ensure_resources_exist(self):
        """Ensure required GCP resources exist (bucket, dataset, tables)"""
        # Create GCS bucket if it doesn't exist
        try:
            storage_client.get_bucket(BUCKET_NAME)
        except Exception:
            bucket = storage_client.create_bucket(BUCKET_NAME)
            logger.info(f"Created bucket {bucket.name}")
        
        # Create BigQuery dataset if it doesn't exist
        try:
            bq_client.get_dataset(DATASET_ID)
        except Exception:
            dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
            dataset.location = "US"
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {DATASET_ID}")
        
        # Create tables if they don't exist
        for feed, config in FEED_CONFIG.items():
            table_id = f"{PROJECT_ID}.{DATASET_ID}.{config['table_id']}"
            try:
                bq_client.get_table(table_id)
            except Exception:
                # Auto-detect schema based on first batch of data
                logger.info(f"Table {table_id} will be created on first insert")
    
    def collect_feed_data(self, feed_name: str) -> List[Dict[str, Any]]:
        """Collect data from a specific feed"""
        if feed_name not in FEED_CONFIG:
            raise ValueError(f"Unknown feed: {feed_name}")
        
        config = FEED_CONFIG[feed_name]
        headers = {}
        
        if "auth_header" in config and "auth_key" in config:
            headers[config["auth_header"]] = config["auth_key"]
        
        try:
            response = requests.get(config["url"], headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Process response based on feed type
            if feed_name == "alienvault":
                return data.get("results", [])
            elif feed_name == "misp":
                return data.get("response", [])
            elif feed_name == "threatfox":
                return data.get("data", [])
            
            return []
        
        except Exception as e:
            logger.error(f"Error collecting data from {feed_name}: {str(e)}")
            return []
    
    def store_raw_data(self, feed_name: str, data: List[Dict[str, Any]]) -> str:
        """Store raw data in Cloud Storage"""
        if not data:
            logger.warning(f"No data to store for feed {feed_name}")
            return ""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        blob_name = f"{feed_name}/{timestamp}.json"
        
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(blob_name)
        
        blob.upload_from_string(
            json.dumps(data, indent=2),
            content_type="application/json"
        )
        
        logger.info(f"Stored raw data in gs://{BUCKET_NAME}/{blob_name}")
        return f"gs://{BUCKET_NAME}/{blob_name}"
    
    def load_to_bigquery(self, feed_name: str, data: List[Dict[str, Any]]) -> int:
        """Load processed data to BigQuery"""
        if not data:
            logger.warning(f"No data to load to BigQuery for feed {feed_name}")
            return 0
        
        config = FEED_CONFIG[feed_name]
        table_id = f"{PROJECT_ID}.{DATASET_ID}.{config['table_id']}"
        
        # Add ingestion timestamp
        for item in data:
            item["_ingestion_timestamp"] = datetime.utcnow().isoformat()
        
        # Load data to BigQuery
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            schema_update_options=[
                bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
            ],
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            autodetect=True
        )
        
        json_data = "\n".join([json.dumps(item) for item in data])
        
        load_job = bq_client.load_table_from_string(
            json_data, table_id, job_config=job_config
        )
        load_job.result()  # Wait for job to complete
        
        logger.info(f"Loaded {len(data)} records to {table_id}")
        return len(data)
    
    def publish_ingestion_event(self, feed_name: str, count: int, gcs_path: str) -> None:
        """Publish ingestion event to Pub/Sub for downstream processing"""
        topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        
        message = {
            "feed_name": feed_name,
            "record_count": count,
            "raw_data_location": gcs_path,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed"
        }
        
        message_json = json.dumps(message)
        future = publisher.publish(topic_path, data=message_json.encode("utf-8"))
        message_id = future.result()
        
        logger.info(f"Published ingestion event {message_id} to {topic_path}")
    
    def process_feed(self, feed_name: str) -> Dict[str, Any]:
        """Process a single feed end-to-end"""
        logger.info(f"Processing feed: {feed_name}")
        
        # Collect data from feed
        data = self.collect_feed_data(feed_name)
        
        if not data:
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": "No data collected",
                "record_count": 0
            }
        
        # Store raw data
        gcs_path = self.store_raw_data(feed_name, data)
        
        # Load to BigQuery
        record_count = self.load_to_bigquery(feed_name, data)
        
        # Publish event
        self.publish_ingestion_event(feed_name, record_count, gcs_path)
        
        return {
            "feed_name": feed_name,
            "status": "success",
            "record_count": record_count,
            "raw_data_location": gcs_path
        }
    
    def process_all_feeds(self) -> List[Dict[str, Any]]:
        """Process all configured feeds"""
        results = []
        
        for feed_name in FEED_CONFIG.keys():
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


# Cloud Function entry point
def ingest_threat_data(request):
    """HTTP Cloud Function entry point"""
    ingestion = ThreatDataIngestion()
    
    # Check if specific feed is requested
    request_json = request.get_json(silent=True)
    feed_name = request_json.get("feed_name") if request_json else None
    
    if feed_name:
        if feed_name not in FEED_CONFIG:
            return {"error": f"Unknown feed: {feed_name}"}, 400
        
        result = ingestion.process_feed(feed_name)
        return result, 200
    else:
        # Process all feeds
        results = ingestion.process_all_feeds()
        return {"results": results}, 200


# CLI entry point
if __name__ == "__main__":
    ingestion = ThreatDataIngestion()
    results = ingestion.process_all_feeds()
    print(json.dumps(results, indent=2))
