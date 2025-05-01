"""
Threat Intelligence Platform - Ingestion Module
Fetches threat data from external feeds and loads it into BigQuery.
"""

import os
import json
import logging
import csv
import time
import base64
import re
import uuid
import hashlib
import traceback
from io import StringIO
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union

import requests
from google.cloud import bigquery
from google.cloud.exceptions import NotFound

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from config module
PROJECT_ID = config.project_id
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-data-ingestion")

# Define feed sources with accurate URLs and parameters
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "table_id": "threatfox_iocs",
        "format": "json",
        "description": "ThreatFox IOCs - Malware indicators database",
        "json_path": "data",  # Path to actual data in the JSON
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "table_id": "phishtank_urls",
        "format": "json",
        "description": "PhishTank - Community-verified phishing URLs",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv",
        "skip_lines": 8,  # Skip header info/comments
        "description": "URLhaus - Database of malicious URLs",
    }
}

# IOC regex patterns for extraction
IOC_PATTERNS = {
    "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%/.]*)*',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
}

def make_request(url, timeout=30, max_retries=3):
    """Make an HTTP request with retries and error handling"""
    domain = url.split('/')[2]
    headers = {
        'User-Agent': f'ThreatIntelligencePlatform/1.0 (Research)',
        'Accept': 'application/json, text/plain, */*',
    }
    
    # Implement basic rate limiting
    for retry in range(max_retries):
        try:
            # Add small delay between retries
            if retry > 0:
                time.sleep(5 * retry)
                
            logger.info(f"Requesting URL: {url} (attempt {retry+1})")
            response = requests.get(url, timeout=timeout, headers=headers, verify=False)
            
            # Check for successful response
            if response.status_code == 200:
                return response
            else:
                logger.warning(f"HTTP error {response.status_code} from {domain}")
                
        except requests.RequestException as e:
            logger.warning(f"Request error: {str(e)}. Retrying...")
    
    # If we've exhausted retries
    raise requests.RequestException(f"Failed to retrieve data from {url} after {max_retries} attempts")

def ensure_dataset_exists():
    """Ensure the BigQuery dataset exists"""
    client = bigquery.Client(project=PROJECT_ID)
    
    try:
        # Try to get the dataset
        dataset_ref = f"{PROJECT_ID}.{DATASET_ID}"
        client.get_dataset(dataset_ref)
        logger.info(f"Dataset {DATASET_ID} already exists")
    except NotFound:
        # Create the dataset if it doesn't exist
        dataset = bigquery.Dataset(dataset_ref)
        dataset.location = "US"
        client.create_dataset(dataset)
        logger.info(f"Created dataset {DATASET_ID}")
    
    return True

def ensure_table_exists(table_id, schema=None):
    """Ensure the specified BigQuery table exists"""
    client = bigquery.Client(project=PROJECT_ID)
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    try:
        # Try to get the table
        client.get_table(full_table_id)
        logger.info(f"Table {table_id} already exists")
        return True
    except NotFound:
        # Create a basic schema if none provided
        if not schema:
            schema = [
                bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("_ingestion_id", "STRING"),
                bigquery.SchemaField("_source", "STRING"),
                bigquery.SchemaField("_feed_type", "STRING")
            ]
        
        # Create the table
        table = bigquery.Table(full_table_id, schema=schema)
        client.create_table(table)
        logger.info(f"Created table {table_id}")
        return True

def insert_rows_to_bigquery(table_id, rows):
    """Insert rows into BigQuery with error handling"""
    if not rows:
        logger.warning(f"No rows to insert for {table_id}")
        return 0
    
    client = bigquery.Client(project=PROJECT_ID)
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    # Process rows to ensure correct format
    processed_rows = []
    for row in rows:
        processed_row = {}
        for k, v in row.items():
            # Format datetime fields
            if isinstance(v, datetime):
                processed_row[k] = v.isoformat()
            # Serialize JSON fields
            elif isinstance(v, (dict, list)):
                processed_row[k] = json.dumps(v)
            else:
                processed_row[k] = v
        processed_rows.append(processed_row)
    
    # Insert in batches of 100 for better reliability
    total_inserted = 0
    batch_size = 100
    
    for i in range(0, len(processed_rows), batch_size):
        batch = processed_rows[i:i+batch_size]
        
        try:
            errors = client.insert_rows_json(full_table_id, batch)
            if not errors:
                logger.info(f"Successfully inserted {len(batch)} rows into {table_id}")
                total_inserted += len(batch)
            else:
                logger.error(f"Errors during insertion: {errors}")
                
                # Try to update schema if it's a schema mismatch
                try:
                    logger.info("Attempting to update table schema...")
                    table = client.get_table(full_table_id)
                    current_schema = {field.name: field for field in table.schema}
                    
                    # Find missing fields
                    missing_fields = []
                    for row in batch:
                        for field in row:
                            if field not in current_schema:
                                missing_fields.append(bigquery.SchemaField(field, "STRING"))
                    
                    if missing_fields:
                        new_schema = list(table.schema) + missing_fields
                        table.schema = new_schema
                        client.update_table(table, ["schema"])
                        logger.info(f"Updated schema for {table_id}")
                        
                        # Try insert again
                        errors = client.insert_rows_json(full_table_id, batch)
                        if not errors:
                            logger.info(f"Successfully inserted {len(batch)} rows after schema update")
                            total_inserted += len(batch)
                except Exception as e:
                    logger.error(f"Schema update failed: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error inserting batch: {str(e)}")
    
    return total_inserted

def process_json_feed(feed_name, response):
    """Process JSON feed data"""
    feed_config = FEED_SOURCES[feed_name]
    table_id = feed_config["table_id"]
    
    try:
        # Parse JSON data
        data = response.json()
        
        # Extract data from the specified path if provided
        if "json_path" in feed_config:
            path_parts = feed_config["json_path"].split('.')
            for part in path_parts:
                if part and data and isinstance(data, dict):
                    data = data.get(part, {})
        
        # Handle special cases
        if feed_name == "threatfox":
            # Ensure data is a list
            if not isinstance(data, list) and isinstance(data, dict) and "data" in data:
                if "iocs" in data["data"]:
                    # Format is {"data": {"iocs": [...]}}
                    data = data["data"]["iocs"]
                else:
                    # Format is {"data": [...]}
                    data = data["data"]
        elif feed_name == "phishtank":
            # PhishTank data is already a list
            if not isinstance(data, list):
                logger.warning(f"Unexpected PhishTank data format: {type(data)}")
                # Try to find a list in the response
                for key, value in data.items():
                    if isinstance(value, list):
                        data = value
                        break
                else:
                    data = []
        
        # Convert to list if not already
        if not isinstance(data, list):
            data = [data]
        
        # Create records
        records = []
        timestamp = datetime.utcnow().isoformat()
        ingestion_id = f"{feed_name}_{int(time.time())}"
        
        for item in data:
            if not isinstance(item, dict):
                continue
                
            # Create a record with standard fields
            record = item.copy()
            record.update({
                "_ingestion_timestamp": timestamp,
                "_ingestion_id": ingestion_id,
                "_source": feed_name,
                "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
            })
            
            # Handle feed-specific transformations
            if feed_name == "threatfox":
                if "first_seen" in record and record["first_seen"]:
                    try:
                        # Convert timestamp to datetime
                        first_seen = int(record["first_seen"])
                        record["first_seen"] = datetime.fromtimestamp(first_seen).isoformat()
                    except (ValueError, TypeError):
                        record["first_seen"] = timestamp
            
            records.append(record)
        
        # Ensure table exists
        ensure_table_exists(table_id)
        
        # Insert records
        inserted = insert_rows_to_bigquery(table_id, records)
        
        return {
            "feed_name": feed_name,
            "status": "success" if inserted > 0 else "warning",
            "record_count": inserted,
            "total_records": len(records),
            "ingestion_id": ingestion_id,
            "timestamp": timestamp
        }
        
    except Exception as e:
        logger.error(f"Error processing {feed_name} JSON: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "feed_name": feed_name,
            "status": "error",
            "error": str(e),
            "record_count": 0,
            "timestamp": datetime.utcnow().isoformat()
        }

def process_csv_feed(feed_name, response):
    """Process CSV feed data"""
    feed_config = FEED_SOURCES[feed_name]
    table_id = feed_config["table_id"]
    
    try:
        # Get content
        content = response.text
        
        # Handle skip lines
        skip_lines = feed_config.get("skip_lines", 0)
        if skip_lines > 0:
            lines = content.split('\n')
            if len(lines) > skip_lines:
                content = '\n'.join(lines[skip_lines:])
        
        # Parse CSV
        rows = []
        reader = csv.DictReader(StringIO(content))
        
        # Process records
        records = []
        timestamp = datetime.utcnow().isoformat()
        ingestion_id = f"{feed_name}_{int(time.time())}"
        
        for row in reader:
            if not row or all(not v for v in row.values()):
                continue
                
            # Create a record with standard fields
            record = {k: v.strip() if isinstance(v, str) else v for k, v in row.items()}
            record.update({
                "_ingestion_timestamp": timestamp,
                "_ingestion_id": ingestion_id,
                "_source": feed_name,
                "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
            })
            
            records.append(record)
        
        # Ensure table exists
        ensure_table_exists(table_id)
        
        # Insert records
        inserted = insert_rows_to_bigquery(table_id, records)
        
        return {
            "feed_name": feed_name,
            "status": "success" if inserted > 0 else "warning",
            "record_count": inserted,
            "total_records": len(records),
            "ingestion_id": ingestion_id,
            "timestamp": timestamp
        }
        
    except Exception as e:
        logger.error(f"Error processing {feed_name} CSV: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "feed_name": feed_name,
            "status": "error",
            "error": str(e),
            "record_count": 0,
            "timestamp": datetime.utcnow().isoformat()
        }

def extract_iocs_from_content(content):
    """Extract IOCs from content using regex patterns"""
    iocs = []
    
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, content)
        for value in matches:
            iocs.append({
                "type": ioc_type,
                "value": value,
                "timestamp": datetime.utcnow().isoformat()
            })
    
    # Remove duplicates
    unique_iocs = []
    seen = set()
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)
    
    return unique_iocs

def create_analysis_entry(feed_name, records, ingestion_id):
    """Create an analysis entry in the threat_analysis table"""
    # Extract IOCs from records
    all_iocs = []
    
    # Convert records to string for IOC extraction
    for record in records:
        record_str = json.dumps(record)
        iocs = extract_iocs_from_content(record_str)
        
        for ioc in iocs:
            ioc["source"] = feed_name
            all_iocs.append(ioc)
    
    # Create analysis record
    analysis = {
        "source_id": ingestion_id,
        "source_type": feed_name,
        "iocs": json.dumps(all_iocs),
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "severity": "medium",  # Default severity
        "confidence": "medium"  # Default confidence
    }
    
    # Add vertex analysis placeholder
    analysis["vertex_analysis"] = json.dumps({
        "summary": f"Ingestion of {len(records)} records from {feed_name}",
        "threat_actor": "Unknown",
        "targets": "Unknown",
        "techniques": "Unknown",
        "malware": "Unknown",
        "severity": "medium",
        "confidence": "medium"
    })
    
    # Ensure table exists
    ensure_table_exists("threat_analysis")
    
    # Insert analysis
    inserted = insert_rows_to_bigquery("threat_analysis", [analysis])
    
    return inserted > 0

class ThreatDataIngestion:
    """Main class for threat data ingestion"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        logger.info("Initializing ThreatDataIngestion")
        
        # Ensure BigQuery dataset exists
        ensure_dataset_exists()
    
    def process_feed(self, feed_name):
        """Process a specific feed"""
        logger.info(f"Processing feed: {feed_name}")
        
        if feed_name not in FEED_SOURCES:
            return {
                "feed_name": feed_name,
                "status": "error",
                "error": "Unknown feed",
                "record_count": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        feed_config = FEED_SOURCES[feed_name]
        
        try:
            # Make request to feed URL
            response = make_request(feed_config["url"])
            
            # Process based on format
            if feed_config["format"] == "json":
                result = process_json_feed(feed_name, response)
            elif feed_config["format"] == "csv":
                result = process_csv_feed(feed_name, response)
            else:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "error": f"Unsupported format: {feed_config['format']}",
                    "record_count": 0,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Create analysis entry if records were inserted
            if result["status"] == "success" and result["record_count"] > 0:
                create_analysis_entry(feed_name, result.get("records", []), result["ingestion_id"])
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "feed_name": feed_name,
                "status": "error",
                "error": str(e),
                "record_count": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def process_all_feeds(self):
        """Process all configured feeds"""
        results = []
        
        for feed_name in FEED_SOURCES:
            try:
                result = self.process_feed(feed_name)
                results.append(result)
                # Add a small delay between feeds
                time.sleep(2)
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                results.append({
                    "feed_name": feed_name,
                    "status": "error",
                    "error": str(e),
                    "record_count": 0,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Log summary
        success_count = sum(1 for r in results if r.get("status") == "success")
        record_count = sum(r.get("record_count", 0) for r in results)
        logger.info(f"Processed {len(results)} feeds: {success_count} successful, {record_count} records ingested")
        
        return results
    
    def analyze_csv_file(self, csv_content, feed_name="csv_upload"):
        """Process an uploaded CSV file"""
        if not csv_content:
            return {"error": "Empty CSV content"}
        
        try:
            # Generate a unique table ID
            table_id = f"upload_{feed_name.lower().replace(' ', '_').replace('-', '_')}"
            timestamp = datetime.utcnow().isoformat()
            ingestion_id = f"csv_{int(time.time())}"
            
            # Parse CSV
            reader = csv.DictReader(StringIO(csv_content))
            
            # Process records
            records = []
            for row in reader:
                if not row or all(not v for v in row.values()):
                    continue
                    
                # Create a record with standard fields
                record = {k: v.strip() if isinstance(v, str) else v for k, v in row.items()}
                record.update({
                    "_ingestion_timestamp": timestamp,
                    "_ingestion_id": ingestion_id,
                    "_source": "csv_upload",
                    "_feed_type": f"Uploaded CSV: {feed_name}"
                })
                
                records.append(record)
            
            # Ensure table exists
            ensure_table_exists(table_id)
            
            # Insert records
            inserted = insert_rows_to_bigquery(table_id, records)
            
            # Create analysis entry
            create_analysis_entry(f"csv_{feed_name}", records, ingestion_id)
            
            return {
                "feed_name": feed_name,
                "status": "success" if inserted > 0 else "warning",
                "record_count": inserted,
                "table_id": table_id,
                "ingestion_id": ingestion_id,
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error(f"Error processing CSV: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "feed_name": feed_name,
                "status": "error",
                "error": str(e),
                "record_count": 0,
                "timestamp": datetime.utcnow().isoformat()
            }

def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion"""
    try:
        # Parse request
        request_json = request.get_json(silent=True)
        
        # Initialize ingestion engine
        ingestion = ThreatDataIngestion()
        
        if request_json:
            # Check for CSV upload
            if request_json.get("file_type") == "csv" and "content" in request_json:
                feed_name = request_json.get("feed_name", "csv_upload")
                content = request_json["content"]
                
                # Handle base64 encoded content
                if request_json.get("encoding") == "base64":
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                    except Exception as e:
                        return {"error": f"Failed to decode base64 content: {str(e)}"}, 400
                
                return ingestion.analyze_csv_file(content, feed_name)
            
            # Check for specific feed
            feed_name = request_json.get("feed_name")
            if feed_name:
                if feed_name == "all":
                    results = ingestion.process_all_feeds()
                    return {"results": results, "count": len(results)}
                elif feed_name not in FEED_SOURCES:
                    return {"error": f"Unknown feed: {feed_name}"}, 400
                
                return ingestion.process_feed(feed_name)
        
        # Default to processing all feeds
        results = ingestion.process_all_feeds()
        return {"results": results, "count": len(results)}
        
    except Exception as e:
        logger.error(f"Error handling ingestion request: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": str(e)}, 500

# Execute when run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting ingestion from command line")
    
    # Initialize ingestion engine
    ingestion = ThreatDataIngestion()
    
    # Process all feeds
    results = ingestion.process_all_feeds()
    
    # Print summary
    for result in results:
        print(f"{result['feed_name']}: {result['status']} - {result.get('record_count', 0)} records")
    
    success_count = sum(1 for r in results if r.get("status") == "success")
    record_count = sum(r.get("record_count", 0) for r in results)
    print(f"\nProcessed {len(results)} feeds: {success_count} successful, {record_count} records ingested")
