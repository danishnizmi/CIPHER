"""
Threat Intelligence Platform - Ingestion Module
Handles collection of threat data from open-source feeds and loads it into BigQuery.
Streamlined implementation focused on reliability.
"""

import os
import json
import logging
import csv
import time
import re
import uuid
from datetime import datetime
from io import StringIO
import traceback
import requests
from google.cloud import bigquery

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
ENVIRONMENT = config.environment

# Disable SSL warnings for problematic sites
requests.packages.urllib3.disable_warnings()

# Feed definitions with URLs and parsing configurations
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "table_id": "threatfox_iocs",
        "format": "json",
        "description": "ThreatFox IOCs - Malware indicators database"
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "table_id": "phishtank_urls",
        "format": "json",
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

class ThreatDataIngestion:
    """Handles ingestion of threat data from various sources"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        logger.info("Initializing ThreatDataIngestion engine")
        
        # Initialize BigQuery client
        self.bq_client = self._get_bigquery_client()
        if not self.bq_client:
            logger.error("Failed to initialize BigQuery client")
            return
            
        # Make sure dataset exists
        self._ensure_dataset_exists()
        
        # Make sure tables exist
        self._ensure_tables_exist()
        
        logger.info("ThreatDataIngestion engine initialized successfully")

    def _get_bigquery_client(self):
        """Get BigQuery client or initialize directly if needed"""
        try:
            # First try to get from config
            client = config.get_client('bigquery')
            if not isinstance(client, config.DummyClient):
                return client
                
            # If not available, try direct initialization
            logger.info("Initializing BigQuery client directly")
            return bigquery.Client(project=PROJECT_ID)
        except Exception as e:
            logger.error(f"Error initializing BigQuery client: {str(e)}")
            logger.error(traceback.format_exc())
            return None

    def _ensure_dataset_exists(self):
        """Ensure the BigQuery dataset exists"""
        try:
            dataset_id = f"{PROJECT_ID}.{DATASET_ID}"
            try:
                self.bq_client.get_dataset(dataset_id)
                logger.info(f"Dataset {DATASET_ID} already exists")
            except Exception:
                # Create the dataset
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = "US"
                self.bq_client.create_dataset(dataset, exists_ok=True)
                logger.info(f"Created dataset {DATASET_ID}")
        except Exception as e:
            logger.error(f"Error ensuring dataset exists: {str(e)}")
            logger.error(traceback.format_exc())

    def _ensure_tables_exist(self):
        """Ensure tables exist for all feeds"""
        for feed_name, feed_config in FEED_SOURCES.items():
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                # Check if table exists
                try:
                    self.bq_client.get_table(full_table_id)
                    logger.info(f"Table {table_id} already exists")
                    continue
                except Exception:
                    # Table doesn't exist, create it
                    pass
                
                # Create basic schema based on feed type
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("_ingestion_id", "STRING"),
                    bigquery.SchemaField("_source", "STRING"),
                    bigquery.SchemaField("_feed_type", "STRING")
                ]
                
                # Add feed-specific fields
                if feed_name == "threatfox":
                    schema.extend([
                        bigquery.SchemaField("ioc_value", "STRING"),
                        bigquery.SchemaField("ioc_type", "STRING"),
                        bigquery.SchemaField("threat_type", "STRING"),
                        bigquery.SchemaField("malware", "STRING"),
                        bigquery.SchemaField("malware_printable", "STRING"),
                        bigquery.SchemaField("first_seen_utc", "STRING"),
                        bigquery.SchemaField("confidence_level", "INTEGER"),
                        bigquery.SchemaField("reference", "STRING"),
                        bigquery.SchemaField("tags", "STRING"),
                        bigquery.SchemaField("reporter", "STRING")
                    ])
                elif feed_name == "phishtank":
                    schema.extend([
                        bigquery.SchemaField("url", "STRING"),
                        bigquery.SchemaField("phish_id", "STRING"),
                        bigquery.SchemaField("submission_time", "STRING"),
                        bigquery.SchemaField("verification_time", "STRING"),
                        bigquery.SchemaField("target", "STRING")
                    ])
                elif feed_name == "urlhaus":
                    schema.extend([
                        bigquery.SchemaField("id", "STRING"),
                        bigquery.SchemaField("dateadded", "STRING"),
                        bigquery.SchemaField("url", "STRING"),
                        bigquery.SchemaField("url_status", "STRING"),
                        bigquery.SchemaField("threat", "STRING"),
                        bigquery.SchemaField("tags", "STRING"),
                        bigquery.SchemaField("reporter", "STRING")
                    ])
                
                # Create the table
                table = bigquery.Table(full_table_id, schema=schema)
                table.description = feed_config.get("description", "Threat Intelligence Feed")
                self.bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
                
            except Exception as e:
                logger.error(f"Error creating table {table_id}: {str(e)}")
                logger.error(traceback.format_exc())

    def process_all_feeds(self):
        """Process all configured feeds"""
        results = []
        logger.info(f"Processing {len(FEED_SOURCES)} feeds")
        
        for feed_name in FEED_SOURCES:
            try:
                result = self.process_feed(feed_name)
                results.append(result)
                # Small delay between feeds
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                logger.error(traceback.format_exc())
                results.append({
                    "feed_name": feed_name,
                    "status": "error",
                    "message": str(e),
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                })
        
        return results

    def process_feed(self, feed_name):
        """Process a specific feed"""
        start_time = datetime.now()
        logger.info(f"Processing feed: {feed_name}")
        
        if feed_name not in FEED_SOURCES:
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": "Unknown feed",
                "record_count": 0,
                "timestamp": datetime.now().isoformat()
            }
        
        feed_config = FEED_SOURCES[feed_name]
        table_id = feed_config["table_id"]
        url = feed_config["url"]
        feed_format = feed_config.get("format", "json")
        
        # Generate unique ingestion ID
        ingestion_id = f"{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        try:
            # Fetch data from feed
            logger.info(f"Fetching data from {url}")
            response = requests.get(url, timeout=30, verify=False)
            
            if response.status_code != 200:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": f"HTTP error: {response.status_code}",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Process based on format
            if feed_format == "json":
                records = self._process_json_feed(feed_name, response.text, ingestion_id)
            elif feed_format == "csv":
                records = self._process_csv_feed(feed_name, response.text, ingestion_id, feed_config)
            else:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": f"Unsupported format: {feed_format}",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records extracted",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Insert into BigQuery
            logger.info(f"Inserting {len(records)} records into {table_id}")
            inserted_count = self._insert_into_bigquery(table_id, records)
            
            # Create analysis entry
            self._create_analysis_entry(feed_name, records, ingestion_id)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return {
                "feed_name": feed_name,
                "status": "success",
                "record_count": inserted_count,
                "duration_seconds": duration,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "feed_name": feed_name,
                "status": "error",
                "message": str(e),
                "record_count": 0,
                "timestamp": datetime.now().isoformat()
            }

    def _process_json_feed(self, feed_name, content, ingestion_id):
        """Process JSON feed data"""
        records = []
        timestamp = datetime.now().isoformat()
        
        try:
            # Parse JSON
            data = json.loads(content)
            
            # Handle different feed formats
            if feed_name == "threatfox":
                # ThreatFox has a specific structure with IDs as keys
                for key, items in data.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                record = item.copy()
                                # Convert confidence level to integer
                                if 'confidence_level' in record:
                                    try:
                                        record['confidence_level'] = int(record['confidence_level'])
                                    except (ValueError, TypeError):
                                        record['confidence_level'] = 50
                                
                                # Add standard metadata
                                record.update({
                                    "_ingestion_timestamp": timestamp,
                                    "_ingestion_id": ingestion_id,
                                    "_source": feed_name,
                                    "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                                })
                                records.append(record)
            
            elif feed_name == "phishtank":
                # PhishTank is a simple array
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            record = item.copy()
                            # Add standard metadata
                            record.update({
                                "_ingestion_timestamp": timestamp,
                                "_ingestion_id": ingestion_id,
                                "_source": feed_name,
                                "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                            })
                            records.append(record)
                elif isinstance(data, dict) and 'results' in data:
                    # Handle an alternative structure
                    for item in data['results']:
                        if isinstance(item, dict):
                            record = item.copy()
                            # Add standard metadata
                            record.update({
                                "_ingestion_timestamp": timestamp,
                                "_ingestion_id": ingestion_id,
                                "_source": feed_name,
                                "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                            })
                            records.append(record)
            
            # If no records were extracted but we have data, try a generic approach
            if not records and data:
                logger.warning(f"Using generic JSON parser for {feed_name}")
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            record = item.copy()
                            record.update({
                                "_ingestion_timestamp": timestamp,
                                "_ingestion_id": ingestion_id,
                                "_source": feed_name,
                                "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                            })
                            records.append(record)
                elif isinstance(data, dict):
                    # If top-level is a dict, it might be a container, check all values for lists
                    for key, value in data.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict):
                                    record = item.copy()
                                    record.update({
                                        "_ingestion_timestamp": timestamp,
                                        "_ingestion_id": ingestion_id,
                                        "_source": feed_name,
                                        "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                                    })
                                    records.append(record)
        
        except Exception as e:
            logger.error(f"Error processing JSON feed {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            
        logger.info(f"Extracted {len(records)} records from {feed_name}")
        return records

    def _process_csv_feed(self, feed_name, content, ingestion_id, feed_config):
        """Process CSV feed data"""
        records = []
        timestamp = datetime.now().isoformat()
        
        try:
            # Handle skip lines if specified
            skip_lines = feed_config.get("skip_lines", 0)
            lines = content.split('\n')
            
            if skip_lines > 0 and len(lines) > skip_lines:
                content = '\n'.join(lines[skip_lines:])
            
            # Parse CSV
            csv_file = StringIO(content)
            csv_reader = csv.DictReader(csv_file)
            
            for row in csv_reader:
                if not row or not any(row.values()):
                    continue
                
                # Clean up the record
                record = {k: v.strip() if isinstance(v, str) else v for k, v in row.items() if k}
                
                # Add standard metadata
                record.update({
                    "_ingestion_timestamp": timestamp,
                    "_ingestion_id": ingestion_id,
                    "_source": feed_name,
                    "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                })
                
                records.append(record)
        
        except Exception as e:
            logger.error(f"Error processing CSV feed {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            
        logger.info(f"Extracted {len(records)} records from {feed_name}")
        return records

    def _insert_into_bigquery(self, table_id, records):
        """Insert records into BigQuery"""
        if not records:
            return 0
            
        full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
        
        try:
            # Process records to ensure JSON compatibility
            processed_rows = []
            for row in records:
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
            
            # Insert in smaller batches for reliability
            batch_size = 50
            total_inserted = 0
            
            for i in range(0, len(processed_rows), batch_size):
                batch = processed_rows[i:i+batch_size]
                
                try:
                    errors = self.bq_client.insert_rows_json(full_table_id, batch)
                    
                    if not errors:
                        total_inserted += len(batch)
                    else:
                        logger.error(f"Errors inserting batch: {errors}")
                        
                        # Try to update schema and insert again
                        try:
                            table = self.bq_client.get_table(full_table_id)
                            current_schema = {field.name: field for field in table.schema}
                            
                            # Find missing fields
                            missing_fields = []
                            for row in batch:
                                for field in row:
                                    if field not in current_schema:
                                        missing_fields.append(bigquery.SchemaField(field, "STRING"))
                            
                            if missing_fields:
                                # Update schema
                                new_schema = list(table.schema) + missing_fields
                                table.schema = new_schema
                                self.bq_client.update_table(table, ["schema"])
                                logger.info(f"Updated schema for {full_table_id}")
                                
                                # Try insert again
                                errors = self.bq_client.insert_rows_json(full_table_id, batch)
                                if not errors:
                                    total_inserted += len(batch)
                                else:
                                    logger.error(f"Still got errors after schema update: {errors}")
                        except Exception as e:
                            logger.error(f"Schema update error: {str(e)}")
                            logger.error(traceback.format_exc())
                            
                except Exception as e:
                    logger.error(f"Error inserting batch: {str(e)}")
                    logger.error(traceback.format_exc())
            
            return total_inserted
            
        except Exception as e:
            logger.error(f"Error inserting into BigQuery: {str(e)}")
            logger.error(traceback.format_exc())
            return 0

    def _create_analysis_entry(self, feed_name, records, ingestion_id):
        """Create an analysis entry in the threat_analysis table"""
        try:
            # Extract IOCs from records
            iocs = []
            
            for record in records:
                ioc = None
                
                # Extract based on feed type
                if feed_name == "threatfox" and "ioc_value" in record and "ioc_type" in record:
                    ioc = {
                        "type": record["ioc_type"].split(":")[0] if ":" in record["ioc_type"] else record["ioc_type"],
                        "value": record["ioc_value"],
                        "source": feed_name,
                        "threat_type": record.get("threat_type"),
                        "malware": record.get("malware"),
                        "confidence": record.get("confidence_level", 50),
                        "first_seen": record.get("first_seen_utc"),
                        "tags": record.get("tags", "").split(",") if record.get("tags") else []
                    }
                elif feed_name == "phishtank" and "url" in record:
                    ioc = {
                        "type": "url",
                        "value": record["url"],
                        "source": feed_name,
                        "verified": record.get("verified", True),
                        "target": record.get("target", "Unknown"),
                        "confidence": 70,
                        "first_seen": record.get("submission_time")
                    }
                elif feed_name == "urlhaus" and "url" in record:
                    ioc = {
                        "type": "url",
                        "value": record["url"],
                        "source": feed_name,
                        "threat_type": record.get("threat"),
                        "tags": record.get("tags", "").split(",") if record.get("tags") else [],
                        "confidence": 70,
                        "first_seen": record.get("dateadded")
                    }
                
                if ioc:
                    iocs.append(ioc)
            
            # If no IOCs were found, don't create an analysis entry
            if not iocs:
                logger.warning(f"No IOCs extracted from {feed_name}, skipping analysis entry")
                return
                
            # Create analysis record
            analysis_result = {
                "source_id": ingestion_id,
                "source_type": feed_name,
                "iocs": json.dumps(iocs),
                "analysis_timestamp": datetime.now().isoformat(),
                "severity": "medium",
                "confidence": "medium",
                "vertex_analysis": json.dumps({
                    "summary": f"Ingestion of {len(records)} records from {feed_name}",
                    "threat_actor": "Unknown",
                    "targets": "Unknown",
                    "techniques": "Unknown",
                    "malware": "Unknown",
                    "severity": "medium",
                    "confidence": "medium"
                })
            }
            
            # Insert into threat_analysis table
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
            
            # Ensure the table exists
            try:
                self.bq_client.get_table(full_table_id)
            except Exception:
                # Create table
                schema = [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("confidence", "STRING")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                self.bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table threat_analysis")
            
            # Insert analysis record
            errors = self.bq_client.insert_rows_json(full_table_id, [analysis_result])
            
            if not errors:
                logger.info(f"Created analysis entry for {feed_name} with {len(iocs)} IOCs")
                return True
            else:
                logger.error(f"Error creating analysis entry: {errors}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating analysis entry: {str(e)}")
            logger.error(traceback.format_exc())
            return False

    def analyze_csv_file(self, csv_content, feed_name="csv_upload"):
        """Analyze an uploaded CSV file to extract threat intelligence"""
        if not csv_content:
            return {"error": "Empty CSV data"}
            
        try:
            # Generate a unique ingestion ID
            ingestion_id = f"upload_{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Parse CSV
            csv_io = StringIO(csv_content)
            csv_reader = csv.DictReader(csv_io)
            
            # Process rows
            records = []
            timestamp = datetime.now().isoformat()
            
            for row in csv_reader:
                if not row or all(not cell.strip() for cell in row.values()):
                    continue
                
                record = {
                    key: value for key, value in row.items()
                }
                
                # Add metadata
                record.update({
                    "_ingestion_timestamp": timestamp,
                    "_ingestion_id": ingestion_id,
                    "_source": "csv_upload",
                    "_feed_type": f"Uploaded CSV: {feed_name}"
                })
                
                records.append(record)
            
            # Upload to BigQuery with custom table name
            table_id = f"upload_{feed_name.lower().replace(' ', '_').replace('-', '_')}"
            
            # Insert records
            inserted_count = self._insert_into_bigquery(table_id, records)
            
            # Create analysis entry
            self._create_analysis_entry("csv_upload", records, ingestion_id)
            
            return {
                "status": "success",
                "feed_name": feed_name,
                "record_count": inserted_count,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing CSV file: {str(e)}")
            logger.error(traceback.format_exc())
            return {"error": f"Analysis failed: {str(e)}"}


# HTTP endpoint for Cloud Functions
def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion"""
    logger.info("Ingestion endpoint called")
    
    # Parse request
    try:
        request_json = request.get_json(silent=True)
    except Exception as e:
        logger.error(f"Error parsing request: {str(e)}")
        request_json = {"process_all": True}  # Default to process all if error
    
    # Initialize ingestion engine
    try:
        logger.info("Initializing ThreatDataIngestion engine")
        ingestion = ThreatDataIngestion()
    except Exception as e:
        logger.error(f"Error initializing ingestion engine: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": f"Failed to initialize: {str(e)}"}, 500
    
    if request_json:
        # Check for CSV upload
        if request_json.get("file_type") == "csv" and "content" in request_json:
            feed_name = request_json.get("feed_name", "csv_upload")
            content = request_json["content"]
            return ingestion.analyze_csv_file(content, feed_name)
        
        # Check for specific feed
        feed_name = request_json.get("feed_name")
        if feed_name:
            if feed_name == "all":
                # Process all feeds
                results = ingestion.process_all_feeds()
                return {"results": results, "count": len(results)}
            elif feed_name not in FEED_SOURCES:
                return {"error": f"Unknown feed: {feed_name}"}, 400
            
            try:
                result = ingestion.process_feed(feed_name)
                return result
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                logger.error(traceback.format_exc())
                return {"error": f"Processing error: {str(e)}"}, 500
    
    # Default to processing all feeds
    try:
        logger.info("Processing all feeds")
        results = ingestion.process_all_feeds()
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Error processing all feeds: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": f"Processing error: {str(e)}"}, 500


# Entry point for running directly
if __name__ == "__main__":
    # Process all feeds when run directly
    try:
        logging.basicConfig(level=logging.INFO)
        logger.info("Starting ingestion directly")
        
        ingestion = ThreatDataIngestion()
        results = ingestion.process_all_feeds()
        
        # Print results
        for result in results:
            print(f"{result.get('feed_name')}: {result.get('status')} ({result.get('record_count')} records)")
            
        print(f"Total feeds processed: {len(results)}")
        processed_feeds = sum(1 for r in results if r.get('status') == 'success')
        print(f"Successfully processed: {processed_feeds}/{len(results)}")
        print(f"Total records: {sum(r.get('record_count', 0) for r in results)}")
        
    except Exception as e:
        print(f"Error processing feeds: {str(e)}")
        traceback.print_exc()
