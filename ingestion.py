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
    level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
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

# OTX AlienVault integration if API key is available
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
if OTX_API_KEY:
    FEED_SOURCES["otx_alienvault"] = {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "table_id": "otx_alienvault",
        "format": "json",
        "api_key": OTX_API_KEY,
        "description": "OTX AlienVault - Threat intelligence from Open Threat Exchange"
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
                logger.info(f"Successfully obtained BigQuery client from config for project {PROJECT_ID}")
                
                # Verify client functionality with a simple query
                try:
                    query_job = client.query("SELECT 1")
                    query_job.result()
                    logger.info("BigQuery client connection test successful")
                except Exception as e:
                    logger.warning(f"BigQuery client test query failed: {str(e)}")
                
                return client
                
            # If not available, try direct initialization
            logger.info(f"Initializing BigQuery client directly for project {PROJECT_ID}")
            from google.cloud import bigquery
            client = bigquery.Client(project=PROJECT_ID)
            
            # Verify client functionality
            try:
                query_job = client.query("SELECT 1")
                query_job.result()
                logger.info("Direct BigQuery client connection test successful")
            except Exception as e:
                logger.warning(f"Direct BigQuery client test query failed: {str(e)}")
                
            return client
        except Exception as e:
            logger.error(f"Error initializing BigQuery client: {str(e)}")
            logger.error(traceback.format_exc())
            return None

    def _ensure_dataset_exists(self):
        """Ensure the BigQuery dataset exists"""
        try:
            if not self.bq_client:
                logger.error("Cannot ensure dataset exists: BigQuery client is None")
                return False
                
            dataset_id = f"{PROJECT_ID}.{DATASET_ID}"
            try:
                self.bq_client.get_dataset(dataset_id)
                logger.info(f"Dataset {DATASET_ID} already exists")
                return True
            except Exception as e:
                logger.info(f"Dataset {DATASET_ID} does not exist, will create: {str(e)}")
                
                # Create the dataset
                from google.cloud import bigquery
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = "US"
                self.bq_client.create_dataset(dataset, exists_ok=True)
                logger.info(f"Created dataset {DATASET_ID}")
                return True
        except Exception as e:
            logger.error(f"Error ensuring dataset exists: {str(e)}")
            logger.error(traceback.format_exc())
            return False

    def _ensure_tables_exist(self):
        """Ensure tables exist for all feeds"""
        if not self.bq_client:
            logger.error("Cannot ensure tables exist: BigQuery client is None")
            return False
            
        table_creation_success = True
        
        for feed_name, feed_config in FEED_SOURCES.items():
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                # Check if table exists
                try:
                    self.bq_client.get_table(full_table_id)
                    logger.info(f"Table {table_id} already exists")
                    continue
                except Exception as e:
                    logger.info(f"Table {table_id} does not exist, will create: {str(e)}")
                
                # Create basic schema based on feed type
                from google.cloud import bigquery
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
                        bigquery.SchemaField("last_online", "STRING"),
                        bigquery.SchemaField("threat", "STRING"),
                        bigquery.SchemaField("tags", "STRING"),
                        bigquery.SchemaField("urlhaus_link", "STRING"),
                        bigquery.SchemaField("reporter", "STRING")
                    ])
                elif feed_name == "otx_alienvault":
                    schema.extend([
                        bigquery.SchemaField("id", "STRING"),
                        bigquery.SchemaField("name", "STRING"),
                        bigquery.SchemaField("description", "STRING"),
                        bigquery.SchemaField("author_name", "STRING"),
                        bigquery.SchemaField("created", "STRING"),
                        bigquery.SchemaField("modified", "STRING"),
                        bigquery.SchemaField("tags", "STRING"),
                        bigquery.SchemaField("targeted_countries", "STRING"),
                        bigquery.SchemaField("malware_families", "STRING"),
                        bigquery.SchemaField("attack_ids", "STRING"),
                        bigquery.SchemaField("references", "STRING"),
                        bigquery.SchemaField("indicators", "STRING")
                    ])
                
                # Create the table
                table = bigquery.Table(full_table_id, schema=schema)
                table.description = feed_config.get("description", "Threat Intelligence Feed")
                created_table = self.bq_client.create_table(table, exists_ok=True)
                logger.info(f"Successfully created/updated table {table_id}")
                
                # Verify the table was created correctly
                try:
                    verified_table = self.bq_client.get_table(full_table_id)
                    logger.info(f"Verified table {table_id} exists with {len(verified_table.schema)} columns")
                except Exception as e:
                    logger.error(f"Failed to verify table {table_id} after creation: {str(e)}")
                    table_creation_success = False
                    
            except Exception as e:
                logger.error(f"Error creating table {table_id}: {str(e)}")
                logger.error(traceback.format_exc())
                table_creation_success = False
        
        # Also ensure threat_analysis table exists for IOCs
        try:
            analysis_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
            try:
                self.bq_client.get_table(analysis_table_id)
                logger.info("Table threat_analysis already exists")
            except Exception:
                # Create table with schema
                from google.cloud import bigquery
                schema = [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("confidence", "STRING")
                ]
                table = bigquery.Table(analysis_table_id, schema=schema)
                self.bq_client.create_table(table, exists_ok=True)
                logger.info("Created table threat_analysis")
        except Exception as e:
            logger.error(f"Error ensuring threat_analysis table: {str(e)}")
            table_creation_success = False

        # Also create the threat_campaigns table if it doesn't exist
        try:
            campaigns_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
            try:
                self.bq_client.get_table(campaigns_table_id)
                logger.info("Table threat_campaigns already exists")
            except Exception:
                # Create table with schema
                from google.cloud import bigquery
                schema = [
                    bigquery.SchemaField("campaign_id", "STRING"),
                    bigquery.SchemaField("campaign_name", "STRING"),
                    bigquery.SchemaField("threat_actor", "STRING"),
                    bigquery.SchemaField("malware", "STRING"),
                    bigquery.SchemaField("techniques", "STRING"),
                    bigquery.SchemaField("targets", "STRING"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("sources", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("source_count", "INTEGER"),
                    bigquery.SchemaField("ioc_count", "INTEGER"),
                    bigquery.SchemaField("first_seen", "STRING"),
                    bigquery.SchemaField("last_seen", "STRING"),
                    bigquery.SchemaField("detection_timestamp", "STRING")
                ]
                table = bigquery.Table(campaigns_table_id, schema=schema)
                self.bq_client.create_table(table, exists_ok=True)
                logger.info("Created table threat_campaigns")
        except Exception as e:
            logger.error(f"Error ensuring threat_campaigns table: {str(e)}")
            table_creation_success = False
            
        return table_creation_success

    def verify_feed_access(self):
        """Verify that all feed URLs are accessible"""
        feed_status = {}
        
        for feed_name, feed_config in FEED_SOURCES.items():
            url = feed_config["url"]
            feed_status[feed_name] = {"url": url, "accessible": False, "status_code": None, "error": None}
            
            try:
                logger.info(f"Testing access to feed URL: {url}")
                
                # Build headers for feeds that need API keys
                headers = {}
                if "api_key" in feed_config:
                    if feed_name == "otx_alienvault":
                        headers["X-OTX-API-KEY"] = feed_config["api_key"]
                    else:
                        headers["Authorization"] = f"Bearer {feed_config['api_key']}"
                
                response = requests.get(url, headers=headers, timeout=30, verify=False)
                feed_status[feed_name]["status_code"] = response.status_code
                
                if response.status_code == 200:
                    feed_status[feed_name]["accessible"] = True
                    content_length = len(response.content)
                    feed_status[feed_name]["content_length"] = content_length
                    logger.info(f"Successfully accessed feed URL: {url} - Content length: {content_length} bytes")
                else:
                    logger.warning(f"Feed URL returned non-200 status: {url} - {response.status_code}")
            except Exception as e:
                logger.error(f"Error accessing feed URL {url}: {str(e)}")
                feed_status[feed_name]["error"] = str(e)
        
        # Log summary
        accessible_feeds = [name for name, status in feed_status.items() if status["accessible"]]
        inaccessible_feeds = [name for name, status in feed_status.items() if not status["accessible"]]
        
        if accessible_feeds:
            logger.info(f"Accessible feeds: {', '.join(accessible_feeds)}")
        if inaccessible_feeds:
            logger.warning(f"Inaccessible feeds: {', '.join(inaccessible_feeds)}")
        
        return feed_status

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
        """Process a specific feed with enhanced error handling"""
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
            # Verify BigQuery client exists
            if not self.bq_client:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": "BigQuery client not initialized",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Fetch data from feed with retries
            logger.info(f"Fetching data from {url}")
            
            max_retries = 3
            retry_delay = 2
            response = None
            
            # Build headers for feeds that need API keys
            headers = {}
            if "api_key" in feed_config:
                if feed_name == "otx_alienvault":
                    headers["X-OTX-API-KEY"] = feed_config["api_key"]
                else:
                    headers["Authorization"] = f"Bearer {feed_config['api_key']}"
            
            for attempt in range(max_retries):
                try:
                    response = requests.get(url, headers=headers, timeout=30, verify=False)
                    if response.status_code == 200 and response.content:
                        break
                        
                    logger.warning(f"Feed URL returned non-200 status or empty content on attempt {attempt+1}: {response.status_code}")
                    
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (2 ** attempt))
                except Exception as e:
                    logger.warning(f"Request error on attempt {attempt+1}: {str(e)}")
                    
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (2 ** attempt))
            
            if not response or response.status_code != 200:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": f"HTTP error: {response.status_code if response else 'No response'}",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            content_length = len(response.content)
            logger.info(f"Received {content_length} bytes from {url}")
            
            if content_length == 0:
                return {
                    "feed_name": feed_name,
                    "status": "error",
                    "message": "Empty response from feed",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Process based on format
            if feed_format == "json":
                records = self._process_json_feed(feed_name, response.text, ingestion_id, feed_config)
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
            
            if inserted_count == 0:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "Zero records inserted",
                    "record_count": 0,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Create analysis entry
            analysis_created = self._create_analysis_entry(feed_name, records, ingestion_id)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Return successful result
            return {
                "feed_name": feed_name,
                "status": "success",
                "record_count": inserted_count,
                "duration_seconds": duration,
                "timestamp": datetime.now().isoformat(),
                "analysis_created": analysis_created
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

    def _process_json_feed(self, feed_name, content, ingestion_id, feed_config):
        """Process JSON feed data"""
        records = []
        timestamp = datetime.now().isoformat()
        
        try:
            # Parse JSON
            data = json.loads(content)
            
            # Handle different feed formats
            if feed_name == "threatfox":
                # ThreatFox has a specific structure with IDs as keys
                if isinstance(data, dict) and "data" in data:
                    # New API format
                    for item in data.get("data", []):
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
                else:
                    # Old API format
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
            
            elif feed_name == "otx_alienvault":
                # OTX AlienVault structure
                if isinstance(data, dict) and "results" in data:
                    for pulse in data["results"]:
                        if not isinstance(pulse, dict):
                            continue
                            
                        # Process the pulse data
                        record = {
                            "id": pulse.get("id", ""),
                            "name": pulse.get("name", ""),
                            "description": pulse.get("description", ""),
                            "author_name": pulse.get("author_name", ""),
                            "created": pulse.get("created", ""),
                            "modified": pulse.get("modified", ""),
                            "tags": json.dumps(pulse.get("tags", [])),
                            "targeted_countries": json.dumps(pulse.get("targeted_countries", [])),
                            "malware_families": json.dumps(pulse.get("malware_families", [])),
                            "attack_ids": json.dumps(pulse.get("attack_ids", [])),
                            "references": json.dumps(pulse.get("references", [])),
                            "indicators": json.dumps(pulse.get("indicators", []))
                        }
                        
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
            # Special handling for URLhaus
            if feed_name == "urlhaus":
                # URLhaus CSV has a comment header that starts with #
                # Find the actual CSV header line (first non-comment line)
                lines = content.split('\n')
                header_line_index = None
                
                for i, line in enumerate(lines):
                    if line and not line.startswith('#'):
                        header_line_index = i
                        break
                
                if header_line_index is not None:
                    # Use only the content from the header line onwards
                    content = '\n'.join(lines[header_line_index:])
                    
                    # Parse CSV
                    csv_file = StringIO(content)
                    csv_reader = csv.DictReader(csv_file)
                    
                    expected_columns = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
                    
                    for row in csv_reader:
                        if not row or not any(row.values()):
                            continue
                        
                        # Verify we have the URL field which is most important
                        if "url" not in row or not row["url"]:
                            continue
                            
                        # Create clean record
                        record = {}
                        
                        # Map fields we care about
                        for column in expected_columns:
                            if column in row:
                                record[column] = row[column].strip() if isinstance(row[column], str) else row[column]
                        
                        # Add standard metadata
                        record.update({
                            "_ingestion_timestamp": timestamp,
                            "_ingestion_id": ingestion_id,
                            "_source": feed_name,
                            "_feed_type": FEED_SOURCES[feed_name].get("description", "Threat Feed")
                        })
                        
                        records.append(record)
            else:
                # Handle skip lines if specified for other CSV feeds
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
        """Insert records into BigQuery with enhanced error handling and batching"""
        if not records:
            logger.warning("No records to insert")
            return 0
            
        if not self.bq_client:
            logger.error("BigQuery client not initialized")
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
            batches = [processed_rows[i:i+batch_size] for i in range(0, len(processed_rows), batch_size)]
            
            logger.info(f"Inserting {len(processed_rows)} records in {len(batches)} batches to {table_id}")
            
            for batch_idx, batch in enumerate(batches):
                logger.debug(f"Processing batch {batch_idx+1}/{len(batches)} with {len(batch)} records")
                
                try:
                    errors = self.bq_client.insert_rows_json(full_table_id, batch)
                    
                    if not errors:
                        total_inserted += len(batch)
                        logger.debug(f"Successfully inserted batch {batch_idx+1} of {len(batch)} records")
                    else:
                        logger.error(f"Errors inserting batch {batch_idx+1}: {errors}")
                        
                        # Try to update schema and insert again
                        try:
                            table = self.bq_client.get_table(full_table_id)
                            current_schema = {field.name: field for field in table.schema}
                            
                            # Find missing fields
                            missing_fields = []
                            new_fields_by_name = {}
                            
                            for row in batch:
                                for field in row:
                                    if field not in current_schema and field not in new_fields_by_name:
                                        from google.cloud import bigquery
                                        new_field = bigquery.SchemaField(field, "STRING")
                                        missing_fields.append(new_field)
                                        new_fields_by_name[field] = new_field
                            
                            if missing_fields:
                                # Update schema
                                new_schema = list(table.schema) + missing_fields
                                table.schema = new_schema
                                self.bq_client.update_table(table, ["schema"])
                                logger.info(f"Updated schema for {full_table_id} with {len(missing_fields)} new fields: {', '.join(new_fields_by_name.keys())}")
                                
                                # Try insert again
                                retry_errors = self.bq_client.insert_rows_json(full_table_id, batch)
                                if not retry_errors:
                                    total_inserted += len(batch)
                                    logger.debug(f"Successfully inserted batch {batch_idx+1} after schema update")
                                else:
                                    logger.error(f"Still got errors after schema update for batch {batch_idx+1}: {retry_errors}")
                            else:
                                logger.warning(f"No missing fields identified for batch {batch_idx+1} despite insertion errors")
                        except Exception as e:
                            logger.error(f"Schema update error for batch {batch_idx+1}: {str(e)}")
                            logger.error(traceback.format_exc())
                except Exception as e:
                    logger.error(f"Error inserting batch {batch_idx+1}: {str(e)}")
                    logger.error(traceback.format_exc())
                
                # Add a small delay between batches to avoid rate limiting
                if batch_idx < len(batches) - 1:
                    time.sleep(0.2)
            
            logger.info(f"Inserted {total_inserted}/{len(processed_rows)} records into {table_id}")
            return total_inserted
                
        except Exception as e:
            logger.error(f"Error inserting into BigQuery table {table_id}: {str(e)}")
            logger.error(traceback.format_exc())
            return 0

    def _extract_iocs(self, records, feed_name):
        """Extract indicators of compromise from feed records"""
        iocs = []
        timestamp = datetime.now().isoformat()
        
        # IOC regex patterns
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
        
        # Extract IOCs based on feed type
        try:
            if feed_name == "threatfox":
                for record in records:
                    if "ioc_value" in record and "ioc_type" in record:
                        ioc_value = record["ioc_value"]
                        ioc_type_raw = record["ioc_type"]
                        
                        # Map ThreatFox types to our standard types
                        ioc_type_map = {
                            "ip:port": "ip",
                            "domain": "domain",
                            "url": "url",
                            "md5_hash": "md5",
                            "sha1_hash": "sha1",
                            "sha256_hash": "sha256",
                            "email": "email"
                        }
                        
                        # Extract base type (e.g., "ip:port" -> "ip")
                        base_type = ioc_type_raw.split(":")[0] if ":" in ioc_type_raw else ioc_type_raw
                        ioc_type = ioc_type_map.get(base_type, base_type)
                        
                        # Create IOC with available context
                        ioc = {
                            "type": ioc_type,
                            "value": ioc_value,
                            "source": feed_name,
                            "threat_type": record.get("threat_type"),
                            "malware": record.get("malware"),
                            "confidence": record.get("confidence_level", 50),
                            "first_seen": record.get("first_seen_utc"),
                            "tags": record.get("tags", "").split(",") if record.get("tags") else []
                        }
                        
                        # Add geolocation for IPs
                        if ioc_type == "ip":
                            ioc["geo"] = {"country": "Unknown", "city": "Unknown"}
                            
                        iocs.append(ioc)
                        
            elif feed_name == "phishtank":
                for record in records:
                    if "url" in record:
                        url = record["url"]
                        
                        # Create IOC
                        ioc = {
                            "type": "url",
                            "value": url,
                            "source": feed_name,
                            "verified": record.get("verified", "1") == "1",
                            "target": record.get("target", "Unknown"),
                            "confidence": 70, # PhishTank URLs are verified
                            "first_seen": record.get("submission_time")
                        }
                        
                        iocs.append(ioc)
                        
            elif feed_name == "urlhaus":
                for record in records:
                    if "url" in record:
                        url = record["url"]
                        
                        # Create IOC
                        ioc = {
                            "type": "url",
                            "value": url,
                            "source": feed_name,
                            "threat_type": record.get("threat"),
                            "tags": record.get("tags", "").split(",") if record.get("tags") else [],
                            "confidence": 70,
                            "first_seen": record.get("dateadded")
                        }
                        
                        iocs.append(ioc)
                        
            elif feed_name == "otx_alienvault":
                for record in records:
                    if "indicators" in record:
                        try:
                            indicators = json.loads(record["indicators"])
                            for indicator in indicators:
                                if not isinstance(indicator, dict):
                                    continue
                                    
                                ioc_type = indicator.get("type")
                                ioc_value = indicator.get("indicator")
                                
                                if not ioc_type or not ioc_value:
                                    continue
                                    
                                # Map OTX types to our standard types
                                type_map = {
                                    "IPv4": "ip",
                                    "IPv6": "ip",
                                    "domain": "domain",
                                    "hostname": "domain",
                                    "URL": "url",
                                    "FileHash-MD5": "md5",
                                    "FileHash-SHA1": "sha1", 
                                    "FileHash-SHA256": "sha256",
                                    "email": "email",
                                    "CVE": "cve"
                                }
                                
                                std_type = type_map.get(ioc_type, ioc_type.lower())
                                
                                # Create IOC
                                ioc = {
                                    "type": std_type,
                                    "value": ioc_value,
                                    "source": feed_name,
                                    "confidence": 60,
                                    "first_seen": record.get("created"),
                                    "tags": json.loads(record.get("tags", "[]")),
                                    "pulse_name": record.get("name"),
                                    "author": record.get("author_name")
                                }
                                
                                # Add geo for IPs
                                if std_type == "ip":
                                    ioc["geo"] = {"country": "Unknown", "city": "Unknown"}
                                    
                                iocs.append(ioc)
                        except (json.JSONDecodeError, TypeError) as e:
                            logger.warning(f"Error parsing indicators in OTX record: {e}")
                            
            # Generic extraction for any feed without specific handling
            if not iocs:
                for record in records:
                    # Convert record to text to scan with regex
                    record_text = json.dumps(record)
                    
                    # Extract IOCs using regex patterns
                    for ioc_type, pattern in IOC_PATTERNS.items():
                        matches = re.findall(pattern, record_text)
                        for match in matches:
                            # Skip standard fields
                            if match in ["_ingestion_timestamp", "_ingestion_id", "_source", "_feed_type"]:
                                continue
                                
                            # Create basic IOC
                            ioc = {
                                "type": ioc_type,
                                "value": match,
                                "source": feed_name,
                                "confidence": 50,
                                "first_seen": timestamp
                            }
                            
                            # Add geo for IPs
                            if ioc_type == "ip":
                                ioc["geo"] = {"country": "Unknown", "city": "Unknown"}
                                
                            iocs.append(ioc)
            
            # Remove duplicates
            unique_iocs = []
            seen_iocs = set()
            
            for ioc in iocs:
                key = (ioc["type"], ioc["value"])
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    unique_iocs.append(ioc)
            
            logger.info(f"Extracted {len(unique_iocs)} unique IOCs from {feed_name}")
            return unique_iocs
            
        except Exception as e:
            logger.error(f"Error extracting IOCs from {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            return []

    def _create_analysis_entry(self, feed_name, records, ingestion_id):
        """Create an analysis entry in the threat_analysis table"""
        try:
            # Extract IOCs from records
            iocs = self._extract_iocs(records, feed_name)
            
            if not iocs:
                logger.warning(f"No IOCs extracted from {feed_name}, skipping analysis entry")
                return False
                
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
                from google.cloud import bigquery
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
                
                # Try to create a campaign entry if we have enough information
                self._create_campaign_entry(feed_name, iocs, records)
                
                return True
            else:
                logger.error(f"Error creating analysis entry: {errors}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating analysis entry: {str(e)}")
            logger.error(traceback.format_exc())
            return False

    def _create_campaign_entry(self, feed_name, iocs, records):
        """Create a campaign entry if the feed provides campaign information"""
        try:
            # Only create campaign for certain feeds that have campaign info
            if feed_name not in ["threatfox", "otx_alienvault"]:
                return False
                
            # Extract campaign information
            campaign_name = None
            threat_actor = "Unknown"
            malware = None
            severity = "medium"
            techniques = None
            targets = None
            
            if feed_name == "threatfox":
                # Extract from first record
                if records and isinstance(records[0], dict):
                    first_record = records[0]
                    malware = first_record.get("malware_printable")
                    if malware:
                        campaign_name = f"{malware} Campaign"
                        
                    threat_type = first_record.get("threat_type")
                    if threat_type == "botnet_c2":
                        severity = "high"
                        techniques = "Command and Control"
                    elif threat_type == "payload_delivery":
                        techniques = "Initial Access, Execution"
                    
            elif feed_name == "otx_alienvault":
                if records and isinstance(records[0], dict):
                    first_record = records[0]
                    campaign_name = first_record.get("name")
                    
                    # Look for author name as potential threat actor
                    author = first_record.get("author_name")
                    if author and author != "AlienVault":
                        threat_actor = author
                        
                    # Try to extract malware families
                    try:
                        malware_families = json.loads(first_record.get("malware_families", "[]"))
                        if malware_families:
                            malware = ", ".join(malware_families)
                    except (json.JSONDecodeError, TypeError):
                        pass
                        
                    # Try to extract attacked countries as targets
                    try:
                        targeted_countries = json.loads(first_record.get("targeted_countries", "[]"))
                        if targeted_countries:
                            targets = ", ".join(targeted_countries)
                    except (json.JSONDecodeError, TypeError):
                        pass
                        
                    # Look for attack IDs for techniques
                    try:
                        attack_ids = json.loads(first_record.get("attack_ids", "[]"))
                        if attack_ids:
                            techniques = ", ".join(attack_ids)
                    except (json.JSONDecodeError, TypeError):
                        pass
            
            # Skip if we don't have enough information
            if not campaign_name:
                return False
                
            # Create campaign ID
            campaign_id = f"{feed_name}_{datetime.now().strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"
            
            # Create campaign record
            campaign = {
                "campaign_id": campaign_id,
                "campaign_name": campaign_name,
                "threat_actor": threat_actor,
                "malware": malware or "Unknown",
                "techniques": techniques or "Unknown",
                "targets": targets or "Unknown",
                "severity": severity,
                "sources": json.dumps([feed_name]),
                "iocs": json.dumps(iocs[:50]),  # Limit to first 50 IOCs
                "source_count": 1,
                "ioc_count": len(iocs),
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "detection_timestamp": datetime.now().isoformat()
            }
            
            # Insert into threat_campaigns table
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
            
            # Ensure the table exists
            try:
                self.bq_client.get_table(full_table_id)
            except Exception:
                # Create table with schema
                from google.cloud import bigquery
                schema = [
                    bigquery.SchemaField("campaign_id", "STRING"),
                    bigquery.SchemaField("campaign_name", "STRING"),
                    bigquery.SchemaField("threat_actor", "STRING"),
                    bigquery.SchemaField("malware", "STRING"),
                    bigquery.SchemaField("techniques", "STRING"),
                    bigquery.SchemaField("targets", "STRING"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("sources", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("source_count", "INTEGER"),
                    bigquery.SchemaField("ioc_count", "INTEGER"),
                    bigquery.SchemaField("first_seen", "STRING"),
                    bigquery.SchemaField("last_seen", "STRING"),
                    bigquery.SchemaField("detection_timestamp", "STRING")
                ]
                table = bigquery.Table(full_table_id, schema=schema)
                self.bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table threat_campaigns")
            
            # Insert campaign record
            errors = self.bq_client.insert_rows_json(full_table_id, [campaign])
            
            if not errors:
                logger.info(f"Created campaign entry '{campaign_name}' with {len(iocs)} IOCs")
                return True
            else:
                logger.error(f"Error creating campaign entry: {errors}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating campaign entry: {str(e)}")
            logger.error(traceback.format_exc())
            return False

    def analyze_csv_file(self, csv_content, feed_name="csv_upload"):
        """Analyze uploaded CSV for threat intelligence"""
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
            
            if not records:
                return {"error": "No valid records found in CSV"}
            
            # Upload to BigQuery with custom table name
            table_id = f"upload_{feed_name.lower().replace(' ', '_').replace('-', '_')}"
            
            # Insert records
            inserted_count = self._insert_into_bigquery(table_id, records)
            
            if inserted_count == 0:
                return {"error": "Failed to insert records into BigQuery"}
            
            # Extract IOCs from the records
            iocs = self._extract_iocs(records, "csv_upload")
            
            # Create analysis entry
            analysis_result = {
                "source_id": ingestion_id,
                "source_type": "csv_upload",
                "iocs": json.dumps(iocs),
                "analysis_timestamp": datetime.now().isoformat(),
                "severity": "medium",
                "confidence": "medium",
                "vertex_analysis": json.dumps({
                    "summary": f"Analysis of uploaded CSV: {feed_name}",
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
                from google.cloud import bigquery
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
                logger.info(f"Created analysis entry for uploaded CSV with {len(iocs)} IOCs")
                
                # Return success response
                return {
                    "status": "success",
                    "feed_name": feed_name,
                    "table": table_id,
                    "record_count": inserted_count,
                    "ioc_count": len(iocs),
                    "iocs": iocs[:10],  # Return first 10 IOCs for preview
                    "analysis_id": ingestion_id,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                logger.error(f"Error creating analysis entry: {errors}")
                return {"error": f"Error creating analysis entry: {errors}"}
                
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
