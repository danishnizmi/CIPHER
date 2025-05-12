"""
Optimized ingestion module for threat intelligence feeds.
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
import socket
import time
import threading
import uuid
from typing import Dict, List, Any, Optional, Tuple, Union
from functools import lru_cache
from google.cloud import storage, bigquery, pubsub_v1
from google.api_core.exceptions import NotFound, GoogleAPIError
from google.cloud.exceptions import Conflict

# Import configuration
from config import Config, ServiceManager, ServiceStatus, report_error

# Configure logging
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

# Lock for thread-safe operations
_ingestion_lock = threading.Lock()

# Default feed configs for testing
DEFAULT_FEEDS = [
    {
        "id": "threatfox",
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent indicators from ThreatFox",
        "format": "json",
        "type": "mixed",
        "update_frequency": "daily",
        "enabled": True
    },
    {
        "id": "urlhaus",
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recent malware URLs from URLhaus",
        "format": "csv",
        "type": "url",
        "update_frequency": "daily",
        "enabled": True
    }
]

# -------------------- Helper Functions --------------------

def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    return (
        service_manager.get_client('bigquery'),
        service_manager.get_client('storage'),
        service_manager.get_client('publisher'),
        service_manager.get_client('subscriber')
    )

def publish_event(event_type: str, data: dict = None):
    """Publish event through event bus if available."""
    try:
        from flask import g
        if hasattr(g, 'event_bus'):
            g.event_bus.publish(event_type, data)
            logger.debug(f"Published event: {event_type}")
    except Exception as e:
        logger.debug(f"Not in Flask context, skipping event publish: {e}")

def ensure_default_feeds():
    """Ensure default feeds exist if none configured."""
    if not hasattr(Config, 'FEEDS') or not Config.FEEDS:
        logger.warning("No feeds configured, using defaults")
        Config.FEEDS = DEFAULT_FEEDS
        
        # Try to save to environment for future loads
        os.environ['FEED_CONFIG'] = json.dumps({"feeds": DEFAULT_FEEDS})
        
        # Also save to a local file
        try:
            with open('/tmp/feed_config.json', 'w') as f:
                json.dump({"feeds": DEFAULT_FEEDS}, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save feed config to disk: {e}")
    
    return Config.FEEDS

# -------------------- Data Processing --------------------

class DataProcessor:
    """Handles data cleaning, sanitization, and validation."""
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string values to prevent XSS and injection attacks."""
        if not value or not isinstance(value, str):
            return value
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        return value[:32768] if len(value) > 32768 else value
        
    @staticmethod
    def sanitize_ioc(ioc_type: str, value: str) -> Optional[str]:
        """Sanitize IOC values based on their type."""
        if not value:
            return value
            
        value = DataProcessor.sanitize_string(value)
        
        patterns = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
            'domain': r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            'url': r'^(https?|ftp)://.+$',
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'ip:port': r'^(\d{1,3}\.){3}\d{1,3}:\d+$'
        }
        
        if ioc_type in patterns and not re.match(patterns[ioc_type], value.lower()):
            if ioc_type == 'url' and re.match(r'^www\.', value.lower()):
                return "http://" + value
            logger.debug(f"Suspicious {ioc_type} format: {value}")
                
        return value
        
    @staticmethod
    def sanitize_record(record: Dict, record_type: str = None) -> Dict:
        """Sanitize an entire record."""
        if not record:
            return {}
            
        sanitized = {}
        
        for key, value in record.items():
            if isinstance(value, dict):
                sanitized[key] = DataProcessor.sanitize_record(value)
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    sanitized[key] = [DataProcessor.sanitize_record(item) for item in value]
                else:
                    sanitized[key] = value
            elif isinstance(value, str):
                if record_type == 'ioc' and key == 'value' and 'type' in record:
                    sanitized[key] = DataProcessor.sanitize_ioc(record['type'], value)
                else:
                    sanitized[key] = DataProcessor.sanitize_string(value)
            else:
                sanitized[key] = value
                
        return sanitized

    @staticmethod
    def determine_ioc_type(value: str) -> str:
        """Determine the IOC type based on value format."""
        if not value or not isinstance(value, str):
            return 'unknown'
            
        value = value.strip().lower()
        
        # Handle ip:port format specially (for ThreatFox)
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}:\d+$', value):
            return 'ip:port'
        
        patterns = {
            'ip': r'^(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$',
            'domain': r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            'url': r'^(https?|ftp)://.+$',
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
        
        for ioc_type, pattern in patterns.items():
            if re.match(pattern, value):
                return ioc_type
                
        return 'unknown'

# -------------------- Storage Operations --------------------

def ensure_bucket_exists(bucket_name: str) -> bool:
    """Ensure the GCS bucket exists and create it if it doesn't."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return False
    
    try:
        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            logger.info(f"Creating bucket {bucket_name}")
            bucket = storage_client.create_bucket(
                bucket_name, 
                location=Config.GCP_REGION,
                predefined_acl='projectPrivate'
            )
            
            # Add lifecycle rules for cost optimization
            lifecycle_rules = {
                'rule': [
                    {'action': {'type': 'Delete'}, 'condition': {'age': 30, 'isLive': True}},
                    {'action': {'type': 'Delete'}, 'condition': {'numNewerVersions': 3, 'isLive': False}}
                ]
            }
            bucket.lifecycle_rules = [
                storage.LifecycleRule(**rule) for rule in lifecycle_rules['rule']
            ]
            bucket.patch()
            
            # Create folder structure
            for folder in ['feeds', 'raw', 'processed', 'cache', 'exports']:
                blob = bucket.blob(f"{folder}/.keep")
                blob.upload_from_string('')
            logger.info(f"Created bucket {bucket_name}")
                
            return True
        else:
            logger.debug(f"Bucket {bucket_name} already exists")
            return True
            
    except Exception as e:
        logger.error(f"Error ensuring bucket exists: {str(e)}")
        report_error(e)
        return False

def initialize_bigquery_tables() -> bool:
    """Initialize all required BigQuery tables."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("Cannot initialize BigQuery tables - client not available")
        return False
    
    service_manager = Config.get_service_manager()
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        try:
            bq_client.get_dataset(dataset_id)
            logger.debug(f"Dataset {dataset_id} already exists")
        except NotFound:
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = Config.BIGQUERY_LOCATION
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {dataset_id}")
        
        # Define table schemas
        tables_config = {
            'indicators': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("value", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("source", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("feed_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("confidence", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("campaign_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("raw_data", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("last_analyzed", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("risk_score", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("analysis_summary", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("malware_printable", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("reference", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("reporter", "STRING", mode="NULLABLE"),
            ],
            'vulnerabilities': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("cve_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("title", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("severity", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("cvss_score", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("affected_products", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("published_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("source", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("references", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
            ],
            'threat_actors': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("aliases", "STRING", mode="REPEATED"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("country", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("motivation", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("tactics", "STRING", mode="REPEATED"),
                bigquery.SchemaField("techniques", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tools", "STRING", mode="REPEATED"),
                bigquery.SchemaField("targets", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
            ],
            'campaigns': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("threat_actor_id", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("start_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("end_date", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("targets", "STRING", mode="REPEATED"),
                bigquery.SchemaField("tactics", "STRING", mode="REPEATED"),
                bigquery.SchemaField("techniques", "STRING", mode="REPEATED"),
                bigquery.SchemaField("indicators", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
            ],
            'malware': [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("name", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("aliases", "STRING", mode="REPEATED"),
                bigquery.SchemaField("type", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("platform", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("capabilities", "STRING", mode="REPEATED"),
                bigquery.SchemaField("indicators", "STRING", mode="REPEATED"),
                bigquery.SchemaField("created_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("updated_at", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("first_seen", "TIMESTAMP", mode="NULLABLE"),
                bigquery.SchemaField("last_seen", "TIMESTAMP", mode="NULLABLE"),
            ]
        }
        
        # Create or update tables
        for table_name, schema in tables_config.items():
            table_id = f"{dataset_id}.{table_name}"
            try:
                try:
                    table = bq_client.get_table(table_id)
                    logger.debug(f"Table {table_id} exists, checking schema")
                    
                    existing_fields = {field.name: field for field in table.schema}
                    new_fields = [field for field in schema if field.name not in existing_fields]
                    
                    if new_fields:
                        logger.info(f"Updating schema for {table_id} with {len(new_fields)} new fields")
                        table.schema = list(table.schema) + new_fields
                        bq_client.update_table(table, ["schema"])
                        
                except NotFound:
                    table = bigquery.Table(table_id, schema=schema)
                    bq_client.create_table(table)
                    logger.info(f"Created table {table_id}")
                
                # Verify with test query
                test_query = f"SELECT COUNT(*) as count FROM `{table_id}` LIMIT 1"
                bq_client.query(test_query).result()
                
            except Exception as e:
                logger.warning(f"Issue with table {table_id}: {str(e)}")
                # Continue with other tables
                
        return True
        
    except Exception as e:
        logger.error(f"Error initializing BigQuery tables: {str(e)}")
        report_error(e)
        return False

def upload_to_gcs(bucket_name: str, blob_name: str, data: Union[str, bytes], content_type: str = None) -> Optional[str]:
    """Upload data to GCS bucket."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if content_type is None:
            if blob_name.endswith('.json'):
                content_type = 'application/json'
            elif blob_name.endswith('.csv'):
                content_type = 'text/csv'
            elif blob_name.endswith('.txt'):
                content_type = 'text/plain'
            else:
                content_type = 'application/octet-stream'
        
        if isinstance(data, str):
            data_to_upload = data.encode('utf-8')
        else:
            data_to_upload = data
            
        blob.content_type = content_type
        blob.upload_from_string(data_to_upload, content_type=content_type)
        
        gcs_uri = f"gs://{bucket_name}/{blob_name}"
        logger.info(f"Uploaded data to {gcs_uri}")
        return gcs_uri
        
    except Exception as e:
        logger.error(f"Error uploading to GCS: {str(e)}")
        report_error(e)
        return None

def upload_to_bigquery(table_id: str, records: List[Dict]) -> Optional[str]:
    """Upload records to BigQuery with optimized batching."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client or not records:
        return None
    
    logger.info(f"Uploading {len(records)} records to {table_id}")
    
    batch_size = 50
    job_ids = []
    
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        batch_num = i//batch_size + 1
        logger.info(f"Processing batch {batch_num}/{(len(records) + batch_size - 1) // batch_size}")
        
        try:
            processed_batch = []
            for record in batch:
                processed_record = {}
                
                for key, value in record.items():
                    if isinstance(value, (datetime.datetime, datetime.date)):
                        processed_record[key] = value.isoformat()
                    elif key in ['created_at', 'first_seen', 'last_seen', 'timestamp'] and isinstance(value, str):
                        try:
                            dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                            processed_record[key] = dt.isoformat()
                        except ValueError:
                            processed_record[key] = datetime.datetime.utcnow().isoformat()
                    elif isinstance(value, dict):
                        processed_record[key] = json.dumps(value)
                    elif key == 'tags' and isinstance(value, list):
                        processed_record[key] = [str(item) for item in value]
                    elif isinstance(value, list) and not value:
                        processed_record[key] = [] if key == 'tags' else value
                    elif isinstance(value, (dict, list)) and key not in ['tags']:
                        processed_record[key] = json.dumps(value)
                    else:
                        processed_record[key] = value
                
                if 'id' not in processed_record:
                    processed_record['id'] = hashlib.md5(str(record).encode()).hexdigest()
                
                if 'value' not in processed_record:
                    if 'ioc' in processed_record:
                        processed_record['value'] = str(processed_record['ioc'])
                    elif 'indicator' in processed_record:
                        processed_record['value'] = str(processed_record['indicator'])
                    else:
                        processed_record['value'] = 'unknown_' + str(uuid.uuid4())
                elif not isinstance(processed_record['value'], str):
                    processed_record['value'] = str(processed_record['value'])
                
                processed_batch.append(processed_record)
            
            if not processed_batch:
                continue
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    job_config = bigquery.LoadJobConfig(
                        schema_update_options=[bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
                        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
                        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                    )
                    
                    job = bq_client.load_table_from_json(
                        processed_batch,
                        table_id,
                        job_config=job_config
                    )
                    
                    result = job.result(timeout=60)
                    
                    if job.errors:
                        logger.error(f"Errors in batch {batch_num}: {job.errors}")
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)
                            continue
                    else:
                        job_ids.append(job.job_id)
                        logger.info(f"Successfully uploaded batch {batch_num}")
                    
                    break
                        
                except Exception as e:
                    logger.error(f"Error uploading batch {batch_num}: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to upload batch {batch_num} after {max_retries} attempts")
            
        except Exception as e:
            logger.error(f"Error processing batch {batch_num}: {str(e)}")
    
    return job_ids[0] if job_ids else None

# -------------------- Feed Processing --------------------

def download_feed(url: str, headers: Dict = None, timeout: int = 60) -> Tuple[Optional[str], Optional[bytes]]:
    """Download content from a feed URL with retry logic."""
    if not headers:
        headers = {'User-Agent': f"ThreatIntelligencePlatform/{Config.VERSION}"}
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading feed from {url} (attempt {attempt+1}/{max_retries})")
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 429:
                # Handle rate limiting
                wait_time = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
                
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '')
            return content_type, response.content
            
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Request failed: {str(e)}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Request failed after {max_retries} attempts: {str(e)}")
                return None, None
    
    return None, None

def parse_json_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse JSON feed data."""
    try:
        # Try multiple decodings
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    content_str = content.decode(encoding, errors='replace')
                    data = json.loads(content_str)
                    break
                except:
                    continue
            else:
                content_str = content.decode('utf-8', errors='ignore')
                json_start = content_str.find('{')
                json_array_start = content_str.find('[')
                
                if json_start >= 0 and (json_array_start < 0 or json_start < json_array_start):
                    data = json.loads(content_str[json_start:])
                elif json_array_start >= 0:
                    data = json.loads(content_str[json_array_start:])
                else:
                    raise Exception("Could not find valid JSON content")
        
        # Handle different formats
        processed_data = []
        
        # Handle ThreatFox format (threat IDs as keys)
        if isinstance(data, dict) and 'data' in data and isinstance(data['data'], list):
            processed_data = data['data']
        elif isinstance(data, dict) and all(key.isdigit() for key in list(data.keys())[:5]):
            for threat_id, threat_items in data.items():
                if isinstance(threat_items, list):
                    for item in threat_items:
                        if isinstance(item, dict):
                            item_copy = item.copy()
                            item_copy['threat_id'] = threat_id
                            processed_data.append(item_copy)
        # Handle regular JSON array or dict with 'data' field
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                    for item in value:
                        item_copy = item.copy()
                        item_copy['threat_id'] = key
                        processed_data.append(item_copy)
                elif key == 'data' and isinstance(value, list):
                    processed_data.extend(value)
        elif isinstance(data, list):
            processed_data = data
        
        return processed_data
    except Exception as e:
        logger.error(f"Error parsing JSON feed: {str(e)}")
        return []

def parse_csv_feed(content: bytes, parser_config: Dict) -> List[Dict]:
    """Parse CSV feed data with improved URLhaus handling."""
    try:
        # Try different encodings to handle various CSV files
        content_str = None
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'utf-16']:
            try:
                content_str = content.decode(encoding)
                # Check if decoding worked reasonably well
                if len(content_str) > 0 and ',' in content_str[:1000]:
                    break
            except UnicodeDecodeError:
                continue
        
        if not content_str:
            # Last resort decoding with error replacement
            content_str = content.decode('utf-8', errors='replace')
        
        # Log a sample for debugging
        logger.debug(f"CSV sample (first 200 chars): {content_str[:200]}")
        
        # Skip comment lines at the beginning (specifically for URLhaus)
        lines = content_str.splitlines()
        clean_lines = []
        url_haus_format = False
        
        # Check if this is likely URLhaus format
        if any(line.startswith('#') for line in lines[:5]) and any('URLhaus' in line for line in lines[:10]):
            url_haus_format = True
            logger.info("Detected URLhaus CSV format")
            
            # Find the header line - in URLhaus it's the first non-comment with expected columns
            header_line_idx = -1
            for i, line in enumerate(lines):
                if not line.startswith('#') and 'url,date_added' in line.lower():
                    header_line_idx = i
                    break
                    
            if header_line_idx >= 0:
                # Add only header and data lines
                clean_lines = [lines[header_line_idx]] + lines[header_line_idx+1:]
            else:
                # Fall back to standard comment skipping if we can't find URLhaus header
                clean_lines = [line for line in lines if not line.startswith('#')]
        else:
            # Standard comment skipping for other feeds
            clean_lines = [line for line in lines if not line.startswith('#')]
        
        if not clean_lines:
            logger.warning("No valid CSV content found after filtering comments")
            return []
            
        # Rejoin into a string
        content_str = '\n'.join(clean_lines)
        
        # Try to detect dialect
        try:
            dialect = csv.Sniffer().sniff(content_str[:1024] if len(content_str) > 1024 else content_str)
            logger.debug(f"Detected CSV dialect: delimiter={dialect.delimiter}, quotechar={dialect.quotechar}")
        except:
            # Fall back to standard dialect if detection fails
            dialect = csv.excel
            logger.debug("Using default CSV dialect (excel)")
        
        # First try standard DictReader
        csv_data = []
        reader = csv.DictReader(io.StringIO(content_str), dialect=dialect)
        
        # Validate column headers
        if not reader.fieldnames:
            logger.warning("CSV has no headers, attempting manual header detection")
            
            # Fall back to manual header detection - sometimes headers are malformed
            first_line = clean_lines[0].strip() if clean_lines else ""
            header_candidates = first_line.split(dialect.delimiter)
            
            # Remove quotes from headers if present
            header_candidates = [h.strip('"\'') for h in header_candidates]
            
            # Use manual headers if they look valid
            if len(header_candidates) > 1:
                logger.info(f"Using manual headers: {header_candidates}")
                reader = csv.DictReader(
                    io.StringIO('\n'.join(clean_lines[1:])), 
                    fieldnames=header_candidates,
                    dialect=dialect
                )
            else:
                logger.error("Failed to detect CSV headers")
                return []
        
        csv_data = list(reader)
        
        # Special handling for URLhaus
        if url_haus_format:
            logger.info(f"Processing URLhaus data with {len(csv_data)} rows")
            
            # Convert URLhaus format to standard format
            standardized_data = []
            for row in csv_data:
                # Skip empty rows
                if not row or not any(row.values()):
                    continue
                
                # Log a sample row for debugging
                if len(standardized_data) == 0:
                    logger.debug(f"URLhaus sample row: {row}")
                
                # Create a standardized record
                std_record = {
                    'ioc_type': 'url',
                    'ioc_value': row.get('url', '').strip(),
                    'threat_type': row.get('tags', '').strip() or 'malware',
                    'first_seen_utc': row.get('date_added', '').strip(),
                    'reporter': row.get('reporter', '').strip(),
                    'reference': row.get('urlhaus_reference', '').strip() or f"https://urlhaus.abuse.ch/url/{hashlib.md5(row.get('url', '').encode()).hexdigest()[:16]}/",
                    'source': 'urlhaus'
                }
                
                # Add additional fields if present
                if 'status' in row:
                    std_record['status'] = row.get('status', '').strip()
                if 'threat' in row:
                    std_record['threat_type'] = row.get('threat', '').strip()
                if 'tags' in row:
                    std_record['tags'] = row.get('tags', '').strip()
                if 'gsb' in row:
                    std_record['gsb'] = row.get('gsb', '').strip()
                if 'url_status' in row:
                    std_record['url_status'] = row.get('url_status', '').strip()
                
                # Only add if we have a valid URL
                if std_record['ioc_value'] and not std_record['ioc_value'].startswith('#'):
                    standardized_data.append(std_record)
            
            logger.info(f"Standardized {len(standardized_data)} URLhaus records")
            return standardized_data
        
        # Standard processing for other CSV feeds
        # Remove empty rows
        csv_data = [row for row in csv_data if any(value.strip() if isinstance(value, str) else value for value in row.values())]
        
        return csv_data
    except Exception as e:
        logger.error(f"Error parsing CSV feed: {str(e)}")
        logger.error(traceback.format_exc())
        return []

def parse_feed(content: bytes, format_type: str = None, parser_config: Dict = None) -> List[Dict]:
    """Parse feed data with format auto-detection."""
    if not content:
        return []
    
    if parser_config is None:
        parser_config = {}
    
    if not format_type:
        content_start = content[:100].strip()
        if content_start.startswith(b'{') or content_start.startswith(b'['):
            format_type = 'json'
        elif b',' in content_start and b'\n' in content[:1000]:
            format_type = 'csv'
        else:
            format_type = 'text'
    
    try:
        logger.info(f"Parsing feed data as {format_type} format")
        if format_type == 'json':
            results = parse_json_feed(content, parser_config)
        elif format_type == 'csv':
            results = parse_csv_feed(content, parser_config)
        else:
            logger.warning(f"Unknown format type: {format_type}, falling back to JSON")
            results = parse_json_feed(content, parser_config)
            
        logger.info(f"Successfully parsed {len(results)} records from feed")
        return results
    except Exception as e:
        logger.error(f"Error parsing feed data: {str(e)}")
        logger.error(traceback.format_exc())
        return []

def normalize_indicators(records: List[Dict], feed_name: str) -> List[Dict]:
    """Normalize indicators to a common format."""
    normalized = []
    
    for record in records:
        try:
            # Skip empty records
            if not record:
                continue
                
            # Handle ThreatFox format
            if 'ioc_value' in record and 'ioc_type' in record:
                value = record['ioc_value']
                ioc_type = record['ioc_type']
                
                # Parse tags
                tags = record.get('tags', '')
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',') if t.strip()]
                elif not isinstance(tags, list):
                    tags = []
                
                # Parse malware aliases
                malware_aliases = record.get('malware_alias', '')
                if isinstance(malware_aliases, str):
                    malware_aliases = [a.strip() for a in malware_aliases.split(',') if a.strip()]
                elif not isinstance(malware_aliases, list):
                    malware_aliases = []
                
                # Create indicator
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                    "value": value,
                    "type": ioc_type,
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": datetime.datetime.utcnow().isoformat(),
                    "confidence": int(record.get('confidence_level', 50)),
                    "tags": tags,
                    "description": f"Indicator from {feed_name}",
                    "threat_type": record.get('threat_type'),
                    "threat_id": record.get('threat_id'),
                    "malware": record.get('malware'),
                    "malware_printable": record.get('malware_printable'),
                    "first_seen": record.get('first_seen_utc'),
                    "last_seen": record.get('last_seen_utc'),
                    "reference": record.get('reference'),
                    "reporter": record.get('reporter'),
                    "raw_data": json.dumps(record)
                }
                
                # Add malware aliases to tags
                for alias in malware_aliases:
                    if alias not in indicator['tags']:
                        indicator['tags'].append(f"malware:{alias}")
                
            # Handle URLhaus format (CSV with 'url' column)
            elif ('url' in record or 'ioc_value' in record) and (feed_name.lower() == 'urlhaus' or 'threat' in record):
                value = record.get('ioc_value') or record.get('url', '')
                
                # Ensure we have a proper URL
                if not value.startswith(('http://', 'https://', 'ftp://')):
                    if value.startswith('www.'):
                        value = 'http://' + value
                    elif '.' in value and not value.startswith('#'):
                        value = 'http://' + value
                
                tags = record.get('tags', '')
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',') if t.strip()]
                elif not isinstance(tags, list):
                    tags = []
                
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                    "value": value,
                    "type": 'url',
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": datetime.datetime.utcnow().isoformat(),
                    "confidence": 80 if record.get('url_status') == 'online' else 60,
                    "tags": tags,
                    "description": f"URL from {feed_name}",
                    "threat_type": record.get('threat_type') or record.get('threat', 'malware_download'),
                    "first_seen": record.get('first_seen_utc') or record.get('date_added'),
                    "last_seen": record.get('last_seen_utc') or record.get('last_online'),
                    "reporter": record.get('reporter'),
                    "reference": record.get('reference') or record.get('urlhaus_reference'),
                    "raw_data": json.dumps(record)
                }
                
            else:
                # Generic format
                value = record.get('value') or record.get('indicator') or record.get('ioc') or record.get('url') or ''
                if not value:
                    continue
                    
                indicator = {
                    "id": hashlib.md5(f"{feed_name}:{value}".encode()).hexdigest(),
                    "value": value,
                    "type": record.get('type') or DataProcessor.determine_ioc_type(value),
                    "source": feed_name,
                    "feed_id": feed_name,
                    "created_at": datetime.datetime.utcnow().isoformat(),
                    "confidence": int(record.get('confidence', 50)),
                    "tags": record.get('tags', []) if isinstance(record.get('tags'), list) else [],
                    "description": record.get('description', f"Indicator from {feed_name}"),
                    "raw_data": json.dumps(record)
                }
            
            if not indicator['value']:
                continue
                
            # Ensure confidence is an integer
            if not isinstance(indicator['confidence'], int):
                indicator['confidence'] = 50
                
            # Calculate initial risk score
            risk_score = calculate_initial_risk_score(indicator)
            indicator['risk_score'] = risk_score
                
            normalized.append(indicator)
            
        except Exception as e:
            logger.warning(f"Error normalizing record from {feed_name}: {str(e)}")
            continue
    
    logger.info(f"Normalized {len(normalized)} records from {feed_name}")
    return normalized

def calculate_initial_risk_score(indicator: Dict) -> int:
    """Calculate initial risk score for an indicator."""
    base_score = indicator.get('confidence', 50)
    
    # Adjust based on threat type
    threat_type = indicator.get('threat_type', '').lower()
    if 'botnet' in threat_type:
        base_score += 20
    elif 'malware' in threat_type:
        base_score += 15
    elif 'phishing' in threat_type:
        base_score += 10
    
    # Adjust based on malware type
    malware = indicator.get('malware', '').lower()
    if 'ransomware' in malware:
        base_score += 25
    elif 'cobalt' in malware or 'strike' in malware:
        base_score += 20
    elif 'remcos' in malware or 'rat' in malware:
        base_score += 15
    
    # Adjust based on activity
    if indicator.get('first_seen'):
        try:
            first_seen = datetime.datetime.fromisoformat(indicator['first_seen'].replace('Z', '+00:00'))
            age_days = (datetime.datetime.utcnow() - first_seen).days
            if age_days < 7:
                base_score += 10
            elif age_days < 30:
                base_score += 5
        except:
            pass
    
    return min(max(base_score, 0), 100)

# -------------------- Main Processing --------------------

def process_feed(feed_config: Dict) -> Dict:
    """Process a single feed and store its data."""
    feed_name = feed_config.get("name", "Unknown")
    feed_id = feed_config.get("id", feed_name)
    
    logger.info(f"Starting ingestion for feed '{feed_name}'")
    
    result = {
        "feed_name": feed_name,
        "feed_id": feed_id,
        "start_time": datetime.datetime.utcnow().isoformat(),
        "status": "failed",
        "record_count": 0,
        "error": None
    }
    
    try:
        if not feed_config.get("enabled", True):
            logger.info(f"Feed '{feed_name}' is disabled, skipping")
            result["status"] = "skipped"
            result["error"] = "Feed is disabled"
            return result
        
        bq_client, storage_client, publisher, subscriber = get_clients()
        
        # Ensure bucket exists
        bucket_name = Config.GCS_BUCKET
        if not ensure_bucket_exists(bucket_name):
            result["error"] = "Failed to ensure GCS bucket exists"
            return result
        
        # Download feed data
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        timeout = feed_config.get("timeout", 60)
        
        content_type, content = download_feed(url, headers, timeout)
        if not content:
            result["error"] = "Failed to download feed data"
            return result
        
        result["content_type"] = content_type
        
        # Store raw data
        storage_path = feed_config.get("storage_path", f"feeds/{feed_id}")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        format_type = feed_config.get("format", "")
        if format_type == "json":
            file_extension = ".json"
            content_type_to_use = "application/json"
        elif format_type == "csv":
            file_extension = ".csv"
            content_type_to_use = "text/csv"
        else:
            if content_type and 'json' in content_type.lower():
                file_extension = '.json'
                content_type_to_use = "application/json"
                format_type = "json"
            elif content_type and 'csv' in content_type.lower():
                file_extension = '.csv'
                content_type_to_use = "text/csv"
                format_type = "csv"
            else:
                file_extension = '.txt'
                content_type_to_use = "text/plain"
                format_type = "text"
        
        raw_blob_name = f"{storage_path}/raw/{timestamp}{file_extension}"
        raw_uri = upload_to_gcs(bucket_name, raw_blob_name, content, content_type_to_use)
        if not raw_uri:
            result["error"] = "Failed to store raw feed data"
            return result
        
        result["raw_uri"] = raw_uri
        
        # Parse feed data
        parser_config = feed_config.get("parser_config", {})
        parsed_data = parse_feed(content, format_type, parser_config)
        if not parsed_data:
            logger.warning(f"No valid records found in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No valid records found"
            return result
        
        # Normalize data
        normalized_data = normalize_indicators(parsed_data, feed_id)
        
        if not normalized_data:
            logger.info(f"No records to process in feed '{feed_name}'")
            result["status"] = "success"
            result["warning"] = "No records to process"
            return result
        
        # Store processed data
        processed_blob_name = f"{storage_path}/processed/{timestamp}.json"
        processed_uri = upload_to_gcs(
            bucket_name, 
            processed_blob_name,
            json.dumps(normalized_data, indent=2),
            "application/json"
        )
        
        if not processed_uri:
            result["error"] = "Failed to store processed feed data"
            return result
        
        result["processed_uri"] = processed_uri
        result["record_count"] = len(normalized_data)
        
        # Ensure tables exist
        if not initialize_bigquery_tables():
            logger.warning("BigQuery tables initialization reported issues")
        
        # Upload to BigQuery
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        indicators_table_id = f"{dataset_id}.indicators"
        job_id = upload_to_bigquery(indicators_table_id, normalized_data)
        
        if not job_id:
            result["error"] = "Failed to upload data to BigQuery"
            return result
        
        result["bigquery_job_id"] = job_id
        
        # Publish to Pub/Sub
        if publisher:
            topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
            
            message_data = {
                "operation": "feed_processed",
                "feed_name": feed_name,
                "feed_id": feed_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "record_count": len(normalized_data),
                "raw_uri": raw_uri,
                "processed_uri": processed_uri
            }
            
            try:
                message_json = json.dumps(message_data)
                future = publisher.publish(topic_path, message_json.encode("utf-8"), feed_id=feed_id)
                message_id = future.result()
                result["pubsub_message_id"] = message_id
            except Exception as e:
                logger.warning(f"Failed to publish message to Pub/Sub: {str(e)}")
        
        # Publish event for cache invalidation
        publish_event('data_ingested', {
            'feed_id': feed_id,
            'record_count': len(normalized_data)
        })
        
        result["status"] = "success"
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        
        logger.info(f"Successfully processed feed '{feed_name}': {len(normalized_data)} records")
        return result
    
    except Exception as e:
        logger.error(f"Error processing feed '{feed_name}': {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        
        result["error"] = str(e)
        result["end_time"] = datetime.datetime.utcnow().isoformat()
        return result

# -------------------- Public API Functions --------------------

def ingest_feed(feed_name: str) -> Dict:
    """Process a single feed by name."""
    global ingestion_status
    
    service_manager = Config.get_service_manager()
    
    with _ingestion_lock:
        service_manager.update_status('ingestion', ServiceStatus.READY)
        ingestion_status["running"] = True
    
    feed_config = None
    if hasattr(Config, 'get_feed_by_id'):
        feed_config = Config.get_feed_by_id(feed_name)
    
    if not feed_config and hasattr(Config, 'FEEDS'):
        for feed in Config.FEEDS:
            if feed.get('id') == feed_name or feed.get('name') == feed_name:
                feed_config = feed
                break
    
    if not feed_config:
        logger.error(f"Feed '{feed_name}' not found in configuration")
        error_result = {
            "feed_name": feed_name,
            "status": "failed",
            "error": "Feed not found in configuration"
        }
        with _ingestion_lock:
            ingestion_status["feeds_failed"] += 1
            ingestion_status["errors"].append(f"Feed '{feed_name}' not found")
        return error_result
    
    result = process_feed(feed_config)
    
    with _ingestion_lock:
        if result["status"] == "success":
            ingestion_status["feeds_processed"] += 1
            ingestion_status["total_records"] += result.get("record_count", 0)
        elif result["status"] != "skipped":
            ingestion_status["feeds_failed"] += 1
            error_msg = result.get("error", "Unknown error")
            ingestion_status["errors"].append(f"Feed '{feed_name}': {error_msg}")
    
    return result

def ingest_all_feeds() -> List[Dict]:
    """Process all enabled feeds."""
    global ingestion_status
    service_manager = Config.get_service_manager()
    
    with _ingestion_lock:
        ingestion_status = {
            "last_run": datetime.datetime.utcnow().isoformat(),
            "running": True,
            "feeds_processed": 0,
            "feeds_failed": 0,
            "total_records": 0,
            "errors": []
        }
        service_manager.update_status('ingestion', ServiceStatus.READY)
    
    # Initialize tables
    initialize_bigquery_tables()
    
    # Ensure feed configuration
    ensure_default_feeds()
    
    feeds = []
    if hasattr(Config, 'get_enabled_feeds'):
        feeds = Config.get_enabled_feeds()
    elif hasattr(Config, 'FEEDS'):
        feeds = [f for f in Config.FEEDS if f.get('enabled', True)]
    
    if not feeds:
        logger.warning("No enabled feeds found in configuration")
        with _ingestion_lock:
            ingestion_status["running"] = False
            service_manager.update_status('ingestion', ServiceStatus.DEGRADED, "No feeds configured")
        return []
    
    logger.info(f"Processing {len(feeds)} enabled feeds")
    
    results = []
    for feed_config in feeds:
        try:
            feed_id = feed_config.get("id") or feed_config.get("name")
            if not feed_id:
                continue
                
            result = process_feed(feed_config)
            results.append(result)
            
            with _ingestion_lock:
                if result["status"] == "success":
                    ingestion_status["feeds_processed"] += 1
                    ingestion_status["total_records"] += result.get("record_count", 0)
                elif result["status"] != "skipped":
                    ingestion_status["feeds_failed"] += 1
                    error_msg = result.get("error", "Unknown error")
                    ingestion_status["errors"].append(f"Feed '{feed_id}': {error_msg}")
                    
        except Exception as e:
            feed_name = feed_config.get("name", "Unknown")
            logger.error(f"Error processing feed '{feed_name}': {str(e)}")
            
            results.append({
                "feed_name": feed_name,
                "status": "failed",
                "error": str(e)
            })
            
            with _ingestion_lock:
                ingestion_status["feeds_failed"] += 1
                ingestion_status["errors"].append(f"Feed '{feed_name}': {str(e)}")
    
    with _ingestion_lock:
        ingestion_status["running"] = False
        if ingestion_status["feeds_failed"] > 0:
            service_manager.update_status('ingestion', ServiceStatus.DEGRADED, 
                                        f"{ingestion_status['feeds_failed']} feeds failed")
        else:
            service_manager.update_status('ingestion', ServiceStatus.READY)
    
    # Publish completion event
    publish_event('ingestion_completed', {
        'total_feeds': len(feeds),
        'processed': ingestion_status["feeds_processed"],
        'failed': ingestion_status["feeds_failed"],
        'records': ingestion_status["total_records"]
    })
    
    success_count = sum(1 for r in results if r["status"] == "success")
    logger.info(f"Completed processing: {success_count}/{len(results)} feeds processed successfully")
    
    return results

def get_ingestion_status() -> Dict:
    """Get the current status of the ingestion process."""
    global ingestion_status
    
    with _ingestion_lock:
        status_copy = dict(ingestion_status)
    
    status_copy["current_time"] = datetime.datetime.utcnow().isoformat()
    return status_copy

# -------------------- Background Processing --------------------

def trigger_ingestion_in_background() -> threading.Thread:
    """Trigger ingestion in a background thread."""
    def ingestion_thread():
        service_manager = Config.get_service_manager()
        try:
            logger.info("Starting background ingestion thread")
            ingest_all_feeds()
            logger.info("Background ingestion thread completed")
        except Exception as e:
            logger.error(f"Error in background ingestion thread: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            report_error(e)
            service_manager.update_status('ingestion', ServiceStatus.ERROR, str(e))
    
    thread = threading.Thread(target=ingestion_thread)
    thread.daemon = True
    thread.start()
    logger.info("Background ingestion thread started")
    return thread

def ingest_from_pubsub(event, context):
    """Cloud Function entry point for PubSub triggered ingestion."""
    try:
        logger.info(f"Received PubSub message for ingestion")
        
        if 'data' in event:
            import base64
            message_data_bytes = base64.b64decode(event['data'])
            message_data = json.loads(message_data_bytes)
        else:
            message_data = {}
        
        process_all = message_data.get('process_all', False)
        feed_id = message_data.get('feed_id')
        force_tables = message_data.get('force_tables', False)
        
        if force_tables:
            logger.info("Forcing BigQuery tables update as requested")
            initialize_bigquery_tables()
            
        if process_all:
            results = ingest_all_feeds()
            logger.info(f"Processed all feeds: {len(results)} feeds")
        elif feed_id:
            result = ingest_feed(feed_id)
            logger.info(f"Processed feed {feed_id}: {result['status']}")
        else:
            logger.warning("No feed_id or process_all flag provided in message")
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)

# CLI entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Platform Ingestion Tool')
    parser.add_argument('--feed', type=str, help='Process a specific feed by ID or name')
    parser.add_argument('--all', action='store_true', help='Process all configured feeds')
    parser.add_argument('--verify', action='store_true', help='Verify ingestion setup')
    args = parser.parse_args()
    
    Config.init_app()
    
    if args.verify:
        logger.info("Verifying ingestion setup...")
        
        if ensure_bucket_exists(Config.GCS_BUCKET):
            logger.info(f"GCS bucket {Config.GCS_BUCKET} exists")
        else:
            logger.error(f"Failed to ensure GCS bucket {Config.GCS_BUCKET} exists")
        
        if initialize_bigquery_tables():
            logger.info("BigQuery tables initialized successfully")
        else:
            logger.error("Failed to initialize BigQuery tables")
            
    elif args.feed:
        logger.info(f"Processing feed: {args.feed}")
        result = ingest_feed(args.feed)
        logger.info(f"Result: {result}")
        
    elif args.all:
        logger.info("Processing all feeds...")
        results = ingest_all_feeds()
        success_count = sum(1 for r in results if r.get('status') == 'success')
        logger.info(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
        
    else:
        logger.info("No action specified, using --all")
        results = ingest_all_feeds()
        success_count = sum(1 for r in results if r.get('status') == 'success')
        logger.info(f"Processed {len(results)} feeds: {success_count} successful, {len(results) - success_count} failed")
