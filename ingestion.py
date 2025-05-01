"""
Threat Intelligence Platform - Enhanced Ingestion Module
Handles collection of threat data from open-source feeds and loads it into BigQuery.
Optimized for GCP services with improved reliability and performance.
"""

import os
import json
import logging
import csv
import time
import base64
import http.client
import socket
import re
import zipfile
import ssl
import uuid
import random
import hashlib
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from collections import defaultdict
from functools import wraps

import requests

# Import config module for centralized configuration
import config

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Configuration from config module
PROJECT_ID = config.project_id
BUCKET_NAME = config.gcs_bucket
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-data-ingestion")
ENVIRONMENT = config.environment

# Get OTX API Key from environment or config
OTX_API_KEY = os.environ.get('OTX_API_KEY', '')

# BigQuery specific configuration
BQ_INSERT_BATCH_SIZE = 500  # Number of rows to insert in a single batch
BQ_MAX_RETRIES = 3         # Maximum number of retries for BigQuery operations

# Rate limiting and request management
_last_request_time = defaultdict(float)
_rate_limit_delays = {
    "phishtank.com": 60, "data.phishtank.com": 60,  
    "urlhaus.abuse.ch": 10, "threatfox.abuse.ch": 10, 
    "otx.alienvault.com": 15, "cisa.gov": 5, "www.cisa.gov": 5,
    "check.torproject.org": 5, "default": 5              
}

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

# Enhanced Open Source Feed Definitions
FEED_SOURCES = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "fallback_url": "https://threatfox.abuse.ch/export/csv/recent/", 
        "table_id": "threatfox_iocs",
        "format": "json",
        "auth_required": False,
        "description": "ThreatFox IOCs - Malware indicators database",
        "json_mapping": {
            "path_options": ["data", "data.iocs", ""],
            "id_fields": ["id", "ioc_id"]
        }
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json",
        "fallback_url": "https://data.phishtank.com/data/online-valid.csv",
        "table_id": "phishtank_urls",
        "format": "json",
        "auth_required": False,
        "description": "PhishTank - Community-verified phishing URLs"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "fallback_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "table_id": "urlhaus_malware",
        "format": "csv",
        "skip_lines": 8,  # Skip header info/comments
        "description": "URLhaus - Database of malicious URLs"
    },
    "cisa_known": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "table_id": "cisa_vulnerabilities",
        "format": "json",
        "json_root": "vulnerabilities",
        "auth_required": False,
        "description": "CISA Known Exploited Vulnerabilities Catalog"
    },
    "tor_exit": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "table_id": "tor_exit_nodes",
        "format": "text",
        "auth_required": False,
        "description": "Tor Exit Node List"
    },
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "fallback_url": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
        "table_id": "alienvault_otx",
        "format": "json",
        "auth_required": True,
        "auth_header": "X-OTX-API-KEY",
        "api_key_env": "OTX_API_KEY",
        "description": "AlienVault OTX - Open Threat Exchange",
        "json_root": "results"
    }
}

# ======== Decorators and Utilities ========

def exponential_backoff_retry(max_retries=BQ_MAX_RETRIES, base_delay=1.5):
    """Decorator for exponential backoff retries on functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for retry in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retry >= max_retries - 1:
                        logger.error(f"Max retries ({max_retries}) reached for {func.__name__}: {str(e)}")
                        raise
                    wait_time = base_delay * (2 ** retry)
                    logger.warning(f"Retry {retry+1}/{max_retries} for {func.__name__}: {str(e)}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
        return wrapper
    return decorator if max_retries != BQ_MAX_RETRIES or base_delay != 1.5 else decorator(func=None)

def get_client(client_type):
    """Get GCP client using the config module's centralized client management"""
    return config.get_client(client_type)

@exponential_backoff_retry
def publish_event(topic, data):
    """Publish event to Pub/Sub topic with retry logic"""
    pubsub_client = get_client('pubsub')
    if isinstance(pubsub_client, config.DummyClient):
        logger.warning(f"Pub/Sub client not available, cannot publish to {topic}")
        return False
    
    topic_path = pubsub_client.topic_path(PROJECT_ID, topic)
    json_data = json.dumps(data).encode("utf-8")
    future = pubsub_client.publish(topic_path, data=json_data)
    message_id = future.result(timeout=30)
    logger.info(f"Published event {message_id} to {topic}")
    return True

@exponential_backoff_retry
def insert_into_bigquery(table_id, rows):
    """Insert rows into BigQuery with schema adaptation"""
    if not rows:
        return 0
        
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        logger.warning("BigQuery client not available, cannot insert data")
        return 0
    
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    # Ensure table exists, create if it doesn't
    try:
        from google.cloud import bigquery
        from google.cloud.exceptions import NotFound
        
        try:
            client.get_table(full_table_id)
        except NotFound:
            # Create a basic schema based on the first row
            schema = [
                bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("_ingestion_id", "STRING"),
                bigquery.SchemaField("_source", "STRING"),
                bigquery.SchemaField("_feed_type", "STRING")
            ]
            
            # Add fields from the first row
            if rows and isinstance(rows[0], dict):
                for key, value in rows[0].items():
                    if key not in ["_ingestion_timestamp", "_ingestion_id", "_source", "_feed_type"]:
                        field_type = "STRING"
                        if isinstance(value, int): field_type = "INTEGER"
                        elif isinstance(value, float): field_type = "FLOAT"
                        elif isinstance(value, bool): field_type = "BOOLEAN"
                        elif isinstance(value, datetime): field_type = "TIMESTAMP"
                        schema.append(bigquery.SchemaField(key, field_type))
            
            table = bigquery.Table(full_table_id, schema=schema)
            client.create_table(table, exists_ok=True)
            logger.info(f"Created table {full_table_id}")
    except Exception as e:
        logger.error(f"Error checking/creating table {full_table_id}: {str(e)}")
    
    # Process rows to ensure JSON compatibility
    processed_rows = [{k: (v.isoformat() if isinstance(v, datetime) else 
                          json.dumps(v) if isinstance(v, (dict, list)) else v) 
                       for k, v in row.items()} for row in rows]
    
    # Try to insert rows
    errors = client.insert_rows_json(full_table_id, processed_rows)
    
    if not errors:
        logger.info(f"Successfully inserted {len(processed_rows)} rows into {table_id}")
        return len(processed_rows)
    
    # Handle schema mismatches by updating schema
    try:
        table = client.get_table(full_table_id)
        current_schema = {field.name: field for field in table.schema}
        
        # Find missing fields
        missing_fields = []
        for row in processed_rows:
            for field in row:
                if field not in current_schema:
                    missing_fields.append(bigquery.SchemaField(field, "STRING"))
        
        if missing_fields:
            # Update schema
            table.schema = list(table.schema) + missing_fields
            client.update_table(table, ["schema"])
            logger.info(f"Updated schema for {full_table_id} with fields: {[f.name for f in missing_fields]}")
            
            # Try insert again
            errors = client.insert_rows_json(full_table_id, processed_rows)
            if not errors:
                logger.info(f"Successfully inserted {len(processed_rows)} rows after schema update")
                return len(processed_rows)
    except Exception as e:
        logger.error(f"Schema update error: {str(e)}")
    
    logger.error(f"Insert errors: {errors}")
    return 0

def _rate_limited_request(url, timeout=30, max_retries=3, headers=None, api_key=None, auth_header=None):
    """Make a rate-limited HTTP request with retries"""
    domain = url.split('/')[2]
    delay = _rate_limit_delays.get(domain, _rate_limit_delays['default'])
    
    # Set default headers if none provided
    if not headers:
        client_id = uuid.uuid4().hex[:8]
        headers = {
            'User-Agent': f'ThreatIntelligencePlatform/1.0.1 (Research; {PROJECT_ID}; {client_id})',
            'Accept': 'application/json, text/plain, */*',
            'Referer': 'https://threatintelligence.research.platform/',
            'Cache-Control': 'no-cache'
        }
    
    # Add authentication if provided
    if api_key and auth_header:
        headers[auth_header] = api_key
    
    # Add random IP rotation headers to avoid rate limiting
    headers.update({
        'X-Forwarded-For': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'X-Client-ID': uuid.uuid4().hex[:8],
        'X-Request-ID': uuid.uuid4().hex
    })
    
    # Make request with retry
    for retry in range(max_retries):
        # Check if we need to wait
        time_since_last = time.time() - _last_request_time.get(domain, 0)
        if time_since_last < delay:
            wait_time = delay - time_since_last
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s before requesting from {domain}")
            time.sleep(wait_time)
        
        try:
            logger.info(f"Requesting URL: {url} (retry {retry})")
            
            # Use a session for consistent behavior
            session = requests.Session()
            
            # Use more randomized headers on retry
            if retry > 0:
                headers.update({
                    'User-Agent': random.choice([
                        f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 99)}.0.{random.randint(1000, 9999)}.0 Safari/537.36',
                        f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.{random.randint(0, 9)} Safari/605.1.{random.randint(10, 50)}'
                    ]),
                    'X-Forwarded-For': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                })
            
            # Make the request
            response = session.get(
                url, 
                timeout=timeout, 
                headers=headers,
                verify=False  # Skip SSL verification for problematic sites
            )
            
            _last_request_time[domain] = time.time()
            
            # Handle rate limit responses
            if response.status_code == 429:
                if retry < max_retries - 1:
                    wait_time = int(response.headers.get('Retry-After', 60 * (2 ** retry)))
                    logger.warning(f"Rate limited by {domain}, waiting {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                else:
                    raise requests.RequestException(f"Rate limit exceeded for {domain}")
            
            # Handle other error codes
            response.raise_for_status()
            
            return response
            
        except (requests.RequestException, http.client.HTTPException, socket.error) as e:
            if retry < max_retries - 1:
                wait_time = (2 ** retry) * 10
                logger.info(f"Request error: {str(e)}. Retrying in {wait_time}s")
                time.sleep(wait_time)
            else:
                raise
    
    raise requests.RequestException(f"Failed to make request to {url} after {max_retries} retries")

def extract_iocs(content, content_type="text"):
    """Extract IOCs from different content types"""
    if not content:
        return []
        
    results = []
    timestamp = datetime.utcnow().isoformat()
    
    # Extract from text content
    if content_type == "text":
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, content)
            for value in matches:
                results.append({"value": value, "type": ioc_type, "timestamp": timestamp})
    
    # Extract from CSV content
    elif content_type == "csv":
        try:
            csv_reader = csv.reader(StringIO(content))
            headers = next(csv_reader, [])
            
            if headers:
                for row_idx, row in enumerate(csv_reader, start=2):
                    if not row or len(row) == 0:
                        continue
                        
                    for col_idx, cell in enumerate(row):
                        if cell:
                            for ioc_type, pattern in IOC_PATTERNS.items():
                                if re.match(pattern, cell):
                                    col_name = headers[col_idx] if col_idx < len(headers) else f"column_{col_idx}"
                                    results.append({
                                        "value": cell, "type": ioc_type, "source_row": row_idx,
                                        "source_column": col_name, "timestamp": timestamp
                                    })
        except Exception as e:
            logger.error(f"Error extracting IOCs from CSV: {str(e)}")
    
    # Extract from JSON content
    elif content_type == "json":
        def process_json_item(item, path=""):
            if isinstance(item, dict):
                for key, value in item.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, (dict, list)):
                        process_json_item(value, current_path)
                    elif isinstance(value, str):
                        for ioc_type, pattern in IOC_PATTERNS.items():
                            if re.match(pattern, value):
                                results.append({
                                    "value": value, "type": ioc_type,
                                    "path": current_path, "timestamp": timestamp
                                })
            elif isinstance(item, list):
                for i, value in enumerate(item):
                    process_json_item(value, f"{path}[{i}]")
                    
        process_json_item(content)
    
    # Remove duplicates while preserving order
    unique_results = []
    seen = set()
    for ioc in results:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_results.append(ioc)
    
    return unique_results

def enrich_ioc(ioc):
    """Enrich an IOC with additional context"""
    if not ioc or "value" not in ioc or "type" not in ioc:
        return ioc
        
    enriched = ioc.copy()
    if "timestamp" not in enriched:
        enriched["timestamp"] = datetime.utcnow().isoformat()
    
    # Perform enrichment based on IOC type
    ioc_type, ioc_value = ioc["type"], ioc["value"]
    
    if ioc_type == "ip":
        # Simple GeoIP classification for internal/private IPs
        if (ioc_value.startswith('10.') or 
            ioc_value.startswith('192.168.') or 
            (ioc_value.startswith('172.') and 16 <= int(ioc_value.split('.')[1]) <= 31)):
            enriched["geo"] = {"country": "Private", "city": "Internal"}
        else:
            # Basic classification by IP range
            first_octet = int(ioc_value.split('.')[0])
            if first_octet <= 126:
                enriched["geo"] = {"country": "Unknown (Class A)", "city": "Unknown"}
            elif first_octet <= 191:
                enriched["geo"] = {"country": "Unknown (Class B)", "city": "Unknown"}
            else:
                enriched["geo"] = {"country": "Unknown (Class C)", "city": "Unknown"}
    
    # Add severity assessment
    if "context" in enriched and isinstance(enriched["context"], dict):
        context_str = str(enriched["context"]).lower()
        if any(kw in context_str for kw in ["critical", "ransomware", "backdoor", "exploit"]):
            enriched["severity"] = "high"
        elif any(kw in context_str for kw in ["suspicious", "malware", "trojan"]):
            enriched["severity"] = "medium"
        else:
            enriched["severity"] = "low"
    else:
        # Default severity based on IOC type
        if ioc_type in ["md5", "sha1", "sha256"]:
            enriched["severity"] = "medium"  # Hash-based IOCs default to medium
        elif ioc_type == "url" and any(kw in ioc_value.lower() for kw in ["malware", "trojan", "hack", "phish"]):
            enriched["severity"] = "high"   # Suspicious URLs
        else:
            enriched["severity"] = "low"    # Everything else defaults to low
    
    # Add confidence level if not present
    if "confidence" not in enriched:
        enriched["confidence"] = "medium"
    
    return enriched

def ensure_resources(force_create=False):
    """Ensure BigQuery datasets and tables exist"""
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        return False
    
    try:
        from google.cloud import bigquery
        from google.cloud.exceptions import NotFound
        
        # Check/create dataset
        try:
            client.get_dataset(f"{PROJECT_ID}.{DATASET_ID}")
            logger.info(f"Dataset {DATASET_ID} already exists")
        except NotFound:
            dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
            dataset.location = "US"
            dataset.description = "Threat Intelligence Platform Dataset"
            dataset.labels = {
                "env": ENVIRONMENT, "department": "security",
                "application": "threat-intelligence"
            }
            client.create_dataset(dataset, exists_ok=True)
            logger.info(f"Created dataset {DATASET_ID}")
        
        # Create standard fields all tables should have
        standard_fields = [
            bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
            bigquery.SchemaField("_ingestion_id", "STRING"),
            bigquery.SchemaField("_source", "STRING"),
            bigquery.SchemaField("_feed_type", "STRING")
        ]
        
        # Create tables for each feed source
        for feed_name, feed_config in FEED_SOURCES.items():
            table_id = feed_config["table_id"]
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            
            try:
                if not force_create:
                    client.get_table(full_table_id)
                    logger.info(f"Table {table_id} already exists")
                else:
                    raise NotFound("Forcing table creation")
            except NotFound:
                # Create schema based on feed type
                schema = standard_fields.copy()
                
                # Special feed-specific schemas based on feed type
                if feed_name == "threatfox":
                    schema.extend([
                        bigquery.SchemaField("id", "STRING"),
                        bigquery.SchemaField("ioc_type", "STRING"),
                        bigquery.SchemaField("ioc_value", "STRING"),
                        bigquery.SchemaField("threat_type", "STRING"),
                        bigquery.SchemaField("malware", "STRING"),
                        bigquery.SchemaField("confidence_level", "INTEGER"),
                        bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
                        bigquery.SchemaField("first_seen", "TIMESTAMP")
                    ])
                elif feed_name == "phishtank":
                    schema.extend([
                        bigquery.SchemaField("url", "STRING"),
                        bigquery.SchemaField("phish_id", "STRING"),
                        bigquery.SchemaField("submission_time", "TIMESTAMP"),
                        bigquery.SchemaField("verified", "BOOLEAN"),
                        bigquery.SchemaField("verification_time", "TIMESTAMP"),
                        bigquery.SchemaField("target", "STRING")
                    ])
                
                # Create the table with schema
                table = bigquery.Table(full_table_id, schema=schema)
                table.description = feed_config.get("description", "Threat Intelligence Feed")
                
                # Add partitioning for large tables
                if feed_name in ["threatfox", "phishtank", "urlhaus", "alienvault_otx"]:
                    table.time_partitioning = bigquery.TimePartitioning(
                        type_=bigquery.TimePartitioningType.DAY,
                        field="_ingestion_timestamp"
                    )
                    if feed_name == "threatfox":
                        table.clustering_fields = ["ioc_type", "threat_type"]
                    elif feed_name == "phishtank":
                        table.clustering_fields = ["target", "verified"]
                
                client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
        
        # Create additional analysis tables
        analysis_tables = {
            "threat_analysis": [
                bigquery.SchemaField("source_id", "STRING"),
                bigquery.SchemaField("source_type", "STRING"),
                bigquery.SchemaField("iocs", "STRING"),
                bigquery.SchemaField("vertex_analysis", "STRING"),
                bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("severity", "STRING"),
                bigquery.SchemaField("confidence", "STRING")
            ],
            "threat_campaigns": [
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
        }
        
        for table_name, schema in analysis_tables.items():
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_name}"
            try:
                client.get_table(full_table_id)
                logger.info(f"Table {table_name} already exists")
            except NotFound:
                table = bigquery.Table(full_table_id, schema=schema)
                table.description = f"Threat Intelligence {table_name.replace('_', ' ').title()}"
                
                # Add partitioning
                table.time_partitioning = bigquery.TimePartitioning(
                    type_=bigquery.TimePartitioningType.DAY,
                    field="analysis_timestamp"
                )
                
                client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_name}")
        
        # Ensure PubSub topic exists
        pubsub_client = get_client('pubsub')
        if not isinstance(pubsub_client, config.DummyClient):
            topic_path = pubsub_client.topic_path(PROJECT_ID, PUBSUB_TOPIC)
            try:
                pubsub_client.get_topic(request={"topic": topic_path})
                logger.info(f"PubSub topic {PUBSUB_TOPIC} already exists")
            except Exception:
                pubsub_client.create_topic(request={"name": topic_path})
                logger.info(f"Created PubSub topic {PUBSUB_TOPIC}")
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring resources: {str(e)}")
        return False

# ======== Core Ingestion Class ========

class ThreatDataIngestion:
    """Enhanced threat data ingestion with improved reliability and performance"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        self.ready = ensure_resources(force_create=False)
        self.feed_stats = {}
        self.api_keys = self._get_api_keys()
    
    def _get_api_keys(self):
        """Get API keys for authenticated feeds"""
        api_keys = {}
        
        # Get keys for feeds requiring authentication
        for feed_name, feed_config in FEED_SOURCES.items():
            if feed_config.get("auth_required", False):
                # First check environment variables
                env_var = feed_config.get("api_key_env")
                if env_var and os.environ.get(env_var):
                    api_keys[feed_name] = os.environ.get(env_var)
                    continue
                
                # Try config cache
                api_keys_config = config.get_cached_config('api-keys')
                if api_keys_config:
                    key_name = f"{feed_name}_api_key"
                    api_keys[feed_name] = api_keys_config.get(key_name)
                    
                    if not api_keys.get(feed_name):
                        # Try alternate key name format
                        alternate_key = feed_name.replace("_", "-") + "-api-key"
                        api_keys[feed_name] = api_keys_config.get(alternate_key)
        
        # Special handling for OTX
        if "alienvault_otx" in FEED_SOURCES and OTX_API_KEY and "alienvault_otx" not in api_keys:
            api_keys["alienvault_otx"] = OTX_API_KEY
        
        return api_keys
    
    def process_all_feeds(self):
        """Process all configured feeds"""
        if not self.ready:
            # Try to initialize resources again
            self.ready = ensure_resources(force_create=True)
            if not self.ready:
                return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        logger.info(f"Processing {len(FEED_SOURCES)} feeds")
        
        # Process feeds in priority order
        feed_order = ["cisa_known", "tor_exit", "urlhaus", "phishtank", "threatfox", "alienvault_otx"]
        feed_order += [f for f in FEED_SOURCES if f not in feed_order]
        
        for feed_name in feed_order:
            if feed_name not in FEED_SOURCES:
                continue
                
            try:
                logger.info(f"Starting ingestion for feed: {feed_name}")
                
                # Check if feed requires authentication
                feed_config = FEED_SOURCES[feed_name]
                if feed_config.get("auth_required", False) and not self.api_keys.get(feed_name):
                    logger.warning(f"Missing API key for {feed_name}, skipping")
                    results.append({
                        "feed_name": feed_name, "status": "error",
                        "message": "Missing API key", "record_count": 0,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    continue
                
                # Process the feed
                result = self.process_feed(feed_name)
                results.append(result)
                time.sleep(2)  # Small delay between feeds
            except Exception as e:
                logger.error(f"Error processing feed {feed_name}: {str(e)}")
                results.append({
                    "feed_name": feed_name, "status": "error",
                    "message": f"Unexpected error: {str(e)}", "record_count": 0,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Save stats and publish summary event
        success_count = sum(1 for r in results if r.get("status") == "success")
        total_records = sum(r.get("record_count", 0) for r in results)
        
        self.feed_stats = {
            "last_run": datetime.utcnow().isoformat(),
            "feeds_processed": len(results),
            "successful_feeds": success_count,
            "total_records": total_records,
            "details": results
        }
        
        # Store stats in GCS if available
        self._store_stats()
        
        # Publish summary event
        try:
            publish_event(PUBSUB_TOPIC, {
                "event_type": "feeds_processed",
                "feeds_count": len(results),
                "successful_feeds": success_count,
                "total_records": total_records,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.warning(f"Failed to publish summary event: {e}")
        
        return results
    
    def _store_stats(self):
        """Store feed statistics in GCS for persistence"""
        storage_client = get_client('storage')
        if isinstance(storage_client, config.DummyClient) or not self.feed_stats:
            return False
        
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            stats_blob = bucket.blob("stats/feed_stats_latest.json")
            stats_data = json.dumps(self.feed_stats)
            stats_blob.upload_from_string(stats_data, content_type="application/json")
            
            # Also store a timestamped version for history
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            history_blob = bucket.blob(f"stats/feed_stats_{timestamp}.json")
            history_blob.upload_from_string(stats_data, content_type="application/json")
            
            return True
        except Exception as e:
            logger.error(f"Failed to store stats in GCS: {str(e)}")
            return False
    
    def process_feed(self, feed_name):
        """Process a feed and return results"""
        start_time = datetime.now()
        ingestion_id = f"{feed_name}_{start_time.strftime('%Y%m%d%H%M%S')}_{hashlib.md5(feed_name.encode()).hexdigest()[:8]}"
        
        # Validate feed
        if not self.ready:
            return self._error_result(feed_name, "Processor not properly initialized")
            
        if feed_name not in FEED_SOURCES:
            return self._error_result(feed_name, "Unknown feed")
            
        feed_config = FEED_SOURCES[feed_name]
        
        try:
            # Get API key if needed
            api_key = None
            auth_header = None
            if feed_config.get("auth_required", False):
                api_key = self.api_keys.get(feed_name)
                auth_header = feed_config.get("auth_header")
                
                if not api_key:
                    return self._error_result(feed_name, "Missing API key for authenticated feed")
            
            # Get feed data - first try primary URL
            data, error = self._fetch_feed_data(feed_name, api_key, auth_header)
            
            if error:
                logger.warning(f"Primary feed fetch failed: {error}")
                # Try fallback URL if available
                if "fallback_url" in feed_config and feed_config["fallback_url"] != feed_config["url"]:
                    logger.info(f"Trying fallback URL for {feed_name}")
                    # Store original URL and format
                    original_url = feed_config["url"]
                    original_format = feed_config.get("format")
                    try:
                        # Use fallback URL
                        feed_config["url"] = feed_config["fallback_url"]
                        # Adjust format if fallback URL is different type
                        if original_format == "json" and feed_config["fallback_url"].endswith(".csv"):
                            feed_config["format"] = "csv"
                            
                        data, fallback_error = self._fetch_feed_data(feed_name, api_key, auth_header)
                        
                        # Restore original values
                        feed_config["url"] = original_url
                        feed_config["format"] = original_format
                        
                        if fallback_error:
                            return self._error_result(feed_name, f"Primary and fallback fetch failed: {error}, {fallback_error}")
                    except Exception as e:
                        # Restore original URL
                        feed_config["url"] = original_url
                        feed_config["format"] = original_format
                        return self._error_result(feed_name, f"Fallback error: {str(e)}")
                else:
                    return self._error_result(feed_name, f"Fetch error: {error}")
                
            if not data:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No data collected",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Process records based on feed format
            feed_format = feed_config.get("format", "json")
            records = self._process_data(data, feed_name, feed_config, ingestion_id, feed_format)
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records extracted",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Upload to BigQuery in batches
            record_count = 0
            for i in range(0, len(records), BQ_INSERT_BATCH_SIZE):
                batch = records[i:i+BQ_INSERT_BATCH_SIZE]
                inserted = insert_into_bigquery(feed_config["table_id"], batch)
                record_count += inserted
            
            if record_count == 0:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records uploaded",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Create an analysis record combining feed data
            self._create_analysis_entry(feed_name, records, ingestion_id)
            
            # Publish event
            self._publish_event(feed_name, record_count, ingestion_id)
            
            # Return success result
            duration = (datetime.now() - start_time).total_seconds()
            return {
                "feed_name": feed_name,
                "feed_type": feed_config.get("description", "Unknown feed"),
                "record_format": feed_config.get("format", "unknown"),
                "status": "success",
                "record_count": record_count,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat(),
                "ingestion_id": ingestion_id
            }
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            return self._error_result(feed_name, str(e), start_time, ingestion_id)
    
    def _error_result(self, feed_name, message, start_time=None, ingestion_id=None):
        """Create standardized error result"""
        duration = (datetime.now() - start_time).total_seconds() if start_time else 0
        if not ingestion_id:
            ingestion_id = f"{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}_error"
            
        return {
            "feed_name": feed_name,
            "status": "error",
            "message": message,
            "record_count": 0,
            "duration_seconds": duration,
            "timestamp": datetime.utcnow().isoformat(),
            "ingestion_id": ingestion_id
        }
    
    def _fetch_feed_data(self, feed_name, api_key=None, auth_header=None):
        """Fetch data from a feed source with enhanced error handling"""
        feed_config = FEED_SOURCES[feed_name]
        url = feed_config["url"]
        
        # Handle compressed data
        if feed_config.get("zip_compressed"):
            try:
                response = _rate_limited_request(url, timeout=30, api_key=api_key, auth_header=auth_header)
                
                with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
                    # Get first file or specified file
                    target_file = feed_config.get("zip_file_name") or zip_file.namelist()[0]
                    with zip_file.open(target_file) as file:
                        return file.read().decode('utf-8', errors='ignore'), None
            except Exception as e:
                return None, f"Error processing compressed data: {str(e)}"
        
        # Standard request
        try:
            response = _rate_limited_request(url, timeout=30, api_key=api_key, auth_header=auth_header)
            
            # Determine content type and format
            feed_format = feed_config.get("format", "json")
            content_type = response.headers.get('Content-Type', '')
            
            # Auto-adjust format based on content type
            if feed_format == "json" and "text/csv" in content_type:
                feed_format = "csv"
            elif feed_format == "csv" and "application/json" in content_type:
                feed_format = "json"
                
            # Return data based on format
            if feed_format == "json":
                try:
                    data = response.json()
                    
                    # Handle nested data (json root)
                    if "json_root" in feed_config and feed_config["json_root"] in data:
                        data = data[feed_config["json_root"]]
                    
                    # Special handling for ThreatFox
                    if feed_name == "threatfox":
                        data = self._extract_threatfox_data(data)
                    
                    # Special handling for AlienVault OTX
                    if feed_name == "alienvault_otx" and isinstance(data, dict) and "results" in data:
                        for pulse in data.get("results", []):
                            if "indicators" in pulse:
                                pulse["pulse_indicators"] = json.dumps(pulse["indicators"])
                                del pulse["indicators"]
                    
                    return data, None
                except json.JSONDecodeError as e:
                    # Try to parse as CSV if JSON fails
                    if "text/csv" in content_type:
                        return response.text, None
                    return None, f"JSON decode error: {str(e)}"
                
            elif feed_format in ["csv", "text"]:
                return response.text, None
                
            return None, f"Unsupported format: {feed_format}"
            
        except Exception as e:
            return None, f"Request error: {str(e)}"
    
    def _extract_threatfox_data(self, data):
        """Extract ThreatFox data with recursive exploration"""
        # Try each possible path
        path_options = FEED_SOURCES["threatfox"].get("json_mapping", {}).get("path_options", ["data.iocs", "data", ""])
        
        for path in path_options:
            current_data = data
            
            # Try direct path
            if not path:
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    if "iocs" in data and isinstance(data["iocs"], list):
                        return data["iocs"]
                    elif "data" in data and isinstance(data["data"], dict) and "iocs" in data["data"]:
                        return data["data"]["iocs"]
            else:
                # Try nested path
                try:
                    for part in path.split("."):
                        current_data = current_data[part]
                    
                    if isinstance(current_data, list):
                        return current_data
                except (KeyError, TypeError):
                    pass
        
        # Flatten the structure if needed
        if isinstance(data, dict):
            # Try to extract from unknown structure
            flattened = []
            
            # Check for numeric keys that might be IDs
            for key, value in data.items():
                if key.isdigit() and isinstance(value, list):
                    flattened.extend(value)
                elif key.isdigit() and isinstance(value, dict) and "ioc_value" in value:
                    flattened.append(value)
            
            if flattened:
                return flattened
            
            # Try to find data in the "data" field
            if "data" in data:
                if isinstance(data["data"], dict) and "iocs" in data["data"]:
                    return data["data"]["iocs"]
                return [data["data"]]
        
        # Return data as-is
        return [data] if not isinstance(data, list) else data
    
    def _process_data(self, data, feed_name, feed_config, ingestion_id, feed_format=None):
        """Process feed data into standardized records"""
        if not feed_format:
            feed_format = feed_config.get("format", "json")
        
        records = []
        timestamp = datetime.utcnow().isoformat()
        
        # Process based on format
        if feed_format == "json":
            # Ensure data is a list for consistent processing
            if not isinstance(data, list):
                if feed_name == "phishtank" and isinstance(data, dict):
                    data = list(data.values())[0] if data else []
                elif feed_name == "cisa_known" and isinstance(data, dict) and "vulnerabilities" in data:
                    data = data["vulnerabilities"]
                else:
                    data = [data]
            
            # Process each record
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
                
                # Handle feed-specific processing
                if feed_name == "threatfox":
                    # Type conversions
                    if "confidence_level" in record and record["confidence_level"] is not None:
                        try:
                            record["confidence_level"] = int(record["confidence_level"])
                        except (ValueError, TypeError):
                            pass
                    
                    # Convert timestamps
                    if "first_seen" in record and record["first_seen"] is not None:
                        try:
                            first_seen = int(record["first_seen"])
                            record["first_seen"] = datetime.fromtimestamp(first_seen).isoformat()
                        except (ValueError, TypeError):
                            pass
                    
                    # Convert tags to array
                    if "tags" in record and isinstance(record["tags"], str):
                        record["tags"] = [tag.strip() for tag in record["tags"].split(",")]
                
                # Process AlienVault OTX dates
                elif feed_name == "alienvault_otx":
                    for date_field in ["created", "modified"]:
                        if date_field in record and record[date_field]:
                            try:
                                dt = datetime.fromisoformat(record[date_field].replace('Z', '+00:00'))
                                record[date_field] = dt.isoformat()
                            except (ValueError, TypeError, AttributeError):
                                pass
                
                records.append(record)
        
        elif feed_format == "csv":
            # Handle skip lines if specified
            skip_lines = feed_config.get("skip_lines", 0)
            comment_char = feed_config.get("comment_char", "#")
            
            # Filter out comment lines
            lines = data.split('\n')
            content_lines = []
            
            if skip_lines > 0:
                content_lines = [l for l in lines[skip_lines:] if l.strip() and not l.strip().startswith(comment_char)]
            else:
                content_lines = [l for l in lines if l.strip() and not l.strip().startswith(comment_char)]
            
            if not content_lines:
                return []
            
            # Join filtered content and parse
            filtered_data = '\n'.join(content_lines)
            
            try:
                # Try to detect CSV dialect
                dialect = csv.Sniffer().sniff(filtered_data[:min(1024, len(filtered_data))])
                reader = csv.DictReader(StringIO(filtered_data), dialect=dialect)
            except:
                reader = csv.DictReader(StringIO(filtered_data))
            
            # Process each row
            for row in reader:
                if not row or not any(value.strip() for value in row.values() if value):
                    continue
                
                # Clean up the record
                record = {k: v.strip() if k and v else v for k, v in row.items() if k}
                
                # Add standard metadata
                record.update({
                    "_ingestion_timestamp": timestamp,
                    "_ingestion_id": ingestion_id,
                    "_source": feed_name,
                    "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
                })
                
                # Special URLhaus handling
                if feed_name == "urlhaus":
                    if "tags" in record and record["tags"]:
                        tags_str = record["tags"].strip('"')
                        record["tags"] = [t.strip() for t in tags_str.split(",")]
                
                records.append(record)
        
        elif feed_format == "text":
            # Process text-based feeds
            lines = data.strip().split('\n')
            comment_char = feed_config.get("comment_char", "#")
            
            # Special handling for Tor exit nodes
            if feed_name == "tor_exit":
                for i, line in enumerate(lines):
                    if not line or line.strip().startswith(comment_char):
                        continue
                    
                    ip = line.strip()
                    if re.match(IOC_PATTERNS["ip"], ip):
                        record = {
                            "ip": ip,
                            "type": "tor_exit_node",
                            "line_number": i + 1,
                            "_ingestion_timestamp": timestamp,
                            "_ingestion_id": ingestion_id,
                            "_source": feed_name,
                            "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
                        }
                        records.append(record)
            else:
                # Generic text processing
                for i, line in enumerate(lines):
                    if not line or line.strip().startswith(comment_char):
                        continue
                    
                    # Extract metadata from comments
                    metadata = {}
                    if i > 0 and lines[i-1].startswith(comment_char):
                        comment_line = lines[i-1].lstrip(comment_char).strip()
                        for kv_pair in comment_line.split(','):
                            if ':' in kv_pair:
                                k, v = kv_pair.split(':', 1)
                                metadata[k.strip()] = v.strip()
                    
                    content = line.strip()
                    
                    # Determine content type based on pattern matching
                    content_type = "unknown"
                    for ioc_type, pattern in IOC_PATTERNS.items():
                        if re.match(pattern, content):
                            content_type = ioc_type
                            break
                    
                    record = {
                        "line_number": i + 1,
                        "content": content,
                        "content_type": content_type,
                        "_ingestion_timestamp": timestamp,
                        "_ingestion_id": ingestion_id,
                        "_source": feed_name,
                        "_feed_type": feed_config.get("description", "Threat Intelligence Feed")
                    }
                    
                    # Add any extracted metadata
                    record.update(metadata)
                    records.append(record)
        
        return records
    
    def _create_analysis_entry(self, feed_name, records, ingestion_id):
        """Create threat analysis entry combining feed data"""
        # Extract all IOCs from records
        iocs = []
        for record in records:
            extracted = []
            
            # Extract IOCs from specific fields or from any text content
            if "ioc_type" in record and "ioc_value" in record:
                extracted.append({
                    "type": record["ioc_type"],
                    "value": record["ioc_value"],
                    "timestamp": record.get("_ingestion_timestamp")
                })
            elif "url" in record and feed_name in ["phishtank", "urlhaus"]:
                extracted.append({
                    "type": "url",
                    "value": record["url"],
                    "timestamp": record.get("_ingestion_timestamp")
                })
            elif "ip" in record and feed_name == "tor_exit":
                extracted.append({
                    "type": "ip",
                    "value": record["ip"],
                    "timestamp": record.get("_ingestion_timestamp"),
                    "attributes": {"tor_exit_node": True}
                })
            elif "cveID" in record and feed_name == "cisa_known":
                extracted.append({
                    "type": "cve",
                    "value": record["cveID"],
                    "timestamp": record.get("_ingestion_timestamp"),
                    "attributes": {
                        "vendor": record.get("vendorProject", ""),
                        "product": record.get("product", ""),
                        "name": record.get("vulnerabilityName", "")
                    }
                })
            elif "pulse_indicators" in record and feed_name == "alienvault_otx":
                try:
                    indicators = json.loads(record["pulse_indicators"])
                    for indicator in indicators:
                        if "type" in indicator and "indicator" in indicator:
                            extracted.append({
                                "type": indicator["type"],
                                "value": indicator["indicator"],
                                "timestamp": record.get("_ingestion_timestamp"),
                                "source": "alienvault_otx"
                            })
                except (json.JSONDecodeError, TypeError):
                    pass
            else:
                # Try to extract from any text fields
                for key, value in record.items():
                    if isinstance(value, str) and len(value) > 5:
                        found_iocs = extract_iocs(value)
                        extracted.extend(found_iocs)
            
            # Enrich and add to global list
            for ioc in extracted:
                enriched = enrich_ioc(ioc)
                enriched["source"] = feed_name
                iocs.append(enriched)
        
        # If no IOCs were found, don't create an analysis entry
        if not iocs:
            return False
        
        # Create analysis record
        analysis_result = {
            "source_id": ingestion_id,
            "source_type": feed_name,
            "iocs": json.dumps(iocs),
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "severity": "medium",  # Default severity
            "confidence": "medium"  # Default confidence
        }
        
        # Add vertex analysis placeholder
        vertex_analysis = {
            "summary": f"Ingestion of {len(records)} records from {feed_name}",
            "threat_actor": "Unknown",
            "targets": "Unknown",
            "techniques": "Unknown",
            "malware": "Unknown",
            "severity": "medium",
            "confidence": "medium"
        }
        analysis_result["vertex_analysis"] = json.dumps(vertex_analysis)
        
        # Insert into threat_analysis table
        try:
            inserted = insert_into_bigquery("threat_analysis", [analysis_result])
            return inserted > 0
        except Exception as e:
            logger.error(f"Failed to create analysis entry: {e}")
            return False
    
    def _publish_event(self, feed_name, count, ingestion_id):
        """Publish event to Pub/Sub to trigger analysis"""
        message = {
            "feed_name": feed_name,
            "record_count": count,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "ingestion_complete",
            "ingestion_id": ingestion_id,
            "project_id": PROJECT_ID,
            "dataset_id": DATASET_ID
        }
        
        return publish_event(PUBSUB_TOPIC, message)
    
    def analyze_csv_file(self, csv_content, feed_name="csv_upload"):
        """Analyze an uploaded CSV file to extract threat intelligence"""
        if not csv_content:
            return {"error": "Empty CSV data"}
            
        try:
            # Generate a unique ingestion ID
            ingestion_id = f"upload_{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # First, determine the CSV dialect
            try:
                sample = csv_content[:min(10000, len(csv_content))]
                dialect = csv.Sniffer().sniff(sample)
                has_header = csv.Sniffer().has_header(sample)
            except Exception:
                dialect = csv.excel
                has_header = True
            
            # Parse CSV
            csv_io = StringIO(csv_content)
            csv_reader = csv.reader(csv_io, dialect=dialect)
            
            # Get headers and reset
            headers = next(csv_reader) if has_header else [f"column_{i+1}" for i in range(len(next(csv_reader)))]
            csv_io.seek(0)
            if has_header:
                next(csv_reader)
            
            # Process rows
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in csv_reader:
                if not row or all(not cell.strip() for cell in row):
                    continue
                
                record = {
                    headers[i]: value for i, value in enumerate(row) if i < len(headers)
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
            
            # Upload in batches
            record_count = 0
            for i in range(0, len(records), BQ_INSERT_BATCH_SIZE):
                batch = records[i:i+BQ_INSERT_BATCH_SIZE]
                inserted = insert_into_bigquery(table_id, batch)
                record_count += inserted
            
            # Extract IOCs for analysis
            iocs = []
            for record in records:
                # Convert record to text for IOC extraction
                record_text = "\n".join(f"{k}: {v}" for k, v in record.items() 
                                     if k not in ["_ingestion_timestamp", "_ingestion_id", "_source", "_feed_type"])
                
                extracted_iocs = extract_iocs(record_text)
                iocs.extend(extracted_iocs)
            
            # Create analysis entry
            if iocs:
                analysis_record = {
                    "source_id": ingestion_id,
                    "source_type": f"uploaded_csv_{feed_name}",
                    "iocs": json.dumps(iocs),
                    "analysis_timestamp": timestamp,
                    "severity": "medium",
                    "confidence": "medium",
                    "vertex_analysis": json.dumps({
                        "summary": f"Analysis of uploaded CSV {feed_name} with {len(records)} records",
                        "threat_actor": "Unknown",
                        "targets": "Unknown",
                        "techniques": "Unknown",
                        "malware": "Unknown",
                        "severity": "medium",
                        "confidence": "medium"
                    })
                }
                
                insert_into_bigquery("threat_analysis", [analysis_record])
            
            # Trigger analysis by publishing event
            publish_event(PUBSUB_TOPIC, {
                "file_type": "csv",
                "feed_name": feed_name,
                "timestamp": timestamp,
                "event_type": "csv_upload",
                "analysis_id": ingestion_id,
                "record_count": record_count,
                "ioc_count": len(iocs)
            })
            
            # Return result
            return {
                "analysis_id": ingestion_id,
                "feed_name": feed_name,
                "table_id": table_id,
                "record_count": record_count,
                "column_count": len(headers),
                "headers": headers,
                "has_header": has_header,
                "ioc_count": len(iocs),
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error(f"Error analyzing CSV file: {str(e)}")
            return {"error": f"Analysis failed: {str(e)}"}

# ======== HTTP Endpoint ========

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
        ingestion = ThreatDataIngestion()
    except Exception as e:
        logger.error(f"Error initializing ingestion engine: {str(e)}")
        return {"error": f"Failed to initialize: {str(e)}"}, 500
    
    if request_json:
        # Check for statistics request
        if request_json.get("get_stats"):
            return ingestion.feed_stats if hasattr(ingestion, 'feed_stats') else {"status": "Stats not available"}
        
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
                return {"error": f"Processing error: {str(e)}"}, 500
    
    # Default to processing all feeds
    try:
        # Update tables and resources
        ensure_resources()
        
        # Process feeds
        results = ingestion.process_all_feeds()
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Error processing all feeds: {str(e)}")
        return {"error": f"Processing error: {str(e)}"}, 500

# ======== Main Execution ========

if __name__ == "__main__":
    # Process all feeds when run directly
    try:
        ingestion = ThreatDataIngestion()
        results = ingestion.process_all_feeds()
        
        # Print results
        for result in results:
            print(f"{result.get('feed_name')}: {result.get('status')} ({result.get('record_count')} records)")
    except Exception as e:
        print(f"Error processing feeds: {str(e)}")
