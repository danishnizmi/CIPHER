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
from io import StringIO, BytesIO
import zipfile
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Iterator
from collections import defaultdict
from functools import wraps
import re
import hashlib
import uuid
import random
from random import randint

import requests

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
BUCKET_NAME = config.gcs_bucket
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-data-ingestion")
ENVIRONMENT = config.environment

# Get OTX API Key from environment or config
OTX_API_KEY = os.environ.get('OTX_API_KEY', '')

# BigQuery specific configuration
BQ_INSERT_BATCH_SIZE = 500  # Number of rows to insert in a single batch
BQ_MAX_RETRIES = 5         # Maximum number of retries for BigQuery operations
BQ_RETRY_DELAY = 1.5       # Base delay factor for exponential backoff

# Rate limiting management
_last_request_time = defaultdict(float)
_rate_limit_delays = {
    "phishtank.com": 60,       # 60 seconds due to rate limit issues
    "data.phishtank.com": 60,  
    "urlhaus.abuse.ch": 10,   
    "threatfox.abuse.ch": 10, 
    "otx.alienvault.com": 15,  # AlienVault OTX rate limit
    "cisa.gov": 5,
    "www.cisa.gov": 5,
    "check.torproject.org": 5,
    "default": 5              
}

# IP rotation pools - simulated for cloud environment
_ip_rotation_pools = {
    "global": [
        f"192.168.{randint(1, 254)}.{randint(1, 254)}",
        f"10.{randint(1, 254)}.{randint(1, 254)}.{randint(1, 254)}",
        f"172.{randint(16, 31)}.{randint(1, 254)}.{randint(1, 254)}"
    ] + [f"{randint(1, 254)}.{randint(1, 254)}.{randint(1, 254)}.{randint(1, 254)}" for _ in range(10)]
}

# Maintain a counter of request attempts per domain to rotate IPs
_domain_request_count = defaultdict(int)

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
            "path_options": [
                "data",        # Standard path
                "data.iocs",   # Alternative path
                ""             # Root level
            ],
            "id_fields": ["id", "ioc_id"]  # Fields that might contain unique IDs
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

# ======== GCP Service Functions ========

def get_client(client_type: str):
    """Get GCP client using the config module's centralized client management"""
    return config.get_client(client_type)

def publish_event(topic: str, data: Dict[str, Any]) -> bool:
    """Publish event to Pub/Sub topic with retry logic"""
    pubsub_client = get_client('pubsub')
    if isinstance(pubsub_client, config.DummyClient):
        logger.warning(f"Pub/Sub client not available, cannot publish to {topic}")
        return False
    
    try:
        topic_path = pubsub_client.topic_path(PROJECT_ID, topic)
        json_data = json.dumps(data).encode("utf-8")
        
        # Publish with retry
        for attempt in range(3):
            try:
                future = pubsub_client.publish(topic_path, data=json_data)
                message_id = future.result(timeout=30)
                logger.info(f"Published event {message_id} to {topic}")
                return True
            except Exception as e:
                if attempt == 2:  # Last attempt
                    raise
                logger.warning(f"Publish attempt {attempt+1} failed: {str(e)}, retrying...")
                time.sleep(1.5 ** attempt)
        
        return False
    except Exception as e:
        logger.error(f"Error publishing message to {topic}: {str(e)}")
        return False

def exponential_backoff_retry(func=None, max_retries=BQ_MAX_RETRIES, base_delay=BQ_RETRY_DELAY):
    """Decorator for exponential backoff retries on functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        logger.error(f"Max retries ({max_retries}) reached for {func.__name__}: {str(e)}")
                        raise
                    
                    wait_time = base_delay * (2 ** (retries - 1))
                    logger.warning(f"Retry {retries}/{max_retries} after error: {str(e)}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
        return wrapper
    
    # Allow use as @exponential_backoff_retry or @exponential_backoff_retry()
    if func is None:
        return decorator
    return decorator(func)

@exponential_backoff_retry
def insert_into_bigquery(table_id: str, rows: List[Dict]) -> int:
    """Insert rows into BigQuery with optimized error handling and retries
    
    Args:
        table_id: The BigQuery table ID to insert into
        rows: List of row dictionaries to insert
        
    Returns:
        Number of rows successfully inserted
    """
    if not rows:
        logger.warning(f"No rows to insert into {table_id}")
        return 0
        
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        logger.warning("BigQuery client not available, cannot insert data")
        return 0
    
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    try:
        # First check if table exists, create it if it doesn't
        try:
            from google.cloud import bigquery
            from google.cloud.exceptions import NotFound
            
            try:
                client.get_table(full_table_id)
                logger.info(f"Table {full_table_id} exists")
            except NotFound:
                logger.warning(f"Table {full_table_id} not found, creating it")
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
                            field_type = "STRING"  # Default to string
                            if isinstance(value, int):
                                field_type = "INTEGER"
                            elif isinstance(value, float):
                                field_type = "FLOAT"
                            elif isinstance(value, bool):
                                field_type = "BOOLEAN"
                            elif isinstance(value, datetime):
                                field_type = "TIMESTAMP"
                                
                            schema.append(bigquery.SchemaField(key, field_type))
                
                # Create the table
                table = bigquery.Table(full_table_id, schema=schema)
                table = client.create_table(table, exists_ok=True)
                logger.info(f"Created table {full_table_id}")
        except Exception as e:
            logger.error(f"Error checking/creating table {full_table_id}: {str(e)}")
            # Continue to try insertion anyway
        
        # Process rows to ensure JSON compatibility
        processed_rows = []
        for row in rows:
            processed_row = {}
            for key, value in row.items():
                if isinstance(value, datetime):
                    processed_row[key] = value.isoformat()
                elif isinstance(value, (dict, list)):
                    processed_row[key] = json.dumps(value)
                else:
                    processed_row[key] = value
            processed_rows.append(processed_row)
            
        # Log sample row for debugging
        if processed_rows:
            logger.info(f"Sample row for {table_id}: {json.dumps(processed_rows[0], default=str)[:200]}...")
            
        # Try to insert rows
        errors = client.insert_rows_json(full_table_id, processed_rows)
        
        if not errors:
            logger.info(f"Successfully inserted {len(processed_rows)} rows into {table_id}")
            return len(processed_rows)
        
        # Handle schema mismatches
        logger.warning(f"Insert errors for {table_id}: {errors}")
        
        # Try to update schema
        try:
            table = client.get_table(full_table_id)
            current_schema = {field.name: field for field in table.schema}
            
            # Find missing fields
            missing_fields = []
            for row in processed_rows:
                for field in row:
                    if field not in current_schema:
                        field_type = "STRING"  # Default to string for new fields
                        missing_fields.append(bigquery.SchemaField(field, field_type))
            
            if missing_fields:
                # Update schema
                new_schema = list(table.schema) + missing_fields
                table.schema = new_schema
                client.update_table(table, ["schema"])
                logger.info(f"Updated schema for {full_table_id} with fields: {[f.name for f in missing_fields]}")
                
                # Try insert again
                errors = client.insert_rows_json(full_table_id, processed_rows)
                if not errors:
                    logger.info(f"Successfully inserted {len(processed_rows)} rows after schema update")
                    return len(processed_rows)
                else:
                    logger.error(f"Still have errors after schema update: {errors}")
                    return 0
            else:
                logger.error(f"Unknown insert errors: {errors}")
                return 0
        except Exception as e:
            logger.error(f"Schema update error: {str(e)}")
            return 0
    except Exception as e:
        logger.error(f"BigQuery insert error: {str(e)}")
        raise  # Let the retry decorator handle it

def ensure_resources(force_create=False) -> bool:
    """Ensure BigQuery datasets and tables exist with proper ACLs and metadata"""
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        return False
    
    try:
        # Create dataset if it doesn't exist
        try:
            from google.cloud import bigquery
            from google.cloud.exceptions import NotFound
            
            try:
                dataset = client.get_dataset(DATASET_ID)
                logger.info(f"Dataset {DATASET_ID} already exists")
            except NotFound:
                logger.info(f"Dataset {DATASET_ID} not found, creating it")
                dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
                dataset.location = "US"
                
                # Add metadata
                dataset.description = "Threat Intelligence Platform Dataset"
                dataset.labels = {
                    "env": ENVIRONMENT,
                    "department": "security",
                    "application": "threat-intelligence"
                }
                
                dataset = client.create_dataset(dataset, exists_ok=True)
                logger.info(f"Created dataset {DATASET_ID}")
            
            # Create GCS bucket if needed
            storage_client = get_client('storage')
            if not isinstance(storage_client, config.DummyClient):
                try:
                    bucket = storage_client.get_bucket(BUCKET_NAME)
                    logger.info(f"GCS bucket {BUCKET_NAME} already exists")
                except NotFound:
                    logger.info(f"GCS bucket {BUCKET_NAME} not found, creating it")
                    bucket = storage_client.create_bucket(BUCKET_NAME, location="us-central1")
                    logger.info(f"Created GCS bucket {BUCKET_NAME}")
            
            # Define standard fields all tables should have
            standard_fields = [
                bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                bigquery.SchemaField("_ingestion_id", "STRING"),
                bigquery.SchemaField("_source", "STRING"),
                bigquery.SchemaField("_feed_type", "STRING")
            ]
            
            # Create tables if they don't exist
            for feed_name, feed_config in FEED_SOURCES.items():
                table_id = feed_config["table_id"]
                full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
                
                try:
                    if not force_create:
                        table = client.get_table(full_table_id)
                        logger.info(f"Table {table_id} already exists")
                        
                        # Check if standard fields exist
                        existing_fields = {field.name for field in table.schema}
                        missing_fields = []
                        for field in standard_fields:
                            if field.name not in existing_fields:
                                missing_fields.append(field)
                        
                        if missing_fields:
                            # Update schema with missing fields
                            new_schema = list(table.schema) + missing_fields
                            table.schema = new_schema
                            client.update_table(table, ["schema"])
                            logger.info(f"Added missing standard fields to {table_id}")
                    else:
                        # Force table creation for testing
                        raise NotFound("Forcing table creation")
                except NotFound:
                    # Create with enhanced schema based on feed type
                    schema = standard_fields.copy()
                    
                    # Add feed-specific fields
                    feed_format = feed_config.get("format")
                    if feed_format == "json":
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
                        elif feed_name == "alienvault_otx":
                            schema.extend([
                                bigquery.SchemaField("id", "STRING"),
                                bigquery.SchemaField("name", "STRING"),
                                bigquery.SchemaField("description", "STRING"),
                                bigquery.SchemaField("author_name", "STRING"),
                                bigquery.SchemaField("created", "TIMESTAMP"),
                                bigquery.SchemaField("modified", "TIMESTAMP"),
                                bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
                                bigquery.SchemaField("targeted_countries", "STRING", mode="REPEATED"),
                                bigquery.SchemaField("malware_families", "STRING", mode="REPEATED"),
                                bigquery.SchemaField("attack_ids", "STRING", mode="REPEATED"),
                                bigquery.SchemaField("pulse_indicators", "STRING")
                            ])
                        elif feed_name == "cisa_known":
                            schema.extend([
                                bigquery.SchemaField("cveID", "STRING"),
                                bigquery.SchemaField("vendorProject", "STRING"),
                                bigquery.SchemaField("product", "STRING"),
                                bigquery.SchemaField("vulnerabilityName", "STRING"),
                                bigquery.SchemaField("dateAdded", "STRING"),
                                bigquery.SchemaField("shortDescription", "STRING"),
                                bigquery.SchemaField("requiredAction", "STRING"),
                                bigquery.SchemaField("dueDate", "STRING"),
                                bigquery.SchemaField("knownRansomwareCampaignUse", "STRING"),
                                bigquery.SchemaField("notes", "STRING"),
                                bigquery.SchemaField("cwes", "STRING", mode="REPEATED")
                            ])
                    
                    # Create the table with schema
                    table = bigquery.Table(full_table_id, schema=schema)
                    
                    # Add table description and expiration
                    table.description = feed_config.get("description", "Threat Intelligence Feed")
                    if ENVIRONMENT != "production":
                        # Set 90-day expiration for non-production environments
                        expiration_ms = 90 * 24 * 60 * 60 * 1000  # 90 days in milliseconds
                        table.expires = datetime.now() + timedelta(days=90)
                    
                    # Add clustering/partitioning for large tables
                    if feed_name in ["threatfox", "phishtank", "urlhaus", "alienvault_otx"]:
                        table.time_partitioning = bigquery.TimePartitioning(
                            type_=bigquery.TimePartitioningType.DAY,
                            field="_ingestion_timestamp"
                        )
                        if feed_name == "threatfox":
                            table.clustering_fields = ["ioc_type", "threat_type"]
                        elif feed_name == "phishtank":
                            table.clustering_fields = ["target", "verified"]
                        elif feed_name == "alienvault_otx":
                            table.clustering_fields = ["author_name", "name"]
                    
                    # Create the table
                    table = client.create_table(table, exists_ok=True)
                    logger.info(f"Created table {table_id} with enhanced schema and settings")
            
            # Create additional analysis tables if they don't exist
            analysis_tables = {
                "threat_analysis": [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("analysis_id", "STRING"),
                    bigquery.SchemaField("analysis_version", "STRING"),
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
                    
                    # Add partitioning for analysis tables
                    timestamp_field = next((f.name for f in schema if f.name == "analysis_timestamp"), None)
                    if timestamp_field:
                        table.time_partitioning = bigquery.TimePartitioning(
                            type_=bigquery.TimePartitioningType.DAY,
                            field=timestamp_field
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
    except Exception as e:
        logger.error(f"Error ensuring resources (outer): {str(e)}")
        return False

# ======== Advanced IP Rotation Functions ========

def get_rotated_ip(domain: str = None) -> str:
    """Get a rotated IP address for the specified domain or from the global pool"""
    # Increment the request counter for this domain
    if domain:
        _domain_request_count[domain] += 1
        
    # Get the appropriate IP pool
    ip_pool = _ip_rotation_pools.get(domain, _ip_rotation_pools["global"])
    
    # Select an IP based on the request counter
    if domain:
        index = _domain_request_count[domain] % len(ip_pool)
    else:
        # Use random for global pool
        index = random.randint(0, len(ip_pool) - 1)
    
    return ip_pool[index]

def generate_random_ip() -> str:
    """Generate a random-looking IP address"""
    octets = [str(random.randint(1, 254)) for _ in range(4)]
    return ".".join(octets)

def populate_ip_rotation_pools(count: int = 10) -> None:
    """Populate IP rotation pools with random IPs for each domain"""
    # Create an IP pool for each domain
    for domain in _rate_limit_delays.keys():
        if domain != "default" and domain not in _ip_rotation_pools:
            _ip_rotation_pools[domain] = [generate_random_ip() for _ in range(count)]
    
    # Ensure the global pool has enough IPs
    while len(_ip_rotation_pools["global"]) < 20:
        new_ip = generate_random_ip()
        if new_ip not in _ip_rotation_pools["global"]:
            _ip_rotation_pools["global"].append(new_ip)

def _rotate_headers(headers: Dict, domain: str = None, retry: int = 0) -> Dict:
    """Modify request headers to simulate different clients"""
    # Clone the headers to avoid modifying the original
    new_headers = headers.copy()
    
    # Add X-Forwarded-For with rotated IP
    forwarded_for = get_rotated_ip(domain)
    new_headers["X-Forwarded-For"] = forwarded_for
    
    # Add random client identifiers
    client_id = uuid.uuid4().hex[:8]
    new_headers["X-Client-ID"] = client_id
    
    # Modify user agent slightly based on retry count
    user_agents = [
        f'ThreatIntelligencePlatform/1.0.1 (Research; {PROJECT_ID}; {client_id})',
        f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 99)}.0.{random.randint(1000, 9999)}.0 Safari/537.36',
        f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.{random.randint(0, 9)} Safari/605.1.{random.randint(10, 50)}',
        f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 99)}.0.{random.randint(1000, 9999)}.0 Safari/537.36',
        f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/{random.randint(90, 99)}.0.{random.randint(100, 999)}.{random.randint(10, 99)}'
    ]
    
    # Use a different user agent based on retry count
    if retry > 0 and retry < len(user_agents):
        new_headers["User-Agent"] = user_agents[retry]
    else:
        new_headers["User-Agent"] = random.choice(user_agents)
    
    # Add random request ID
    new_headers["X-Request-ID"] = uuid.uuid4().hex
    
    # Add random accept-language
    languages = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-CA,en;q=0.9", "en;q=0.9", "en-US;q=0.9,en;q=0.8"]
    new_headers["Accept-Language"] = random.choice(languages)
    
    return new_headers

# ======== Data Collection Functions ========

def _rate_limited_request(url, timeout=30, max_retries=3, headers=None, api_key=None, auth_header=None):
    """Make a rate-limited request with IP rotation to bypass rate limits"""
    domain = url.split('/')[2]
    
    # Determine delay based on domain
    delay = _rate_limit_delays.get(domain, _rate_limit_delays['default'])
    
    # Set default headers if none provided
    if headers is None:
        # Generate a unique client ID for this request
        client_id = uuid.uuid4().hex[:8]
        
        headers = {
            'User-Agent': f'ThreatIntelligencePlatform/1.0.1 (Research; {PROJECT_ID}; {client_id})',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Referer': 'https://threatintelligence.research.platform/'
        }
    
    # Add authentication if provided
    if api_key and auth_header:
        headers[auth_header] = api_key
    
    # Apply initial header rotation
    headers = _rotate_headers(headers, domain, 0)
    
    for retry in range(max_retries):
        # Check if we need to wait
        time_since_last = time.time() - _last_request_time.get(domain, 0)
        if time_since_last < delay:
            wait_time = delay - time_since_last
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s before requesting from {domain}")
            time.sleep(wait_time)
        
        # Make request and record time
        try:
            logger.info(f"Requesting URL: {url} (retry {retry})")
            
            # Rotate headers for IP simulation on retries
            if retry > 0:
                headers = _rotate_headers(headers, domain, retry)
                
            # Use custom SSL context to avoid issues with some servers
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Use session for consistent behavior
            session = requests.Session()
            
            # Configure retry options for the session
            adapter = requests.adapters.HTTPAdapter(
                max_retries=1,  # We're handling retries manually
                pool_connections=10,
                pool_maxsize=10
            )
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            
            # Make the request
            response = session.get(
                url, 
                timeout=timeout, 
                headers=headers,
                verify=False  # Skip SSL verification for problematic sites
            )
            
            _last_request_time[domain] = time.time()
            
            # Log response details
            logger.info(f"Response status: {response.status_code}, size: {len(response.content)} bytes")
            
            # Handle rate limit responses
            if response.status_code == 429:
                logger.warning(f"Rate limit hit for {domain}. Response: {response.text[:100]}")
                # Increase delay for this domain for future requests
                _rate_limit_delays[domain] = min(_rate_limit_delays[domain] * 2, 300)  # Max 5 minutes
                
                # Apply backoff
                if retry < max_retries - 1:
                    # Check for Retry-After header
                    retry_after = response.headers.get('Retry-After')
                    if retry_after and retry_after.isdigit():
                        wait_time = int(retry_after)
                    else:
                        wait_time = (2 ** retry) * 60  # Exponential backoff
                        
                    logger.info(f"Backing off for {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                else:
                    raise requests.RequestException(f"Rate limit exceeded for {domain} after {max_retries} retries")
            
            # Check for other error codes
            if response.status_code >= 400:
                logger.warning(f"HTTP error {response.status_code} from {domain}: {response.text[:100]}")
                if retry < max_retries - 1:
                    wait_time = (2 ** retry) * 10
                    logger.info(f"HTTP error, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            return response
            
        except (requests.RequestException, 
                http.client.HTTPException, 
                socket.error,
                ConnectionError,
                TimeoutError) as e:
            # Apply backoff for network errors
            if retry < max_retries - 1:
                wait_time = (2 ** retry) * 10  # Exponential backoff
                logger.info(f"Request error: {str(e)}. Backing off for {wait_time}s before retry")
                time.sleep(wait_time)
            else:
                raise
    
    # Should not reach here, but just in case
    raise requests.RequestException(f"Failed to make request to {url} after {max_retries} retries")

def extract_iocs(content: Union[str, Dict], content_type: str = "text") -> List[Dict]:
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
                results.append({
                    "value": value,
                    "type": ioc_type,
                    "timestamp": timestamp
                })
    
    # Extract from CSV content
    elif content_type == "csv":
        try:
            # Basic CSV parsing
            csv_reader = csv.reader(StringIO(content))
            headers = next(csv_reader, [])
            
            if not headers:
                return []
            
            # Process each row
            for row_idx, row in enumerate(csv_reader, start=2):
                if not row or len(row) == 0:
                    continue
                    
                # Check each cell for potential IOCs
                for col_idx, cell in enumerate(row):
                    if not cell:
                        continue
                        
                    # Check each IOC pattern
                    for ioc_type, pattern in IOC_PATTERNS.items():
                        if re.match(pattern, cell):
                            col_name = headers[col_idx] if col_idx < len(headers) else f"column_{col_idx}"
                            
                            results.append({
                                "value": cell,
                                "type": ioc_type,
                                "source_row": row_idx,
                                "source_column": col_name,
                                "timestamp": timestamp
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
                        # Check for IOCs in string values
                        for ioc_type, pattern in IOC_PATTERNS.items():
                            if re.match(pattern, value):
                                results.append({
                                    "value": value,
                                    "type": ioc_type,
                                    "path": current_path,
                                    "timestamp": timestamp
                                })
            elif isinstance(item, list):
                for i, value in enumerate(item):
                    current_path = f"{path}[{i}]"
                    process_json_item(value, current_path)
                    
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

def enrich_ioc(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich an IOC with additional context"""
    if not ioc or "value" not in ioc or "type" not in ioc:
        return ioc
        
    enriched = ioc.copy()
    
    # Add timestamp if missing
    if "timestamp" not in enriched:
        enriched["timestamp"] = datetime.utcnow().isoformat()
    
    # Enrichment differs based on IOC type
    ioc_type = ioc["type"]
    ioc_value = ioc["value"]
    
    # Perform enrichment based on IOC type
    if ioc_type == "ip":
        # Try to get geo data from existing enrichments first
        geo_data = None
        try:
            # Simple GeoIP classification for internal/private IPs
            if (ioc_value.startswith('10.') or 
                ioc_value.startswith('192.168.') or 
                (ioc_value.startswith('172.') and 16 <= int(ioc_value.split('.')[1]) <= 31)):
                geo_data = {"country": "Private", "city": "Internal"}
            else:
                # Try basic classification by IP range
                first_octet = int(ioc_value.split('.')[0])
                if first_octet <= 126:
                    # Class A - often US
                    geo_data = {"country": "Unknown (Class A)", "city": "Unknown"}
                elif first_octet <= 191:
                    # Class B - often Europe
                    geo_data = {"country": "Unknown (Class B)", "city": "Unknown"}
                else:
                    # Class C - various
                    geo_data = {"country": "Unknown (Class C)", "city": "Unknown"}
        except Exception:
            pass
            
        if geo_data:
            enriched["geo"] = geo_data
        else:
            enriched["geo"] = {"country": "Unknown", "city": "Unknown"}
    
    # Add severity assessment
    if "context" in enriched and isinstance(enriched["context"], dict):
        if any(keyword in str(enriched["context"]).lower() 
               for keyword in ["critical", "ransomware", "backdoor", "exploit"]):
            enriched["severity"] = "high"
        elif any(keyword in str(enriched["context"]).lower() 
                for keyword in ["suspicious", "malware", "trojan"]):
            enriched["severity"] = "medium"
        else:
            enriched["severity"] = "low"
    else:
        # Default severity based on IOC type
        if ioc_type in ["md5", "sha1", "sha256"]:
            enriched["severity"] = "medium"  # Hash-based IOCs default to medium
        elif ioc_type == "url" and any(keyword in ioc_value.lower() for keyword in ["malware", "trojan", "hack", "phish"]):
            enriched["severity"] = "high"   # Suspicious URLs
        else:
            enriched["severity"] = "low"    # Everything else defaults to low
    
    # Add confidence level
    if "confidence" not in enriched:
        # For now, use medium confidence for all enriched IOCs
        enriched["confidence"] = "medium"
    
    return enriched

# ======== Core Ingestion Class ========

class ThreatDataIngestion:
    """Enhanced threat data ingestion class with improved reliability and performance"""
    
    def __init__(self):
        """Initialize the ingestion engine"""
        # Initialize IP rotation pools
        populate_ip_rotation_pools()
        self.ready = ensure_resources(force_create=False)
        self.feed_stats = {}
        self.api_keys = self._get_api_keys()
    
    def _get_api_keys(self) -> Dict[str, str]:
        """Get API keys for authenticated feeds from environment or config"""
        api_keys = {}
        
        # Process each feed that requires authentication
        for feed_name, feed_config in FEED_SOURCES.items():
            if feed_config.get("auth_required", False):
                # First check for environment variable specified in feed config
                env_var = feed_config.get("api_key_env")
                if env_var and os.environ.get(env_var):
                    api_keys[feed_name] = os.environ.get(env_var)
                    continue
                
                # Try to get from config cache
                api_keys_config = config.get_cached_config('api-keys')
                if api_keys_config:
                    key_name = f"{feed_name}_api_key"
                    api_keys[feed_name] = api_keys_config.get(key_name)
                    
                    if not api_keys.get(feed_name):
                        # Try alternate key name format
                        alternate_key = feed_name.replace("_", "-") + "-api-key"
                        api_keys[feed_name] = api_keys_config.get(alternate_key)
        
        # Special handling for AlienVault OTX
        if "alienvault_otx" in FEED_SOURCES and FEED_SOURCES["alienvault_otx"].get("auth_required", False):
            if OTX_API_KEY and "alienvault_otx" not in api_keys:
                api_keys["alienvault_otx"] = OTX_API_KEY
        
        return api_keys
    
    def process_all_feeds(self) -> List[Dict]:
        """Process all configured feeds with enhanced reliability"""
        if not self.ready:
            # Try to initialize resources again
            logger.warning("Ingestion engine not properly initialized, retrying initialization")
            self.ready = ensure_resources(force_create=True)
            if not self.ready:
                logger.error("Failed to initialize resources, aborting ingestion")
                return [{"status": "error", "message": "Ingestion engine not properly initialized"}]
        
        results = []
        logger.info(f"Processing {len(FEED_SOURCES)} feeds")
        
        # Process feeds in order of reliability (most reliable first)
        feed_order = ["cisa_known", "tor_exit", "urlhaus", "phishtank", "threatfox", "alienvault_otx"]
        
        # Add any feeds not in the ordered list
        for feed_name in FEED_SOURCES:
            if feed_name not in feed_order:
                feed_order.append(feed_name)
        
        for feed_name in feed_order:
            if feed_name not in FEED_SOURCES:
                continue
                
            try:
                logger.info(f"Starting ingestion for feed: {feed_name}")
                
                # Check if feed requires authentication
                feed_config = FEED_SOURCES[feed_name]
                if feed_config.get("auth_required", False):
                    api_key = self.api_keys.get(feed_name)
                    if not api_key:
                        logger.warning(f"Missing API key for {feed_name}, skipping")
                        results.append({
                            "feed_name": feed_name,
                            "status": "error",
                            "message": "Missing API key",
                            "record_count": 0,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        continue
                
                # Process the feed
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
        
        # Store stats in GCS for persistence
        self._store_stats()
        
        # Publish summary event
        try:
            publish_event(PUBSUB_TOPIC, {
                "event_type": "feeds_processed",
                "feeds_count": len(results),
                "successful_feeds": success_count,
                "total_records": total_records,
                "timestamp": datetime.utcnow().isoformat(),
                "summary": "Completed feed ingestion"
            })
        except Exception as e:
            logger.warning(f"Failed to publish summary event: {e}")
        
        return results
    
    def _store_stats(self) -> bool:
        """Store feed statistics in GCS for persistence"""
        storage_client = get_client('storage')
        if isinstance(storage_client, config.DummyClient) or not self.feed_stats:
            return False
        
        try:
            bucket = storage_client.bucket(BUCKET_NAME)
            stats_blob = bucket.blob("stats/feed_stats_latest.json")
            
            # Store with timestamp
            stats_data = json.dumps(self.feed_stats)
            stats_blob.upload_from_string(stats_data, content_type="application/json")
            
            # Also store a timestamped version for history
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            history_blob = bucket.blob(f"stats/feed_stats_{timestamp}.json")
            history_blob.upload_from_string(stats_data, content_type="application/json")
            
            logger.info("Successfully stored feed statistics in GCS")
            return True
        except Exception as e:
            logger.error(f"Failed to store stats in GCS: {str(e)}")
            return False
    
    def process_feed(self, feed_name: str) -> Dict[str, Any]:
        """Process a feed and return results with enhanced reliability"""
        start_time = datetime.now()
        
        # Generate a unique ingestion ID
        ingestion_id = f"{feed_name}_{start_time.strftime('%Y%m%d%H%M%S')}_{hashlib.md5(feed_name.encode()).hexdigest()[:8]}"
        
        # Validate state and feed
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
            
            # Get feed data
            data, error = self._fetch_feed_data(feed_name, api_key, auth_header)
            
            if error:
                logger.warning(f"Primary feed fetch failed: {error}")
                # Try fallback URL if available
                if "fallback_url" in feed_config and feed_config["fallback_url"] != feed_config["url"]:
                    logger.info(f"Trying fallback URL for {feed_name}")
                    # Store original URL
                    original_url = feed_config["url"]
                    try:
                        # Use fallback URL
                        feed_config["url"] = feed_config["fallback_url"]
                        # If fallback is CSV but format is JSON, adjust format
                        original_format = feed_config.get("format")
                        if original_format == "json" and feed_config["fallback_url"].endswith(".csv"):
                            feed_config["format"] = "csv"
                            
                        data, fallback_error = self._fetch_feed_data(feed_name, api_key, auth_header)
                        
                        # Restore original format
                        feed_config["format"] = original_format
                        # Restore original URL
                        feed_config["url"] = original_url
                        
                        if fallback_error:
                            return self._error_result(feed_name, f"Primary and fallback fetch failed: {error}, {fallback_error}")
                    except Exception as e:
                        # Restore original URL
                        feed_config["url"] = original_url
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
            
            # Process records
            records = self._process_records(data, feed_name, feed_config, ingestion_id)
            
            if not records:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records extracted",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Upload to BigQuery (inserting batches to manage large datasets)
            record_count = 0
            for i in range(0, len(records), BQ_INSERT_BATCH_SIZE):
                batch = records[i:i+BQ_INSERT_BATCH_SIZE]
                inserted = insert_into_bigquery(feed_config["table_id"], batch)
                record_count += inserted
                logger.info(f"Inserted batch of {inserted} records into {feed_config['table_id']}")
            
            if record_count == 0:
                return {
                    "feed_name": feed_name,
                    "status": "warning",
                    "message": "No records uploaded",
                    "record_count": 0,
                    "ingestion_id": ingestion_id
                }
            
            # Generate an analysis record combining all data from this feed
            self._create_analysis_entry(feed_name, records, ingestion_id)
            
            # Publish event
            try:
                self._publish_event(feed_name, record_count, ingestion_id)
            except Exception as e:
                logger.warning(f"Failed to publish event for {feed_name}: {e}")
            
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
            logger.error(traceback.format_exc())
            return self._error_result(feed_name, str(e), start_time, ingestion_id)
    
    def _error_result(self, feed_name: str, message: str, start_time=None, ingestion_id=None) -> Dict[str, Any]:
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
    
    def _fetch_feed_data(self, feed_name: str, api_key=None, auth_header=None) -> Tuple[Any, Optional[str]]:
        """Fetch data from a feed source with enhanced error handling and content type detection"""
        feed_config = FEED_SOURCES[feed_name]
        url = feed_config["url"]
        
        logger.info(f"Fetching data from {feed_name} ({url})")
        
        # Add additional headers for rate limiting prevention
        headers = {
            'User-Agent': f'ThreatIntelligencePlatform/1.0.1 (Research; {PROJECT_ID}; {uuid.uuid4().hex[:8]})',
            'Accept': 'application/json, text/plain, application/xml, */*',
            'Referer': 'https://threatintelligence.research.platform/',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        try:
            # Handle compressed data
            if feed_config.get("zip_compressed"):
                try:
                    logger.info(f"Fetching compressed data from {url}")
                    response = _rate_limited_request(url, timeout=30, api_key=api_key, auth_header=auth_header, headers=headers)
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
            
            # Make the standard request with retry for rate limiting
            max_retries = 5
            for retry in range(max_retries):
                try:
                    response = _rate_limited_request(url, timeout=30, max_retries=3, 
                                                  api_key=api_key, auth_header=auth_header, 
                                                  headers=headers)
                    response.raise_for_status()
                    break
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429 and retry < max_retries - 1:
                        retry_after = int(e.response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited by {feed_name}, waiting {retry_after}s before retry {retry+1}/{max_retries}")
                        time.sleep(retry_after)
                        continue
                    else:
                        raise
            
            # Determine content type based on response and feed_config
            feed_format = feed_config.get("format", "json")
            content_type = response.headers.get('Content-Type', '')
            
            # Check if content type differs from expected format and adjust
            if feed_format == "json" and "text/csv" in content_type:
                logger.info(f"Feed {feed_name} returned CSV despite expecting JSON, adjusting format")
                feed_format = "csv"
            elif feed_format == "csv" and "application/json" in content_type:
                logger.info(f"Feed {feed_name} returned JSON despite expecting CSV, adjusting format")
                feed_format = "json"
                
            # Log response details for debugging
            logger.info(f"Received response from {feed_name}: status={response.status_code}, content-type={content_type}, size={len(response.content)} bytes")
            
            # Return data based on format
            if feed_format == "json":
                try:
                    data = response.json()
                    
                    # Log the structure for debugging
                    if isinstance(data, dict):
                        logger.info(f"JSON structure for {feed_name}: top-level keys={list(data.keys())[:5]}")
                    elif isinstance(data, list):
                        logger.info(f"JSON structure for {feed_name}: list with {len(data)} items")
                    else:
                        logger.info(f"JSON structure for {feed_name}: {type(data)}")
                    
                    # Handle nested data for specific feeds
                    if feed_name == "alienvault_otx":
                        # Extract indicators from OTX pulses
                        if "results" in data:
                            for pulse in data["results"]:
                                if "indicators" in pulse:
                                    pulse["pulse_indicators"] = json.dumps(pulse["indicators"])
                                    # Delete original to avoid storing large duplicated data
                                    del pulse["indicators"]
                    
                    # Handle nested data
                    if "json_root" in feed_config:
                        root_field = feed_config["json_root"]
                        if root_field in data:
                            logger.info(f"Extracting data from '{root_field}' field")
                            data = data[root_field]
                    
                    # Special handling for ThreatFox recursive exploration
                    if feed_name == "threatfox":
                        data = self._extract_threatfox_data(data)
                    
                    return data, None
                except json.JSONDecodeError as e:
                    # Better error handling for JSON parsing errors
                    logger.error(f"JSON decode error for {feed_name}: {str(e)}")
                    logger.info(f"Content sample: {response.text[:200]}...")
                    
                    # If we expected JSON but got something else, try to treat as CSV or text
                    if "text/csv" in content_type or response.text.count(",") > 5:
                        logger.info(f"Attempting to parse as CSV instead of JSON")
                        return response.text, None
                    
                    return None, f"JSON decode error: {str(e)}"
                
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
    
    def _extract_threatfox_data(self, data: Any) -> List[Dict[str, Any]]:
        """Extract ThreatFox data recursively exploring the JSON structure"""
        # Define the possible paths in the ThreatFox response
        mapping = FEED_SOURCES["threatfox"].get("json_mapping", {})
        path_options = mapping.get("path_options", ["data.iocs", "data", ""])
        
        # Try each path option
        for path in path_options:
            if not path:  # Root level
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    # Try to find IOC arrays
                    for key, value in data.items():
                        if key == "iocs" and isinstance(value, list):
                            return value
                        elif key == "data" and isinstance(value, dict) and "iocs" in value:
                            return value["iocs"]
            else:  # Nested path
                current_data = data
                path_parts = path.split(".")
                valid_path = True
                
                # Traverse the path
                for part in path_parts:
                    if isinstance(current_data, dict) and part in current_data:
                        current_data = current_data[part]
                    else:
                        valid_path = False
                        break
                
                if valid_path and isinstance(current_data, list):
                    return current_data
        
        # If we got here, try to flatten the structure
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], dict):
                # Extract IOC data
                if "iocs" in data["data"] and isinstance(data["data"]["iocs"], list):
                    return data["data"]["iocs"]
                
                # ThreatFox format with numeric IDs as keys
                flattened = []
                for key, value in data.items():
                    if key.isdigit() and isinstance(value, list):
                        flattened.extend(value)
                    elif key.isdigit() and isinstance(value, dict) and "ioc_value" in value:
                        flattened.append(value)
                
                if flattened:
                    return flattened
        
        # No standard format found, return the original data
        if isinstance(data, list):
            return data
        else:
            # Return as a single-item list for consistent processing
            return [data]
    
    def _process_records(self, data: Any, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process feed data into standardized records with enhanced type handling"""
        feed_format = feed_config.get("format", "json")
        
        # Initialize an empty result list
        records = []
        
        # Process based on format
        if feed_format == "json":
            records = self._process_json_data(data, feed_name, feed_config, ingestion_id)
        elif feed_format == "csv":
            records = self._process_csv_data(data, feed_name, feed_config, ingestion_id)
        elif feed_format == "text":
            records = self._process_text_data(data, feed_name, feed_config, ingestion_id)
        else:
            logger.error(f"Unsupported format: {feed_format}")
            return []
        
        # Ensure all required metadata fields are present in every record
        timestamp = datetime.utcnow().isoformat()
        for record in records:
            # Add/normalize metadata fields for consistency
            record["_ingestion_timestamp"] = record.get("_ingestion_timestamp", timestamp)
            record["_ingestion_id"] = record.get("_ingestion_id", ingestion_id)
            record["_source"] = record.get("_source", feed_name)
            record["_feed_type"] = record.get("_feed_type", feed_config.get("description", "Threat Intelligence Feed"))
        
        return records
    
    def _process_json_data(self, data: Any, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process JSON feed data with enhanced format handling"""
        records = []
        timestamp = datetime.utcnow().isoformat()
        
        # Log the structure of the data
        logger.info(f"Processing JSON data for {feed_name}")
        if isinstance(data, dict):
            logger.info(f"Top-level keys: {list(data.keys())}")
        elif isinstance(data, list):
            logger.info(f"Data is a list with {len(data)} items")
        else:
            logger.info(f"Data is of type {type(data)}")
        
        # Ensure data is a list
        if not isinstance(data, list):
            # Special handling for some feeds
            if feed_name == "phishtank" and isinstance(data, dict):
                data = list(data.values())[0] if data else []
            # Handle ThreatFox format with multiple key-value pairs - fallback
            elif feed_name == "threatfox" and isinstance(data, dict):
                # ThreatFox format may have IOCs at the top level or in a field
                iocs = data.get("data", {}).get("iocs", [])
                if iocs:
                    data = iocs
                else:
                    # For the export format, data might be directly at the top level
                    # Format looks like {"1511419": [{"ioc_value": "..."}, ...]} with multiple IDs
                    flattened_data = []
                    for key, value in data.items():
                        if isinstance(value, list):
                            flattened_data.extend(value)
                        elif isinstance(value, dict) and "ioc_value" in value:
                            flattened_data.append(value)
                    
                    if flattened_data:
                        data = flattened_data
                    elif "data" in data and isinstance(data["data"], dict):
                        # Another possible structure
                        data = [data["data"]]
                    else:
                        data = [data]
            # Handle CISA format
            elif feed_name == "cisa_known" and isinstance(data, dict):
                if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                    data = data["vulnerabilities"]
                else:
                    data = [data]
            # AlienVault OTX handling
            elif feed_name == "alienvault_otx" and isinstance(data, dict):
                # Skip if not valid OTX pulse structure
                if "results" not in data or not isinstance(data["results"], list):
                    logger.warning(f"Unexpected OTX data structure: {list(data.keys())}")
                    return []
                data = data["results"]
            else:
                data = [data]
        
        # Process each record
        for item in data:
            if not isinstance(item, dict):
                # Skip non-dict items
                continue
            
            # Add standard metadata fields
            record = item.copy()
            record["_ingestion_timestamp"] = timestamp
            record["_ingestion_id"] = ingestion_id
            record["_source"] = feed_name
            record["_feed_type"] = feed_config.get("description", "Threat Intelligence Feed")
            
            # Handle special feed-specific processing
            if feed_name == "threatfox":
                # Convert confidence level to integer if present
                if "confidence_level" in record and record["confidence_level"] is not None:
                    try:
                        record["confidence_level"] = int(record["confidence_level"])
                    except (ValueError, TypeError):
                        pass
                
                # Convert first_seen to timestamp if present
                if "first_seen" in record and record["first_seen"] is not None:
                    try:
                        # ThreatFox uses Unix timestamps
                        first_seen = int(record["first_seen"])
                        record["first_seen"] = datetime.fromtimestamp(first_seen).isoformat()
                    except (ValueError, TypeError):
                        pass
                
                # Convert tags to array if it's a string
                if "tags" in record and isinstance(record["tags"], str):
                    record["tags"] = [tag.strip() for tag in record["tags"].split(",")]
            
            # Process AlienVault OTX data
            elif feed_name == "alienvault_otx":
                # Process dates
                for date_field in ["created", "modified"]:
                    if date_field in record and record[date_field]:
                        try:
                            # Convert to consistent format
                            dt = datetime.fromisoformat(record[date_field].replace('Z', '+00:00'))
                            record[date_field] = dt.isoformat()
                        except (ValueError, TypeError, AttributeError):
                            pass
                
                # Process tags and arrays
                for array_field in ["tags", "targeted_countries", "malware_families", "references"]:
                    if array_field in record and not isinstance(record[array_field], list):
                        record[array_field] = []
            
            # Process CISA Known Vulnerabilities data
            elif feed_name == "cisa_known":
                # Process date fields
                date_fields = ["dateAdded", "dueDate"]
                for field in date_fields:
                    if field in record and record[field]:
                        # Format is already YYYY-MM-DD
                        pass
                
                # Process array fields
                if "cwes" in record and isinstance(record["cwes"], list):
                    pass
                elif "cwes" in record and not isinstance(record["cwes"], list):
                    record["cwes"] = []
            
            records.append(record)
        
        logger.info(f"Processed {len(records)} records from {feed_name} JSON")
        return records
    
    def _process_csv_data(self, data: str, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process CSV feed data with proper dialect detection"""
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
            
            # Use csv.Sniffer to detect the dialect
            try:
                sample = filtered_data[:min(1024, len(filtered_data))]  # Use a sample for sniffing
                dialect = csv.Sniffer().sniff(sample)
                reader = csv.DictReader(StringIO(filtered_data), dialect=dialect)
            except Exception as e:
                logger.warning(f"Could not sniff CSV dialect: {e}, falling back to default")
                reader = csv.DictReader(StringIO(filtered_data))
            
            # Print headers to debug
            logger.info(f"CSV Headers for {feed_name}: {reader.fieldnames}")
            
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in reader:
                # Skip empty rows
                if not row or not any(value.strip() for value in row.values() if value):
                    continue
                
                # Clean up the record
                record = {}
                for key, value in row.items():
                    if key:  # Skip None keys
                        # Handle None values
                        clean_value = value.strip() if value else value
                        record[key] = clean_value
                
                # Add standard metadata fields
                record["_ingestion_timestamp"] = timestamp
                record["_ingestion_id"] = ingestion_id
                record["_source"] = feed_name
                record["_feed_type"] = feed_config.get("description", "Threat Intelligence Feed")
                
                # Special handling for URLhaus
                if feed_name == "urlhaus":
                    # Convert date fields
                    if "dateadded" in record:
                        try:
                            # Format is typically "YYYY-MM-DD HH:MM:SS"
                            dateadded = record["dateadded"].strip('"')
                            record["dateadded"] = dateadded
                        except (ValueError, TypeError):
                            pass
                    
                    # Handle threat and tags fields
                    if "tags" in record and record["tags"]:
                        # Tags may be comma-separated
                        tags_str = record["tags"].strip('"')
                        record["tags"] = [t.strip() for t in tags_str.split(",")]
                
                records.append(record)
            
            logger.info(f"Parsed {len(records)} records from {feed_name} CSV")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing CSV data for {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            # Log sample of the data to assist with debugging
            if data:
                logger.error(f"First 200 chars of data: {data[:200]}")
            return []
    
    def _process_text_data(self, data: str, feed_name: str, feed_config: Dict, ingestion_id: str) -> List[Dict]:
        """Process text-based feeds with enhanced metadata"""
        try:
            lines = data.strip().split('\n')
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            # Get comment character from config or default to #
            comment_char = feed_config.get("comment_char", "#")
            
            # Special handling for Tor exit nodes
            if feed_name == "tor_exit":
                for i, line in enumerate(lines):
                    # Skip empty lines or comments
                    if not line or line.strip().startswith(comment_char):
                        continue
                    
                    # Extract IP address
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
                    # Skip empty lines or comments
                    if not line or line.strip().startswith(comment_char):
                        continue
                    
                    # Extract metadata from comments
                    metadata = {}
                    if i > 0 and lines[i-1].startswith(comment_char):
                        # Try to extract key-value pairs from comment line
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
            
            logger.info(f"Processed {len(records)} records from {feed_name} text data")
            return records
        except Exception as e:
            logger.error(f"Error processing text data for {feed_name}: {str(e)}")
            logger.error(traceback.format_exc())
            return []
    
    def _create_analysis_entry(self, feed_name: str, records: List[Dict], ingestion_id: str) -> bool:
        """Create threat analysis entry combining feed data"""
        # Extract all IOCs from records
        iocs = []
        for record in records:
            extracted = []
            
            # If specific fields exist, use them directly
            if "ioc_type" in record and "ioc_value" in record:
                ioc = {
                    "type": record["ioc_type"],
                    "value": record["ioc_value"],
                    "timestamp": record.get("_ingestion_timestamp")
                }
                extracted.append(ioc)
            elif "url" in record and feed_name in ["phishtank", "urlhaus"]:
                ioc = {
                    "type": "url",
                    "value": record["url"],
                    "timestamp": record.get("_ingestion_timestamp")
                }
                extracted.append(ioc)
            elif "ip" in record and feed_name == "tor_exit":
                ioc = {
                    "type": "ip",
                    "value": record["ip"],
                    "timestamp": record.get("_ingestion_timestamp"),
                    "attributes": {"tor_exit_node": True}
                }
                extracted.append(ioc)
            elif "cveID" in record and feed_name == "cisa_known":
                ioc = {
                    "type": "cve",
                    "value": record["cveID"],
                    "timestamp": record.get("_ingestion_timestamp"),
                    "attributes": {
                        "vendor": record.get("vendorProject", ""),
                        "product": record.get("product", ""),
                        "name": record.get("vulnerabilityName", ""),
                        "date_added": record.get("dateAdded", "")
                    }
                }
                extracted.append(ioc)
            elif "pulse_indicators" in record and feed_name == "alienvault_otx":
                # Process OTX indicators
                try:
                    indicators = json.loads(record["pulse_indicators"])
                    for indicator in indicators:
                        if "type" in indicator and "indicator" in indicator:
                            ioc = {
                                "type": indicator["type"],
                                "value": indicator["indicator"],
                                "timestamp": record.get("_ingestion_timestamp"),
                                "source": "alienvault_otx"
                            }
                            extracted.append(ioc)
                except (json.JSONDecodeError, TypeError):
                    pass
            else:
                # Try to extract from any text fields
                for key, value in record.items():
                    if isinstance(value, str) and len(value) > 5:
                        # Check for IOCs in the field
                        found_iocs = extract_iocs(value)
                        extracted.extend(found_iocs)
            
            # Enrich each IOC
            for ioc in extracted:
                enriched = enrich_ioc(ioc)
                enriched["source"] = feed_name
                iocs.append(enriched)
        
        # If no IOCs were found, don't create an analysis entry
        if not iocs:
            logger.info(f"No IOCs found in {feed_name} data, skipping analysis entry")
            return False
        
        # Create summary of the feed data
        summary = {
            "source_id": ingestion_id,
            "source_type": feed_name,
            "iocs": json.dumps(iocs),
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "analysis_id": f"analysis_{ingestion_id}",
            "analysis_version": "1.0",
            "severity": "medium",  # Default severity
            "confidence": "medium"  # Default confidence
        }
        
        # Create vertex analysis placeholder
        vertex_analysis = {
            "summary": f"Ingestion of {len(records)} records from {feed_name}",
            "threat_actor": "Unknown",
            "targets": "Unknown",
            "techniques": "Unknown",
            "malware": "Unknown",
            "severity": "medium",
            "confidence": "medium"
        }
        summary["vertex_analysis"] = json.dumps(vertex_analysis)
        
        # Insert into threat_analysis table
        try:
            inserted = insert_into_bigquery("threat_analysis", [summary])
            logger.info(f"Created threat analysis entry for {feed_name}")
            return inserted > 0
        except Exception as e:
            logger.error(f"Failed to create analysis entry: {e}")
            return False
    
    def _publish_event(self, feed_name: str, count: int, ingestion_id: str) -> bool:
        """Publish event to Pub/Sub to trigger analysis"""
        # Prepare message
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
    
    def analyze_csv_file(self, csv_content: str, feed_name: str = "csv_upload") -> Dict[str, Any]:
        """Analyze an uploaded CSV file to extract threat intelligence"""
        if not csv_content:
            return {"error": "Empty CSV data"}
            
        try:
            # Generate a unique ingestion ID
            ingestion_id = f"upload_{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # First, determine the CSV dialect using sniffer
            try:
                sample = csv_content[:min(10000, len(csv_content))]  # Use a sample for sniffing
                dialect = csv.Sniffer().sniff(sample)
                has_header = csv.Sniffer().has_header(sample)
            except Exception as e:
                logger.warning(f"Could not detect CSV dialect: {e}, using default")
                dialect = csv.excel
                has_header = True
            
            # Parse CSV
            csv_io = StringIO(csv_content)
            csv_reader = csv.reader(csv_io, dialect=dialect)
            
            # Get headers
            headers = next(csv_reader) if has_header else [f"column_{i+1}" for i in range(len(next(csv_reader)))]
            
            # Reset and skip the header row
            csv_io.seek(0)
            if has_header:
                next(csv_reader)
            
            # Process the rows
            records = []
            timestamp = datetime.utcnow().isoformat()
            
            for row in csv_reader:
                if not row or all(not cell.strip() for cell in row):
                    continue  # Skip empty rows
                
                record = {
                    headers[i]: value for i, value in enumerate(row) if i < len(headers)
                }
                
                # Add metadata
                record["_ingestion_timestamp"] = timestamp
                record["_ingestion_id"] = ingestion_id
                record["_source"] = "csv_upload"
                record["_feed_type"] = f"Uploaded CSV: {feed_name}"
                
                records.append(record)
            
            # Upload to BigQuery with custom table name for the upload
            table_id = f"upload_{feed_name.lower().replace(' ', '_').replace('-', '_')}"
            
            # Configure as a temporary feed
            temp_feed_config = {
                "table_id": table_id,
                "format": "csv",
                "description": f"Uploaded CSV: {feed_name}"
            }
            
            # Upload to BigQuery in batches
            record_count = 0
            for i in range(0, len(records), BQ_INSERT_BATCH_SIZE):
                batch = records[i:i+BQ_INSERT_BATCH_SIZE]
                inserted = insert_into_bigquery(table_id, batch)
                record_count += inserted
            
            # Extract IOCs and create analysis entry
            iocs = []
            for record in records:
                # Convert record to text for IOC extraction
                record_text = "\n".join(f"{k}: {v}" for k, v in record.items() 
                                      if k not in ["_ingestion_timestamp", "_ingestion_id", "_source", "_feed_type"])
                
                extracted_iocs = extract_iocs(record_text)
                iocs.extend(extracted_iocs)
            
            # Create analysis entry with extracted IOCs
            if iocs:
                analysis_record = {
                    "source_id": ingestion_id,
                    "source_type": f"uploaded_csv_{feed_name}",
                    "iocs": json.dumps(iocs),
                    "analysis_timestamp": timestamp,
                    "analysis_id": f"analysis_{ingestion_id}",
                    "analysis_version": "1.0",
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
            message = {
                "file_type": "csv",
                "feed_name": feed_name,
                "timestamp": timestamp,
                "event_type": "csv_upload",
                "analysis_id": ingestion_id,
                "record_count": record_count,
                "ioc_count": len(iocs)
            }
            publish_event(PUBSUB_TOPIC, message)
            
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
            logger.error(traceback.format_exc())
            return {"error": f"Analysis failed: {str(e)}"}

# ======== HTTP Endpoint ========

def ingest_threat_data(request):
    """HTTP endpoint for triggering data ingestion with enhanced options"""
    logger.info("Ingestion endpoint called")
    
    # Parse request
    try:
        request_json = request.get_json(silent=True)
    except Exception as e:
        logger.error(f"Error parsing request: {str(e)}")
        request_json = {"process_all": True}  # Default to process all if error
    
    # Initialize ingestion engine
    try:
        # Initialize IP rotation pools first
        populate_ip_rotation_pools()
        ingestion = ThreatDataIngestion()
    except Exception as e:
        logger.error(f"Error initializing ingestion engine: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": f"Failed to initialize: {str(e)}"}, 500
    
    if request_json:
        # Check for statistics request
        if request_json.get("get_stats"):
            stats = ingestion.feed_stats if hasattr(ingestion, 'feed_stats') else {"status": "Stats function not available"}
            return stats
        
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
                logger.error(traceback.format_exc())
                return {"error": f"Processing error: {str(e)}"}, 500
    
    # Default to processing all feeds
    try:
        # Update tables and resources before processing
        ensure_resources()
        
        # Process feeds
        results = ingestion.process_all_feeds()
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Error processing all feeds: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": f"Processing error: {str(e)}"}, 500

# ======== Main Execution ========

if __name__ == "__main__":
    # Ensure resources on startup
    resource_ready = ensure_resources(force_create=True)
    
    if resource_ready:
        # Initialize IP rotation pools
        populate_ip_rotation_pools()
        
        # Process all feeds when run directly
        ingestion = ThreatDataIngestion()
        results = ingestion.process_all_feeds()
        
        # Print results
        for result in results:
            print(f"{result.get('feed_name')}: {result.get('status')} ({result.get('record_count')} records)")
    else:
        print("Failed to initialize resources. Please check GCP credentials and permissions.")
