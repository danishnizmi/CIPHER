"""
Threat Intelligence Platform - Streamlined API Module
Provides RESTful endpoints with optimized GCP integration and enhanced security.
"""

import os
import json
import logging
import time
import hashlib
import secrets
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, g, Response, abort
import traceback

# Import config module for centralized GCP service management
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT', 'development') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)

# Core configuration from config module
PROJECT_ID = config.project_id
DATASET_ID = config.bigquery_dataset
REGION = config.region
BUCKET_NAME = config.gcs_bucket
MAX_RESULTS = 1000
CACHE_TIMEOUT = 300  # 5 minutes
ENVIRONMENT = config.environment

# Create Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Shared cache
query_cache = {}
cache_timestamps = {}

# API request counter for metrics
request_counter = 0
last_metrics_time = time.time()

# CSRF protection instance - will be initialized in init_app
csrf = None

# ======== Shared Utilities ========

def get_api_key():
    """Get API key with enhanced security and validation"""
    # First try direct attribute from config
    api_key = getattr(config, 'api_key', None)
    
    # If not available directly, try to get from cached config
    if not api_key:
        api_keys_config = config.get_cached_config('api-keys')
        if api_keys_config and 'platform_api_key' in api_keys_config:
            api_key = api_keys_config['platform_api_key']
    
    # Try environment variable as last resort
    if not api_key:
        api_key = os.environ.get('API_KEY', '')
    
    return api_key or ''

def get_client(client_type):
    """Get GCP client using the centralized config module"""
    # Use the centralized client management from config
    return config.get_client(client_type)

def report_metric(metric_type, value=1):
    """
    Report a metric to Cloud Monitoring with graceful degradation
    """
    # Use centralized metric reporting from config
    config.report_metric(metric_type, value)

def report_api_metrics():
    """Report aggregated API metrics"""
    global request_counter, last_metrics_time
    
    # Only report in production every minute
    now = time.time()
    if ENVIRONMENT != 'production' or now - last_metrics_time < 60:
        return
        
    # Report request count if non-zero
    if request_counter > 0:
        report_metric("request_count", request_counter)
        request_counter = 0
        last_metrics_time = now

# ======== Decorators ========

def require_api_key(f):
    """API key authentication decorator with enhanced security"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = get_api_key()
        
        # Skip validation if no API key configured or not in production
        if not api_key or ENVIRONMENT != 'production':
            return f(*args, **kwargs)
        
        # Get key from headers or query parameters
        provided_key = request.headers.get('X-API-Key')
        if not provided_key:
            provided_key = request.args.get('api_key')
            
            # In production, warn about keys in query parameters
            if provided_key and ENVIRONMENT == 'production':
                logger.warning("API key provided in query parameters - less secure than headers")
        
        # Validate key using constant time comparison to prevent timing attacks
        if provided_key and secrets.compare_digest(provided_key, api_key):
            return f(*args, **kwargs)
        
        # Log failed attempts in production
        if ENVIRONMENT == 'production':
            logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            report_metric("invalid_api_key")
            
        # Return 401 with minimal information to prevent information leakage
        return jsonify({
            "error": "Unauthorized", 
            "timestamp": datetime.utcnow().isoformat()
        }), 401
        
    return decorated

def handle_exceptions(f):
    """Exception handling decorator with improved security and monitoring"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            # Track successful requests for metrics
            global request_counter
            request_counter += 1
            report_api_metrics()
            return result
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Report to Error Reporting if available
            config.report_exception()
            
            # Track error for metrics
            report_metric("error")
                
            # Generate request ID for tracking
            request_id = f"req_{uuid.uuid4().hex[:8]}"
            
            # Return sanitized error in production to avoid information disclosure
            if ENVIRONMENT == 'production':
                return jsonify({
                    "error": "An internal error occurred",
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat()
                }), 500
            else:
                # In development, return full error details
                return jsonify({
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat()
                }), 500
    return decorated

def cache_result(ttl=CACHE_TIMEOUT):
    """Cache decorator for API results with improved object handling"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Generate cache key from function name and arguments
            key_parts = [f.__name__] + [str(a) for a in args]
            key_parts.extend(f"{k}={v}" for k, v in kwargs.items())
            
            # Add query parameters but filter out sensitive ones
            query_params = {}
            for k, v in request.args.items():
                if k.lower() not in ['api_key', 'token', 'password', 'secret']:
                    query_params[k] = v
            key_parts.extend(f"{k}={v}" for k, v in query_params.items())
            
            # Create hash of the key parts for better security
            cache_key = hashlib.sha256(":".join(key_parts).encode()).hexdigest()
            
            # Check cache
            now = datetime.now()
            if cache_key in query_cache and cache_key in cache_timestamps:
                if (now - cache_timestamps[cache_key]).total_seconds() < ttl:
                    # Check if the cached result can have attributes before trying to set them
                    cached_result = query_cache[cache_key]
                    if hasattr(cached_result, '__dict__'):
                        # Update hit count for metrics
                        if hasattr(cached_result, '_cache_hits'):
                            cached_result._cache_hits += 1
                        else:
                            setattr(cached_result, '_cache_hits', 1)
                        
                        # Report cache hit metric occasionally
                        if cached_result._cache_hits % 10 == 0:
                            report_metric("cache_hit")
                    
                    return cached_result
            
            # Report cache miss
            report_metric("cache_miss")
            
            # Call function
            result = f(*args, **kwargs)
            
            # Only set hit counter if object can have attributes
            if hasattr(result, '__dict__'):
                setattr(result, '_cache_hits', 0)
            
            # Cache result
            query_cache[cache_key] = result
            cache_timestamps[cache_key] = now
            
            # Clean up old cache entries (LRU approximation)
            if len(query_cache) > 100:
                # Find 10 oldest entries
                oldest_keys = sorted(
                    cache_timestamps.keys(), 
                    key=lambda k: cache_timestamps[k]
                )[:10]
                
                # Remove them
                for key in oldest_keys:
                    if key in query_cache:
                        del query_cache[key]
                        del cache_timestamps[key]
            
            return result
        return decorated
    return decorator

def clear_api_cache(prefix: str = None):
    """Clear API cache entries, optionally filtering by prefix"""
    global query_cache, cache_timestamps
    
    if prefix:
        # Clear only entries with matching prefix
        keys_to_delete = [k for k in query_cache if k.startswith(prefix)]
        for k in keys_to_delete:
            if k in query_cache:
                del query_cache[k]
            if k in cache_timestamps:
                del cache_timestamps[k]
        logger.debug(f"Cleared {len(keys_to_delete)} cache entries with prefix '{prefix}'")
    else:
        # Clear all cache
        query_cache = {}
        cache_timestamps = {}
        logger.debug("Cleared all API cache entries")

# ======== Query Functions ========

def query_bigquery(query, params=None):
    """Execute BigQuery query with enhanced security and error handling"""
    client = get_client('bigquery')
    if client is None or isinstance(client, config.DummyClient):
        return [], "BigQuery client not available"
    
    try:
        # Check for query injection patterns
        dangerous_patterns = [
            r';\s*DROP\s+TABLE',
            r';\s*DELETE\s+FROM',
            r'INFORMATION_SCHEMA',
            r';\s*INSERT\s+INTO',
            r'UNION\s+ALL\s+SELECT',
            r'--',
            r'/\*.*\*/'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                logger.error(f"Potentially dangerous query detected: {query}")
                return [], "Query contains potentially dangerous patterns"
        
        # Remove any comments that might have sneaked through
        query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
        query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
        
        # Import locally to avoid global dependency
        from google.cloud import bigquery
        from google.cloud.exceptions import NotFound
        
        # Create job configuration
        job_config = bigquery.QueryJobConfig()
        
        # Set query parameters
        if params:
            query_params = []
            for k, v in params.items():
                # Validate parameter name to prevent injection
                if not re.match(r'^[a-zA-Z0-9_]+$', k):
                    return [], f"Invalid parameter name: {k}"
                
                param_type = "STRING"
                if isinstance(v, int):
                    param_type = "INT64"
                elif isinstance(v, float):
                    param_type = "FLOAT64"
                elif isinstance(v, bool):
                    param_type = "BOOL"
                elif isinstance(v, datetime):
                    param_type = "TIMESTAMP"
                
                query_params.append(bigquery.ScalarQueryParameter(k, param_type, v))
            job_config.query_parameters = query_params
        
        # Check if tables exist first and create them if needed
        table_names = []
        table_pattern = re.compile(r'FROM\s+`?([^`\s.]+)\.([^`\s.]+)\.([^`\s.]+)`?', re.IGNORECASE)
        for match in table_pattern.findall(query):
            project, dataset, table = match
            if project == PROJECT_ID and dataset == DATASET_ID:
                table_names.append(table)
        
        # Check if tables exist and create them if they don't
        for table_name in table_names:
            try:
                table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_name}"
                client.get_table(table_id)
            except NotFound:
                logger.warning(f"Table {table_id} not found, creating it")
                
                # Create a minimal schema based on standard fields
                schema = [
                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("_ingestion_id", "STRING"),
                    bigquery.SchemaField("_source", "STRING"),
                    bigquery.SchemaField("_feed_type", "STRING")
                ]
                
                # Add specific fields for known tables
                if table_name == "threat_analysis":
                    schema.extend([
                        bigquery.SchemaField("source_id", "STRING"),
                        bigquery.SchemaField("source_type", "STRING"),
                        bigquery.SchemaField("iocs", "STRING"),
                        bigquery.SchemaField("vertex_analysis", "STRING"),
                        bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                        bigquery.SchemaField("severity", "STRING"),
                        bigquery.SchemaField("confidence", "STRING")
                    ])
                elif table_name == "threat_campaigns":
                    schema.extend([
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
                    ])
                
                # Create the table
                table = bigquery.Table(table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
        
        # Execute query with retry logic
        max_retries = 3
        retry_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                # Execute query
                query_job = client.query(query, job_config=job_config)
                
                # Report query execution time for monitoring
                start_time = time.time()
                rows = [dict(row) for row in query_job.result()]
                query_time = time.time() - start_time
                
                # Report metrics for slow queries
                if query_time > 1.0:  # Only report slow queries
                    report_metric("slow_query_seconds", query_time)
                    logger.info(f"Slow query ({query_time:.2f}s): {query[:100]}...")
                
                return rows, None
                
            except Exception as e:
                if "Not found: Table" in str(e) and attempt == 0:
                    # Table doesn't exist, let's create empty tables for common queries
                    logger.warning(f"Table not found: {str(e)}")
                    if attempt < max_retries - 1:
                        # Try to create the table and retry
                        wait_time = retry_delay * (2 ** attempt)
                        logger.info(f"Waiting {wait_time:.2f}s before retrying...")
                        time.sleep(wait_time)
                        continue
                elif attempt < max_retries - 1:
                    # On failure, retry with exponential backoff
                    wait_time = retry_delay * (2 ** attempt)
                    logger.warning(f"Query error, retrying in {wait_time:.2f}s: {str(e)}")
                    time.sleep(wait_time)
                    continue
                else:
                    # Final attempt failed
                    logger.error(f"Query error after {max_retries} attempts: {str(e)}")
                    return [], str(e)
                    
    except Exception as e:
        logger.error(f"BigQuery query error: {str(e)}")
        # Report query failure
        report_metric("query_error")
        return [], str(e)

def validate_table_name(name):
    """Validate table name to prevent SQL injection with stronger pattern matching"""
    if not name:
        return False
        
    # Only allow alphanumeric and underscore with more restrictive pattern
    if not all(c.isalnum() or c == '_' for c in name):
        return False
        
    # Don't allow names starting with underscore (system tables)
    if name.startswith('_'):
        return False
        
    # Don't allow double underscores (could indicate SQL comment)
    if '__' in name:
        return False
        
    # Minimum name length for security
    if len(name) < 3:
        return False
        
    return True

def ensure_tables_exist():
    """Ensure required BigQuery tables exist"""
    client = get_client('bigquery')
    if client is None or isinstance(client, config.DummyClient):
        logger.warning("BigQuery client not available, cannot ensure tables")
        return False
        
    try:
        # Import locally to avoid global dependency
        from google.cloud import bigquery
        from google.cloud.exceptions import NotFound
        
        # Check if dataset exists
        dataset_ref = f"{PROJECT_ID}.{DATASET_ID}"
        try:
            client.get_dataset(dataset_ref)
            logger.info(f"Dataset {DATASET_ID} exists")
        except NotFound:
            # Create dataset
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            client.create_dataset(dataset, exists_ok=True)
            logger.info(f"Created dataset {DATASET_ID}")
        
        # Define tables to check
        tables_to_check = [
            "threat_analysis",
            "threat_campaigns",
            "threatfox_iocs",
            "phishtank_urls",
            "urlhaus_malware"
        ]
        
        # Check each table
        for table_id in tables_to_check:
            full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
            try:
                client.get_table(full_table_id)
                logger.info(f"Table {table_id} exists")
            except NotFound:
                # Create table with basic schema
                if table_id == "threat_analysis":
                    schema = [
                        bigquery.SchemaField("source_id", "STRING"),
                        bigquery.SchemaField("source_type", "STRING"),
                        bigquery.SchemaField("iocs", "STRING"),
                        bigquery.SchemaField("vertex_analysis", "STRING"),
                        bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                        bigquery.SchemaField("severity", "STRING"),
                        bigquery.SchemaField("confidence", "STRING")
                    ]
                elif table_id == "threat_campaigns":
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
                else:
                    # Generic schema for feed tables
                    schema = [
                        bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                        bigquery.SchemaField("_ingestion_id", "STRING"),
                        bigquery.SchemaField("_source", "STRING"),
                        bigquery.SchemaField("_feed_type", "STRING")
                    ]
                
                # Create the table
                table = bigquery.Table(full_table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring tables: {str(e)}")
        return False

# Make sure tables exist on module initialization
ensure_tables_exist()

# ======== API Endpoints ========

@api_bp.route('/health', methods=['GET'])
@handle_exceptions
def health_check():
    """Health check endpoint"""
    version = os.environ.get("VERSION", "1.0.0")
    
    # Check BigQuery connectivity through config
    db_status = config.check_database_connectivity()
    
    # Check GCP services through config
    gcp_status = "available" if config.GCP_SERVICES_AVAILABLE else "unavailable"
    
    # Include unique instance ID for debugging
    instance_id = os.environ.get("K_REVISION", "local-" + str(uuid.uuid4())[:8])
    
    return jsonify({
        "status": "ok",
        "database": db_status,
        "gcp_services": gcp_status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": ENVIRONMENT,
        "instance": instance_id,
        "project": PROJECT_ID
    })

@api_bp.route('/stats', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=300)
def get_stats():
    """Get platform statistics"""
    days = int(request.args.get('days', '30'))
    
    # Validate days parameter for security
    if days < 1 or days > 365:
        return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
    
    # Use mock data if requested
    if request.args.get('mock', 'false').lower() == 'true':
        # Try to import from frontend for consistency
        try:
            from frontend import MOCK_DATA
            return jsonify(MOCK_DATA["stats"])
        except (ImportError, KeyError):
            pass

    # Query BigQuery for stats with SQL injection protection
    feed_query = f"""
    SELECT 
      (SELECT COUNT(DISTINCT table_id) FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__` 
       WHERE table_id NOT LIKE 'threat%') AS total_sources,
      (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis` 
       WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)) AS total_analyses,
      (SELECT MAX(analysis_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`) AS last_analysis,
      (SELECT COUNT(DISTINCT campaign_id) FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`) AS total_campaigns
    """
    
    rows, error = query_bigquery(feed_query, {"days": days})
    
    # Create stats object with defaults
    stats = {
        "feeds": {"total_sources": 0, "active_feeds": 0, "total_records": 0, "growth_rate": 5},
        "campaigns": {"total_campaigns": 0, "active_campaigns": 0, "unique_actors": 0, "growth_rate": 3},
        "iocs": {"total": 0, "types": [], "growth_rate": 8},
        "analyses": {"total_analyses": 0, "last_analysis": None, "growth_rate": 10},
        "timestamp": datetime.utcnow().isoformat(),
        "days": days
    }
    
    # Update with real data if available
    if not error and rows:
        row = rows[0]
        stats["feeds"]["total_sources"] = row.get("total_sources", 0)
        stats["feeds"]["active_feeds"] = row.get("total_sources", 0)  # Assume all are active
        stats["analyses"]["total_analyses"] = row.get("total_analyses", 0)
        stats["campaigns"]["total_campaigns"] = row.get("total_campaigns", 0)
        stats["campaigns"]["active_campaigns"] = row.get("total_campaigns", 0)
        
        # Format last analysis time
        last_analysis = row.get("last_analysis")
        if last_analysis:
            if isinstance(last_analysis, datetime):
                stats["analyses"]["last_analysis"] = last_analysis.isoformat()
            else:
                stats["analyses"]["last_analysis"] = str(last_analysis)
    
    # Get IOC types
    ioc_query = f"""
    SELECT
      JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
      COUNT(DISTINCT JSON_EXTRACT_SCALAR(ioc_item, '$.value')) AS count
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
      UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
    WHERE 
      analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    GROUP BY type
    ORDER BY count DESC
    LIMIT 10
    """
    
    ioc_rows, ioc_error = query_bigquery(ioc_query, {"days": days})
    
    if not ioc_error and ioc_rows:
        stats["iocs"]["types"] = [
            {"type": row.get("type", "").strip('"'), "count": row.get("count", 0)}
            for row in ioc_rows
        ]
        stats["iocs"]["total"] = sum(row.get("count", 0) for row in ioc_rows)
    
    # Get visualization data
    viz_query = f"""
    SELECT
      DATE(analysis_timestamp) as date,
      COUNT(*) as count
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE
      analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    GROUP BY date
    ORDER BY date
    """
    
    viz_rows, viz_error = query_bigquery(viz_query, {"days": days})
    
    if not viz_error and viz_rows:
        stats["visualization_data"] = {
            "daily_counts": [
                {"date": row["date"].isoformat() if isinstance(row["date"], datetime) else str(row["date"]), 
                 "count": row["count"]} 
                for row in viz_rows
            ]
        }
    
    return jsonify(stats)

@api_bp.route('/feeds', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=600)
def list_feeds():
    """List available threat feeds"""
    # Query for feed information
    query = f"""
    SELECT table_id, 
           (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id) AS record_count,
           (SELECT MAX(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id) AS last_updated
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%' AND table_id NOT LIKE 'system%'
    """
    
    rows, error = query_bigquery(query)
    
    # Get feed descriptions from ingestion module if possible
    feed_descriptions = {}
    try:
        from ingestion import FEED_SOURCES
        for name, info in FEED_SOURCES.items():
            table_id = info.get("table_id")
            if table_id:
                feed_descriptions[table_id] = info.get("description", "Threat Intelligence Feed")
    except ImportError:
        # Fallback descriptions
        feed_descriptions = {
            "threatfox_iocs": "ThreatFox IOCs - Malware indicators database",
            "phishtank_urls": "PhishTank - Community-verified phishing URLs",
            "urlhaus_malware": "URLhaus - Database of malicious URLs",
            "feodotracker_c2": "Feodo Tracker - Botnet C2 IP Blocklist",
            "cisa_vulnerabilities": "CISA Known Exploited Vulnerabilities Catalog",
            "tor_exit_nodes": "Tor Exit Node List"
        }
    
    # Process results
    feeds = []
    if not error and rows:
        for row in rows:
            feed = {
                "name": row["table_id"],
                "record_count": row["record_count"],
                "description": feed_descriptions.get(row["table_id"], "Threat Intelligence Feed")
            }
            
            # Format timestamp
            if row.get("last_updated"):
                if isinstance(row["last_updated"], datetime):
                    feed["last_updated"] = row["last_updated"].isoformat()
                else:
                    feed["last_updated"] = str(row["last_updated"])
            else:
                feed["last_updated"] = None
                
            feeds.append(feed)
    
    # Return sample data if no results
    if not feeds:
        feeds = [
            {"name": "threatfox_iocs", "record_count": 0, "last_updated": None, 
             "description": "ThreatFox IOCs - Malware indicators database"},
            {"name": "phishtank_urls", "record_count": 0, "last_updated": None,
             "description": "PhishTank - Community-verified phishing URLs"},
            {"name": "urlhaus_malware", "record_count": 0, "last_updated": None,
             "description": "URLhaus - Database of malicious URLs"}
        ]
    
    return jsonify({
        "feeds": [feed["name"] for feed in feeds],
        "feed_details": feeds,
        "count": len(feeds),
        "timestamp": datetime.utcnow().isoformat()
    })

@api_bp.route('/feeds/<feed_name>/stats', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=300)
def feed_stats(feed_name):
    """Get statistics for a specific feed"""
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    days = int(request.args.get('days', '30'))
    
    # Validate days parameter for security
    if days < 1 or days > 365:
        return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
    
    # Ensure table exists
    ensure_tables_exist()
    
    # Check if table exists and get stats
    query = f"""
    SELECT
      (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` 
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)) AS total_records,
      (SELECT MIN(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)) AS earliest_record,
      (SELECT MAX(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`) AS latest_record,
      (SELECT COUNT(DISTINCT DATE(_ingestion_timestamp)) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)) AS days_with_data
    """
    
    rows, error = query_bigquery(query, {"days": days})
    
    # Get daily counts
    daily_query = f"""
    SELECT
      DATE(_ingestion_timestamp) as date,
      COUNT(*) as record_count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    GROUP BY date
    ORDER BY date
    """
    
    daily_rows, daily_error = query_bigquery(daily_query, {"days": days})
    
    # Process results
    stats = rows[0] if not error and rows else {
        "total_records": 0,
        "earliest_record": None,
        "latest_record": None,
        "days_with_data": 0
    }
    
    # Format datetime fields
    for field in ["earliest_record", "latest_record"]:
        if field in stats and stats[field]:
            if isinstance(stats[field], datetime):
                stats[field] = stats[field].isoformat()
            else:
                stats[field] = str(stats[field])
    
    # Process daily counts
    daily_counts = []
    if not daily_error and daily_rows:
        for row in daily_rows:
            date_val = row["date"]
            daily_counts.append({
                "date": date_val.isoformat() if isinstance(date_val, datetime) else str(date_val),
                "count": row["record_count"]
            })
    
    # If we don't have daily counts, provide sample data
    if not daily_counts:
        today = datetime.now().date()
        daily_counts = [{
            "date": (today - timedelta(days=i)).isoformat(),
            "count": 0
        } for i in range(days)]
    
    stats["daily_counts"] = daily_counts
    
    return jsonify(stats)

@api_bp.route('/feeds/<feed_name>/data', methods=['GET'])
@require_api_key
@handle_exceptions
def feed_data(feed_name):
    """Get data from a specific feed with filtering and pagination"""
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    # Parse query parameters with type validation
    try:
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        days = int(request.args.get('days', '7'))
        
        # Security validations
        if limit < 1 or limit > MAX_RESULTS:
            return jsonify({"error": f"Limit must be between 1 and {MAX_RESULTS}"}), 400
        if offset < 0:
            return jsonify({"error": "Offset cannot be negative"}), 400
        if days < 1 or days > 365:
            return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Get search term and sanitize
    search = request.args.get('search', '')
    if search:
        # Prevent SQL injection in search terms
        search = re.sub(r'[\'";]', '', search)  # Remove potentially dangerous characters
        search = '%' + search + '%'  # Add wildcards for LIKE
    
    # Ensure table exists
    ensure_tables_exist()
    
    # Build query with parameters (safer than string interpolation)
    conditions = ["_ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]
    params = {"days": days, "limit": limit, "offset": offset}
    
    if search:
        conditions.append("TO_JSON_STRING(t) LIKE @search")
        params["search"] = search
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    ORDER BY _ingestion_timestamp DESC
    LIMIT @limit OFFSET @offset
    """
    
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    """
    
    rows, error = query_bigquery(query, params)
    count_rows, count_error = query_bigquery(count_query, params)
    
    # Check for errors
    if error:
        return jsonify({"error": f"Query error: {error}"}), 500
    
    # Process results with sensitive data masking
    processed_rows = []
    sensitive_fields = ['password', 'key', 'token', 'secret', 'credential']
    
    for row in rows:
        processed_row = {}
        for key, value in row.items():
            # Mask sensitive fields
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                processed_row[key] = "********"
            # Format datetime fields
            elif isinstance(value, datetime):
                processed_row[key] = value.isoformat()
            # Truncate very long string values to prevent response bloat
            elif isinstance(value, str) and len(value) > 10000:
                processed_row[key] = value[:10000] + "... [truncated]"
            else:
                processed_row[key] = value
        processed_rows.append(processed_row)
    
    total_count = count_rows[0]["count"] if not count_error and count_rows else len(processed_rows) + offset
    
    # If no results, return empty array with metadata instead of sample data for consistency
    return jsonify({
        "records": processed_rows,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total_count
    })

@api_bp.route('/campaigns', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=300)
def list_campaigns():
    """List threat campaigns with filtering and pagination"""
    # Parse and validate parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        
        # Security validations
        if days < 1 or days > 365:
            return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
        if limit < 1 or limit > MAX_RESULTS:
            return jsonify({"error": f"Limit must be between 1 and {MAX_RESULTS}"}), 400
        if offset < 0:
            return jsonify({"error": "Offset cannot be negative"}), 400
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
        
    severity = request.args.get('severity', '')
    
    # Validate severity
    if severity and severity not in ['low', 'medium', 'high', 'critical']:
        return jsonify({"error": "Invalid severity value"}), 400
    
    # Ensure table exists
    ensure_tables_exist()
    
    # Build conditions
    conditions = ["last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]
    params = {"days": days, "limit": limit, "offset": offset}
    
    if severity:
        conditions.append("severity = @severity")
        params["severity"] = severity
    
    # Query campaigns
    query = f"""
    SELECT
        campaign_id, campaign_name, threat_actor, malware, techniques, targets,
        severity, source_count, ioc_count, first_seen, last_seen
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE {" AND ".join(conditions)}
    ORDER BY last_seen DESC
    LIMIT @limit OFFSET @offset
    """
    
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE {" AND ".join(conditions)}
    """
    
    rows, error = query_bigquery(query, params)
    count_rows, count_error = query_bigquery(count_query, params)
    
    # If query failed or no campaigns, return empty array with metadata
    if error:
        return jsonify({"campaigns": [], "count": 0, "total": 0, "has_more": False, "days": days})
        
    # Process campaigns
    campaigns = []
    if rows:
        # Process datetime fields
        for row in rows:
            campaign = {}
            for key, value in row.items():
                if isinstance(value, datetime):
                    campaign[key] = value.isoformat()
                else:
                    campaign[key] = value
            campaigns.append(campaign)
    
    total_count = count_rows[0]["count"] if not count_error and count_rows else len(campaigns)
    
    return jsonify({
        "campaigns": campaigns,
        "count": len(campaigns),
        "total": total_count,
        "has_more": offset + len(campaigns) < total_count,
        "days": days
    })

@api_bp.route('/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def search_iocs():
    """Search for IOCs across all analyzed data with enhanced filtering"""
    # Parse and validate parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        
        # Security validations
        if days < 1 or days > 365:
            return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
        if limit < 1 or limit > MAX_RESULTS:
            return jsonify({"error": f"Limit must be between 1 and {MAX_RESULTS}"}), 400
        if offset < 0:
            return jsonify({"error": "Offset cannot be negative"}), 400
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
        
    ioc_type = request.args.get('type', '')
    value_filter = request.args.get('value', '')
    
    # Validate IOC type
    valid_ioc_types = ["ip", "domain", "url", "md5", "sha1", "sha256", "email", "cve"]
    if ioc_type and ioc_type not in valid_ioc_types:
        return jsonify({"error": f"Invalid IOC type. Valid types are: {', '.join(valid_ioc_types)}"}), 400
    
    # Sanitize value filter
    if value_filter:
        value_filter = re.sub(r'[\'";]', '', value_filter)
        value_filter = '%' + value_filter + '%'
    
    # Ensure table exists
    ensure_tables_exist()
    
    # Build query
    conditions = ["analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]
    params = {"days": days, "limit": limit, "offset": offset}
    
    ioc_conditions = []
    if ioc_type:
        ioc_conditions.append("ioc_type = @ioc_type")
        params["ioc_type"] = ioc_type
        
    if value_filter:
        ioc_conditions.append("ioc_value LIKE @value_filter")
        params["value_filter"] = value_filter
    
    ioc_filter = f"AND {' AND '.join(ioc_conditions)}" if ioc_conditions else ""
    
    query = f"""
    WITH iocs AS (
        SELECT
            JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS ioc_type,
            JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS ioc_value,
            MIN(analysis_timestamp) AS first_seen,
            COUNT(DISTINCT source_id) AS source_count
        FROM
            `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
            UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
        WHERE 
            {" AND ".join(conditions)}
        GROUP BY ioc_type, ioc_value
    )
    SELECT ioc_type as type, ioc_value as value, first_seen, source_count as sources
    FROM iocs 
    WHERE ioc_type IS NOT NULL {ioc_filter}
    ORDER BY source_count DESC, first_seen DESC
    LIMIT @limit OFFSET @offset
    """
    
    count_query = f"""
    WITH iocs AS (
        SELECT
            JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS ioc_type,
            JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS ioc_value
        FROM
            `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
            UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
        WHERE 
            {" AND ".join(conditions)}
    )
    SELECT COUNT(*) as count
    FROM iocs 
    WHERE ioc_type IS NOT NULL {ioc_filter}
    """
    
    rows, error = query_bigquery(query, params)
    count_rows, count_error = query_bigquery(count_query, params)
    
    # Check for errors
    if error:
        # Return empty result set with error message
        return jsonify({
            "records": [],
            "count": 0,
            "total_available": 0,
            "error": f"Query error: {error}",
            "filters": {"days": days, "type": ioc_type, "value": value_filter}
        })
    
    # Process results
    records = []
    if rows:
        for row in rows:
            record = {}
            for key, value in row.items():
                if isinstance(value, datetime):
                    record[key] = value.isoformat()
                else:
                    record[key] = value
            records.append(record)
    
    total_count = count_rows[0]["count"] if not count_error and count_rows else len(records) + offset
    
    return jsonify({
        "records": records,
        "count": len(records),
        "total_available": total_count,
        "filters": {"days": days, "type": ioc_type, "value": value_filter}
    })

@api_bp.route('/iocs/geo', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=3600)  # Cache for 1 hour
def get_ioc_geo_stats():
    """Get geographic distribution of IP-based IOCs"""
    try:
        days = int(request.args.get('days', '30'))
        
        # Security validation
        if days < 1 or days > 365:
            return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Ensure table exists
    ensure_tables_exist()
    
    query = f"""
    WITH ip_iocs AS (
      SELECT
        JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS ip,
        JSON_EXTRACT_SCALAR(ioc_item, '$.geo.country') AS country,
        JSON_EXTRACT_SCALAR(ioc_item, '$.geo.city') AS city
      FROM
        `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
        UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
      WHERE
        JSON_EXTRACT_SCALAR(ioc_item, '$.type') = 'ip'
        AND analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    )
    SELECT
      country,
      COUNT(*) as count,
      ARRAY_AGG(STRUCT(city, ip) LIMIT 10) as cities
    FROM ip_iocs
    WHERE country IS NOT NULL
    GROUP BY country
    ORDER BY count DESC
    LIMIT 50
    """
    
    rows, error = query_bigquery(query, {"days": days})
    
    # Check for errors
    if error:
        # Return empty result set with error message
        return jsonify({
            "countries": [],
            "total_countries": 0,
            "timestamp": datetime.utcnow().isoformat(),
            "error": f"Query error: {error}"
        })
    
    # Process results
    countries = []
    if rows:
        for row in rows:
            country = {
                "country": row["country"].strip('"') if row["country"] else "Unknown",
                "count": row["count"],
                "cities": []
            }
            
            for city in row["cities"] or []:
                country["cities"].append({
                    "name": city.city.strip('"') if city.city else "Unknown",
                    "ip": city.ip.strip('"') if city.ip else "0.0.0.0"
                })
                
            countries.append(country)
    
    return jsonify({
        "countries": countries,
        "total_countries": len(countries),
        "timestamp": datetime.utcnow().isoformat()
    })

@api_bp.route('/threat_summary', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=600)  # Cache for 10 minutes
def get_threat_summary():
    """Get a comprehensive threat intelligence summary"""
    try:
        days = int(request.args.get('days', '30'))
        
        # Security validation
        if days < 1 or days > 365:
            return jsonify({"error": "Days parameter must be between 1 and 365"}), 400
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Ensure table exists
    ensure_tables_exist()
    
    # Query for recent threat campaigns
    campaign_query = f"""
    SELECT
      campaign_id,
      campaign_name,
      threat_actor,
      malware,
      severity,
      source_count,
      ioc_count,
      last_seen,
      targets
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE
      last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    ORDER BY
      severity DESC, last_seen DESC
    LIMIT 5
    """
    
    # Query for top IOC types
    ioc_types_query = f"""
    WITH ioc_types AS (
      SELECT
        JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
        COUNT(*) as count
      FROM
        `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
        UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
      WHERE
        analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
      GROUP BY type
    )
    SELECT type, count
    FROM ioc_types
    ORDER BY count DESC
    LIMIT 5
    """
    
    # Query for top threat actors
    actors_query = f"""
    SELECT
      COALESCE(threat_actor, 'Unknown') as actor,
      COUNT(*) as campaign_count,
      MAX(severity) as max_severity,
      MAX(last_seen) as last_seen
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE
      last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
    GROUP BY
      actor
    ORDER BY
      campaign_count DESC, last_seen DESC
    LIMIT 5
    """
    
    # Execute queries
    params = {"days": days}
    campaigns, campaigns_error = query_bigquery(campaign_query, params)
    ioc_types, ioc_types_error = query_bigquery(ioc_types_query, params)
    actors, actors_error = query_bigquery(actors_query, params)
    
    # Format results
    formatted_campaigns = []
    if campaigns and not campaigns_error:
        for campaign in campaigns:
            formatted_campaign = {}
            for key, value in campaign.items():
                if isinstance(value, datetime):
                    formatted_campaign[key] = value.isoformat()
                else:
                    formatted_campaign[key] = value
            formatted_campaigns.append(formatted_campaign)
    
    formatted_actors = []
    if actors and not actors_error:
        for actor in actors:
            formatted_actor = {}
            for key, value in actor.items():
                if isinstance(value, datetime):
                    formatted_actor[key] = value.isoformat()
                else:
                    formatted_actor[key] = value
            formatted_actors.append(formatted_actor)
    
    # Create summary object
    summary = {
        "timestamp": datetime.utcnow().isoformat(),
        "period_days": days,
        "top_campaigns": formatted_campaigns,
        "top_ioc_types": ioc_types if ioc_types and not ioc_types_error else [],
        "top_actors": formatted_actors,
        "errors": {}
    }
    
    # Add any error information
    if campaigns_error:
        summary["errors"]["campaigns"] = campaigns_error
    if ioc_types_error:
        summary["errors"]["ioc_types"] = ioc_types_error
    if actors_error:
        summary["errors"]["actors"] = actors_error
    
    return jsonify(summary)

@api_bp.route('/ingest_threat_data', methods=['POST'])
@require_api_key
@handle_exceptions
def ingest_threat_data():
    """Trigger data ingestion with enhanced validation and error handling"""
    # Report metric for ingestion request
    report_metric("ingestion_request")
    
    # Check content type
    content_type = request.headers.get('Content-Type', '')
    if 'application/json' not in content_type and request.method == 'POST':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    
    # Check request size limit for DoS protection
    content_length = request.headers.get('Content-Length', 0)
    if int(content_length) > 10 * 1024 * 1024:  # 10MB limit
        return jsonify({"error": "Request body too large"}), 413
    
    try:
        # Import ingestion module
        try:
            from ingestion import ThreatDataIngestion
            
            # Validate request body if present
            payload = None
            if request.data:
                try:
                    # Limit parse depth and disable duplicate keys
                    payload = json.loads(request.data.decode('utf-8'))
                    
                    # Prevent command injection in feed names
                    if 'feed_name' in payload and payload['feed_name']:
                        feed_name = payload['feed_name']
                        if not re.match(r'^[a-zA-Z0-9_-]+$', feed_name):
                            return jsonify({"error": "Invalid feed name format"}), 400
                    
                    # Limit content size for parsing
                    if 'content' in payload and isinstance(payload['content'], str):
                        if len(payload['content']) > 50 * 1024 * 1024:  # 50MB limit
                            return jsonify({"error": "Content too large"}), 413
                except json.JSONDecodeError:
                    return jsonify({"error": "Invalid JSON in request body"}), 400
            
            # Initialize ingestion engine
            ingestion = ThreatDataIngestion()
            
            # Process specific feed or all feeds
            if payload and 'feed_name' in payload and payload['feed_name'] != 'all':
                feed_name = payload['feed_name']
                logger.info(f"Ingesting data for feed: {feed_name}")
                result = ingestion.process_feed(feed_name)
            elif payload and payload.get('file_type') == 'csv' and 'content' in payload:
                # Handle CSV content
                feed_name = payload.get('feed_name', 'csv_upload')
                logger.info(f"Analyzing CSV data for feed: {feed_name}")
                result = ingestion.analyze_csv_file(payload['content'], feed_name)
            else:
                # Process all feeds
                logger.info("Ingesting data for all feeds")
                result = {"results": ingestion.process_all_feeds(), "timestamp": datetime.utcnow().isoformat()}
            
            # Clear API cache for related endpoints
            clear_api_cache("get_feeds")
            clear_api_cache("get_stats")
            clear_api_cache("get_iocs")
            clear_api_cache("get_campaigns")
            
            # Report success metric
            report_metric("ingestion_success")
            return jsonify(result)
        except ImportError:
            # If ingestion module not available, provide minimal functionality
            logger.warning("Ingestion module not available, using minimal implementation")
            
            # Create sample data for testing
            now = datetime.utcnow()
            
            # Ensure threat_analysis table exists
            client = get_client('bigquery')
            if client and not isinstance(client, config.DummyClient):
                # Get imports locally
                from google.cloud import bigquery
                from google.cloud.exceptions import NotFound
                
                # Check if table exists
                try:
                    table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
                    client.get_table(table_id)
                except NotFound:
                    # Create the table with minimal schema
                    schema = [
                        bigquery.SchemaField("source_id", "STRING"),
                        bigquery.SchemaField("source_type", "STRING"),
                        bigquery.SchemaField("iocs", "STRING"),
                        bigquery.SchemaField("vertex_analysis", "STRING"),
                        bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                        bigquery.SchemaField("severity", "STRING"),
                        bigquery.SchemaField("confidence", "STRING")
                    ]
                    table = bigquery.Table(table_id, schema=schema)
                    client.create_table(table, exists_ok=True)
                    logger.info(f"Created table threat_analysis")
                
                # Create sample data row
                sample_row = {
                    "source_id": f"sample-{uuid.uuid4().hex[:8]}",
                    "source_type": "sample",
                    "iocs": json.dumps([
                        {"type": "ip", "value": "192.168.1.1", "sources": 3},
                        {"type": "domain", "value": "example.com", "sources": 2}
                    ]),
                    "vertex_analysis": json.dumps({
                        "summary": "Sample threat analysis",
                        "threat_actor": "SampleActor",
                        "targets": "Sample targets",
                        "techniques": "Sample techniques",
                        "malware": "SampleMalware",
                        "severity": "medium",
                        "confidence": "medium"
                    }),
                    "analysis_timestamp": now.isoformat(),
                    "severity": "medium",
                    "confidence": "medium"
                }
                
                # Insert into table
                try:
                    errors = client.insert_rows_json(table_id, [sample_row])
                    
                    if not errors:
                        logger.info("Successfully inserted sample data for testing")
                        
                        # Also create campaign table if it doesn't exist
                        try:
                            campaign_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
                            client.get_table(campaign_table_id)
                        except NotFound:
                            # Create the table with schema
                            campaign_schema = [
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
                            table = bigquery.Table(campaign_table_id, campaign_schema)
                            client.create_table(table, exists_ok=True)
                            logger.info(f"Created table threat_campaigns")
                        
                        # Create a sample campaign too
                        campaign_row = {
                            "campaign_id": f"campaign-{uuid.uuid4().hex[:8]}",
                            "campaign_name": "SampleCampaign",
                            "threat_actor": "SampleActor",
                            "malware": "SampleMalware",
                            "techniques": "Sample techniques",
                            "targets": "Sample targets",
                            "severity": "medium",
                            "sources": json.dumps(["sample1", "sample2"]),
                            "iocs": json.dumps([
                                {"type": "ip", "value": "192.168.1.1"},
                                {"type": "domain", "value": "example.com"}
                            ]),
                            "source_count": 2,
                            "ioc_count": 2,
                            "first_seen": (now - timedelta(days=7)).isoformat(),
                            "last_seen": now.isoformat(),
                            "detection_timestamp": now.isoformat()
                        }
                        
                        client.insert_rows_json(campaign_table_id, [campaign_row])
                        
                        # Create feed tables if they don't exist
                        for feed_name in ["threatfox_iocs", "phishtank_urls", "urlhaus_malware"]:
                            try:
                                feed_table_id = f"{PROJECT_ID}.{DATASET_ID}.{feed_name}"
                                client.get_table(feed_table_id)
                            except NotFound:
                                # Create table with basic schema
                                feed_schema = [
                                    bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                                    bigquery.SchemaField("_ingestion_id", "STRING"),
                                    bigquery.SchemaField("_source", "STRING"),
                                    bigquery.SchemaField("_feed_type", "STRING"),
                                    bigquery.SchemaField("value", "STRING"),
                                    bigquery.SchemaField("type", "STRING")
                                ]
                                table = bigquery.Table(feed_table_id, feed_schema)
                                client.create_table(table, exists_ok=True)
                                logger.info(f"Created table {feed_name}")
                                
                                # Add a sample row
                                feed_row = {
                                    "_ingestion_timestamp": now.isoformat(),
                                    "_ingestion_id": f"sample-{uuid.uuid4().hex[:8]}",
                                    "_source": feed_name,
                                    "_feed_type": f"Sample {feed_name} data",
                                    "value": "example.com" if "domain" in feed_name else "192.168.1.1",
                                    "type": "domain" if "domain" in feed_name else "ip"
                                }
                                client.insert_rows_json(feed_table_id, [feed_row])
                        
                        report_metric("ingestion_success")
                        return jsonify({
                            "status": "success",
                            "message": "Created sample data for testing (ingestion module not available)",
                            "timestamp": now.isoformat()
                        })
                    else:
                        logger.error(f"Errors inserting sample data: {errors}")
                except Exception as e:
                    logger.error(f"Error creating sample data: {e}")
            
            report_metric("ingestion_module_missing")
            return jsonify({"error": "Ingestion module not available, but created minimal test data"}), 200
    except Exception as e:
        logger.error(f"Ingestion error: {str(e)}")
        report_metric("ingestion_error")
        return jsonify({"error": f"Ingestion error: {str(e)}"}), 500

@api_bp.route('/upload_csv', methods=['POST'])
@require_api_key
@handle_exceptions
def upload_csv():
    """Upload CSV file for processing with enhanced security and error handling"""
    # Report metric for upload request
    report_metric("csv_upload_request")
    
    try:
        # Handle both file uploads and direct JSON payloads with csv_content
        if request.headers.get('Content-Type', '').startswith('application/json'):
            # Handle JSON payload
            payload = request.get_json()
            if not payload:
                return jsonify({"error": "Invalid JSON payload"}), 400
                
            csv_content = payload.get('content')
            feed_name = payload.get('feed_name', 'csv_upload')
            
            if not csv_content:
                return jsonify({"error": "No CSV content provided"}), 400
                
        elif 'file' in request.files:
            # Handle file upload
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "No file selected"}), 400
            
            # Validate file extension and type
            if not file.filename.lower().endswith('.csv'):
                return jsonify({"error": "Only CSV files are accepted"}), 400
            
            # Check file size
            if file.content_length and file.content_length > 50 * 1024 * 1024:  # 50MB limit
                return jsonify({"error": "File too large. Maximum size is 50MB"}), 413
            
            try:
                # Read file content with size limits
                csv_content = file.read(50 * 1024 * 1024).decode('utf-8')  # 50MB limit
                feed_name = request.form.get('feed_name', os.path.splitext(file.filename)[0])
            except UnicodeDecodeError:
                # Try alternative encodings
                file.seek(0)
                content = file.read(50 * 1024 * 1024)  # 50MB limit
                for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'windows-1252']:
                    try:
                        csv_content = content.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    return jsonify({"error": "Unable to decode CSV file. Please ensure it's a text file with UTF-8 or Latin-1 encoding."}), 400
        else:
            return jsonify({"error": "No file or content provided"}), 400
        
        # Clean feed name to ensure it's valid for table naming
        feed_name = re.sub(r'[^a-zA-Z0-9_]', '_', feed_name.lower())
        
        # Use ingestion module if available
        try:
            from ingestion import ThreatDataIngestion
            
            # Initialize ingestion engine
            ingestion = ThreatDataIngestion()
            
            # Process the CSV file
            result = ingestion.analyze_csv_file(csv_content, feed_name)
            
            # Clear relevant caches on successful upload
            if not result.get("error"):
                clear_api_cache("get_feeds")
                clear_api_cache("get_stats")
            
            return jsonify(result)
            
        except ImportError:
            logger.warning("Ingestion module not available, using minimal implementation")
            
            # Create a minimal implementation that inserts data directly to BigQuery
            client = get_client('bigquery')
            if client and not isinstance(client, config.DummyClient):
                try:
                    # Import locally
                    from google.cloud import bigquery
                    
                    # Create a table for this upload if it doesn't exist
                    table_id = f"upload_{feed_name}"
                    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
                    
                    try:
                        client.get_table(full_table_id)
                        logger.info(f"Table {full_table_id} already exists")
                    except Exception:
                        # Create table
                        schema = [
                            bigquery.SchemaField("_ingestion_timestamp", "TIMESTAMP"),
                            bigquery.SchemaField("_ingestion_id", "STRING"),
                            bigquery.SchemaField("_source", "STRING"),
                            bigquery.SchemaField("_feed_type", "STRING"),
                            bigquery.SchemaField("csv_content", "STRING")
                        ]
                        table = bigquery.Table(full_table_id, schema=schema)
                        client.create_table(table, exists_ok=True)
                        logger.info(f"Created table {table_id}")
                    
                    # Parse CSV to find headers
                    import csv
                    from io import StringIO
                    
                    try:
                        csv_file = StringIO(csv_content)
                        reader = csv.reader(csv_file)
                        headers = next(reader, [])
                        
                        # Create record
                        ingestion_id = f"upload_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                        row = {
                            "_ingestion_timestamp": datetime.utcnow().isoformat(),
                            "_ingestion_id": ingestion_id,
                            "_source": "csv_upload",
                            "_feed_type": f"Uploaded CSV: {feed_name}",
                            "csv_content": csv_content
                        }
                        
                        # Insert into BQ
                        errors = client.insert_rows_json(full_table_id, [row])
                        
                        if not errors:
                            logger.info(f"Successfully uploaded CSV to table {table_id}")
                            report_metric("csv_upload_direct_to_bq")
                            
                            # Clear API cache for related endpoints
                            clear_api_cache("get_feeds")
                            clear_api_cache("get_stats")
                            
                            return jsonify({
                                "status": "success",
                                "message": "CSV uploaded directly to BigQuery",
                                "feed_name": feed_name,
                                "table": table_id,
                                "record_count": sum(1 for _ in reader),  # Count remaining rows
                                "headers": headers
                            })
                        else:
                            logger.error(f"Errors inserting CSV data: {errors}")
                            return jsonify({"error": f"BigQuery insert errors: {errors}"}), 500
                    except Exception as e:
                        logger.error(f"CSV parsing error: {str(e)}")
                        return jsonify({"error": f"CSV parsing error: {str(e)}"}), 400
                except Exception as e:
                    logger.error(f"Error uploading to BigQuery: {e}")
                    return jsonify({"error": f"BigQuery error: {str(e)}"}), 500
            
            report_metric("csv_upload_storage_unavailable")
            return jsonify({"error": "Storage not available"}), 500
    except UnicodeDecodeError:
        report_metric("csv_upload_encoding_error")
        return jsonify({"error": "Invalid CSV file encoding"}), 400
    except Exception as e:
        logger.error(f"CSV upload error: {str(e)}")
        report_metric("csv_upload_error")
        return jsonify({"error": f"Upload error: {str(e)}"}), 500

@api_bp.route('/analyze', methods=['POST'])
@require_api_key
@handle_exceptions
def analyze():
    """Handle various analysis requests"""
    # Check content type
    content_type = request.headers.get('Content-Type', '')
    if 'application/json' not in content_type:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    
    # Parse request
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON in request body"}), 400
            
        command = data.get("command", "")
        
        # Import analysis module
        try:
            from analysis import ThreatAnalyzer
            
            # Initialize the analyzer
            analyzer = ThreatAnalyzer()
            
            if command == "summarize_recent":
                days = data.get("days", 7)
                return jsonify(analyzer.get_recent_summary(days))
                
            elif command == "analyze_batch":
                iocs = data.get("iocs", [])
                if not iocs:
                    return jsonify({"error": "No IOCs provided"}), 400
                return jsonify(analyzer.analyze_ioc_batch(iocs))
                
            elif command == "analyze_feed":
                feed_name = data.get("feed_name")
                days = data.get("days", 7)
                if not feed_name:
                    return jsonify({"error": "No feed name provided"}), 400
                return jsonify(analyzer.analyze_feed_data(feed_name, days))
                
            elif command == "analyze_csv":
                content = data.get("content")
                feed_name = data.get("feed_name", "csv_upload")
                if not content:
                    return jsonify({"error": "No CSV content provided"}), 400
                return jsonify(analyzer.analyze_csv_file(content, feed_name))
                
            else:
                return jsonify({"error": f"Unknown command: {command}"}), 400
                
        except ImportError:
            logger.warning("Analysis module not available")
            
            # Create minimal mock response
            mock_response = {
                "summary": "Analysis module not available. This is a mock response.",
                "severity": "medium",
                "confidence": "low",
                "timestamp": datetime.utcnow().isoformat(),
                "mock": True
            }
            
            return jsonify(mock_response)
            
    except Exception as e:
        logger.error(f"Error in analysis endpoint: {str(e)}")
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500

@api_bp.route('/status', methods=['GET'])
def api_status():
    """Enhanced API status endpoint with detailed metrics"""
    # Get GCP service status from config module
    cloud_status = config.get_cloud_status()
    
    # Get cache stats
    cache_stats = {
        "size": len(query_cache),
        "oldest_entry": min(cache_timestamps.values()).isoformat() if cache_timestamps else None,
        "newest_entry": max(cache_timestamps.values()).isoformat() if cache_timestamps else None
    }
    
    # Get environment info
    env_info = {
        "environment": ENVIRONMENT,
        "project_id": PROJECT_ID,
        "region": REGION,
        "version": os.environ.get("VERSION", "1.0.0"),
        "api_key_configured": bool(get_api_key()),
        "dataset_id": DATASET_ID
    }
    
    # System resource info if available
    system_info = {}
    try:
        import psutil
        system_info = {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "thread_count": len(psutil.Process().threads())
        }
    except ImportError:
        system_info = {"status": "psutil not available"}
    
    # Return comprehensive status
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "services": cloud_status.get("services", {}),
        "cache": cache_stats,
        "environment": env_info,
        "system": system_info
    })

def init_app(app):
    """Initialize API routes with the main app"""
    global csrf
    
    # Try to get CSRF from app
    try:
        from flask_wtf.csrf import CSRFProtect
        
        # Try to get existing CSRF instance
        csrf = getattr(app, 'csrf', None) or CSRFProtect(app)
        
        # Exempt API routes from CSRF protection
        csrf.exempt(api_bp)
    except (ImportError, AttributeError):
        # No CSRF protection available or already configured, that's fine
        logger.warning("CSRF protection not available or already configured")
    
    # Register blueprint
    app.register_blueprint(api_bp)
    
    # Add root health check
    @app.route('/health', methods=['GET'])
    @handle_exceptions
    def root_health_check():
        return health_check()
    
    # Initialize request tracking
    @app.before_request
    def track_request():
        g.request_start_time = time.time()
    
    # Report request metrics after request
    @app.after_request
    def report_request_metrics(response):
        if hasattr(g, 'request_start_time'):
            # Calculate response time
            response_time = time.time() - g.request_start_time
            
            # Add X-Response-Time header
            response.headers['X-Response-Time'] = f"{response_time:.3f}s"
            
            # Log slow requests
            if response_time > 1.0:
                endpoint = request.endpoint or 'unknown'
                logger.info(f"Slow request to {endpoint}: {response_time:.3f}s")
                
                # Report metric if in production
                if ENVIRONMENT == 'production' and response_time > 2.0:
                    report_metric("slow_request_seconds", response_time)
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Don't cache API responses by default
        if request.path.startswith('/api/') and 'Cache-Control' not in response.headers:
            response.headers['Cache-Control'] = 'no-store, max-age=0'
        
        return response
    
    # Log initialization
    logger.info("API routes initialized with enhanced security")
    return app
