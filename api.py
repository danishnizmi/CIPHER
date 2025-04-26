"""
Threat Intelligence Platform - Streamlined API Module
Provides RESTful endpoints with optimized GCP integration.
"""

import os
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, g
from google.cloud import bigquery, storage, pubsub_v1
import traceback

# Import config module
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Core configuration
PROJECT_ID = config.project_id
DATASET_ID = config.bigquery_dataset
REGION = config.region
BUCKET_NAME = config.gcs_bucket
MAX_RESULTS = 1000
CACHE_TIMEOUT = 300

# Create Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Shared cache
query_cache = {}
cache_timestamps = {}

# ======== Shared Utilities ========

def get_api_key():
    """Get API key with fallbacks"""
    # Try direct attribute first
    if hasattr(config, 'api_key') and config.api_key:
        return config.api_key
        
    # Try environment variable
    api_key = os.environ.get("API_KEY", "")
    if api_key:
        return api_key
    
    # Try from cached config
    api_keys_config = config.get_cached_config('api-keys')
    return api_keys_config.get('platform_api_key', "") if api_keys_config else ""

def get_client(client_type):
    """Get or create GCP client on demand"""
    # Use Flask app context to store clients
    if not hasattr(g, 'gcp_clients'):
        g.gcp_clients = {}
    
    # Return cached client if available
    if client_type in g.gcp_clients:
        return g.gcp_clients[client_type]
    
    # Create new client
    try:
        if client_type == 'bigquery':
            g.gcp_clients[client_type] = bigquery.Client(project=PROJECT_ID)
        elif client_type == 'storage':
            g.gcp_clients[client_type] = storage.Client(project=PROJECT_ID)
        elif client_type == 'pubsub':
            g.gcp_clients[client_type] = pubsub_v1.PublisherClient()
        else:
            return None
            
        return g.gcp_clients[client_type]
    except Exception as e:
        logger.error(f"Error creating {client_type} client: {e}")
        return None

# ======== Decorators ========

def require_api_key(f):
    """API key authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = get_api_key()
        if not api_key:
            return f(*args, **kwargs)
        
        provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if provided_key and provided_key == api_key:
            return f(*args, **kwargs)
        
        return jsonify({"error": "Invalid API key", "timestamp": datetime.utcnow().isoformat()}), 401
    return decorated

def handle_exceptions(f):
    """Exception handling decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    return decorated

def cache_result(ttl=CACHE_TIMEOUT):
    """Cache decorator for API results"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Generate cache key from function name and arguments
            key_parts = [f.__name__] + [str(a) for a in args]
            key_parts.extend(f"{k}={v}" for k, v in kwargs.items())
            key_parts.extend(f"{k}={v}" for k, v in request.args.items())
            cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
            
            # Check cache
            now = datetime.now()
            if cache_key in query_cache and cache_key in cache_timestamps:
                if (now - cache_timestamps[cache_key]).total_seconds() < ttl:
                    return query_cache[cache_key]
            
            # Call function
            result = f(*args, **kwargs)
            
            # Cache result
            query_cache[cache_key] = result
            cache_timestamps[cache_key] = now
            
            # Manage cache size
            if len(query_cache) > 100:
                oldest = min(cache_timestamps.items(), key=lambda x: x[1])[0]
                if oldest in query_cache:
                    del query_cache[oldest]
                    del cache_timestamps[oldest]
            
            return result
        return decorated
    return decorator

# ======== Query Functions ========

def query_bigquery(query, params=None):
    """Execute BigQuery query with parameters"""
    client = get_client('bigquery')
    if not client:
        return [], "BigQuery client not available"
    
    try:
        job_config = bigquery.QueryJobConfig()
        if params:
            query_params = []
            for k, v in params.items():
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
        
        query_job = client.query(query, job_config=job_config)
        rows = [dict(row) for row in query_job.result()]
        return rows, None
    except Exception as e:
        logger.error(f"BigQuery error: {str(e)}")
        return [], str(e)

def validate_table_name(name):
    """Validate table name to prevent SQL injection"""
    return bool(name and name.replace("_", "").isalnum())

# ======== API Endpoints ========

@api_bp.route('/health', methods=['GET'])
@handle_exceptions
def health_check():
    """Health check endpoint"""
    version = os.environ.get("VERSION", "1.0.0")
    
    # Check BigQuery connectivity
    client = get_client('bigquery')
    db_status = "ok" if client else "error"
    
    return jsonify({
        "status": "ok",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": config.environment,
        "project": PROJECT_ID
    })

@api_bp.route('/stats', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=300)
def get_stats():
    """Get platform statistics"""
    days = int(request.args.get('days', '30'))
    
    # Use mock data if requested
    if request.args.get('mock', 'false').lower() == 'true':
        # Try to import from frontend for consistency
        try:
            from frontend import MOCK_DATA
            return jsonify(MOCK_DATA["stats"])
        except (ImportError, KeyError):
            pass

    # Query BigQuery for stats
    feed_query = f"""
    SELECT 
      (SELECT COUNT(DISTINCT table_id) FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__` 
       WHERE table_id NOT LIKE 'threat%') AS total_sources,
      (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis` 
       WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS total_analyses,
      (SELECT MAX(analysis_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`) AS last_analysis,
      (SELECT COUNT(DISTINCT campaign_id) FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`) AS total_campaigns
    """
    
    rows, error = query_bigquery(feed_query)
    
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
      analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    GROUP BY type
    ORDER BY count DESC
    LIMIT 10
    """
    
    ioc_rows, ioc_error = query_bigquery(ioc_query)
    
    if not ioc_error and ioc_rows:
        stats["iocs"]["types"] = [
            {"type": row.get("type", "").strip('"'), "count": row.get("count", 0)}
            for row in ioc_rows
        ]
        stats["iocs"]["total"] = sum(row.get("count", 0) for row in ioc_rows)
    
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
    
    # Check if table exists and get stats
    query = f"""
    SELECT
      (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` 
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS total_records,
      (SELECT MIN(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS earliest_record,
      (SELECT MAX(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`) AS latest_record,
      (SELECT COUNT(DISTINCT DATE(_ingestion_timestamp)) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS days_with_data
    """
    
    rows, error = query_bigquery(query)
    
    # Get daily counts
    daily_query = f"""
    SELECT
      DATE(_ingestion_timestamp) as date,
      COUNT(*) as record_count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    GROUP BY date
    ORDER BY date
    """
    
    daily_rows, daily_error = query_bigquery(daily_query)
    
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
    """Get data from a specific feed with filtering"""
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    # Parse query parameters
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    offset = int(request.args.get('offset', '0'))
    days = int(request.args.get('days', '7'))
    search = request.args.get('search', '')
    
    # Build query
    conditions = [f"_ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    params = {}
    
    if search:
        conditions.append("TO_JSON_STRING(t) LIKE @search")
        params["search"] = f"%{search}%"
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    ORDER BY _ingestion_timestamp DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    """
    
    rows, error = query_bigquery(query, params)
    count_rows, count_error = query_bigquery(count_query, params)
    
    # Process results
    processed_rows = []
    for row in rows:
        processed_row = {}
        for key, value in row.items():
            if isinstance(value, datetime):
                processed_row[key] = value.isoformat()
            else:
                processed_row[key] = value
        processed_rows.append(processed_row)
    
    total_count = count_rows[0]["count"] if not count_error and count_rows else len(processed_rows) + offset
    
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
    """List threat campaigns"""
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    offset = int(request.args.get('offset', '0'))
    severity = request.args.get('severity', '')
    
    # Build conditions
    conditions = [f"last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    params = {}
    
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
    LIMIT {limit} OFFSET {offset}
    """
    
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE {" AND ".join(conditions)}
    """
    
    rows, error = query_bigquery(query, params)
    count_rows, count_error = query_bigquery(count_query, params)
    
    # If query failed or no campaigns, return sample data
    if error or not rows:
        campaigns = [
            {
                "campaign_id": "c123456",
                "campaign_name": "APT-123456",
                "threat_actor": "FancyBear",
                "source_count": 7,
                "last_seen": (datetime.utcnow() - timedelta(days=2)).isoformat(),
                "severity": "high"
            },
            {
                "campaign_id": "c234567",
                "campaign_name": "Ransomware-234567",
                "threat_actor": "Conti",
                "source_count": 5,
                "last_seen": (datetime.utcnow() - timedelta(days=5)).isoformat(),
                "severity": "critical"
            }
        ]
    else:
        # Process datetime fields
        campaigns = []
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
    """Search for IOCs across all analyzed data"""
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    offset = int(request.args.get('offset', '0'))
    ioc_type = request.args.get('type', '')
    
    # Build query
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    params = {}
    
    ioc_conditions = []
    if ioc_type:
        ioc_conditions.append("ioc_type = @ioc_type")
        params["ioc_type"] = ioc_type
    
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
    LIMIT {limit} OFFSET {offset}
    """
    
    rows, error = query_bigquery(query, params)
    
    # Process results
    records = []
    if not error and rows:
        for row in rows:
            record = {}
            for key, value in row.items():
                if isinstance(value, datetime):
                    record[key] = value.isoformat()
                else:
                    record[key] = value
            records.append(record)
    else:
        # Sample data if query fails
        records = [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "sources": 12,
                "first_seen": (datetime.utcnow() - timedelta(days=20)).isoformat()
            },
            {
                "type": "domain",
                "value": "malicious-domain.com",
                "sources": 8,
                "first_seen": (datetime.utcnow() - timedelta(days=15)).isoformat()
            }
        ]
    
    return jsonify({
        "records": records,
        "count": len(records),
        "total_available": len(records) + offset,
        "filters": {"days": days, "type": ioc_type}
    })

@api_bp.route('/iocs/geo', methods=['GET'])
@require_api_key
@handle_exceptions
@cache_result(ttl=3600)  # Cache for 1 hour
def get_ioc_geo_stats():
    """Get geographic distribution of IP-based IOCs"""
    days = int(request.args.get('days', '30'))
    
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
        AND analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
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
    
    rows, error = query_bigquery(query)
    
    # Process results
    countries = []
    if not error and rows:
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
    else:
        # Sample data
        countries = [
            {"country": "US", "count": 120, "cities": [{"name": "New York", "ip": "192.168.1.1"}]},
            {"country": "CN", "count": 95, "cities": [{"name": "Beijing", "ip": "192.168.1.2"}]},
            {"country": "RU", "count": 75, "cities": [{"name": "Moscow", "ip": "192.168.1.3"}]}
        ]
    
    return jsonify({
        "countries": countries,
        "total_countries": len(countries),
        "timestamp": datetime.utcnow().isoformat()
    })

@api_bp.route('/ingest_threat_data', methods=['POST'])
@require_api_key
@handle_exceptions
def handle_ingest_data():
    """Trigger data ingestion"""
    try:
        # Import ingestion module
        from ingestion import ingest_threat_data
        
        # Pass request to ingestion handler
        result = ingest_threat_data(request)
        
        # Return result
        if isinstance(result, tuple):
            return result
        else:
            return jsonify(result)
    except ImportError:
        return jsonify({"error": "Ingestion module not available"}), 500
    except Exception as e:
        logger.error(f"Ingestion error: {str(e)}")
        return jsonify({"error": f"Ingestion error: {str(e)}"}), 500

@api_bp.route('/upload_csv', methods=['POST'])
@require_api_key
@handle_exceptions
def upload_csv():
    """Upload CSV file for processing"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        # Read file content
        content = file.read().decode('utf-8')
        feed_name = request.form.get('feed_name', os.path.splitext(file.filename)[0])
        
        # Use ingestion module
        try:
            from ingestion import ingest_threat_data
            
            # Prepare request data
            data = {
                "file_type": "csv",
                "content": content,
                "feed_name": feed_name
            }
            
            # Create mock request
            class MockRequest:
                def get_json(self, silent=False):
                    return data
            
            # Process CSV
            result = ingest_threat_data(MockRequest())
            
            if isinstance(result, tuple):
                return result
            return jsonify(result)
        except ImportError:
            # Upload to GCS if ingestion not available
            client = get_client('storage')
            if client:
                bucket = client.bucket(BUCKET_NAME)
                blob_name = f"uploads/{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
                blob = bucket.blob(blob_name)
                blob.upload_from_string(content, content_type="text/csv")
                
                return jsonify({
                    "status": "success",
                    "message": "CSV uploaded to storage (ingestion module not available)",
                    "file": file.filename,
                    "feed_name": feed_name,
                    "storage_path": blob_name
                })
            else:
                return jsonify({"error": "Storage not available"}), 500
    except UnicodeDecodeError:
        return jsonify({"error": "Invalid CSV file encoding"}), 400
    except Exception as e:
        logger.error(f"CSV upload error: {str(e)}")
        return jsonify({"error": f"Upload error: {str(e)}"}), 500

def init_app(app):
    """Initialize API routes with the main app"""
    # Register blueprint
    app.register_blueprint(api_bp)
    
    # Add root health check
    @app.route('/health', methods=['GET'])
    @handle_exceptions
    def root_health_check():
        return health_check()
    
    logger.info("API routes initialized")
    return app
