"""
Threat Intelligence Platform - API Service Module
Provides RESTful endpoints for accessing threat intelligence data with intelligent query handling.
"""

import os
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
import functools

from flask import Flask, Blueprint, request, jsonify, Response, current_app, send_file, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.cloud import bigquery
from google.cloud import storage
from google.oauth2 import service_account
from functools import wraps, lru_cache
import traceback
import tempfile
import csv
import io

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from config module
PROJECT_ID = config.project_id
DATASET_ID = config.bigquery_dataset

# Get API key from config
if not hasattr(config, 'api_key') or config.api_key is None:
    # Attempt to load API key from environment or config
    API_KEY = os.environ.get("API_KEY", "")
    if not API_KEY:
        # Try to get from cached config
        api_keys_config = config.get_cached_config('api-keys')
        API_KEY = api_keys_config.get('platform_api_key', "") if api_keys_config else ""
else:
    API_KEY = config.api_key

# API Configuration
MAX_RESULTS = 1000  # Maximum results to return in a single query
CACHE_TIMEOUT = 300  # 5 minutes cache for certain endpoints

# Create Blueprint instead of app for better modular integration
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Client cache for performance
bq_client = None
storage_client = None

# ======== Core Utilities ========

def get_client(client_type: str):
    """Get or initialize a Google Cloud client
    
    Args:
        client_type: Type of client ('bigquery' or 'storage')
        
    Returns:
        Initialized client or None if initialization fails
    """
    global bq_client, storage_client
    
    try:
        if client_type == 'bigquery':
            if bq_client is None:
                bq_client = bigquery.Client(project=PROJECT_ID)
                logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
            return bq_client
        elif client_type == 'storage':
            if storage_client is None:
                storage_client = storage.Client(project=PROJECT_ID)
                logger.info(f"Storage client initialized for project {PROJECT_ID}")
            return storage_client
        else:
            logger.error(f"Unknown client type: {client_type}")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize {client_type} client: {str(e)}")
        logger.error(traceback.format_exc())
        return None

# Authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY:
            # No API key configured, allow all requests
            return f(*args, **kwargs)
        
        # Check for API key in header or query parameter
        provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if provided_key and provided_key == API_KEY:
            return f(*args, **kwargs)
        else:
            logger.warning(f"Invalid API key provided from {request.remote_addr}")
            return api_error("Unauthorized - Invalid API key", status=401)
    
    return decorated_function

def handle_exceptions(f):
    """Decorator to handle exceptions uniformly"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            return api_error(str(e))
    
    return decorated_function

def validate_params(*param_names, types=None):
    """Decorator to validate request parameters"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            params = {}
            for i, name in enumerate(param_names):
                try:
                    value = request.args.get(name)
                    if not value:
                        continue
                    
                    # Convert to specified type
                    if types and i < len(types) and types[i]:
                        value = types[i](value)
                    
                    params[name] = value
                except ValueError:
                    return api_error(f"Invalid parameter: {name}", status=400)
            
            # Add validated params to kwargs
            kwargs.update(params)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_table_name(table_name: str) -> bool:
    """Validate table name to prevent SQL injection"""
    # Only allow alphanumeric characters and underscores
    return bool(table_name and table_name.replace("_", "").isalnum())

def api_response(data, status=200):
    """Standardized API response"""
    return jsonify(data), status

def api_error(message, status=500, extra=None):
    """Standardized API error response"""
    response = {
        "error": message,
        "timestamp": datetime.utcnow().isoformat(),
        "path": request.path
    }
    if extra:
        response.update(extra)
    return jsonify(response), status

# ======== Query Cache ========

class QueryCache:
    """Cache for BigQuery queries with timeout"""
    def __init__(self, cache_time=CACHE_TIMEOUT):
        self.cache = {}
        self.cache_time = cache_time
    
    def get(self, query_key):
        """Get cached query result if valid"""
        if query_key in self.cache:
            timestamp, results = self.cache[query_key]
            if (datetime.now() - timestamp).total_seconds() < self.cache_time:
                return results
            # Clean up expired entry
            del self.cache[query_key]
        return None
    
    def set(self, query_key, results):
        """Store query result in cache"""
        self.cache[query_key] = (datetime.now(), results)
        # Limit cache size by removing oldest entries if needed
        if len(self.cache) > 100:  # Limit to 100 entries
            oldest_key = min(self.cache, key=lambda k: self.cache[k][0])
            del self.cache[oldest_key]

# Initialize query cache
query_cache = QueryCache()

def execute_bigquery(query: str, params: Optional[Dict] = None, use_cache: bool = False) -> Tuple[List[Dict], Optional[Exception]]:
    """Execute a BigQuery query and return results"""
    client = get_client('bigquery')
    if not client:
        return [], Exception("BigQuery client not available")
    
    # Generate cache key for this query
    cache_key = None
    if use_cache:
        cache_key = hashlib.md5((query + str(params)).encode()).hexdigest()
        cached_result = query_cache.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached result for query: {query[:100]}...")
            return cached_result, None
    
    try:
        job_config = bigquery.QueryJobConfig()
        if params:
            job_config.query_parameters = [
                bigquery.ScalarQueryParameter(key, "STRING", value)
                for key, value in params.items()
            ]
        
        start_time = time.time()
        query_job = client.query(query, job_config=job_config)
        results = query_job.result()
        query_time = time.time() - start_time
        
        # Log query performance
        if query_time > 2.0:  # Log slow queries
            logger.warning(f"Slow query ({query_time:.2f}s): {query[:150]}...")
        else:
            logger.debug(f"Query executed in {query_time:.2f}s")
        
        # Convert to list of dicts
        result_list = [dict(row.items()) for row in results]
        
        # Cache result if needed
        if use_cache and cache_key:
            query_cache.set(cache_key, result_list)
        
        return result_list, None
    except Exception as e:
        logger.error(f"BigQuery error: {str(e)}")
        logger.error(traceback.format_exc())
        return [], e

def with_cached_result(cache_key_fn):
    """Decorator to implement caching for endpoint results"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if cache should be skipped
            force_refresh = request.args.get('refresh', 'false').lower() == 'true'
            if not force_refresh:
                cache_key = cache_key_fn(*args, **kwargs)
                cached_result = query_cache.get(cache_key)
                if cached_result:
                    return jsonify(cached_result)
            
            # Execute function and cache result
            result = f(*args, **kwargs)
            
            # If result is a tuple (likely response, status_code), use just the response
            data = result[0] if isinstance(result, tuple) else result
            
            # Cache the result
            if not force_refresh and isinstance(data, (dict, list)):
                cache_key = cache_key_fn(*args, **kwargs)
                query_cache.set(cache_key, data)
            
            return result
        return decorated_function
    return decorator

# ======== Endpoint Handlers ========

@api_bp.route('/health', methods=['GET'])
@handle_exceptions
def health_check():
    """Health check endpoint"""
    logger.info("Health check endpoint called")
    version = os.environ.get("VERSION", "1.0.0")
    
    # Check BigQuery connectivity for deep health check
    client = get_client('bigquery')
    db_status = "ok" if client else "error"
    
    return api_response({
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
@validate_params('days', types=[int])
@with_cached_result(lambda days=30, **kwargs: f"stats_{days}")
def get_stats(days=30):
    """Get platform statistics with intelligent caching"""
    # Default stats structure
    stats = {
        "feeds": {
            "total_sources": 0,
            "active_feeds": 0,
            "total_records": 0
        },
        "campaigns": {
            "total_campaigns": 0,
            "active_campaigns": 0,
            "unique_actors": 0
        },
        "iocs": {
            "total": 0,
            "types": []
        },
        "analyses": {
            "total_analyses": 0,
            "last_analysis": None
        },
        "timestamp": datetime.utcnow().isoformat(),
        "days": days
    }
    
    client = get_client('bigquery')
    if not client:
        return api_response(stats)
    
    try:
        # Get feed stats - use a more efficient query
        feed_query = f"""
        SELECT
          COUNT(DISTINCT table_id) AS total_sources,
          COUNT(DISTINCT IF(record_count > 0, table_id, NULL)) AS active_feeds,
          SUM(record_count) AS total_records
        FROM (
          SELECT
            table_id,
            (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id 
             WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS record_count
          FROM
            `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
          WHERE 
            table_id NOT LIKE 'threat%'
        )
        """
        
        feed_results, feed_error = execute_bigquery(feed_query, use_cache=True)
        if not feed_error and feed_results:
            stats["feeds"]["total_sources"] = feed_results[0].get("total_sources", 0)
            stats["feeds"]["active_feeds"] = feed_results[0].get("active_feeds", 0)
            stats["feeds"]["total_records"] = feed_results[0].get("total_records", 0)
        
        # Get campaign stats
        campaign_query = f"""
        SELECT
          COUNT(*) AS total_campaigns,
          COUNT(DISTINCT threat_actor) AS unique_actors,
          COUNT(IF(last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days//2} DAY), 1, NULL)) AS active_campaigns
        FROM
          `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
        WHERE
          detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        campaign_results, campaign_error = execute_bigquery(campaign_query, use_cache=True)
        if not campaign_error and campaign_results:
            stats["campaigns"]["total_campaigns"] = campaign_results[0].get("total_campaigns", 0)
            stats["campaigns"]["active_campaigns"] = campaign_results[0].get("active_campaigns", 0)
            stats["campaigns"]["unique_actors"] = campaign_results[0].get("unique_actors", 0)
        
        # Get IOC stats
        ioc_query = f"""
        WITH ioc_stats AS (
          SELECT
            JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS ioc_type,
            COUNT(*) AS count
          FROM
            `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
            UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
          WHERE
            analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
          GROUP BY 
            ioc_type
        )
        SELECT
          (SELECT SUM(count) FROM ioc_stats) AS total_iocs,
          ARRAY_AGG(STRUCT(ioc_type, count)) AS ioc_types
        FROM ioc_stats
        """
        
        ioc_results, ioc_error = execute_bigquery(ioc_query, use_cache=True)
        if not ioc_error and ioc_results:
            stats["iocs"]["total"] = ioc_results[0].get("total_iocs", 0)
            # Process ioc_types array from BigQuery
            if "ioc_types" in ioc_results[0]:
                types_data = ioc_results[0]["ioc_types"]
                stats["iocs"]["types"] = [
                    {"type": t.get("ioc_type", "unknown").strip('"'), "count": t.get("count", 0)}
                    for t in types_data
                ]
        
        # Get analysis stats
        analysis_query = f"""
        SELECT
          COUNT(*) AS total_analyses,
          MAX(analysis_timestamp) AS last_analysis
        FROM
          `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE
          analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        analysis_results, analysis_error = execute_bigquery(analysis_query, use_cache=True)
        if not analysis_error and analysis_results:
            stats["analyses"]["total_analyses"] = analysis_results[0].get("total_analyses", 0)
            last_analysis = analysis_results[0].get("last_analysis")
            if last_analysis:
                if isinstance(last_analysis, datetime):
                    stats["analyses"]["last_analysis"] = last_analysis.isoformat()
                else:
                    stats["analyses"]["last_analysis"] = str(last_analysis)
                
    except Exception as e:
        logger.error(f"Error fetching stats: {str(e)}")
    
    return api_response(stats)

@api_bp.route('/config', methods=['GET'])
@require_api_key
@handle_exceptions
def get_public_config():
    """Get public configuration"""
    logger.debug("Public config endpoint called")
    
    # Get current feature flags
    features = {
        "alerts_enabled": True,
        "reports_enabled": True,
        "campaign_detection_enabled": True,
        "ioc_enrichment_enabled": "VIRUSTOTAL_API_KEY" in os.environ,
        "ai_insights_enabled": config.get("AI_INSIGHTS_ENABLED", "true").lower() == "true"
    }
    
    return api_response({
        "project_id": PROJECT_ID,
        "region": config.region,
        "environment": config.environment,
        "features": features,
        "max_results": MAX_RESULTS,
        "build_version": os.environ.get("VERSION", "1.0.0"),
        "timestamp": datetime.utcnow().isoformat()
    })

@api_bp.route('/feeds', methods=['GET'])
@require_api_key
@handle_exceptions
@with_cached_result(lambda **kwargs: "feeds_list")
def list_feeds():
    """List available threat feeds"""
    logger.info("Listing available threat feeds")
    
    query = f"""
    SELECT table_id, 
           (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id) as record_count,
           (SELECT MAX(_ingestion_timestamp) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id) as last_updated
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    ORDER BY record_count DESC
    """
    
    rows, error = execute_bigquery(query)
    
    if error or not rows:
        return api_error("Failed to retrieve feed data", extra={"feeds": [], "count": 0})
    
    feeds = []
    for row in rows:
        feed_data = {
            "name": row["table_id"],
            "record_count": row["record_count"]
        }
        
        if row.get("last_updated"):
            if isinstance(row["last_updated"], datetime):
                feed_data["last_updated"] = row["last_updated"].isoformat()
            else:
                feed_data["last_updated"] = str(row["last_updated"])
        
        feeds.append(feed_data)
    
    result = {
        "feeds": [feed["name"] for feed in feeds],
        "feed_details": feeds,
        "count": len(feeds),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return api_response(result)

@api_bp.route('/feeds/<feed_name>/stats', methods=['GET'])
@require_api_key
@handle_exceptions
def feed_stats(feed_name: str):
    """Get statistics for a specific feed"""
    logger.info(f"Getting stats for feed: {feed_name}")
    # Validate feed name (prevent SQL injection)
    if not validate_table_name(feed_name):
        return api_error("Invalid feed name", status=400)
    
    time_range = request.args.get('days', '30')
    try:
        days = int(time_range)
    except ValueError:
        return api_error("Invalid days parameter", status=400)
    
    # Try to get stats from cache
    cache_key = f"feed_stats_{feed_name}_{days}"
    cached_stats = query_cache.get(cache_key)
    if cached_stats:
        return api_response(cached_stats)
    
    # Check if table exists
    client = get_client('bigquery')
    
    if not client:
        return api_error("Database connection failed")
    
    try:
        table_ref = client.dataset(DATASET_ID).table(feed_name)
        client.get_table(table_ref)
    except Exception as e:
        logger.warning(f"Table {feed_name} not found: {str(e)}")
        return api_error(f"Feed not found: {feed_name}", status=404)
    
    # Query real stats from BigQuery with a more efficient query
    query = f"""
    WITH daily_counts AS (
      SELECT
        DATE(_ingestion_timestamp) AS date,
        COUNT(*) AS record_count
      FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
      WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      GROUP BY date
    )
    SELECT
      (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` 
       WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS total_records,
      MIN(_ingestion_timestamp) AS earliest_record,
      MAX(_ingestion_timestamp) AS latest_record,
      (SELECT COUNT(DISTINCT date) FROM daily_counts) AS days_with_data,
      (SELECT ARRAY_AGG(STRUCT(date, record_count)) FROM daily_counts ORDER BY date) AS daily_data
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error retrieving feed statistics: {str(error)}")
    
    stats = rows[0] if rows else {}
    
    # Convert datetime objects to ISO format strings
    for key in ['earliest_record', 'latest_record']:
        if key in stats and stats[key]:
            if isinstance(stats[key], datetime):
                stats[key] = stats[key].isoformat()
            else:
                stats[key] = str(stats[key])
    
    # Process daily counts
    daily_counts = []
    if "daily_data" in stats:
        for day_data in stats["daily_data"]:
            daily_counts.append({
                "date": day_data["date"].isoformat() if isinstance(day_data["date"], datetime) else str(day_data["date"]),
                "count": day_data["record_count"]
            })
    
    stats["daily_counts"] = daily_counts
    
    # Cache the results
    query_cache.set(cache_key, stats)
    
    return api_response(stats)

@api_bp.route('/feeds/<feed_name>/data', methods=['GET'])
@require_api_key
@limiter.limit("50 per minute")  # Higher limit for data access
@handle_exceptions
def feed_data(feed_name: str):
    """Get data from a specific feed with filtering and pagination"""
    logger.info(f"Getting data for feed: {feed_name}")
    # Validate feed name (prevent SQL injection)
    if not validate_table_name(feed_name):
        return api_error("Invalid feed name", status=400)
    
    # Parse query parameters
    try:
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        days = int(request.args.get('days', '7'))
    except ValueError:
        return api_error("Invalid numeric parameter", status=400)
    
    search = request.args.get('search', '')
    field_filter = request.args.get('field', '')
    value_filter = request.args.get('value', '')
    
    # Check if data is in cache for common queries
    use_cache = not search and not field_filter and not value_filter
    cache_key = f"feed_data_{feed_name}_{days}_{limit}_{offset}"
    
    if use_cache:
        cached_data = query_cache.get(cache_key)
        if cached_data:
            return api_response(cached_data)
    
    client = get_client('bigquery')
    if not client:
        return api_error("Database connection failed")
    
    # Check if table exists
    try:
        table_ref = client.dataset(DATASET_ID).table(feed_name)
        client.get_table(table_ref)
    except Exception:
        return api_error(f"Feed not found: {feed_name}", status=404)
    
    # Build query with dynamic filters
    conditions = [f"_ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    # Add search term if provided
    if search:
        # Escape single quotes to prevent SQL injection
        search = search.replace("'", "''")
        conditions.append(f"TO_JSON_STRING(t) LIKE '%{search}%'")
    
    # Add field-specific filter if provided
    if field_filter and value_filter:
        # Validate field name to prevent SQL injection
        if not validate_table_name(field_filter):
            return api_error(f"Invalid field name: {field_filter}", status=400)
        
        # Escape quotes in value
        value_filter = value_filter.replace("'", "''")
        conditions.append(f"{field_filter} = '{value_filter}'")
    
    # Build and execute the query
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    ORDER BY _ingestion_timestamp DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(str(error), status=500)
    
    # Count total matching records
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    """
    
    count_rows, count_error = execute_bigquery(count_query)
    
    total_count = count_rows[0]["count"] if not count_error and count_rows else len(rows) + offset
    
    # Process rows to convert datetime objects to strings
    processed_rows = []
    for row in rows:
        processed_row = {}
        for key, value in row.items():
            if isinstance(value, datetime):
                processed_row[key] = value.isoformat()
            else:
                processed_row[key] = value
        processed_rows.append(processed_row)
    
    result = {
        "records": processed_rows,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total_count
    }
    
    # Cache the results for common queries
    if use_cache:
        query_cache.set(cache_key, result)
    
    return api_response(result)

@api_bp.route('/campaigns', methods=['GET'])
@require_api_key
@handle_exceptions
def list_campaigns():
    """List threat campaigns with filtering options"""
    # Parse query parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        min_sources = int(request.args.get('min_sources', '2'))
        severity = request.args.get('severity', '').lower()
    except ValueError:
        return api_error("Invalid numeric parameter", status=400)
    
    search = request.args.get('search', '')
    actor_filter = request.args.get('actor', '')
    
    # Try to get from cache for common queries
    use_cache = not search and not actor_filter and not severity
    cache_key = f"campaigns_{days}_{limit}_{offset}_{min_sources}"
    
    if use_cache:
        cached_data = query_cache.get(cache_key)
        if cached_data:
            return api_response(cached_data)
    
    # Build query conditions
    conditions = [
        f"detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)",
        f"source_count >= {min_sources}"
    ]
    
    # Add filters if provided
    if severity:
        conditions.append(f"LOWER(severity) = '{severity}'")
    
    if actor_filter:
        actor_filter = actor_filter.replace("'", "''")  # Prevent SQL injection
        conditions.append(f"LOWER(threat_actor) LIKE '%{actor_filter.lower()}%'")
        
    if search:
        search = search.replace("'", "''")  # Prevent SQL injection
        conditions.append(f"""(
            LOWER(campaign_name) LIKE '%{search.lower()}%' OR
            LOWER(threat_actor) LIKE '%{search.lower()}%' OR
            LOWER(malware) LIKE '%{search.lower()}%' OR
            LOWER(targets) LIKE '%{search.lower()}%' OR
            LOWER(techniques) LIKE '%{search.lower()}%'
        )""")
    
    # Build query
    query = f"""
    SELECT
      campaign_id,
      campaign_name,
      threat_actor,
      malware,
      techniques,
      targets,
      source_count,
      ioc_count,
      first_seen,
      last_seen,
      severity,
      detection_timestamp
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE
      {" AND ".join(conditions)}
    ORDER BY
      last_seen DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error retrieving campaigns: {str(error)}")
    
    # Convert datetime objects to strings
    campaigns = []
    for row in rows:
        campaign = dict(row)
        for key, value in campaign.items():
            if isinstance(value, datetime):
                campaign[key] = value.isoformat()
        campaigns.append(campaign)
    
    # Get total count
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE {" AND ".join(conditions)}
    """
    
    count_rows, count_error = execute_bigquery(count_query)
    total = count_rows[0]["count"] if not count_error and count_rows else len(campaigns)
    
    result = {
        "campaigns": campaigns,
        "count": total,
        "has_more": offset + limit < total,
        "days": days
    }
    
    # Cache results
    if use_cache:
        query_cache.set(cache_key, result)
        
    return api_response(result)

@api_bp.route('/campaigns/<campaign_id>', methods=['GET'])
@require_api_key
@handle_exceptions
def get_campaign(campaign_id: str):
    """Get details for a specific campaign"""
    # Try to get from cache
    cache_key = f"campaign_detail_{campaign_id}"
    cached_data = query_cache.get(cache_key)
    if cached_data:
        return api_response(cached_data)
    
    # Sanitize input to prevent SQL injection
    safe_campaign_id = campaign_id.replace("'", "''")
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE campaign_id = '{safe_campaign_id}'
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error retrieving campaign: {str(error)}")
    
    if not rows:
        return api_error(f"Campaign not found: {campaign_id}", status=404)
    
    campaign = dict(rows[0])
    
    # Convert datetime objects to strings
    for key, value in campaign.items():
        if isinstance(value, datetime):
            campaign[key] = value.isoformat()
    
    # Parse complex JSON fields with proper error handling
    for field in ["iocs", "sources"]:
        if field in campaign and campaign[field]:
            try:
                if isinstance(campaign[field], str):
                    campaign[field] = json.loads(campaign[field])
            except (json.JSONDecodeError, TypeError):
                campaign[field] = []
    
    # Cache the result
    query_cache.set(cache_key, campaign)
    
    return api_response(campaign)

@api_bp.route('/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def search_iocs():
    """Search for IOCs across all analyzed data with advanced filtering"""
    # Parse query parameters with validation
    ioc_value = request.args.get('value')
    ioc_type = request.args.get('type')
    confidence = request.args.get('confidence')
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    offset = int(request.args.get('offset', '0'))
    source = request.args.get('source')
    
    if not (ioc_value or ioc_type or source):
        return api_error("At least one search parameter (value, type, or source) is required", status=400)
    
    # Build query conditions
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    # Escape parameters to prevent SQL injection
    if ioc_value:
        ioc_value = ioc_value.replace("'", "''")
        conditions.append(f"iocs LIKE '%\"value\":\"{ioc_value}\"%'")
    
    if ioc_type:
        ioc_type = ioc_type.replace("'", "''")
        conditions.append(f"iocs LIKE '%\"type\":\"{ioc_type}\"%'")
        
    if source:
        source = source.replace("'", "''")
        conditions.append(f"source_type = '{source}'")
        
    if confidence:
        confidence = confidence.replace("'", "''")
        conditions.append(f"iocs LIKE '%\"confidence\":\"{confidence}\"%'")
    
    # Efficient query with pagination
    query = f"""
    SELECT
      source_id,
      source_type,
      iocs,
      analysis_timestamp
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE {" AND ".join(conditions)}
    ORDER BY analysis_timestamp DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error searching IOCs: {str(error)}")
    
    records = []
    for row in rows:
        # Convert to dict
        item = dict(row)
        
        # Convert datetime objects to strings
        for key, value in item.items():
            if isinstance(value, datetime):
                item[key] = value.isoformat()
        
        # Parse JSON fields
        try:
            if "iocs" in item:
                if isinstance(item["iocs"], str):
                    item["iocs"] = json.loads(item["iocs"])
                
                # Filter IOCs based on criteria
                if ioc_value or ioc_type or confidence:
                    filtered_iocs = []
                    for ioc in item["iocs"]:
                        if ((not ioc_value or ioc.get("value") == ioc_value) and
                            (not ioc_type or ioc.get("type") == ioc_type) and
                            (not confidence or ioc.get("confidence") == confidence)):
                            filtered_iocs.append(ioc)
                    
                    item["iocs"] = filtered_iocs
                    
                # Only include records that have matching IOCs after filtering
                if item["iocs"]:
                    records.append(item)
        except json.JSONDecodeError:
            # Skip records with invalid JSON
            logger.warning(f"Invalid JSON in IOC data for source_id: {item.get('source_id')}")
            continue
    
    result = {
        "records": records,
        "count": len(records),
        "total_available": offset + len(records) + (10 if len(records) == limit else 0),  # Estimate more if full limit returned
        "filters": {
            "type": ioc_type,
            "value": ioc_value,
            "source": source,
            "confidence": confidence,
            "days": days
        }
    }
    
    return api_response(result)

@api_bp.route('/search', methods=['GET'])
@require_api_key
@handle_exceptions
def search():
    """Intelligent search across all data types"""
    query = request.args.get('q')
    
    if not query:
        return api_error("Query parameter 'q' is required", status=400)
    
    try:
        days = int(request.args.get('days', '30'))
    except ValueError:
        return api_error("Invalid days parameter", status=400)
    
    # Check cache for common searches
    cache_key = f"search_{query}_{days}"
    cached_result = query_cache.get(cache_key)
    if cached_result:
        return api_response(cached_result)
    
    results = {
        "campaigns": [],
        "iocs": [],
        "analyses": []
    }
    
    # Sanitize query for SQL
    safe_query = query.replace("'", "''")
    
    # Campaign search query
    campaign_query = f"""
    SELECT
      campaign_id,
      campaign_name,
      threat_actor,
      malware,
      targets,
      source_count,
      severity
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE
      detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND (
        campaign_name LIKE '%{safe_query}%'
        OR threat_actor LIKE '%{safe_query}%'
        OR malware LIKE '%{safe_query}%'
        OR targets LIKE '%{safe_query}%'
        OR techniques LIKE '%{safe_query}%'
      )
    LIMIT 10
    """
    
    # IOC search query
    ioc_query = f"""
    WITH matched_iocs AS (
      SELECT
        source_id,
        JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
        JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS value,
        analysis_timestamp
      FROM
        `{PROJECT_ID}.{DATASET_ID}.threat_analysis` AS t,
        UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
      WHERE
        analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND JSON_EXTRACT_SCALAR(ioc_item, '$.value') LIKE '%{safe_query}%'
    )
    SELECT * FROM matched_iocs
    LIMIT 20
    """
    
    # Analysis search query
    analysis_query = f"""
    SELECT
      source_id,
      source_type,
      analysis_timestamp,
      JSON_EXTRACT(vertex_analysis, '$.summary') AS summary
    FROM
      `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE
      analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND (
        vertex_analysis LIKE '%{safe_query}%'
        OR iocs LIKE '%{safe_query}%'
      )
    LIMIT 10
    """
    
    # Execute all three searches
    campaign_rows, _ = execute_bigquery(campaign_query)
    ioc_rows, _ = execute_bigquery(ioc_query)
    analysis_rows, _ = execute_bigquery(analysis_query)
    
    # Process campaign results
    if campaign_rows:
        results["campaigns"] = [dict(row) for row in campaign_rows]
    
    # Process IOC results
    if ioc_rows:
        # Clean up IOC data
        ioc_results = []
        for row in ioc_rows:
            item = dict(row)
            # Clean up string values (remove quotes)
            for key in ['type', 'value']:
                if key in item and item[key]:
                    if item[key].startswith('"') and item[key].endswith('"'):
                        item[key] = item[key][1:-1]
            
            # Convert datetime objects
            if "analysis_timestamp" in item and isinstance(item["analysis_timestamp"], datetime):
                item["analysis_timestamp"] = item["analysis_timestamp"].isoformat()
                
            ioc_results.append(item)
            
        results["iocs"] = ioc_results
    
    # Process analysis results
    if analysis_rows:
        analysis_results = []
        for row in analysis_rows:
            item = dict(row)
            # Clean up summary (remove quotes)
            if "summary" in item and item["summary"]:
                if item["summary"].startswith('"') and item["summary"].endswith('"'):
                    item["summary"] = item["summary"][1:-1]
            
            # Convert datetime objects
            if "analysis_timestamp" in item and isinstance(item["analysis_timestamp"], datetime):
                item["analysis_timestamp"] = item["analysis_timestamp"].isoformat()
                
            analysis_results.append(item)
            
        results["analyses"] = analysis_results
    
    # Add query metadata
    search_result = {
        "query": query,
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
        "days": days
    }
    
    # Cache results
    query_cache.set(cache_key, search_result)
    
    return api_response(search_result)

@api_bp.route('/reports/<report_type>', methods=['GET'])
@require_api_key
@handle_exceptions
def get_report(report_type: str):
    """Get or generate a report"""
    generate = request.args.get('generate', 'false').lower() == 'true'
    days = int(request.args.get('days', '30'))
    campaign_id = request.args.get('campaign_id')
    
    # Check cache first for non-generated requests
    if not generate and not campaign_id:
        cache_key = f"report_{report_type}_{days}"
        cached_report = query_cache.get(cache_key)
        if cached_report:
            return api_response(cached_report)
    
    # Check if report type is valid
    valid_report_types = ["feed_summary", "campaign_analysis", "ioc_trend"]
    if report_type not in valid_report_types:
        return api_error(f"Invalid report type. Valid types are: {', '.join(valid_report_types)}", status=400)
    
    # Query the reports table for existing report
    if not generate and not campaign_id:
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.reports`
        WHERE report_type = '{report_type}'
        AND period_days = {days}
        ORDER BY generated_at DESC
        LIMIT 1
        """
        
        rows, _ = execute_bigquery(query)
        if rows:
            report = dict(rows[0])
            # Convert datetime objects to strings
            for key, value in report.items():
                if isinstance(value, datetime):
                    report[key] = value.isoformat()
            
            # Cache the report
            query_cache.set(f"report_{report_type}_{days}", report)
            return api_response(report)
    
    # Campaign-specific report
    if campaign_id:
        campaign_query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
        WHERE campaign_id = '{campaign_id.replace("'", "''")}'
        """
        campaign_rows, _ = execute_bigquery(campaign_query)
        if campaign_rows:
            campaign_data = dict(campaign_rows[0])
            
            # Convert datetime objects and JSON strings
            for key, value in campaign_data.items():
                if isinstance(value, datetime):
                    campaign_data[key] = value.isoformat()
                elif key in ["iocs", "sources"] and isinstance(value, str):
                    try:
                        campaign_data[key] = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        campaign_data[key] = []
        else:
            return api_error(f"Campaign not found: {campaign_id}", status=404)
    
    # For this implementation, we'll return a minimal report structure
    # In a production system, this would invoke AI or use a template engine
    report_id = f"{report_type}_{datetime.utcnow().strftime('%Y%m%d')}"
    report_content = f"# {report_type.replace('_', ' ').title()} Report\n\nAnalysis period: {days} days"
    
    if campaign_id and 'campaign_data' in locals():
        report_content += f"\n\nCampaign: {campaign_data.get('campaign_name')}"
        report_content += f"\nThreat Actor: {campaign_data.get('threat_actor', 'Unknown')}"
        report_content += f"\nSeverity: {campaign_data.get('severity', 'Unknown')}"
    
    report = {
        "report_id": report_id,
        "report_name": f"{report_type.replace('_', ' ').title()} Report",
        "report_type": report_type,
        "period_days": days,
        "generated_at": datetime.utcnow().isoformat(),
        "report_content": report_content,
        "is_new": generate
    }
    
    # Cache the report (except for campaign-specific ones)
    if not campaign_id:
        query_cache.set(f"report_{report_type}_{days}", report)
    
    return api_response(report)

@api_bp.route('/alerts', methods=['GET'])
@require_api_key
@handle_exceptions
def get_alerts():
    """Get active alerts with intelligent caching"""
    # Parse parameters
    severity_filter = request.args.get('severity')
    days = int(request.args.get('days', '7'))
    
    # Check cache
    cache_key = f"alerts_{severity_filter or 'all'}_{days}"
    cached_alerts = query_cache.get(cache_key)
    if cached_alerts:
        return api_response(cached_alerts)
    
    # Query alerts from the alerts table
    conditions = [f"timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    if severity_filter:
        conditions.append(f"severity = '{severity_filter.replace('', '')}'")
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.alerts`
    WHERE {" AND ".join(conditions)}
    ORDER BY timestamp DESC
    """
    
    rows, error = execute_bigquery(query)
    
    alerts = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    if not error and rows:
        for row in rows:
            alert = dict(row)
            # Convert datetime objects to strings
            for key, value in alert.items():
                if isinstance(value, datetime):
                    alert[key] = value.isoformat()
            
            # Parse JSON fields
            for field in ["recommendations", "context"]:
                if field in alert and isinstance(alert[field], str):
                    try:
                        alert[field] = json.loads(alert[field])
                    except json.JSONDecodeError:
                        alert[field] = []
            
            alerts.append(alert)
            severity = alert.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    # If no results from BigQuery, query threat_analysis for high severity findings
    if not alerts:
        query = f"""
        SELECT
          source_id,
          source_type,
          analysis_timestamp,
          JSON_EXTRACT(vertex_analysis, '$.severity') AS severity,
          JSON_EXTRACT(vertex_analysis, '$.summary') AS summary
        FROM
          `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE
          analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
          AND JSON_EXTRACT(vertex_analysis, '$.severity') IN ('"critical"', '"high"')
        LIMIT 10
        """
        
        analysis_rows, _ = execute_bigquery(query)
        
        if analysis_rows:
            for row in analysis_rows:
                severity = row.get("severity", '"medium"').strip('"').lower()
                if severity_filter and severity != severity_filter.lower():
                    continue
                    
                alert = {
                    "id": f"alert_{row['source_id']}",
                    "title": f"High severity threat detected: {row['source_type']}",
                    "severity": severity,
                    "timestamp": row["analysis_timestamp"].isoformat() if isinstance(row["analysis_timestamp"], datetime) else str(row["analysis_timestamp"]),
                    "description": row.get("summary", "").strip('"'),
                    "affected_systems": 1,
                    "status": "new",
                    "recommendations": [
                        "Investigate this threat immediately",
                        "Check for indicators of compromise",
                        "Review security logs"
                    ]
                }
                alerts.append(alert)
                if severity in severity_counts:
                    severity_counts[severity] += 1
    
    result = {
        "alerts": alerts,
        "count": len(alerts),
        "summary": {
            "total": len(alerts),
            "by_severity": severity_counts
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Cache results
    query_cache.set(cache_key, result)
    
    return api_response(result)

@api_bp.route('/export/feeds/<feed_name>', methods=['GET'])
@require_api_key
@handle_exceptions
def export_feed(feed_name: str):
    """Export feed data in various formats with memory-efficient streaming"""
    # Validate feed name
    if not validate_table_name(feed_name):
        return api_error("Invalid feed name", status=400)
    
    # Get export format
    format_type = request.args.get('format', 'csv').lower()
    if format_type not in ['csv', 'json']:
        return api_error("Invalid format. Supported formats: csv, json", status=400)
    
    # Parse query parameters
    try:
        days = int(request.args.get('days', '7'))
        limit = min(int(request.args.get('limit', '1000')), 10000)  # Allow higher limit for exports
    except ValueError:
        return api_error("Invalid numeric parameter", status=400)
    
    # Check if table exists
    client = get_client('bigquery')
    if not client:
        return api_error("Database connection failed")
    
    try:
        table_ref = client.dataset(DATASET_ID).table(feed_name)
        client.get_table(table_ref)
    except Exception:
        return api_error(f"Feed not found: {feed_name}", status=404)
    
    # Build query
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    ORDER BY _ingestion_timestamp DESC
    LIMIT {limit}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error retrieving feed data: {str(error)}")
    
    if not rows:
        return api_error("No data to export", status=404)
    
    # Process rows to convert datetime objects to strings
    data = []
    for row in rows:
        processed_row = {}
        for key, value in row.items():
            if isinstance(value, datetime):
                processed_row[key] = value.isoformat()
            else:
                processed_row[key] = value
        data.append(processed_row)
    
    # Create a temporary file for the export
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format_type}') as temp_file:
            if format_type == 'csv':
                # Get fieldnames from the first record
                fieldnames = list(data[0].keys())
                
                # Write CSV data
                with open(temp_file.name, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in data:
                        writer.writerow(row)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name=f"{feed_name}_export.csv",
                    mimetype='text/csv'
                )
            elif format_type == 'json':
                # Write JSON data
                with open(temp_file.name, 'w') as jsonfile:
                    json.dump(data, jsonfile, indent=2)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name=f"{feed_name}_export.json",
                    mimetype='application/json'
                )
    finally:
        # Ensure we clean up the temp file regardless of outcome
        try:
            if 'temp_file' in locals():
                os.unlink(temp_file.name)
        except:
            pass
    
    # This shouldn't happen given the validation above
    return api_error("Unsupported export format", status=400)

@api_bp.route('/export/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def export_iocs():
    """Export IOCs data in various formats with memory-efficient streaming"""
    # Get export format
    format_type = request.args.get('format', 'csv').lower()
    if format_type not in ['csv', 'json', 'stix']:
        return api_error("Invalid format. Supported formats: csv, json, stix", status=400)
    
    # Parse query parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '1000')), 5000)  # Higher limit for exports
    except ValueError:
        return api_error("Invalid numeric parameter", status=400)
    
    ioc_type = request.args.get('type')
    
    # Build query conditions
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    if ioc_type:
        ioc_type = ioc_type.replace("'", "''")  # Sanitize input
        conditions.append(f"JSON_EXTRACT_SCALAR(ioc_item, '$.type') = '{ioc_type}'")
    
    # Efficient query for IOC extraction
    query = f"""
    WITH ip_iocs AS (
      SELECT
        JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS value,
        JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
        JSON_EXTRACT_SCALAR(ioc_item, '$.confidence') AS confidence,
        JSON_EXTRACT_SCALAR(ioc_item, '$.geo.country') AS country,
        JSON_EXTRACT_SCALAR(ioc_item, '$.geo.city') AS city,
        JSON_EXTRACT_SCALAR(ioc_item, '$.first_seen') AS first_seen,
        source_id,
        source_type,
        analysis_timestamp
      FROM
        `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
        UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
      WHERE
        {" AND ".join(conditions)}
    )
    SELECT *
    FROM ip_iocs
    ORDER BY analysis_timestamp DESC
    LIMIT {limit}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return api_error(f"Error exporting IOCs: {str(error)}")
    
    # Process rows to clean up and standardize IOC data
    iocs = []
    for row in rows:
        ioc = {
            "type": row.get("type", "").strip('"'),
            "value": row.get("value", "").strip('"'),
            "confidence": row.get("confidence", "").strip('"') or "medium",
            "source_id": row.get("source_id"),
            "source_type": row.get("source_type")
        }
        
        # Process first_seen
        if row.get("first_seen"):
            ioc["first_seen"] = row.get("first_seen").strip('"')
            
        # Process geo data for IPs
        if ioc["type"] == "ip" and row.get("country"):
            ioc["geo"] = {
                "country": row.get("country", "").strip('"'),
                "city": row.get("city", "").strip('"')
            }
        
        # Add timestamp
        if "analysis_timestamp" in row:
            if isinstance(row["analysis_timestamp"], datetime):
                ioc["timestamp"] = row["analysis_timestamp"].isoformat()
            else:
                ioc["timestamp"] = str(row["analysis_timestamp"])
                
        iocs.append(ioc)
    
    if not iocs:
        return api_error("No IOCs found matching your criteria", status=404)
    
    # Export based on requested format
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format_type}') as temp_file:
            if format_type == 'csv':
                # Get all possible fields from IOCs
                fields = set()
                for ioc in iocs:
                    fields.update(ioc.keys())
                fieldnames = sorted(list(fields))
                
                # Write CSV data
                with open(temp_file.name, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for ioc in iocs:
                        # Flatten geo data
                        flat_ioc = ioc.copy()
                        if 'geo' in flat_ioc and isinstance(flat_ioc['geo'], dict):
                            for key, value in flat_ioc['geo'].items():
                                flat_ioc[f'geo_{key}'] = value
                            del flat_ioc['geo']
                        writer.writerow(flat_ioc)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name="iocs_export.csv",
                    mimetype='text/csv'
                )
            
            elif format_type == 'json':
                # Write JSON data
                with open(temp_file.name, 'w') as jsonfile:
                    json.dump(iocs, jsonfile, indent=2)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name="iocs_export.json",
                    mimetype='application/json'
                )
            
            elif format_type == 'stix':
                # Create STIX bundle
                stix_data = {
                    "type": "bundle",
                    "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d')}",
                    "spec_version": "2.0",
                    "objects": []
                }
                
                # Convert IOCs to STIX format
                for ioc in iocs:
                    ioc_type = ioc.get('type')
                    ioc_value = ioc.get('value')
                    first_seen = ioc.get('first_seen', datetime.utcnow().isoformat())
                    
                    # Create STIX object based on IOC type
                    stix_object = {
                        "type": "indicator",
                        "id": f"indicator--{hash(ioc_value) & 0xffffffff:08x}",
                        "created": first_seen,
                        "modified": datetime.utcnow().isoformat(),
                        "name": f"{ioc_type.upper()} Indicator: {ioc_value}",
                        "valid_from": first_seen,
                        "labels": ["malicious-activity"],
                        "pattern_type": "stix"
                    }
                    
                    # Set pattern based on IOC type
                    if ioc_type == 'ip':
                        stix_object["pattern"] = f"[ipv4-addr:value = '{ioc_value}']"
                    elif ioc_type == 'domain':
                        stix_object["pattern"] = f"[domain-name:value = '{ioc_value}']"
                    elif ioc_type in ['md5', 'sha1', 'sha256']:
                        stix_object["pattern"] = f"[file:hashes.'{ioc_type.upper()}' = '{ioc_value}']"
                    elif ioc_type == 'url':
                        stix_object["pattern"] = f"[url:value = '{ioc_value}']"
                    elif ioc_type == 'email':
                        stix_object["pattern"] = f"[email-addr:value = '{ioc_value}']"
                    else:
                        continue  # Skip IOCs that don't map to STIX
                    
                    stix_data["objects"].append(stix_object)
                
                # Write STIX data to temp file
                with open(temp_file.name, 'w') as jsonfile:
                    json.dump(stix_data, jsonfile, indent=2)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name="iocs_export.stix.json",
                    mimetype='application/json'
                )
    finally:
        # Ensure we clean up the temp file
        try:
            if 'temp_file' in locals():
                os.unlink(temp_file.name)
        except:
            pass
    
    # This shouldn't happen given the validation above
    return api_error("Unsupported export format", status=400)

@api_bp.route('/analyze/ioc', methods=['POST'])
@require_api_key
@handle_exceptions
def analyze_ioc():
    """Analyze an IOC with Vertex AI when explicitly requested"""
    # Get request data
    request_json = request.get_json()
    if not request_json:
        return api_error("No data provided", status=400)
    
    ioc_value = request_json.get('value')
    ioc_type = request_json.get('type')
    
    if not ioc_value or not ioc_type:
        return api_error("IOC value and type are required", status=400)
    
    # Check if AI insights are enabled
    ai_enabled = config.get("AI_INSIGHTS_ENABLED", "true").lower() == "true"
    if not ai_enabled:
        return api_error("AI insights are disabled in this environment", status=403)
    
    # Check for existing analysis in the database
    query = f"""
    WITH matched_iocs AS (
      SELECT
        source_id,
        vertex_analysis
      FROM
        `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
        UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
      WHERE
        JSON_EXTRACT_SCALAR(ioc_item, '$.type') = '{ioc_type.replace("'", "''")}'
        AND JSON_EXTRACT_SCALAR(ioc_item, '$.value') = '{ioc_value.replace("'", "''")}'
      ORDER BY analysis_timestamp DESC
      LIMIT 1
    )
    SELECT * FROM matched_iocs
    """
    
    rows, _ = execute_bigquery(query)
    
    if rows and rows[0].get("vertex_analysis"):
        # Use existing analysis if available
        try:
            analysis = json.loads(rows[0]["vertex_analysis"])
            analysis["ioc_value"] = ioc_value
            analysis["ioc_type"] = ioc_type
            analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
            return api_response({
                "analysis": analysis,
                "ai_powered": True,
                "source": "cached"
            })
        except json.JSONDecodeError:
            pass  # Continue to generate new analysis
    
    # Initialize Vertex AI
    try:
        from google.cloud import aiplatform
        from vertexai.language_models import TextGenerationModel
        
        vertexai.init(project=PROJECT_ID, location=config.region)
        model = TextGenerationModel.from_pretrained("text-bison")
    except Exception as e:
        logger.error(f"Error initializing Vertex AI: {str(e)}")
        return api_error(f"AI analysis unavailable: {str(e)}", status=500)
    
    # Create prompt for analysis
    prompt = f"""
    You are a threat intelligence analyst. Analyze the following indicator of compromise (IOC):
    
    Type: {ioc_type}
    Value: {ioc_value}
    
    Provide a structured analysis with the following information:
    1. What is this type of IOC and how is it typically used in attacks?
    2. What are potential threats or campaigns that might use this IOC?
    3. What recommendations would you give for handling this IOC?
    4. How would you rate the confidence level in this analysis?
    
    Format your response as JSON with these keys: overview, potential_threats, recommendations, confidence_level
    """
    
    try:
        response = model.predict(prompt, temperature=0.1, max_output_tokens=1024)
        
        # Extract JSON from response
        try:
            start_index = response.text.find('{')
            end_index = response.text.rfind('}') + 1
            
            if start_index >= 0 and end_index > start_index:
                json_str = response.text[start_index:end_index]
                analysis = json.loads(json_str)
                
                # Add metadata
                analysis["ioc_value"] = ioc_value
                analysis["ioc_type"] = ioc_type
                analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
                
                return api_response({
                    "analysis": analysis,
                    "ai_powered": True
                })
            else:
                logger.warning(f"Could not extract JSON from AI response for IOC {ioc_value}")
                return api_error("Could not parse AI response", status=500)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for IOC analysis: {str(e)}")
            return api_error(f"JSON parse error: {str(e)}", status=500)
    except Exception as e:
        logger.error(f"Error analyzing IOC with AI: {str(e)}")
        return api_error(f"AI analysis failed: {str(e)}", status=500)

# Initialize the app with the api Blueprint
def init_app(app):
    """Initialize the API with the main app"""
    # Initialize the limiter with the app
    limiter.init_app(app)
    
    # Register blueprint with URL prefix
    app.register_blueprint(api_bp)
    
    # Register root health check endpoint for compatibility
    @app.route('/health', methods=['GET'])
    @handle_exceptions
    def root_health_check():
        """Root health check endpoint"""
        logger.info("Root health check called")
        return health_check()
        
    logger.info("API routes initialized successfully")
    
    return app
