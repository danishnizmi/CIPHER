"""
Threat Intelligence Platform - API Service Module
Provides RESTful endpoints for accessing threat intelligence data.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple

from flask import Flask, Blueprint, request, jsonify, Response, current_app
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.cloud import bigquery
from google.cloud import storage
from google.oauth2 import service_account
from functools import wraps
import traceback

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
        API_KEY = api_keys_config.get('platform_api_key', "")
else:
    API_KEY = config.api_key

# API Configuration
MAX_RESULTS = 1000  # Maximum results to return in a single query

# Create Blueprint instead of app for better modular integration
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize BigQuery client with better error handling
def get_bigquery_client():
    """Get BigQuery client with robust error handling"""
    global bq_client
    
    try:
        if 'bq_client' not in globals() or bq_client is None:
            logger.info(f"Initializing BigQuery client for project {PROJECT_ID}")
            bq_client = bigquery.Client(project=PROJECT_ID)
        return bq_client
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery client: {str(e)}")
        logger.error(traceback.format_exc())
        return None

# Initialize Storage client
def get_storage_client():
    """Get Storage client with robust error handling"""
    global storage_client
    
    try:
        if 'storage_client' not in globals() or storage_client is None:
            logger.info(f"Initializing Storage client for project {PROJECT_ID}")
            storage_client = storage.Client(project=PROJECT_ID)
        return storage_client
    except Exception as e:
        logger.error(f"Failed to initialize Storage client: {str(e)}")
        logger.error(traceback.format_exc())
        return None

# Authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY:
            # No API key configured, allow all requests
            logger.debug("No API key configured, allowing request")
            return f(*args, **kwargs)
        
        # Check for API key in header or query parameter
        provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if provided_key and provided_key == API_KEY:
            return f(*args, **kwargs)
        else:
            logger.warning(f"Invalid API key provided from {request.remote_addr}")
            return jsonify({"error": "Unauthorized - Invalid API key"}), 401
    
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
            return jsonify({
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.path
            }), 500
    
    return decorated_function


def validate_table_name(table_name: str) -> bool:
    """Validate table name to prevent SQL injection"""
    # Only allow alphanumeric characters and underscores
    return bool(table_name and table_name.replace("_", "").isalnum())


def execute_bigquery(query: str, params: Optional[Dict] = None) -> Tuple[List[Dict], Optional[Exception]]:
    """Execute a BigQuery query and return results"""
    client = get_bigquery_client()
    if not client:
        return [], Exception("BigQuery client not available")
        
    try:
        job_config = bigquery.QueryJobConfig()
        if params:
            job_config.query_parameters = [
                bigquery.ScalarQueryParameter(key, "STRING", value)
                for key, value in params.items()
            ]
        
        query_job = client.query(query, job_config=job_config)
        results = query_job.result()
        
        # Convert to list of dicts
        return [dict(row.items()) for row in results], None
    except Exception as e:
        logger.error(f"BigQuery error: {str(e)}")
        logger.error(traceback.format_exc())
        return [], e


@api_bp.route('/health', methods=['GET'])
@handle_exceptions
def health_check():
    """Health check endpoint"""
    logger.info("Health check endpoint called")
    version = os.environ.get("VERSION", "1.0.0")
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": config.environment,
        "project": PROJECT_ID
    })


@api_bp.route('/config', methods=['GET'])
@require_api_key
@handle_exceptions
def get_public_config():
    """Get public configuration"""
    logger.debug("Public config endpoint called")
    return jsonify({
        "project_id": PROJECT_ID,
        "region": config.region,
        "environment": config.environment,
        "features": {
            "alerts_enabled": True,
            "reports_enabled": True,
            "campaign_detection_enabled": True,
            "ioc_enrichment_enabled": "VIRUSTOTAL_API_KEY" in os.environ
        }
    })


@api_bp.route('/feeds', methods=['GET'])
@require_api_key
@handle_exceptions
def list_feeds():
    """List available threat feeds"""
    logger.info("Listing available threat feeds")
    query = f"""
    SELECT table_id
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    feeds = [row["table_id"] for row in rows]
    
    return jsonify({
        "feeds": feeds,
        "count": len(feeds)
    })


@api_bp.route('/feeds/<feed_name>/stats', methods=['GET'])
@require_api_key
@handle_exceptions
def feed_stats(feed_name: str):
    """Get statistics for a specific feed"""
    logger.info(f"Getting stats for feed: {feed_name}")
    # Validate feed name (prevent SQL injection)
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    time_range = request.args.get('days', '30')
    try:
        days = int(time_range)
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Check if table exists
    client = get_bigquery_client()
    if not client:
        return jsonify({"error": "Database connection unavailable"}), 503
        
    try:
        table_ref = client.dataset(DATASET_ID).table(feed_name)
        client.get_table(table_ref)
    except Exception as e:
        logger.error(f"Table not found: {str(e)}")
        return jsonify({"error": f"Feed {feed_name} not found"}), 404
    
    query = f"""
    SELECT
      COUNT(*) AS total_records,
      MIN(_ingestion_timestamp) AS earliest_record,
      MAX(_ingestion_timestamp) AS latest_record,
      COUNT(DISTINCT DATE(_ingestion_timestamp)) AS days_with_data
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    stats = rows[0] if rows else {}
    
    # Get daily counts
    daily_query = f"""
    SELECT
      DATE(_ingestion_timestamp) AS date,
      COUNT(*) AS record_count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    GROUP BY date
    ORDER BY date
    """
    
    daily_rows, daily_error = execute_bigquery(daily_query)
    
    if daily_error:
        return jsonify({"error": str(daily_error)}), 500
    
    daily_counts = [
        {"date": row["date"].isoformat() if isinstance(row["date"], datetime) else str(row["date"]), 
         "count": row["record_count"]} 
        for row in daily_rows
    ]
    
    stats["daily_counts"] = daily_counts
    
    return jsonify(stats)


@api_bp.route('/feeds/<feed_name>/data', methods=['GET'])
@require_api_key
@limiter.limit("20 per minute")  # Higher limit for data access
@handle_exceptions
def feed_data(feed_name: str):
    """Get data from a specific feed with filtering"""
    logger.info(f"Getting data for feed: {feed_name}")
    # Validate feed name (prevent SQL injection)
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    # Parse query parameters
    try:
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        days = int(request.args.get('days', '7'))
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Check if table exists
    client = get_bigquery_client()
    if not client:
        return jsonify({"error": "Database connection unavailable"}), 503
        
    try:
        table_ref = client.dataset(DATASET_ID).table(feed_name)
        client.get_table(table_ref)
    except Exception:
        return jsonify({"error": f"Feed {feed_name} not found"}), 404
    
    # Build query with dynamic filters
    conditions = [f"_ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    # Add search term if provided
    search = request.args.get('search')
    if search:
        # Escape single quotes to prevent SQL injection
        search = search.replace("'", "''")
        conditions.append(f"TO_JSON_STRING(t) LIKE '%{search}%'")
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    ORDER BY _ingestion_timestamp DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    # Count total matching records
    count_query = f"""
    SELECT COUNT(*) as count
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    """
    
    count_rows, count_error = execute_bigquery(count_query)
    
    if count_error:
        return jsonify({"error": str(count_error)}), 500
    
    total_count = count_rows[0]["count"] if count_rows else 0
    
    return jsonify({
        "records": rows,
        "total": total_count,
        "limit": limit,
        "offset": offset
    })


# Continue with other routes...

# Register additional API routes below...
@api_bp.route('/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def search_iocs():
    """Search for IOCs across all analyzed data"""
    # Parse query parameters
    ioc_value = request.args.get('value')
    ioc_type = request.args.get('type')
    
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    if not ioc_value and not ioc_type:
        return jsonify({"error": "At least one of 'value' or 'type' parameter is required"}), 400
    
    # Build query conditions
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    # Escape single quotes to prevent SQL injection
    if ioc_value:
        ioc_value = ioc_value.replace("'", "''")
        conditions.append(f"iocs LIKE '%\"value\":\"{ioc_value}\"%'")
    
    if ioc_type:
        ioc_type = ioc_type.replace("'", "''")
        conditions.append(f"iocs LIKE '%\"type\":\"{ioc_type}\"%'")
    
    query = f"""
    SELECT
      source_id,
      source_type,
      iocs,
      analysis_timestamp
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE {" AND ".join(conditions)}
    ORDER BY analysis_timestamp DESC
    LIMIT {limit}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    records = []
    for row in rows:
        # Parse JSON fields
        try:
            if "iocs" in row:
                row["iocs"] = json.loads(row["iocs"])
                
                # Filter IOCs if specific value or type was requested
                if ioc_value or ioc_type:
                    filtered_iocs = []
                    for ioc in row["iocs"]:
                        if (not ioc_value or ioc.get("value") == ioc_value) and \
                           (not ioc_type or ioc.get("type") == ioc_type):
                            filtered_iocs.append(ioc)
                    
                    row["iocs"] = filtered_iocs
            
            records.append(row)
        except json.JSONDecodeError:
            # Skip records with invalid JSON
            logger.warning(f"Invalid JSON in IOC data for source_id: {row.get('source_id')}")
            continue
    
    return jsonify({
        "records": records,
        "count": len(records)
    })


# Initialize the app with the api Blueprint
def init_app(app):
    """Initialize the API with the main app"""
    # Initialize the limiter with the app
    limiter.init_app(app)
    
    # Register blueprint with URL prefix
    app.register_blueprint(api_bp)
    
    # Also register routes directly under /
    # This provides fallback endpoints for compatibility
    # Especially important for the health check endpoint
    
    @app.route('/health', methods=['GET'])
    @handle_exceptions
    def root_health_check():
        """Root health check endpoint"""
        logger.info("Root health check called")
        return health_check()
        
    logger.info("API routes initialized successfully")
    
    return app
