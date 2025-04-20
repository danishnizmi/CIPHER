"""
Threat Intelligence Platform - API Service Module
Provides RESTful endpoints for accessing threat intelligence data.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple

from flask import Flask, request, jsonify, Response
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
API_KEY = config.api_key

# API Configuration
MAX_RESULTS = 1000  # Maximum results to return in a single query

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize BigQuery client
bq_client = bigquery.Client(project=PROJECT_ID)

# Initialize Storage client
storage_client = storage.Client(project=PROJECT_ID)


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
    try:
        job_config = bigquery.QueryJobConfig()
        if params:
            job_config.query_parameters = [
                bigquery.ScalarQueryParameter(key, "STRING", value)
                for key, value in params.items()
            ]
        
        query_job = bq_client.query(query, job_config=job_config)
        results = query_job.result()
        
        # Convert to list of dicts
        return [dict(row.items()) for row in results], None
    except Exception as e:
        logger.error(f"BigQuery error: {str(e)}")
        logger.error(traceback.format_exc())
        return [], e


@app.route('/api/health', methods=['GET'])
@handle_exceptions
def health_check():
    """Health check endpoint"""
    version = os.environ.get("VERSION", "1.0.0")
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": version,
        "environment": config.environment,
        "project": PROJECT_ID
    })


@app.route('/api/config', methods=['GET'])
@require_api_key
@handle_exceptions
def get_public_config():
    """Get public configuration"""
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


@app.route('/api/feeds', methods=['GET'])
@require_api_key
@handle_exceptions
def list_feeds():
    """List available threat feeds"""
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


@app.route('/api/feeds/<feed_name>/stats', methods=['GET'])
@require_api_key
@handle_exceptions
def feed_stats(feed_name: str):
    """Get statistics for a specific feed"""
    # Validate feed name (prevent SQL injection)
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    time_range = request.args.get('days', '30')
    try:
        days = int(time_range)
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Check if table exists
    try:
        table_ref = bq_client.dataset(DATASET_ID).table(feed_name)
        bq_client.get_table(table_ref)
    except Exception:
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


@app.route('/api/feeds/<feed_name>/data', methods=['GET'])
@require_api_key
@limiter.limit("20 per minute")  # Higher limit for data access
@handle_exceptions
def feed_data(feed_name: str):
    """Get data from a specific feed with filtering"""
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
    try:
        table_ref = bq_client.dataset(DATASET_ID).table(feed_name)
        bq_client.get_table(table_ref)
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


@app.route('/api/iocs', methods=['GET'])
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


@app.route('/api/campaigns', methods=['GET'])
@require_api_key
@handle_exceptions
def list_campaigns():
    """List detected threat campaigns"""
    # Parse query parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        min_sources = int(request.args.get('min_sources', '2'))
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
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
      detection_timestamp
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND source_count >= {min_sources}
    ORDER BY detection_timestamp DESC
    LIMIT {limit}
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    # Format datetime fields to ISO string
    campaigns = []
    for row in rows:
        campaign = dict(row)
        for field in ['first_seen', 'last_seen', 'detection_timestamp']:
            if field in campaign and isinstance(campaign[field], datetime):
                campaign[field] = campaign[field].isoformat()
        campaigns.append(campaign)
    
    return jsonify({
        "campaigns": campaigns,
        "count": len(campaigns)
    })


@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
@require_api_key
@handle_exceptions
def campaign_details(campaign_id: str):
    """Get detailed information about a specific campaign"""
    # Escape single quotes to prevent SQL injection
    safe_campaign_id = campaign_id.replace("'", "''")
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE campaign_id = '{safe_campaign_id}'
    LIMIT 1
    """
    
    rows, error = execute_bigquery(query)
    
    if error:
        return jsonify({"error": str(error)}), 500
    
    if not rows:
        return jsonify({"error": f"Campaign {campaign_id} not found"}), 404
    
    campaign = dict(rows[0])
    
    # Format datetime fields to ISO string
    for field in ['first_seen', 'last_seen', 'detection_timestamp']:
        if field in campaign and isinstance(campaign[field], datetime):
            campaign[field] = campaign[field].isoformat()
    
    # Parse JSON fields
    try:
        if "iocs" in campaign:
            campaign["iocs"] = json.loads(campaign["iocs"])
        if "sources" in campaign:
            campaign["sources"] = json.loads(campaign["sources"])
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in campaign data for campaign_id: {campaign_id}")
        campaign["iocs"] = []
        campaign["sources"] = []
    
    return jsonify(campaign)


@app.route('/api/search', methods=['GET'])
@require_api_key
@limiter.limit("10 per minute")  # Lower limit for complex search
@handle_exceptions
def search():
    """Advanced search across all threat data"""
    # Parse query parameters
    query_str = request.args.get('q', '')
    
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '50')), MAX_RESULTS)
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    if not query_str:
        return jsonify({"error": "Query parameter 'q' is required"}), 400
    
    # Escape single quotes to prevent SQL injection
    safe_query = query_str.replace("'", "''")
    
    # Search across multiple sources
    results = {
        "feeds": [],
        "analyses": [],
        "campaigns": []
    }
    
    # Get feeds for searching
    feeds_query = f"""
    SELECT DISTINCT table_id
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    """
    
    feed_rows, feed_error = execute_bigquery(feeds_query)
    
    if feed_error:
        return jsonify({"error": str(feed_error)}), 500
    
    feeds = [row["table_id"] for row in feed_rows]
    
    # Search in each feed (with limit)
    max_feed_results = max(1, limit // len(feeds)) if feeds else 0
    
    for feed in feeds:
        feed_query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed}`
        WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
          AND TO_JSON_STRING(t) LIKE '%{safe_query}%'
        LIMIT {max_feed_results}
        """
        
        try:
            feed_rows, _ = execute_bigquery(feed_query)
            
            if feed_rows:
                # Format datetime fields
                formatted_rows = []
                for row in feed_rows:
                    row_dict = dict(row)
                    for key, value in row_dict.items():
                        if isinstance(value, datetime):
                            row_dict[key] = value.isoformat()
                    formatted_rows.append(row_dict)
                
                results["feeds"].append({
                    "feed_name": feed,
                    "records": formatted_rows,
                    "count": len(formatted_rows)
                })
        except Exception as e:
            logger.warning(f"Error searching feed {feed}: {str(e)}")
            # Continue with other feeds
    
    # Search in analyses
    analysis_query = f"""
    SELECT
      source_id,
      source_type,
      nlp_analysis,
      vertex_analysis,
      analysis_timestamp
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND (
        nlp_analysis LIKE '%{safe_query}%'
        OR vertex_analysis LIKE '%{safe_query}%'
      )
    LIMIT {limit}
    """
    
    analysis_rows, analysis_error = execute_bigquery(analysis_query)
    
    if not analysis_error:
        # Parse JSON fields and format timestamps
        analyses = []
        for row in analysis_rows:
            analysis = dict(row)
            
            # Format timestamp
            if "analysis_timestamp" in analysis and isinstance(analysis["analysis_timestamp"], datetime):
                analysis["analysis_timestamp"] = analysis["analysis_timestamp"].isoformat()
            
            # Parse JSON fields
            for field in ["nlp_analysis", "vertex_analysis"]:
                if field in analysis:
                    try:
                        analysis[field] = json.loads(analysis[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            
            analyses.append(analysis)
        
        results["analyses"] = analyses
    
    # Search in campaigns
    campaign_query = f"""
    SELECT
      campaign_id,
      campaign_name,
      threat_actor,
      malware,
      techniques,
      targets,
      iocs,
      source_count,
      ioc_count,
      first_seen,
      last_seen
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
      AND (
        campaign_name LIKE '%{safe_query}%'
        OR threat_actor LIKE '%{safe_query}%'
        OR malware LIKE '%{safe_query}%'
        OR techniques LIKE '%{safe_query}%'
        OR targets LIKE '%{safe_query}%'
        OR iocs LIKE '%{safe_query}%'
      )
    LIMIT {limit}
    """
    
    campaign_rows, campaign_error = execute_bigquery(campaign_query)
    
    if not campaign_error:
        # Parse JSON fields and format timestamps
        campaigns = []
        for row in campaign_rows:
            campaign = dict(row)
            
            # Format timestamps
            for field in ["first_seen", "last_seen"]:
                if field in campaign and isinstance(campaign[field], datetime):
                    campaign[field] = campaign[field].isoformat()
            
            # Parse JSON fields
            if "iocs" in campaign:
                try:
                    campaign["iocs"] = json.loads(campaign["iocs"])
                except (json.JSONDecodeError, TypeError):
                    campaign["iocs"] = []
            
            campaigns.append(campaign)
        
        results["campaigns"] = campaigns
    
    return jsonify({
        "query": query_str,
        "results": results,
        "feed_count": len(results["feeds"]),
        "analysis_count": len(results["analyses"]),
        "campaign_count": len(results["campaigns"])
    })


@app.route('/api/stats', methods=['GET'])
@require_api_key
@handle_exceptions
def platform_stats():
    """Get overall platform statistics"""
    try:
        days = int(request.args.get('days', '30'))
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    stats = {
        "feeds": {},
        "iocs": {},
        "campaigns": {},
        "analyses": {}
    }
    
    # Get feed stats
    feeds_query = f"""
    SELECT
      table_id,
      COUNT(*) AS record_count
    FROM (
      SELECT
        table_id,
        COUNT(*) AS count
      FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
      WHERE table_id NOT LIKE 'threat%'
      GROUP BY table_id
    )
    GROUP BY table_id
    """
    
    feed_rows, feed_error = execute_bigquery(feeds_query)
    
    if not feed_error:
        stats["feeds"]["sources"] = [
            {"name": row["table_id"], "count": row["record_count"]} 
            for row in feed_rows
        ]
        stats["feeds"]["total_sources"] = len(stats["feeds"]["sources"])
    
    # Get IOC stats
    ioc_query = f"""
    SELECT
      JSON_EXTRACT_SCALAR(ioc, '$.type') AS ioc_type,
      COUNT(*) AS count
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
      UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc
    WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    GROUP BY ioc_type
    ORDER BY count DESC
    """
    
    ioc_rows, ioc_error = execute_bigquery(ioc_query)
    
    if not ioc_error:
        stats["iocs"]["types"] = [
            {"type": row["ioc_type"], "count": row["count"]} 
            for row in ioc_rows
        ]
        stats["iocs"]["total"] = sum(item["count"] for item in stats["iocs"]["types"])
    
    # Get campaign stats
    campaign_query = f"""
    SELECT
      COUNT(*) AS total_campaigns,
      AVG(source_count) AS avg_sources,
      AVG(ioc_count) AS avg_iocs
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    campaign_rows, campaign_error = execute_bigquery(campaign_query)
    
    if not campaign_error and campaign_rows:
        campaign_stats = dict(campaign_rows[0])
        # Convert to appropriate types
        if "avg_sources" in campaign_stats:
            campaign_stats["avg_sources"] = float(campaign_stats["avg_sources"])
        if "avg_iocs" in campaign_stats:
            campaign_stats["avg_iocs"] = float(campaign_stats["avg_iocs"])
        stats["campaigns"] = campaign_stats
    
    # Get analysis stats
    analysis_query = f"""
    SELECT
      COUNT(*) AS total_analyses,
      COUNT(DISTINCT source_type) AS source_types
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    analysis_rows, analysis_error = execute_bigquery(analysis_query)
    
    if not analysis_error and analysis_rows:
        stats["analyses"] = dict(analysis_rows[0])
    
    # Add timestamp
    stats["timestamp"] = datetime.utcnow().isoformat()
    stats["days"] = days
    
    return jsonify(stats)


@app.route('/api/reports/feed_summary', methods=['GET'])
@require_api_key
@handle_exceptions
def feed_summary_report():
    """Generate a summary report of feed data"""
    try:
        days = int(request.args.get('days', '7'))
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Get all feeds
    feeds_query = f"""
    SELECT table_id
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    """
    
    feed_rows, feed_error = execute_bigquery(feeds_query)
    
    if feed_error:
        return jsonify({"error": str(feed_error)}), 500
    
    all_feeds = [row["table_id"] for row in feed_rows]
    feeds_summary = []
    
    # Get stats for each feed
    for feed_name in all_feeds:
        feed_query = f"""
        SELECT
          '{feed_name}' AS feed_name,
          COUNT(*) AS record_count,
          MIN(_ingestion_timestamp) AS earliest_record,
          MAX(_ingestion_timestamp) AS latest_record
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
        WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        try:
            feed_stat_rows, _ = execute_bigquery(feed_query)
            
            if feed_stat_rows:
                feed_stats = dict(feed_stat_rows[0])
                
                # Format datetime fields
                for field in ["earliest_record", "latest_record"]:
                    if field in feed_stats and isinstance(feed_stats[field], datetime):
                        feed_stats[field] = feed_stats[field].isoformat()
                
                feeds_summary.append(feed_stats)
        except Exception as e:
            logger.warning(f"Error getting stats for feed {feed_name}: {str(e)}")
            # Continue with other feeds
    
    # Sort by record count (descending)
    feeds_summary.sort(key=lambda x: x.get("record_count", 0), reverse=True)
    
    return jsonify({
        "report_type": "feed_summary",
        "period_days": days,
        "generated_at": datetime.utcnow().isoformat(),
        "feeds": feeds_summary
    })


@app.route('/api/export/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def export_iocs():
    """Export IOCs in various formats"""
    format_type = request.args.get('format', 'csv').lower()
    ioc_type = request.args.get('type')
    
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '1000')), 10000)  # Higher limit for exports
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Build query conditions
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
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
    
    # Extract and flatten IOCs
    all_iocs = []
    for row in rows:
        try:
            iocs = json.loads(row.get("iocs", "[]"))
            source_id = row.get("source_id", "")
            source_type = row.get("source_type", "")
            timestamp = row.get("analysis_timestamp")
            
            if isinstance(timestamp, datetime):
                timestamp = timestamp.isoformat()
            
            for ioc in iocs:
                if ioc_type and ioc.get("type") != ioc_type:
                    continue
                
                # Add source metadata
                ioc["source_id"] = source_id
                ioc["source_type"] = source_type
                ioc["analysis_timestamp"] = timestamp
                all_iocs.append(ioc)
        except json.JSONDecodeError:
            # Skip invalid JSON
            continue
    
    # Format output based on requested format
    if format_type == 'csv':
        # Get all possible fields
        all_fields = set()
        for ioc in all_iocs:
            all_fields.update(ioc.keys())
        
        # Sort fields for consistency
        fields = sorted(list(all_fields))
        
        # Create CSV content
        csv_lines = [",".join(f'"{field}"' for field in fields)]
        
        for ioc in all_iocs:
            csv_lines.append(",".join(
                f'"{ioc.get(field, "")}"' for field in fields
            ))
        
        csv_content = "\n".join(csv_lines)
        
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=iocs_export.csv"}
        )
    
    elif format_type == 'json':
        return jsonify({
            "iocs": all_iocs,
            "count": len(all_iocs),
            "exported_at": datetime.utcnow().isoformat(),
            "period_days": days
        })
    
    elif format_type == 'stix':
        # Basic STIX 2.1 format
        stix_objects = []
        
        for idx, ioc in enumerate(all_iocs):
            ioc_type = ioc.get("type")
            value = ioc.get("value", "")
            
            if not value:
                continue
            
            # Map IOC type to STIX type
            stix_type = "indicator"
            pattern_type = "stix"
            
            # Generate pattern based on IOC type
            pattern = ""
            if ioc_type == "ip":
                pattern = f"[ipv4-addr:value = '{value}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{value}']"
            elif ioc_type in ["md5", "sha1", "sha256"]:
                pattern = f"[file:hashes.{ioc_type.upper()} = '{value}']"
            elif ioc_type == "email":
                pattern = f"[email-addr:value = '{value}']"
            else:
                # Use custom pattern for unsupported types
                pattern = f"[x-custom-{ioc_type}:value = '{value}']"
                pattern_type = "x-custom"
            
            stix_obj = {
                "id": f"indicator--{idx}-{hash(value) & 0xffffffff:08x}",
                "type": stix_type,
                "spec_version": "2.1",
                "created": ioc.get("analysis_timestamp", datetime.utcnow().isoformat()),
                "modified": datetime.utcnow().isoformat(),
                "name": f"{ioc_type.upper()}: {value}",
                "pattern": pattern,
                "pattern_type": pattern_type,
                "valid_from": ioc.get("analysis_timestamp", datetime.utcnow().isoformat()),
                "indicator_types": ["malicious-activity"],
                "confidence": 70
            }
            
            stix_objects.append(stix_obj)
        
        return jsonify({
            "type": "bundle",
            "id": f"bundle--{hash(str(datetime.utcnow())) & 0xffffffff:08x}",
            "spec_version": "2.1",
            "objects": stix_objects
        })
    
    else:
        return jsonify({"error": f"Unsupported format: {format_type}"}), 400


@app.route('/api/alerts', methods=['GET'])
@require_api_key
@handle_exceptions
def list_alerts():
    """List alerts generated by the system"""
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '50')), MAX_RESULTS)
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Check if alerts table exists
    alerts_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_alerts"
    try:
        bq_client.get_table(alerts_table_id)
        table_exists = True
    except Exception:
        table_exists = False
    
    if table_exists:
        # Query from alerts table
        query = f"""
        SELECT *
        FROM `{alerts_table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        ORDER BY created_at DESC
        LIMIT {limit}
        """
        
        rows, error = execute_bigquery(query)
        
        if error:
            return jsonify({"error": str(error)}), 500
        
        # Format alerts
        alerts = []
        for row in rows:
            alert = dict(row)
            for key, value in alert.items():
                if isinstance(value, datetime):
                    alert[key] = value.isoformat()
            alerts.append(alert)
    else:
        # Generate sample alerts if table doesn't exist
        # This is for demonstration/testing purposes
        alerts = [
            {
                "id": "alert1",
                "title": "New Ransomware Campaign Detected",
                "severity": "critical",
                "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "description": "Multiple indicators of BlackCat ransomware detected in financial sector.",
                "iocs": [
                    {"type": "ip", "value": "192.168.1.1"},
                    {"type": "domain", "value": "evil-ransomware.com"}
                ]
            },
            {
                "id": "alert2",
                "title": "APT Activity Detected",
                "severity": "high",
                "timestamp": (datetime.utcnow() - timedelta(hours=5)).isoformat(),
                "description": "Suspected nation-state actor targeting critical infrastructure.",
                "iocs": [
                    {"type": "ip", "value": "10.0.0.1"},
                    {"type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99"}
                ]
            },
            {
                "id": "alert3",
                "title": "Unusual Authentication Activity",
                "severity": "medium",
                "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat(),
                "description": "Multiple failed login attempts detected from unusual locations.",
                "iocs": []
            }
        ]
    
    return jsonify({
        "alerts": alerts,
        "count": len(alerts)
    })


# Main entry point
if __name__ == "__main__":
    # Initialize app with config from secret manager
    config.init_app_config()
    
    # Start server
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
