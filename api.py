"""
Threat Intelligence Platform - API Service Module
Provides RESTful endpoints for accessing threat intelligence data.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.cloud import bigquery
from google.cloud import storage
from google.oauth2 import service_account
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
DATASET_ID = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")

# API Configuration
API_KEY = os.environ.get("API_KEY", "")  # For simple API key auth
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
bq_client = bigquery.Client()


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


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    })


@app.route('/api/feeds', methods=['GET'])
@require_api_key
def list_feeds():
    """List available threat feeds"""
    query = f"""
    SELECT table_id
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    """
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        feeds = [row.table_id for row in results]
        
        return jsonify({
            "feeds": feeds,
            "count": len(feeds)
        })
    except Exception as e:
        logger.error(f"Error listing feeds: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/feeds/<feed_name>/stats', methods=['GET'])
@require_api_key
def feed_stats(feed_name: str):
    """Get statistics for a specific feed"""
    # Validate feed name (prevent SQL injection)
    if not feed_name.isalnum() and '_' not in feed_name:
        return jsonify({"error": "Invalid feed name"}), 400
    
    time_range = request.args.get('days', '30')
    try:
        days = int(time_range)
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    query = f"""
    SELECT
      COUNT(*) AS total_records,
      MIN(_ingestion_timestamp) AS earliest_record,
      MAX(_ingestion_timestamp) AS latest_record,
      COUNT(DISTINCT DATE(_ingestion_timestamp)) AS days_with_data
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
    WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        stats = dict(next(results).items())
        
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
        
        daily_job = bq_client.query(daily_query)
        daily_results = daily_job.result()
        
        daily_counts = [{"date": row.date.isoformat(), "count": row.record_count} for row in daily_results]
        
        stats["daily_counts"] = daily_counts
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting feed stats: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/feeds/<feed_name>/data', methods=['GET'])
@require_api_key
@limiter.limit("20 per minute")  # Higher limit for data access
def feed_data(feed_name: str):
    """Get data from a specific feed with filtering"""
    # Validate feed name (prevent SQL injection)
    if not feed_name.isalnum() and '_' not in feed_name:
        return jsonify({"error": "Invalid feed name"}), 400
    
    # Parse query parameters
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    offset = int(request.args.get('offset', '0'))
    days = int(request.args.get('days', '7'))
    
    # Build query with dynamic filters
    conditions = [f"_ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    # Add search term if provided
    search = request.args.get('search')
    if search:
        # Simple search implementation - can be expanded based on feed structure
        conditions.append(f"TO_JSON_STRING(t) LIKE '%{search}%'")
    
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
    WHERE {" AND ".join(conditions)}
    ORDER BY _ingestion_timestamp DESC
    LIMIT {limit} OFFSET {offset}
    """
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        # Count total matching records
        count_query = f"""
        SELECT COUNT(*) as count
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}` AS t
        WHERE {" AND ".join(conditions)}
        """
        
        count_job = bq_client.query(count_query)
        count_result = next(count_job.result())
        
        # Convert to list of dicts
        records = [dict(row.items()) for row in results]
        
        return jsonify({
            "records": records,
            "total": count_result.count,
            "limit": limit,
            "offset": offset
        })
    except Exception as e:
        logger.error(f"Error getting feed data: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/iocs', methods=['GET'])
@require_api_key
def search_iocs():
    """Search for IOCs across all analyzed data"""
    # Parse query parameters
    ioc_value = request.args.get('value')
    ioc_type = request.args.get('type')
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    
    if not ioc_value and not ioc_type:
        return jsonify({"error": "At least one of 'value' or 'type' parameter is required"}), 400
    
    # Build query conditions
    conditions = [f"analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
    
    if ioc_value:
        conditions.append(f"iocs LIKE '%\"value\":\"{ioc_value}\"%'")
    
    if ioc_type:
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
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        records = []
        for row in results:
            row_dict = dict(row.items())
            
            # Parse JSON fields
            try:
                row_dict["iocs"] = json.loads(row_dict["iocs"])
                
                # Filter IOCs if specific value or type was requested
                if ioc_value or ioc_type:
                    filtered_iocs = []
                    for ioc in row_dict["iocs"]:
                        if (not ioc_value or ioc.get("value") == ioc_value) and \
                           (not ioc_type or ioc.get("type") == ioc_type):
                            filtered_iocs.append(ioc)
                    
                    row_dict["iocs"] = filtered_iocs
                
                records.append(row_dict)
            except json.JSONDecodeError:
                # Skip records with invalid JSON
                continue
        
        return jsonify({
            "records": records,
            "count": len(records)
        })
    except Exception as e:
        logger.error(f"Error searching IOCs: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/campaigns', methods=['GET'])
@require_api_key
def list_campaigns():
    """List detected threat campaigns"""
    # Parse query parameters
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
    min_sources = int(request.args.get('min_sources', '2'))
    
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
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        campaigns = [dict(row.items()) for row in results]
        
        return jsonify({
            "campaigns": campaigns,
            "count": len(campaigns)
        })
    except Exception as e:
        logger.error(f"Error listing campaigns: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
@require_api_key
def campaign_details(campaign_id: str):
    """Get detailed information about a specific campaign"""
    query = f"""
    SELECT *
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE campaign_id = '{campaign_id}'
    LIMIT 1
    """
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        row = next(results, None)
        if not row:
            return jsonify({"error": f"Campaign {campaign_id} not found"}), 404
        
        campaign = dict(row.items())
        
        # Parse JSON fields
        try:
            campaign["iocs"] = json.loads(campaign["iocs"])
            campaign["sources"] = json.loads(campaign["sources"])
        except json.JSONDecodeError:
            campaign["iocs"] = []
            campaign["sources"] = []
        
        return jsonify(campaign)
    except Exception as e:
        logger.error(f"Error getting campaign details: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/search', methods=['GET'])
@require_api_key
@limiter.limit("10 per minute")  # Lower limit for complex search
def search():
    """Advanced search across all threat data"""
    # Parse query parameters
    query_str = request.args.get('q', '')
    days = int(request.args.get('days', '30'))
    limit = min(int(request.args.get('limit', '50')), MAX_RESULTS)
    
    if not query_str:
        return jsonify({"error": "Query parameter 'q' is required"}), 400
    
    # Search across multiple sources
    results = {
        "feeds": [],
        "analyses": [],
        "campaigns": []
    }
    
    # Search in feeds
    feeds_query = f"""
    SELECT DISTINCT table_id
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
    WHERE table_id NOT LIKE 'threat%'
    """
    
    try:
        feeds_job = bq_client.query(feeds_query)
        feeds = [row.table_id for row in feeds_job.result()]
        
        for feed in feeds:
            feed_query = f"""
            SELECT *
            FROM `{PROJECT_ID}.{DATASET_ID}.{feed}`
            WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
              AND TO_JSON_STRING(t) LIKE '%{query_str}%'
            LIMIT {limit // len(feeds)}
            """
            
            try:
                feed_job = bq_client.query(feed_query)
                feed_results = [dict(row.items()) for row in feed_job.result()]
                
                if feed_results:
                    results["feeds"].append({
                        "feed_name": feed,
                        "records": feed_results,
                        "count": len(feed_results)
                    })
            except Exception:
                # Skip feeds with errors
                continue
    except Exception as e:
        logger.error(f"Error searching feeds: {str(e)}")
    
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
        nlp_analysis LIKE '%{query_str}%'
        OR vertex_analysis LIKE '%{query_str}%'
      )
    LIMIT {limit}
    """
    
    try:
        analysis_job = bq_client.query(analysis_query)
        analyses = [dict(row.items()) for row in analysis_job.result()]
        
        # Parse JSON fields
        for analysis in analyses:
            try:
                if "nlp_analysis" in analysis:
                    analysis["nlp_analysis"] = json.loads(analysis["nlp_analysis"])
                if "vertex_analysis" in analysis:
                    analysis["vertex_analysis"] = json.loads(analysis["vertex_analysis"])
            except json.JSONDecodeError:
                pass
        
        results["analyses"] = analyses
    except Exception as e:
        logger.error(f"Error searching analyses: {str(e)}")
    
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
        campaign_name LIKE '%{query_str}%'
        OR threat_actor LIKE '%{query_str}%'
        OR malware LIKE '%{query_str}%'
        OR techniques LIKE '%{query_str}%'
        OR targets LIKE '%{query_str}%'
        OR iocs LIKE '%{query_str}%'
      )
    LIMIT {limit}
    """
    
    try:
        campaign_job = bq_client.query(campaign_query)
        campaigns = [dict(row.items()) for row in campaign_job.result()]
        
        # Parse JSON fields
        for campaign in campaigns:
            try:
                if "iocs" in campaign:
                    campaign["iocs"] = json.loads(campaign["iocs"])
            except json.JSONDecodeError:
                campaign["iocs"] = []
        
        results["campaigns"] = campaigns
    except Exception as e:
        logger.error(f"Error searching campaigns: {str(e)}")
    
    return jsonify({
        "query": query_str,
        "results": results,
        "feed_count": len(results["feeds"]),
        "analysis_count": len(results["analyses"]),
        "campaign_count": len(results["campaigns"])
    })


@app.route('/api/stats', methods=['GET'])
@require_api_key
def platform_stats():
    """Get overall platform statistics"""
    days = int(request.args.get('days', '30'))
    
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
        SUBSTR(table_id, 0, STRPOS(table_id, '_') - 1) AS table_id,
        COUNT(*) AS count
      FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
      WHERE table_id NOT LIKE 'threat%'
      GROUP BY table_id
    )
    GROUP BY table_id
    """
    
    try:
        feeds_job = bq_client.query(feeds_query)
        stats["feeds"]["sources"] = [{"name": row.table_id, "count": row.record_count} for row in feeds_job.result()]
        stats["feeds"]["total_sources"] = len(stats["feeds"]["sources"])
    except Exception as e:
        logger.error(f"Error getting feed stats: {str(e)}")
    
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
    
    try:
        ioc_job = bq_client.query(ioc_query)
        stats["iocs"]["types"] = [{"type": row.ioc_type, "count": row.count} for row in ioc_job.result()]
        stats["iocs"]["total"] = sum(item["count"] for item in stats["iocs"]["types"])
    except Exception as e:
        logger.error(f"Error getting IOC stats: {str(e)}")
    
    # Get campaign stats
    campaign_query = f"""
    SELECT
      COUNT(*) AS total_campaigns,
      AVG(source_count) AS avg_sources,
      AVG(ioc_count) AS avg_iocs
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
    WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    try:
        campaign_job = bq_client.query(campaign_query)
        campaign_stats = dict(next(campaign_job.result()).items())
        stats["campaigns"] = campaign_stats
    except Exception as e:
        logger.error(f"Error getting campaign stats: {str(e)}")
    
    # Get analysis stats
    analysis_query = f"""
    SELECT
      COUNT(*) AS total_analyses,
      COUNT(DISTINCT source_type) AS source_types
    FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
    WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    """
    
    try:
        analysis_job = bq_client.query(analysis_query)
        analysis_stats = dict(next(analysis_job.result()).items())
        stats["analyses"] = analysis_stats
    except Exception as e:
        logger.error(f"Error getting analysis stats: {str(e)}")
    
    # Add timestamp
    stats["timestamp"] = datetime.utcnow().isoformat()
    stats["days"] = days
    
    return jsonify(stats)


@app.route('/api/reports/feed_summary', methods=['GET'])
@require_api_key
def feed_summary_report():
    """Generate a summary report of feed data"""
    days = int(request.args.get('days', '7'))
    
    query = f"""
    SELECT
      t.__table_id AS feed_name,
      COUNT(*) AS record_count,
      MIN(_ingestion_timestamp) AS earliest_record,
      MAX(_ingestion_timestamp) AS latest_record
    FROM `{PROJECT_ID}.{DATASET_ID}.__TABLES__` AS tables
    JOIN `{PROJECT_ID}.{DATASET_ID}.tables.__table_id` AS t
    WHERE 
      tables.table_id NOT LIKE 'threat%'
      AND _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    GROUP BY feed_name
    ORDER BY record_count DESC
    """
    
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        
        feeds = [dict(row.items()) for row in results]
        
        return jsonify({
            "report_type": "feed_summary",
            "period_days": days,
            "generated_at": datetime.utcnow().isoformat(),
            "feeds": feeds
        })
    except Exception as e:
        logger.error(f"Error generating feed summary report: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
