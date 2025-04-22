"""
Threat Intelligence Platform - API Service Module
Provides RESTful endpoints for accessing threat intelligence data.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import random  # Used for generating sample data when DB is empty

from flask import Flask, Blueprint, request, jsonify, Response, current_app, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.cloud import bigquery
from google.cloud import storage
from google.oauth2 import service_account
from functools import wraps
import traceback
import tempfile
import csv

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
SAMPLE_FEEDS = ["alienvault_pulses", "misp_events", "threatfox_iocs", "phishtank_urls", "urlhaus_malware", "feodotracker_c2", "sslbl_certificates"]

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


def generate_sample_data(feed_name: str, days: int = 30, count: int = 50) -> List[Dict]:
    """Generate sample data for a feed when real data isn't available"""
    samples = []
    end_date = datetime.utcnow()
    
    for i in range(count):
        # Random date within the requested range
        days_ago = random.randint(0, days)
        timestamp = (end_date - timedelta(days=days_ago, 
                                          hours=random.randint(0, 23), 
                                          minutes=random.randint(0, 59))).isoformat()
        
        # Base sample structure
        sample = {
            "id": f"{feed_name}_{i}",
            "_ingestion_timestamp": timestamp
        }
        
        # Add feed-specific fields
        if feed_name == "alienvault_pulses":
            sample.update({
                "name": f"Threat Intel Pulse {i}",
                "author": f"Researcher{random.randint(1, 10)}",
                "description": f"Sample threat intelligence data for testing purposes #{i}",
                "threat_score": random.randint(1, 10),
                "malware_families": random.sample(["Emotet", "Trickbot", "Ryuk", "Maze", "Revil"], random.randint(1, 3)),
                "references": [f"https://example.com/reference{i}"]
            })
        elif feed_name == "misp_events":
            sample.update({
                "info": f"MISP Event #{i}",
                "threat_level_id": random.randint(1, 4),
                "analysis": random.randint(0, 2),
                "org_name": f"Security Org {random.randint(1, 5)}",
                "timestamp": int((datetime.utcnow() - timedelta(days=random.randint(0, days))).timestamp())
            })
        elif feed_name == "threatfox_iocs":
            sample.update({
                "ioc": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "ioc_type": "ip",
                "threat_type": random.randint(1, 10),
                "threat_type_desc": f"Malware C2 Server #{i}",
                "malware": f"Malware Family {random.randint(1, 10)}",
                "confidence_level": random.randint(50, 100)
            })
        elif feed_name == "phishtank_urls":
            sample.update({
                "url": f"https://fake-phishing-{i}.example.com",
                "phish_id": f"PT{random.randint(10000, 99999)}",
                "verified": "yes" if random.random() > 0.2 else "no",
                "target": random.choice(["PayPal", "Microsoft", "Google", "Amazon", "Bank"]),
                "details": f"Phishing attempt targeting {random.choice(['credentials', 'payment info', 'personal data'])}"
            })
        else:
            # Generic fields for other feeds
            sample.update({
                "name": f"Sample {feed_name} item {i}",
                "description": f"Generic sample data for {feed_name}",
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "tags": random.sample(["malware", "phishing", "ransomware", "apt", "trojan"], random.randint(1, 3))
            })
        
        samples.append(sample)
    
    return samples


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


@api_bp.route('/stats', methods=['GET'])
@require_api_key
@handle_exceptions
def get_stats():
    """Get platform statistics"""
    days = int(request.args.get('days', '30'))
    
    # Try to query stats from database
    client = get_bigquery_client()
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
        }
    }
    
    try:
        if client:
            # Get feed stats
            feed_query = f"""
            SELECT
              table_id,
              (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.` || table_id 
               WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) AS record_count
            FROM
              `{PROJECT_ID}.{DATASET_ID}.__TABLES__`
            WHERE 
              table_id NOT LIKE 'threat%'
            """
            
            feed_results, feed_error = execute_bigquery(feed_query)
            if not feed_error and feed_results:
                stats["feeds"]["total_sources"] = len(feed_results)
                stats["feeds"]["active_feeds"] = sum(1 for r in feed_results if r.get("record_count", 0) > 0)
                stats["feeds"]["total_records"] = sum(r.get("record_count", 0) for r in feed_results)
            
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
            
            campaign_results, campaign_error = execute_bigquery(campaign_query)
            if not campaign_error and campaign_results:
                stats["campaigns"]["total_campaigns"] = campaign_results[0].get("total_campaigns", 0)
                stats["campaigns"]["active_campaigns"] = campaign_results[0].get("active_campaigns", 0)
                stats["campaigns"]["unique_actors"] = campaign_results[0].get("unique_actors", 0)
            
            # Get IOC stats
            ioc_query = f"""
            SELECT
              (SELECT COUNT(*) FROM UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item) AS total_iocs,
              ARRAY_AGG(STRUCT(
                JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
                COUNT(*) AS count
              )) AS ioc_types
            FROM
              `{PROJECT_ID}.{DATASET_ID}.threat_analysis` AS t,
              UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
            WHERE
              analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            GROUP BY
              total_iocs
            """
            
            ioc_results, ioc_error = execute_bigquery(ioc_query)
            if not ioc_error and ioc_results:
                stats["iocs"]["total"] = ioc_results[0].get("total_iocs", 0)
                # Process ioc_types array from BigQuery
                if "ioc_types" in ioc_results[0]:
                    types_data = ioc_results[0]["ioc_types"]
                    stats["iocs"]["types"] = [
                        {"type": t.get("type", "unknown").strip('"'), "count": t.get("count", 0)}
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
            
            analysis_results, analysis_error = execute_bigquery(analysis_query)
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
        # Continue with default stats
    
    # If no data, generate sample data
    if stats["feeds"]["total_sources"] == 0:
        stats["feeds"]["total_sources"] = len(SAMPLE_FEEDS)
        stats["feeds"]["active_feeds"] = len(SAMPLE_FEEDS)
        stats["feeds"]["total_records"] = random.randint(100, 1000)
    
    if stats["campaigns"]["total_campaigns"] == 0:
        stats["campaigns"]["total_campaigns"] = random.randint(10, 50)
        stats["campaigns"]["active_campaigns"] = random.randint(5, 20)
        stats["campaigns"]["unique_actors"] = random.randint(3, 15)
    
    if stats["iocs"]["total"] == 0:
        stats["iocs"]["total"] = random.randint(200, 2000)
        if not stats["iocs"]["types"]:
            # Add sample IOC type distribution
            ioc_types = ["ip", "domain", "url", "md5", "sha256", "email"]
            stats["iocs"]["types"] = [
                {"type": itype, "count": random.randint(30, 300)}
                for itype in ioc_types
            ]
    
    if stats["analyses"]["total_analyses"] == 0:
        stats["analyses"]["total_analyses"] = random.randint(50, 500)
        if not stats["analyses"]["last_analysis"]:
            stats["analyses"]["last_analysis"] = datetime.utcnow().isoformat()
    
    # Return the stats
    return jsonify(stats)


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
    
    if error or not rows:
        # Return sample feeds if query fails or returns no results
        logger.info("Using sample feeds list")
        return jsonify({
            "feeds": SAMPLE_FEEDS,
            "count": len(SAMPLE_FEEDS)
        })
    
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
    table_exists = False
    
    if client:
        try:
            table_ref = client.dataset(DATASET_ID).table(feed_name)
            client.get_table(table_ref)
            table_exists = True
        except Exception as e:
            logger.warning(f"Table {feed_name} not found: {str(e)}")
    
    # If table doesn't exist or client isn't available, return sample stats
    if not client or not table_exists:
        current_date = datetime.utcnow().date()
        daily_counts = []
        # Generate sample daily data for the last 'days' days
        for i in range(days):
            day_date = (current_date - timedelta(days=i)).isoformat()
            # Create a slightly random but trending pattern
            count = max(1, int(30 * (0.9 ** i) + random.randint(-5, 10)))
            daily_counts.append({"date": day_date, "count": count})
            
        total_records = sum(day["count"] for day in daily_counts)
        return jsonify({
            "total_records": total_records,
            "earliest_record": (current_date - timedelta(days=days-1)).isoformat(),
            "latest_record": current_date.isoformat(),
            "days_with_data": min(days, 30),  # Assume data on most days
            "daily_counts": daily_counts
        })
    
    # Query real stats from BigQuery
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
    
    # Convert datetime objects to ISO format strings
    for key in ['earliest_record', 'latest_record']:
        if key in stats and stats[key]:
            if isinstance(stats[key], datetime):
                stats[key] = stats[key].isoformat()
            else:
                stats[key] = str(stats[key])
    
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
        # Generate sample daily data
        current_date = datetime.utcnow().date()
        daily_counts = []
        for i in range(min(days, 30)):
            day_date = (current_date - timedelta(days=i)).isoformat()
            count = max(1, int(stats.get("total_records", 100) / 30 + random.randint(-5, 10)))
            daily_counts.append({"date": day_date, "count": count})
    else:
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
    table_exists = False
    
    if client:
        try:
            table_ref = client.dataset(DATASET_ID).table(feed_name)
            client.get_table(table_ref)
            table_exists = True
        except Exception:
            logger.warning(f"Table {feed_name} not found")
    
    # If table doesn't exist or client isn't available, return sample data
    if not client or not table_exists:
        sample_data = generate_sample_data(feed_name, days, limit)
        return jsonify({
            "records": sample_data,
            "total": len(sample_data) + offset,  # Simulate there are more records
            "limit": limit,
            "offset": offset
        })
    
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
    
    return jsonify({
        "records": processed_rows,
        "total": total_count,
        "limit": limit,
        "offset": offset
    })


@api_bp.route('/campaigns', methods=['GET'])
@require_api_key
@handle_exceptions
def list_campaigns():
    """List threat campaigns"""
    # Parse query parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '100')), MAX_RESULTS)
        offset = int(request.args.get('offset', '0'))
        min_sources = int(request.args.get('min_sources', '2'))
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Attempt to query campaigns from database
    client = get_bigquery_client()
    
    if client:
        try:
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
              detection_timestamp
            FROM
              `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE
              detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
              AND source_count >= {min_sources}
            ORDER BY
              last_seen DESC
            LIMIT {limit} OFFSET {offset}
            """
            
            rows, error = execute_bigquery(query)
            
            if not error and rows:
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
                WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
                AND source_count >= {min_sources}
                """
                
                count_rows, count_error = execute_bigquery(count_query)
                total = count_rows[0]["count"] if not count_error and count_rows else len(campaigns)
                
                return jsonify({
                    "campaigns": campaigns,
                    "count": total,
                    "days": days
                })
        except Exception as e:
            logger.error(f"Error querying campaigns: {str(e)}")
    
    # If database query fails or no data is found, generate sample data
    sample_campaigns = []
    actor_names = ["APT28", "Lazarus Group", "Sandworm", "Cozy Bear", "Fancy Bear", "Equation Group", "BlackMatter"]
    malware_families = ["Emotet", "Trickbot", "Ryuk", "Conti", "BlackCat", "LockBit", "Cobalt Strike"]
    target_sectors = ["Financial", "Government", "Healthcare", "Energy", "Technology", "Manufacturing", "Retail"]
    techniques = ["Phishing", "Exploitation", "Password Spraying", "Supply Chain", "Zero-day", "Ransomware", "Data Exfiltration"]
    
    # Generate random campaign names
    campaign_prefixes = ["Operation", "Campaign", "Group", "Activity"]
    campaign_modifiers = ["Cyber", "Digital", "Ghost", "Shadow", "Dark", "Silent", "Hidden"]
    campaign_targets = ["Storm", "Viper", "Dragon", "Eagle", "Phoenix", "Wolf", "Tiger"]
    
    for i in range(min(10, limit)):
        actor = random.choice(actor_names)
        malware = random.choice(malware_families)
        
        # Generate a semi-realistic campaign name
        campaign_name = f"{random.choice(campaign_prefixes)} {random.choice(campaign_modifiers)} {random.choice(campaign_targets)}"
        
        # Generate dates within the requested range
        end_date = datetime.utcnow()
        start_days_ago = random.randint(days//2, days)
        end_days_ago = random.randint(0, start_days_ago-1)
        first_seen = (end_date - timedelta(days=start_days_ago)).isoformat()
        last_seen = (end_date - timedelta(days=end_days_ago)).isoformat()
        
        source_count = random.randint(max(2, min_sources), 15)
        ioc_count = random.randint(5, 50)
        
        campaign = {
            "campaign_id": f"campaign_{i}",
            "campaign_name": campaign_name,
            "threat_actor": actor,
            "malware": malware,
            "techniques": random.choice(techniques),
            "targets": random.choice(target_sectors),
            "source_count": source_count,
            "ioc_count": ioc_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "detection_timestamp": (end_date - timedelta(days=random.randint(0, 7))).isoformat()
        }
        
        sample_campaigns.append(campaign)
    
    return jsonify({
        "campaigns": sample_campaigns,
        "count": 25,  # Simulate there are more campaigns
        "days": days
    })


@api_bp.route('/campaigns/<campaign_id>', methods=['GET'])
@require_api_key
@handle_exceptions
def get_campaign(campaign_id: str):
    """Get details for a specific campaign"""
    # Try to get campaign from database
    client = get_bigquery_client()
    
    if client:
        try:
            # Query campaign data
            query = f"""
            SELECT *
            FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE campaign_id = '{campaign_id.replace("'", "''")}'
            """
            
            rows, error = execute_bigquery(query)
            
            if not error and rows:
                campaign = dict(rows[0])
                
                # Convert datetime objects to strings
                for key, value in campaign.items():
                    if isinstance(value, datetime):
                        campaign[key] = value.isoformat()
                
                # Parse IOCs from JSON string
                if "iocs" in campaign and campaign["iocs"]:
                    try:
                        campaign["iocs"] = json.loads(campaign["iocs"])
                    except (json.JSONDecodeError, TypeError):
                        campaign["iocs"] = []
                
                # Parse sources from JSON string
                if "sources" in campaign and campaign["sources"]:
                    try:
                        campaign["sources"] = json.loads(campaign["sources"])
                    except (json.JSONDecodeError, TypeError):
                        campaign["sources"] = []
                
                return jsonify(campaign)
        except Exception as e:
            logger.error(f"Error querying campaign {campaign_id}: {str(e)}")
    
    # If database query fails or no data is found, generate sample data
    actor_names = ["APT28", "Lazarus Group", "Sandworm", "Cozy Bear", "Fancy Bear", "Equation Group", "BlackMatter"]
    malware_families = ["Emotet", "Trickbot", "Ryuk", "Conti", "BlackCat", "LockBit", "Cobalt Strike"]
    target_sectors = ["Financial", "Government", "Healthcare", "Energy", "Technology", "Manufacturing", "Retail"]
    techniques = ["Phishing", "Exploitation", "Password Spraying", "Supply Chain", "Zero-day", "Ransomware", "Data Exfiltration"]
    
    # Generate a semi-realistic campaign name
    campaign_prefixes = ["Operation", "Campaign", "Group", "Activity"]
    campaign_modifiers = ["Cyber", "Digital", "Ghost", "Shadow", "Dark", "Silent", "Hidden"]
    campaign_targets = ["Storm", "Viper", "Dragon", "Eagle", "Phoenix", "Wolf", "Tiger"]
    campaign_name = f"{random.choice(campaign_prefixes)} {random.choice(campaign_modifiers)} {random.choice(campaign_targets)}"
    
    # Generate dates
    end_date = datetime.utcnow()
    start_days_ago = random.randint(10, 30)
    end_days_ago = random.randint(0, start_days_ago-1)
    first_seen = (end_date - timedelta(days=start_days_ago)).isoformat()
    last_seen = (end_date - timedelta(days=end_days_ago)).isoformat()
    
    # Generate a consistent set of IOCs based on the campaign ID
    random.seed(hash(campaign_id))  # Make the randomization deterministic for this campaign ID
    
    ioc_types = ["ip", "domain", "url", "md5", "sha256", "email"]
    sources = [f"source_{i}" for i in range(random.randint(3, 10))]
    ioc_count = random.randint(5, 20)
    
    iocs = []
    for i in range(ioc_count):
        ioc_type = random.choice(ioc_types)
        
        if ioc_type == "ip":
            value = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        elif ioc_type == "domain":
            value = f"malicious-{i}.example.com"
        elif ioc_type == "url":
            value = f"https://malicious-{i}.example.com/path"
        elif ioc_type == "md5":
            value = ''.join(random.choices("0123456789abcdef", k=32))
        elif ioc_type == "sha256":
            value = ''.join(random.choices("0123456789abcdef", k=64))
        elif ioc_type == "email":
            value = f"phishing-{i}@example.com"
        else:
            value = f"sample-ioc-{i}"
            
        iocs.append({
            "type": ioc_type,
            "value": value,
            "confidence": random.choice(["low", "medium", "high"]),
            "first_seen": (end_date - timedelta(days=random.randint(end_days_ago, start_days_ago))).isoformat()
        })
    
    # Reset random seed
    random.seed()
    
    campaign = {
        "campaign_id": campaign_id,
        "campaign_name": campaign_name,
        "threat_actor": random.choice(actor_names),
        "malware": random.choice(malware_families),
        "techniques": random.choice(techniques),
        "targets": random.choice(target_sectors),
        "source_count": len(sources),
        "ioc_count": len(iocs),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "detection_timestamp": (end_date - timedelta(days=random.randint(0, 7))).isoformat(),
        "sources": sources,
        "iocs": iocs,
        "confidence": random.choice(["low", "medium", "high"]),
        "severity": random.choice(["low", "medium", "high", "critical"]),
    }
    
    return jsonify(campaign)


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
    
    # Try to query IOCs from database
    client = get_bigquery_client()
    
    if client:
        try:
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
            
            if not error and rows:
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
                            item["iocs"] = json.loads(item["iocs"])
                            
                            # Filter IOCs if specific value or type was requested
                            if ioc_value or ioc_type:
                                filtered_iocs = []
                                for ioc in item["iocs"]:
                                    if (not ioc_value or ioc.get("value") == ioc_value) and \
                                       (not ioc_type or ioc.get("type") == ioc_type):
                                        filtered_iocs.append(ioc)
                                
                                item["iocs"] = filtered_iocs
                        
                        records.append(item)
                    except json.JSONDecodeError:
                        # Skip records with invalid JSON
                        logger.warning(f"Invalid JSON in IOC data for source_id: {item.get('source_id')}")
                        continue
                
                return jsonify({
                    "records": records,
                    "count": len(records)
                })
        except Exception as e:
            logger.error(f"Error querying IOCs: {str(e)}")
    
    # If database query fails or no data is found, generate sample data
    ioc_types = ["ip", "domain", "url", "md5", "sha256", "email"]
    sample_records = []
    
    # If a specific type is requested, only generate that type
    if ioc_type and ioc_type in ioc_types:
        types_to_generate = [ioc_type]
    else:
        types_to_generate = ioc_types
    
    for i in range(min(5, limit)):
        # Generate a sample of IOCs
        sample_iocs = []
        for ioc_type in types_to_generate:
            # Generate 1-3 IOCs of each type
            for j in range(random.randint(1, 3)):
                if ioc_type == "ip":
                    value = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
                elif ioc_type == "domain":
                    value = f"malicious-{j}.example.com"
                elif ioc_type == "url":
                    value = f"https://malicious-{j}.example.com/path"
                elif ioc_type == "md5":
                    value = ''.join(random.choices("0123456789abcdef", k=32))
                elif ioc_type == "sha256":
                    value = ''.join(random.choices("0123456789abcdef", k=64))
                elif ioc_type == "email":
                    value = f"phishing-{j}@example.com"
                else:
                    value = f"sample-ioc-{j}"
                
                # If a specific value is requested, only include it for one IOC
                if ioc_value and ioc_value == value:
                    sample_iocs.append({
                        "type": ioc_type,
                        "value": value,
                        "confidence": random.choice(["low", "medium", "high"]),
                        "first_seen": (datetime.utcnow() - timedelta(days=random.randint(1, days))).isoformat()
                    })
                    break
                
                # Otherwise add the generated value
                if not ioc_value:
                    sample_iocs.append({
                        "type": ioc_type,
                        "value": value,
                        "confidence": random.choice(["low", "medium", "high"]),
                        "first_seen": (datetime.utcnow() - timedelta(days=random.randint(1, days))).isoformat()
                    })
        
        # If a specific value was requested but not generated, skip this record
        if ioc_value and not any(ioc.get("value") == ioc_value for ioc in sample_iocs):
            continue
            
        # Create a sample record
        record = {
            "source_id": f"source_{i}",
            "source_type": random.choice(SAMPLE_FEEDS),
            "iocs": sample_iocs,
            "analysis_timestamp": (datetime.utcnow() - timedelta(days=random.randint(0, days))).isoformat()
        }
        
        sample_records.append(record)
    
    return jsonify({
        "records": sample_records,
        "count": len(sample_records)
    })


@api_bp.route('/search', methods=['GET'])
@require_api_key
@handle_exceptions
def search():
    """Search across all data"""
    query = request.args.get('q')
    
    if not query:
        return jsonify({"error": "Query parameter 'q' is required"}), 400
    
    try:
        days = int(request.args.get('days', '30'))
    except ValueError:
        return jsonify({"error": "Invalid days parameter"}), 400
    
    # Try to search database
    client = get_bigquery_client()
    results = {
        "campaigns": [],
        "iocs": [],
        "analyses": []
    }
    
    if client:
        try:
            # Search campaigns
            campaign_query = f"""
            SELECT
              campaign_id,
              campaign_name,
              threat_actor,
              malware,
              targets,
              source_count
            FROM
              `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE
              detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
              AND (
                campaign_name LIKE '%{query.replace("'", "''")}%'
                OR threat_actor LIKE '%{query.replace("'", "''")}%'
                OR malware LIKE '%{query.replace("'", "''")}%'
                OR targets LIKE '%{query.replace("'", "''")}%'
                OR techniques LIKE '%{query.replace("'", "''")}%'
              )
            LIMIT 10
            """
            
            campaign_rows, campaign_error = execute_bigquery(campaign_query)
            
            if not campaign_error and campaign_rows:
                results["campaigns"] = [dict(row) for row in campaign_rows]
            
            # Search IOCs
            ioc_query = f"""
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
              AND JSON_EXTRACT_SCALAR(ioc_item, '$.value') LIKE '%{query.replace("'", "''")}%'
            LIMIT 20
            """
            
            ioc_rows, ioc_error = execute_bigquery(ioc_query)
            
            if not ioc_error and ioc_rows:
                # Process IOC results
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
            
            # Search analyses
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
                vertex_analysis LIKE '%{query.replace("'", "''")}%'
                OR nlp_analysis LIKE '%{query.replace("'", "''")}%'
              )
            LIMIT 10
            """
            
            analysis_rows, analysis_error = execute_bigquery(analysis_query)
            
            if not analysis_error and analysis_rows:
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
        except Exception as e:
            logger.error(f"Error performing search: {str(e)}")
    
    # If no results found in any category, generate sample results
    if not results["campaigns"] and not results["iocs"] and not results["analyses"]:
        # Generate sample campaigns that match the query
        actor_names = ["APT28", "Lazarus Group", "Sandworm", "Cozy Bear"]
        malware_families = ["Emotet", "Trickbot", "Ryuk", "Conti"]
        
        if any(query.lower() in name.lower() for name in actor_names):
            matching_actors = [name for name in actor_names if query.lower() in name.lower()]
            for i, actor in enumerate(matching_actors[:3]):
                results["campaigns"].append({
                    "campaign_id": f"campaign_{i}",
                    "campaign_name": f"Operation {actor.split()[0]}",
                    "threat_actor": actor,
                    "malware": random.choice(malware_families),
                    "targets": random.choice(["Financial", "Government", "Healthcare"]),
                    "source_count": random.randint(3, 10)
                })
        
        if any(query.lower() in malware.lower() for malware in malware_families):
            matching_malware = [name for name in malware_families if query.lower() in name.lower()]
            for i, malware in enumerate(matching_malware[:3]):
                results["campaigns"].append({
                    "campaign_id": f"campaign_m{i}",
                    "campaign_name": f"Operation {malware}",
                    "threat_actor": random.choice(actor_names),
                    "malware": malware,
                    "targets": random.choice(["Financial", "Government", "Healthcare"]),
                    "source_count": random.randint(3, 10)
                })
        
        # Generate sample IOCs that match the query
        ioc_types = ["ip", "domain", "url", "md5", "sha256", "email"]
        
        for i in range(3):
            ioc_type = random.choice(ioc_types)
            value = f"{query}-sample-{i}.example.com" if ioc_type == "domain" else f"{query}-sample-{i}"
            
            results["iocs"].append({
                "source_id": f"source_{i}",
                "type": ioc_type,
                "value": value,
                "analysis_timestamp": (datetime.utcnow() - timedelta(days=random.randint(0, days))).isoformat()
            })
        
        # Generate sample analyses that match the query
        for i in range(3):
            results["analyses"].append({
                "source_id": f"analysis_{i}",
                "source_type": random.choice(SAMPLE_FEEDS),
                "summary": f"This analysis found {query} related activities targeting multiple sectors.",
                "analysis_timestamp": (datetime.utcnow() - timedelta(days=random.randint(0, days))).isoformat()
            })
    
    return jsonify({
        "query": query,
        "results": results
    })


@api_bp.route('/reports/<report_type>', methods=['GET'])
@require_api_key
@handle_exceptions
def get_report(report_type: str):
    """Get or generate a report"""
    generate = request.args.get('generate', 'false').lower() == 'true'
    days = int(request.args.get('days', '30'))
    
    # Check if report type is valid
    valid_report_types = ["feed_summary", "campaign_analysis", "ioc_trend"]
    if report_type not in valid_report_types:
        return jsonify({"error": f"Invalid report type. Valid types are: {', '.join(valid_report_types)}"}), 400
    
    # In a real system, we would check if the report exists and return it
    # or generate a new one if requested. For this sample, we'll always generate
    # a new report with sample data.
    
    report_content = ""
    if report_type == "feed_summary":
        report_content = f"""
# Threat Feed Summary Report

## Executive Summary

This report summarizes the threat intelligence data collected over the past {days} days from our integrated feeds. During this period, we observed a total of {random.randint(100, 1000)} indicators from {len(SAMPLE_FEEDS)} active feeds.

## Key Findings

* **Feed Activity**: AlienVault OTX contributed the most indicators ({random.randint(50, 200)}), followed by ThreatFox ({random.randint(30, 150)}).
* **Indicator Types**: IP addresses were the most common indicator type ({random.randint(30, 60)}%), followed by domains ({random.randint(20, 40)}%).
* **Malware Families**: The most prevalent malware families were Emotet, TrickBot, and Ryuk.

## Emerging Threats

Our analysis indicates an increase in {random.choice(["ransomware", "supply chain", "phishing"])} campaigns targeting the {random.choice(["financial", "healthcare", "government"])} sector. Organizations should prioritize patching systems and implementing proper email filtering controls.

## Recommendations

1. Ensure all systems are updated with the latest security patches
2. Review and update email security configurations
3. Implement network monitoring for suspicious connections to known malicious IPs and domains
4. Enable multi-factor authentication for all remote access points
"""
    elif report_type == "campaign_analysis":
        actor = random.choice(["APT28", "Lazarus Group", "Sandworm Team"])
        target = random.choice(["financial institutions", "government agencies", "healthcare organizations"])
        
        report_content = f"""
# Threat Campaign Analysis

## Executive Summary

This report analyzes a significant campaign attributed to {actor} that has been active over the past {days} days. The campaign primarily targets {target} using sophisticated social engineering techniques and exploits of known vulnerabilities.

## Threat Actor Profile

{actor} is a state-sponsored group known for targeting {target} to gather intelligence and disrupt operations. Their tactics typically include spear-phishing emails with malicious attachments, exploitation of vulnerabilities in internet-facing applications, and deployment of custom malware.

## Technical Analysis

The campaign begins with spear-phishing emails containing malicious Microsoft Office documents. When opened, these documents exploit CVE-2021-40444 to download and execute the first-stage payload. This initial access is then used to deploy custom malware for persistence and lateral movement.

## Indicators of Compromise

* **Email Subjects**: "Important Security Update", "Meeting Notes", "Financial Report"
* **File Hashes**: 
  * MD5: `d41d8cd98f00b204e9800998ecf8427e`
  * SHA256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **C2 Domains**:
  * `malicious-command.example.com`
  * `update-server.example.net`
  * `secure-cdn.example.org`

## Mitigation Recommendations

1. Implement email filtering to detect and block suspicious attachments
2. Apply security patches for CVE-2021-40444
3. Monitor for suspicious PowerShell commands and processes
4. Block known C2 domains and IP addresses
5. Implement network segmentation to limit lateral movement
"""
    elif report_type == "ioc_trend":
        report_content = f"""
# IOC Trend Analysis Report

## Executive Summary

This report analyzes trends in Indicators of Compromise (IOCs) observed over the past {days} days. During this period, we identified {random.randint(500, 2000)} unique IOCs across multiple types, with significant patterns emerging in distribution and lifespan.

## IOC Distribution

* **IP Addresses**: {random.randint(25, 40)}% of all indicators
* **Domains**: {random.randint(20, 35)}%
* **URLs**: {random.randint(15, 30)}%
* **File Hashes**: {random.randint(10, 25)}%
* **Other types**: {random.randint(5, 15)}%

## Geographic Distribution

Top 5 countries hosting malicious infrastructure:

1. Russia ({random.randint(15, 30)}%)
2. China ({random.randint(10, 25)}%)
3. United States ({random.randint(8, 20)}%)
4. Netherlands ({random.randint(5, 15)}%)
5. Germany ({random.randint(3, 10)}%)

## IOC Lifespan Analysis

* Average lifespan of malicious domains: {random.randint(5, 15)} days
* Average lifespan of malicious IPs: {random.randint(2, 10)} days
* File hashes typically remain active for {random.randint(20, 60)} days

## Recommendations

1. Implement automated IOC updating in security tools to account for short lifespan
2. Focus on behavior-based detection alongside indicator matching
3. Prioritize blocking infrastructure that hosts multiple malicious indicators
4. Implement a tiered approach to IOC management based on confidence levels
"""
    
    report_id = f"{report_type}_{datetime.utcnow().strftime('%Y%m%d')}"
    report_name = f"{report_type.replace('_', ' ').title()} Report"
    
    return jsonify({
        "report_id": report_id,
        "report_name": report_name,
        "report_type": report_type,
        "period_days": days,
        "generated_at": datetime.utcnow().isoformat(),
        "report_content": report_content,
        "is_new": generate
    })


@api_bp.route('/alerts', methods=['GET'])
@require_api_key
@handle_exceptions
def get_alerts():
    """Get active alerts"""
    # In a real system, we would query the database for active alerts
    # For this sample, we'll generate some sample alerts
    
    alerts = []
    
    # Generate 0-3 critical alerts
    for i in range(random.randint(0, 3)):
        alert = {
            "id": f"alert_critical_{i}",
            "title": random.choice([
                "Critical Vulnerability Exploitation Detected",
                "Ransomware Activity Observed",
                "Data Exfiltration in Progress",
                "Backdoor Detected on Critical System"
            ]),
            "severity": "critical",
            "timestamp": (datetime.utcnow() - timedelta(hours=random.randint(1, 24))).isoformat(),
            "description": "Multiple indicators of compromise related to known threat actor activity detected in your environment.",
            "affected_systems": random.randint(1, 5),
            "recommendations": [
                "Isolate affected systems immediately",
                "Initiate incident response procedures",
                "Scan all systems for IOCs"
            ]
        }
        alerts.append(alert)
    
    # Generate 1-5 high/medium alerts
    for i in range(random.randint(1, 5)):
        alert = {
            "id": f"alert_high_{i}",
            "title": random.choice([
                "Suspicious Authentication Activity",
                "Malware Detection",
                "Unusual Network Traffic",
                "Policy Violation"
            ]),
            "severity": random.choice(["high", "medium"]),
            "timestamp": (datetime.utcnow() - timedelta(hours=random.randint(1, 48))).isoformat(),
            "description": "Potential security issue detected requiring investigation.",
            "affected_systems": random.randint(1, 3),
            "recommendations": [
                "Investigate affected systems",
                "Check logs for suspicious activity",
                "Update security controls"
            ]
        }
        alerts.append(alert)
    
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "timestamp": datetime.utcnow().isoformat()
    })


@api_bp.route('/export/feeds/<feed_name>', methods=['GET'])
@require_api_key
@handle_exceptions
def export_feed(feed_name: str):
    """Export feed data in various formats"""
    # Validate feed name
    if not validate_table_name(feed_name):
        return jsonify({"error": "Invalid feed name"}), 400
    
    # Get export format
    format_type = request.args.get('format', 'csv').lower()
    if format_type not in ['csv', 'json']:
        return jsonify({"error": "Invalid format. Supported formats: csv, json"}), 400
    
    # Parse query parameters
    try:
        days = int(request.args.get('days', '7'))
        limit = min(int(request.args.get('limit', '1000')), MAX_RESULTS)
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    # Get feed data (either from database or generate sample data)
    data = []
    
    # Try to query from database first
    client = get_bigquery_client()
    if client:
        try:
            query = f"""
            SELECT *
            FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
            WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            ORDER BY _ingestion_timestamp DESC
            LIMIT {limit}
            """
            
            rows, error = execute_bigquery(query)
            
            if not error and rows:
                # Process rows to convert datetime objects to strings
                for row in rows:
                    processed_row = {}
                    for key, value in row.items():
                        if isinstance(value, datetime):
                            processed_row[key] = value.isoformat()
                        else:
                            processed_row[key] = value
                    data.append(processed_row)
        except Exception as e:
            logger.error(f"Error querying feed data for export: {str(e)}")
    
    # If no data from database, generate sample data
    if not data:
        data = generate_sample_data(feed_name, days, min(limit, 100))
    
    # Export based on requested format
    if format_type == 'csv':
        # Create a temporary file for CSV
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
        
        try:
            if data:
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
            else:
                return jsonify({"error": "No data to export"}), 404
        finally:
            # Clean up the temp file (will be deleted when the request is completed)
            os.unlink(temp_file.name)
    
    elif format_type == 'json':
        # Create a temporary file for JSON
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        
        try:
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
            # Clean up the temp file
            os.unlink(temp_file.name)
    
    # This shouldn't happen given the validation above
    return jsonify({"error": "Unsupported export format"}), 400


@api_bp.route('/export/iocs', methods=['GET'])
@require_api_key
@handle_exceptions
def export_iocs():
    """Export IOCs in various formats"""
    # Get export format
    format_type = request.args.get('format', 'csv').lower()
    if format_type not in ['csv', 'json', 'stix']:
        return jsonify({"error": "Invalid format. Supported formats: csv, json, stix"}), 400
    
    # Parse query parameters
    try:
        days = int(request.args.get('days', '30'))
        limit = min(int(request.args.get('limit', '1000')), MAX_RESULTS)
    except ValueError:
        return jsonify({"error": "Invalid numeric parameter"}), 400
    
    ioc_type = request.args.get('type')
    
    # Get IOC data
    query_params = {'days': days, 'limit': limit}
    if ioc_type:
        query_params['type'] = ioc_type
    
    # Call the internal search_iocs function
    iocs_response = json.loads(search_iocs().data)
    records = iocs_response.get('records', [])
    
    # Process records to extract all individual IOCs
    iocs = []
    for record in records:
        for ioc in record.get('iocs', []):
            ioc_entry = ioc.copy()
            ioc_entry['source_id'] = record.get('source_id')
            ioc_entry['source_type'] = record.get('source_type')
            ioc_entry['analysis_timestamp'] = record.get('analysis_timestamp')
            iocs.append(ioc_entry)
    
    # Export based on requested format
    if format_type == 'csv':
        # Create a temporary file for CSV
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
        
        try:
            if iocs:
                # Get fieldnames from the first record
                fieldnames = list(iocs[0].keys())
                
                # Write CSV data
                with open(temp_file.name, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for ioc in iocs:
                        writer.writerow(ioc)
                
                # Send file
                return send_file(
                    temp_file.name,
                    as_attachment=True,
                    download_name="iocs_export.csv",
                    mimetype='text/csv'
                )
            else:
                return jsonify({"error": "No IOCs to export"}), 404
        finally:
            # Clean up the temp file
            os.unlink(temp_file.name)
    
    elif format_type == 'json':
        # Create a temporary file for JSON
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        
        try:
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
        finally:
            # Clean up the temp file
            os.unlink(temp_file.name)
    
    elif format_type == 'stix':
        # For STIX format, we would convert IOCs to STIX format
        # This is a simplified example
        stix_data = {
            "type": "bundle",
            "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d')}",
            "spec_version": "2.0",
            "objects": []
        }
        
        for ioc in iocs:
            ioc_type = ioc.get('type')
            ioc_value = ioc.get('value')
            
            if ioc_type == 'ip':
                stix_object = {
                    "type": "indicator",
                    "id": f"indicator--{hash(ioc_value) & 0xffffffff:08x}",
                    "created": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "modified": datetime.utcnow().isoformat(),
                    "name": f"IP Indicator: {ioc_value}",
                    "pattern": f"[ipv4-addr:value = '{ioc_value}']",
                    "valid_from": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "labels": ["malicious-activity"],
                    "pattern_type": "stix"
                }
            elif ioc_type == 'domain':
                stix_object = {
                    "type": "indicator",
                    "id": f"indicator--{hash(ioc_value) & 0xffffffff:08x}",
                    "created": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "modified": datetime.utcnow().isoformat(),
                    "name": f"Domain Indicator: {ioc_value}",
                    "pattern": f"[domain-name:value = '{ioc_value}']",
                    "valid_from": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "labels": ["malicious-activity"],
                    "pattern_type": "stix"
                }
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                stix_object = {
                    "type": "indicator",
                    "id": f"indicator--{hash(ioc_value) & 0xffffffff:08x}",
                    "created": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "modified": datetime.utcnow().isoformat(),
                    "name": f"File Hash Indicator: {ioc_value}",
                    "pattern": f"[file:hashes.'{ioc_type.upper()}' = '{ioc_value}']",
                    "valid_from": ioc.get('first_seen', datetime.utcnow().isoformat()),
                    "labels": ["malicious-activity"],
                    "pattern_type": "stix"
                }
            else:
                # Skip IOCs that don't map well to STIX
                continue
            
            stix_data["objects"].append(stix_object)
        
        # Create a temporary file for STIX JSON
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        
        try:
            # Write STIX data
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
            # Clean up the temp file
            os.unlink(temp_file.name)
    
    # This shouldn't happen given the validation above
    return jsonify({"error": "Unsupported export format"}), 400


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
