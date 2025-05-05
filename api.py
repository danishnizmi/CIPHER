import os
import json
import logging
import traceback
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from flask import Blueprint, jsonify, request, current_app, abort, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound
import google.auth

# Import configuration
from config import Config, initialize_bigquery, initialize_storage, initialize_pubsub, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Initialize API blueprint
api_blueprint = Blueprint('api', __name__)

# Initialize GCP clients
bq_client = initialize_bigquery()
storage_client = initialize_storage()
publisher, subscriber = initialize_pubsub()

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# -------------------- Authentication & Authorization --------------------

def require_api_key(f):
    """Decorator to require API key for routes with improved session handling for Cloud Run."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from request
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        # Check if user is logged in (for internal requests from frontend)
        # This works better for Cloud Run than IP-based checking
        from flask import session
        if session.get('logged_in'):
            return f(*args, **kwargs)
        
        # Check if API key is valid
        if not api_key or api_key != Config.API_KEY:
            logger.warning(f"Invalid API key attempt from IP: {get_remote_address()}")
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

# -------------------- Helper Functions --------------------

def format_bq_row(row: Dict) -> Dict:
    """Format BigQuery row for JSON response."""
    formatted = {}
    for key, value in dict(row).items():
        if isinstance(value, datetime):
            formatted[key] = value.isoformat()
        elif hasattr(value, 'isoformat'):  # For other datetime-like objects
            formatted[key] = value.isoformat()
        else:
            formatted[key] = value
    return formatted

def execute_bq_query(query: str, params: Optional[List] = None) -> List[Dict]:
    """Execute BigQuery query and return formatted results."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        raise Exception("Database connection unavailable")
    
    job_config = bigquery.QueryJobConfig(
        query_parameters=params if params else []
    )
    
    query_job = bq_client.query(query, job_config=job_config)
    results = [format_bq_row(row) for row in query_job]
    
    return results

def publish_to_topic(topic_name: str, message_data: Dict) -> str:
    """Publish message to Pub/Sub topic."""
    if not publisher:
        logger.error("Pub/Sub publisher not initialized")
        raise Exception("Pub/Sub connection unavailable")
    
    topic_path = publisher.topic_path(Config.GCP_PROJECT, topic_name)
    message = json.dumps(message_data).encode("utf-8")
    
    try:
        publish_future = publisher.publish(topic_path, data=message)
        message_id = publish_future.result()
        return message_id
    except Exception as e:
        logger.error(f"Error publishing to {topic_name}: {str(e)}")
        raise

def check_table_exists(table_name: str) -> bool:
    """Check if BigQuery table exists."""
    if not bq_client:
        return False
        
    try:
        full_table_id = Config.get_table_name(table_name)
        if not full_table_id:
            return False
            
        # Parse full table ID
        project_id, dataset_id, table_id = full_table_id.split('.')
        
        # Get table reference
        dataset_ref = bq_client.dataset(dataset_id, project=project_id)
        table_ref = dataset_ref.table(table_id)
        
        # Try to get table
        bq_client.get_table(table_ref)
        return True
    except NotFound:
        return False
    except Exception as e:
        logger.error(f"Error checking table {table_name}: {str(e)}")
        return False

# -------------------- Health Check Endpoint --------------------

@api_blueprint.route('/health', methods=['GET'])
def api_health_check():
    """Health check endpoint for readiness probe."""
    try:
        health_data = {
            'status': 'ready',
            'timestamp': datetime.utcnow().isoformat(),
            'api_version': Config.API_VERSION,
            'version': Config.VERSION,
            'environment': Config.ENVIRONMENT
        }
        
        # Add service dependency status
        dependencies = {}
        
        # Check BigQuery connection if client initialized
        if bq_client:
            try:
                # Simple query to test connection
                query = "SELECT 1 AS test"
                query_job = bq_client.query(query)
                query_job.result(timeout=2)  # Short timeout
                dependencies['bigquery'] = 'connected'
                
                # Check required tables
                for table_key in Config.BIGQUERY_TABLES:
                    table_exists = check_table_exists(table_key)
                    dependencies[f'table_{table_key}'] = 'exists' if table_exists else 'missing'
            except Exception as e:
                logger.warning(f"BigQuery health check failed: {str(e)}")
                dependencies['bigquery'] = 'error'
        else:
            dependencies['bigquery'] = 'not_initialized'
            
        # Check Cloud Storage connection if client initialized
        if storage_client:
            try:
                # Check if bucket exists
                bucket_name = Config.GCS_BUCKET
                bucket = storage_client.bucket(bucket_name)
                dependencies['storage'] = 'connected' if bucket.exists() else 'bucket_not_found'
            except Exception as e:
                logger.warning(f"Storage health check failed: {str(e)}")
                dependencies['storage'] = 'error'
        else:
            dependencies['storage'] = 'not_initialized'
            
        # Check Pub/Sub connection if client initialized
        if publisher and subscriber:
            try:
                topic_path = publisher.topic_path(Config.GCP_PROJECT, Config.PUBSUB_TOPIC)
                dependencies['pubsub'] = 'initialized'
            except Exception as e:
                logger.warning(f"Pub/Sub health check failed: {str(e)}")
                dependencies['pubsub'] = 'error'
        else:
            dependencies['pubsub'] = 'not_initialized'
        
        # Add dependencies to health data
        health_data['dependencies'] = dependencies
        
        return jsonify(health_data), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        report_error(e)
        return jsonify({
            'status': 'error',
            'message': 'Service is not ready',
            'timestamp': datetime.utcnow().isoformat()
        }), 503

# -------------------- Stats Endpoint --------------------

@api_blueprint.route('/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get platform statistics."""
    try:
        days = int(request.args.get('days', 30))
        
        # Get actual stats from BigQuery
        stats = {
            'feeds': {'total_sources': 0, 'growth_rate': 0},
            'iocs': {'total': 0, 'growth_rate': 0, 'types': []},
            'campaigns': {'total_campaigns': 0, 'growth_rate': 0},
            'analyses': {'total_analyses': 0, 'growth_rate': 0},
            'timestamp': datetime.utcnow().isoformat(),
            'visualization_data': {
                'daily_counts': []
            }
        }
        
        # Query for feeds count
        feed_query = """
        SELECT COUNT(DISTINCT source) as total_sources
        FROM `{table_id}`
        """.format(table_id=Config.get_table_name('indicators'))
        
        feed_results = execute_bq_query(feed_query)
        if feed_results:
            stats['feeds']['total_sources'] = feed_results[0].get('total_sources', 0)
        
        # Query for IOCs count and types
        ioc_query = """
        SELECT 
            COUNT(*) as total,
            type,
            COUNT(*) as count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY type
        ORDER BY count DESC
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        ioc_results = execute_bq_query(ioc_query)
        if ioc_results:
            stats['iocs']['total'] = sum(row.get('count', 0) for row in ioc_results)
            stats['iocs']['types'] = [
                {'type': row['type'], 'count': row['count']} 
                for row in ioc_results
            ]
        
        # Query for daily activity
        daily_query = """
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY date
        ORDER BY date
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        daily_results = execute_bq_query(daily_query)
        if daily_results:
            stats['visualization_data']['daily_counts'] = [
                {'date': str(row['date']), 'count': row['count']}
                for row in daily_results
            ]
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Feeds Endpoint --------------------

@api_blueprint.route('/feeds', methods=['GET'])
@require_api_key
def get_feeds():
    """Get feed information."""
    try:
        # Get feed details from configuration
        feed_details = []
        for feed in Config.FEEDS:
            feed_detail = {
                'id': feed.get('id'),
                'name': feed.get('name'),
                'description': feed.get('description'),
                'record_count': 0,
                'last_updated': None,
                'enabled': feed.get('enabled', True)
            }
            
            # Query for feed record count
            feed_query = """
            SELECT 
                COUNT(*) as count,
                MAX(created_at) as last_updated
            FROM `{table_id}`
            WHERE source = @feed_id
            """.format(table_id=Config.get_table_name('indicators'))
            
            params = [bigquery.ScalarQueryParameter("feed_id", "STRING", feed.get('id'))]
            feed_results = execute_bq_query(feed_query, params)
            
            if feed_results:
                feed_detail['record_count'] = feed_results[0].get('count', 0)
                feed_detail['last_updated'] = feed_results[0].get('last_updated', None)
            
            feed_details.append(feed_detail)
        
        return jsonify({
            'feeds': feed_details,
            'count': len(feed_details),
            'feed_details': feed_details
        })
    except Exception as e:
        logger.error(f"Error getting feeds: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- IOCs Endpoint --------------------

@api_blueprint.route('/iocs', methods=['GET'])
@require_api_key
def get_iocs():
    """Get IOC data."""
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Query for IOCs
        ioc_query = """
        SELECT *
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        ORDER BY created_at DESC
        LIMIT {limit}
        OFFSET {offset}
        """.format(
            table_id=Config.get_table_name('indicators'),
            days=days,
            limit=limit,
            offset=offset
        )
        
        iocs = execute_bq_query(ioc_query)
        
        # Query for total count
        count_query = """
        SELECT COUNT(*) as total
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        count_results = execute_bq_query(count_query)
        total_count = count_results[0].get('total', 0) if count_results else 0
        
        return jsonify({
            'records': iocs,
            'count': len(iocs),
            'total_count': total_count
        })
    except Exception as e:
        logger.error(f"Error getting IOCs: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Campaigns Endpoint --------------------

@api_blueprint.route('/campaigns', methods=['GET'])
@require_api_key
def get_campaigns():
    """Get campaign data."""
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 100))
        
        # Query for campaigns
        campaign_query = """
        SELECT 
            campaign_id,
            campaign_name,
            threat_actor,
            COUNT(*) as source_count,
            MAX(confidence) as max_confidence,
            MIN(created_at) as first_seen,
            MAX(created_at) as last_seen
        FROM `{table_id}`
        WHERE campaign_id IS NOT NULL
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY campaign_id, campaign_name, threat_actor
        ORDER BY source_count DESC
        LIMIT {limit}
        """.format(table_id=Config.get_table_name('indicators'), days=days, limit=limit)
        
        campaign_results = execute_bq_query(campaign_query)
        
        # Add severity based on confidence and source count
        campaigns = []
        for campaign in campaign_results:
            campaign_data = dict(campaign)
            confidence = campaign_data.get('max_confidence', 0)
            source_count = campaign_data.get('source_count', 0)
            
            # Determine severity
            if confidence >= 90 or source_count >= 10:
                campaign_data['severity'] = 'critical'
            elif confidence >= 70 or source_count >= 5:
                campaign_data['severity'] = 'high'
            elif confidence >= 50 or source_count >= 3:
                campaign_data['severity'] = 'medium'
            else:
                campaign_data['severity'] = 'low'
            
            campaigns.append(campaign_data)
        
        # Query for total campaigns count
        count_query = """
        SELECT COUNT(DISTINCT campaign_id) as total
        FROM `{table_id}`
        WHERE campaign_id IS NOT NULL
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        count_results = execute_bq_query(count_query)
        total_campaigns = count_results[0].get('total', 0) if count_results else 0
        
        return jsonify({
            'campaigns': campaigns,
            'count': len(campaigns),
            'total_campaigns': total_campaigns
        })
    except Exception as e:
        logger.error(f"Error getting campaigns: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Threat Summary Endpoint --------------------

@api_blueprint.route('/threat_summary', methods=['GET'])
@require_api_key
def get_threat_summary():
    """Get threat summary data."""
    try:
        days = int(request.args.get('days', 30))
        
        # Query for high-risk indicators
        risk_query = """
        SELECT COUNT(*) as count
        FROM `{table_id}`
        WHERE confidence >= 80
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        risk_results = execute_bq_query(risk_query)
        high_risk_indicators = risk_results[0].get('count', 0) if risk_results else 0
        
        # Query for active campaigns
        campaign_query = """
        SELECT COUNT(DISTINCT campaign_id) as count
        FROM `{table_id}`
        WHERE campaign_id IS NOT NULL
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        campaign_results = execute_bq_query(campaign_query)
        active_campaigns = campaign_results[0].get('count', 0) if campaign_results else 0
        
        # Query for recent detections
        recent_query = """
        SELECT COUNT(*) as count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        """.format(table_id=Config.get_table_name('indicators'))
        
        recent_results = execute_bq_query(recent_query)
        recent_detections = recent_results[0].get('count', 0) if recent_results else 0
        
        summary = {
            'high_risk_indicators': high_risk_indicators,
            'active_campaigns': active_campaigns,
            'recent_detections': recent_detections,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting threat summary: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Geo Stats Endpoint --------------------

@api_blueprint.route('/iocs/geo', methods=['GET'])
@require_api_key
def get_geo_stats():
    """Get geographical IOC distribution."""
    try:
        days = int(request.args.get('days', 30))
        
        # Query for geographical distribution
        geo_query = """
        SELECT 
            enrichment_country as country,
            COUNT(*) as count
        FROM `{table_id}`
        WHERE enrichment_country IS NOT NULL
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY enrichment_country
        ORDER BY count DESC
        LIMIT 10
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        geo_results = execute_bq_query(geo_query)
        
        countries = [
            {'country': row['country'], 'count': row['count']}
            for row in geo_results
        ]
        
        return jsonify({'countries': countries})
    except Exception as e:
        logger.error(f"Error getting geo stats: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Admin Endpoints --------------------

@api_blueprint.route('/admin/ingest', methods=['POST'])
@require_api_key
def trigger_ingest():
    """Trigger data ingestion."""
    try:
        # Get request data
        req_data = request.get_json() or {}
        process_all = req_data.get('process_all', True)
        
        # Trigger ingestion via Pub/Sub
        message_data = {
            'process_all': process_all,
            'triggered_by': 'api',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message_id = publish_to_topic(Config.PUBSUB_TOPIC, message_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Ingestion triggered successfully',
            'message_id': message_id
        })
    except Exception as e:
        logger.error(f"Error triggering ingestion: {str(e)}")
        report_error(e)
        return jsonify({'error': str(e)}), 500

@api_blueprint.route('/admin/analyze', methods=['POST'])
@require_api_key
def trigger_analysis():
    """Trigger data analysis."""
    try:
        # Get request data
        req_data = request.get_json() or {}
        analyze_all = req_data.get('analyze_all', False)
        indicator_ids = req_data.get('indicator_ids', [])
        force_reanalysis = req_data.get('force_reanalysis', False)
        
        # Trigger analysis via Pub/Sub
        message_data = {
            'analyze_all': analyze_all,
            'indicator_ids': indicator_ids,
            'force_reanalysis': force_reanalysis,
            'triggered_by': 'api',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message_id = publish_to_topic(Config.PUBSUB_ANALYSIS_TOPIC, message_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Analysis triggered successfully',
            'message_id': message_id
        })
    except Exception as e:
        logger.error(f"Error triggering analysis: {str(e)}")
        report_error(e)
        return jsonify({'error': str(e)}), 500

# -------------------- API Information Endpoints --------------------

@api_blueprint.route('/info', methods=['GET'])
def get_api_info():
    """Get API information."""
    return jsonify({
        'name': 'Threat Intelligence Platform API',
        'version': Config.API_VERSION,
        'build_version': Config.VERSION,
        'endpoints': [
            {'path': '/api/health', 'method': 'GET', 'description': 'API health check'},
            {'path': '/api/info', 'method': 'GET', 'description': 'API information'},
            {'path': '/api/stats', 'method': 'GET', 'description': 'Get platform statistics'},
            {'path': '/api/feeds', 'method': 'GET', 'description': 'Get threat feeds information'},
            {'path': '/api/iocs', 'method': 'GET', 'description': 'Get indicators of compromise'},
            {'path': '/api/campaigns', 'method': 'GET', 'description': 'Get campaign information'},
            {'path': '/api/threat_summary', 'method': 'GET', 'description': 'Get threat summary'},
            {'path': '/api/iocs/geo', 'method': 'GET', 'description': 'Get geographical distribution'},
            {'path': '/api/admin/ingest', 'method': 'POST', 'description': 'Trigger data ingestion'},
            {'path': '/api/admin/analyze', 'method': 'POST', 'description': 'Trigger data analysis'}
        ]
    })

# -------------------- Error Handlers --------------------

@api_blueprint.errorhandler(400)
def bad_request(e):
    """Handle 400 errors."""
    return jsonify({"error": "Bad request", "message": str(e)}), 400

@api_blueprint.errorhandler(401)
def unauthorized(e):
    """Handle 401 errors."""
    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401

@api_blueprint.errorhandler(403)
def forbidden(e):
    """Handle 403 errors."""
    return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403

@api_blueprint.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Not found", "message": "Resource not found"}), 404

@api_blueprint.errorhandler(405)
def method_not_allowed(e):
    """Handle 405 errors."""
    return jsonify({"error": "Method not allowed", "message": "HTTP method not allowed for this endpoint"}), 405

@api_blueprint.errorhandler(429)
def too_many_requests(e):
    """Handle 429 errors."""
    return jsonify({
        "error": "Too many requests", 
        "message": "Rate limit exceeded. Please try again later."
    }), 429

@api_blueprint.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(e)}\n{traceback.format_exc()}")
    report_error(e)
    return jsonify({"error": "Internal server error", "message": "An unexpected error occurred"}), 500
