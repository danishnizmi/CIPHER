import os
import json
import logging
import traceback
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from flask import Blueprint, jsonify, request, current_app, abort, Response, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import csrf_exempt
from functools import wraps
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound
import google.auth

# Import configuration
from config import Config, ServiceManager, ServiceStatus, initialize_bigquery, initialize_storage, initialize_pubsub, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Initialize API blueprint
api_blueprint = Blueprint('api', __name__)

# Initialize rate limiter for cost efficiency
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"]
)

# API Key Authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'No API key provided'}), 401
        
        # Clean the API key - strip whitespace and quotes
        api_key = api_key.strip().strip('"\'')
        
        # Get the actual API key from config
        expected_key = Config.API_KEY
        if expected_key:
            expected_key = expected_key.strip()
        
        # Allow default key in non-production environments
        if Config.ENVIRONMENT != 'production' and api_key == 'default-api-key':
            return f(*args, **kwargs)
        
        # Check the API key
        if api_key != expected_key:
            logger.warning(f"Invalid API key attempt: {api_key[:10]}...")
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Helper Functions
def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    bq_client = service_manager.get_client('bigquery')
    storage_client = service_manager.get_client('storage')
    publisher = service_manager.get_client('publisher')
    subscriber = service_manager.get_client('subscriber')
    
    return bq_client, storage_client, publisher, subscriber

def format_bq_row(row: Dict) -> Dict:
    """Format BigQuery row for JSON response."""
    formatted = {}
    for key, value in dict(row).items():
        if isinstance(value, datetime):
            formatted[key] = value.isoformat()
        elif hasattr(value, 'isoformat'):
            formatted[key] = value.isoformat()
        else:
            formatted[key] = value
    return formatted

def execute_bq_query(query: str, params: Optional[List] = None) -> List[Dict]:
    """Execute BigQuery query and return formatted results."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return []
    
    job_config = bigquery.QueryJobConfig(
        query_parameters=params if params else []
    )
    
    try:
        query_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in query_job]
        return results
    except Exception as e:
        logger.error(f"Error executing BigQuery query: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return []

def publish_to_topic(topic_name: str, message_data: Dict) -> Optional[str]:
    """Publish message to Pub/Sub topic."""
    _, _, publisher, _ = get_clients()
    
    if not publisher:
        logger.error("Pub/Sub publisher not initialized")
        return None
    
    topic_path = publisher.topic_path(Config.GCP_PROJECT, topic_name)
    message = json.dumps(message_data).encode("utf-8")
    
    try:
        publish_future = publisher.publish(topic_path, data=message)
        message_id = publish_future.result()
        
        # Publish event to event bus if available
        if hasattr(g, 'event_bus'):
            g.event_bus.publish(f"{topic_name}_published", message_data)
        
        return message_id
    except Exception as e:
        logger.error(f"Error publishing to {topic_name}: {str(e)}")
        return None

def check_table_exists(table_name: str) -> bool:
    """Check if BigQuery table exists."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        return False
        
    try:
        full_table_id = Config.get_table_name(table_name)
        if not full_table_id:
            return False
            
        parts = full_table_id.split('.')
        if len(parts) != 3:
            return False
            
        project_id, dataset_id, table_id = parts
        
        dataset_ref = bq_client.dataset(dataset_id, project=project_id)
        table_ref = dataset_ref.table(table_id)
        
        bq_client.get_table(table_ref)
        
        # Try a simple query to verify
        test_query = f"SELECT COUNT(*) as count FROM `{full_table_id}` LIMIT 1"
        bq_client.query(test_query).result()
        
        return True
    except NotFound:
        return False
    except Exception as e:
        logger.error(f"Error checking table {table_name}: {str(e)}")
        return False

def verify_bigquery_tables() -> bool:
    """Verify all required BigQuery tables exist."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    required_tables = ['indicators', 'vulnerabilities', 'threat_actors', 'campaigns', 'malware']
    missing_tables = []
    
    for table_name in required_tables:
        if not check_table_exists(table_name):
            missing_tables.append(table_name)
    
    if missing_tables:
        logger.warning(f"The following tables are missing: {', '.join(missing_tables)}")
        return False
    
    return True

# API Endpoints
@api_blueprint.route('/health', methods=['GET'])
@csrf_exempt
def api_health_check():
    """API health check with service status."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    health_data = {
        'status': status['overall'],
        'timestamp': datetime.utcnow().isoformat(),
        'api_version': Config.API_VERSION,
        'services': status['services'],
        'dependencies': {
            service: status['services'].get(service, 'unknown')
            for service in ['bigquery', 'storage', 'pubsub']
        }
    }
    
    if status['overall'] == ServiceStatus.READY.value:
        return jsonify(health_data), 200
    else:
        return jsonify(health_data), 503

@api_blueprint.route('/stats', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_stats():
    """Get platform statistics."""
    try:
        days = int(request.args.get('days', 30))
        
        stats = {
            'feeds': {'total_sources': 0, 'growth_rate': 0},
            'iocs': {'total': 0, 'growth_rate': 0, 'types': []},
            'analyses': {'total_analyses': 0, 'growth_rate': 0},
            'timestamp': datetime.utcnow().isoformat(),
            'visualization_data': {'daily_counts': []}
        }
        
        if not verify_bigquery_tables():
            logger.warning("BigQuery tables not ready, returning default stats")
            return jsonify(stats)
        
        # Query for feeds count
        feed_query = f"""
        SELECT COUNT(DISTINCT source) as total_sources
        FROM `{Config.get_table_name('indicators')}`
        """
        
        feed_results = execute_bq_query(feed_query)
        if feed_results:
            stats['feeds']['total_sources'] = feed_results[0].get('total_sources', 0)
        
        # Query for IOCs count and types
        ioc_query = f"""
        SELECT 
            COUNT(*) as total,
            type,
            COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY type
        ORDER BY count DESC
        """
        
        ioc_results = execute_bq_query(ioc_query)
        if ioc_results:
            stats['iocs']['total'] = sum(row.get('count', 0) for row in ioc_results)
            stats['iocs']['types'] = [
                {'type': row['type'], 'count': row['count']} 
                for row in ioc_results
            ]
        
        # Query for AI analyses count
        analyses_query = f"""
        SELECT COUNT(*) as total_analyses
        FROM `{Config.get_table_name('indicators')}`
        WHERE last_analyzed IS NOT NULL
        AND last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        analyses_results = execute_bq_query(analyses_query)
        if analyses_results:
            stats['analyses']['total_analyses'] = analyses_results[0].get('total_analyses', 0)
        
        # Query for daily activity
        daily_query = f"""
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY date
        ORDER BY date
        """
        
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

@api_blueprint.route('/feeds', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_feeds():
    """Get feed information."""
    try:
        feed_details = []
        for feed in Config.FEEDS:
            feed_detail = {
                'id': feed.get('id'),
                'name': feed.get('name'),
                'description': feed.get('description'),
                'record_count': 0,
                'last_updated': None,
                'enabled': feed.get('enabled', True),
                'format': feed.get('format', 'json'),
                'update_frequency': feed.get('update_frequency', 'daily')
            }
            
            if verify_bigquery_tables():
                feed_query = f"""
                SELECT 
                    COUNT(*) as count,
                    MAX(created_at) as last_updated
                FROM `{Config.get_table_name('indicators')}`
                WHERE source = @feed_id
                """
                
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

@api_blueprint.route('/iocs', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_iocs():
    """Get IOC data."""
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        ioc_type = request.args.get('type', '')
        
        default_response = {
            'records': [],
            'count': 0,
            'total_count': 0
        }
        
        if not verify_bigquery_tables():
            logger.warning("Tables not ready, returning empty response")
            return jsonify(default_response)
        
        where_conditions = [f"created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"]
        params = []
        
        if ioc_type:
            where_conditions.append("type = @ioc_type")
            params.append(bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type))
        
        ioc_query = f"""
        SELECT *
        FROM `{Config.get_table_name('indicators')}`
        WHERE {" AND ".join(where_conditions)}
        ORDER BY created_at DESC
        LIMIT {limit}
        OFFSET {offset}
        """
        
        iocs = execute_bq_query(ioc_query, params)
        
        count_query = f"""
        SELECT COUNT(*) as total
        FROM `{Config.get_table_name('indicators')}`
        WHERE {" AND ".join(where_conditions)}
        """
        
        count_results = execute_bq_query(count_query, params)
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

@api_blueprint.route('/ai/analyses', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_ai_analyses():
    """Get AI analysis data."""
    try:
        days = int(request.args.get('days', 30))
        
        # Mock response structure based on frontend expectations
        ai_analyses = {
            'overall_threat_level': 'Medium',
            'total_indicators': 0,
            'emerging_threats_count': 0,
            'critical_indicators': 0,
            'threat_patterns': [],
            'recommendations': [],
            'recent_analyses': [],
            'last_run_time': None
        }
        
        if not verify_bigquery_tables():
            return jsonify(ai_analyses)
        
        # Get analysis stats
        analysis_query = f"""
        SELECT 
            COUNT(*) as total_analyzed,
            COUNT(CASE WHEN risk_score > 80 THEN 1 END) as critical_count,
            MAX(last_analyzed) as last_analysis_time
        FROM `{Config.get_table_name('indicators')}`
        WHERE last_analyzed IS NOT NULL
        AND last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        results = execute_bq_query(analysis_query)
        if results:
            ai_analyses['total_indicators'] = results[0].get('total_analyzed', 0)
            ai_analyses['critical_indicators'] = results[0].get('critical_count', 0)
            ai_analyses['last_run_time'] = results[0].get('last_analysis_time')
        
        # Get recent analysis results
        recent_query = f"""
        SELECT 
            id,
            type,
            value as target,
            'threat_assessment' as analysis_type,
            analysis_summary as result,
            CASE 
                WHEN risk_score > 80 THEN 'critical'
                WHEN risk_score > 60 THEN 'high'
                WHEN risk_score > 40 THEN 'medium'
                ELSE 'low'
            END as result_severity,
            confidence,
            last_analyzed as timestamp
        FROM `{Config.get_table_name('indicators')}`
        WHERE last_analyzed IS NOT NULL
        ORDER BY last_analyzed DESC
        LIMIT 10
        """
        
        recent_results = execute_bq_query(recent_query)
        if recent_results:
            ai_analyses['recent_analyses'] = recent_results
        
        # Determine overall threat level based on critical indicators
        if ai_analyses['critical_indicators'] > 50:
            ai_analyses['overall_threat_level'] = 'Critical'
        elif ai_analyses['critical_indicators'] > 20:
            ai_analyses['overall_threat_level'] = 'High'
        elif ai_analyses['critical_indicators'] > 5:
            ai_analyses['overall_threat_level'] = 'Medium'
        else:
            ai_analyses['overall_threat_level'] = 'Low'
        
        return jsonify(ai_analyses)
        
    except Exception as e:
        logger.error(f"Error getting AI analyses: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/threat_summary', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_threat_summary():
    """Get threat summary data."""
    try:
        days = int(request.args.get('days', 30))
        
        threat_summary = {
            'overall_score': 50,
            'threat_level': 'Medium',
            'active_threats': 0,
            'critical_indicators': 0,
            'trending_ioc_types': [],
            'top_threat_actors': [],
            'risk_trend': 'stable'
        }
        
        if not verify_bigquery_tables():
            return jsonify(threat_summary)
        
        # Calculate threat metrics
        summary_query = f"""
        SELECT 
            AVG(risk_score) as avg_risk_score,
            COUNT(CASE WHEN risk_score > 80 THEN 1 END) as critical_count,
            COUNT(DISTINCT threat_actor) as active_threat_actors
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        results = execute_bq_query(summary_query)
        if results:
            threat_summary['overall_score'] = int(results[0].get('avg_risk_score', 50))
            threat_summary['critical_indicators'] = results[0].get('critical_count', 0)
            threat_summary['active_threats'] = results[0].get('active_threat_actors', 0)
        
        # Determine threat level
        if threat_summary['overall_score'] > 80:
            threat_summary['threat_level'] = 'Critical'
        elif threat_summary['overall_score'] > 60:
            threat_summary['threat_level'] = 'High'
        elif threat_summary['overall_score'] > 40:
            threat_summary['threat_level'] = 'Medium'
        else:
            threat_summary['threat_level'] = 'Low'
        
        return jsonify(threat_summary)
        
    except Exception as e:
        logger.error(f"Error getting threat summary: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/ai/summary', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_ai_summary():
    """Get AI summary for dashboard."""
    try:
        ai_summary = {
            'risk_level': 'Medium',
            'trending_threats': 'None detected',
            'critical_indicators': 0,
            'key_findings': [],
            'last_updated': datetime.utcnow().isoformat()
        }
        
        if not verify_bigquery_tables():
            return jsonify(ai_summary)
        
        # Get critical indicators count
        critical_query = f"""
        SELECT COUNT(*) as critical_count
        FROM `{Config.get_table_name('indicators')}`
        WHERE risk_score > 80
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        """
        
        results = execute_bq_query(critical_query)
        if results:
            ai_summary['critical_indicators'] = results[0].get('critical_count', 0)
        
        # Determine risk level
        if ai_summary['critical_indicators'] > 10:
            ai_summary['risk_level'] = 'High'
        elif ai_summary['critical_indicators'] > 5:
            ai_summary['risk_level'] = 'Medium'
        else:
            ai_summary['risk_level'] = 'Low'
        
        return jsonify(ai_summary)
        
    except Exception as e:
        logger.error(f"Error getting AI summary: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/iocs/geo', methods=['GET'])
@limiter.limit("30 per minute")
@csrf_exempt
@require_api_key
def get_iocs_geo():
    """Get geographical statistics for IOCs."""
    try:
        days = int(request.args.get('days', 30))
        
        geo_stats = {
            'countries': [],
            'top_sources': [],
            'threat_map_data': []
        }
        
        if not verify_bigquery_tables():
            return jsonify(geo_stats)
        
        # Mock geographic data for now
        # In production, this would query enriched IOC data with geo information
        geo_stats['countries'] = [
            {'country': 'US', 'count': 150, 'risk_level': 'high'},
            {'country': 'RU', 'count': 120, 'risk_level': 'critical'},
            {'country': 'CN', 'count': 100, 'risk_level': 'high'},
            {'country': 'DE', 'count': 50, 'risk_level': 'medium'},
            {'country': 'GB', 'count': 45, 'risk_level': 'medium'}
        ]
        
        return jsonify(geo_stats)
        
    except Exception as e:
        logger.error(f"Error getting geo stats: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/admin/ingest', methods=['POST'])
@limiter.limit("5 per minute")
@csrf_exempt
@require_api_key
def trigger_ingest():
    """Trigger data ingestion."""
    try:
        req_data = request.get_json() or {}
        process_all = req_data.get('process_all', True)
        force_tables = req_data.get('force_tables', False)
        
        message_data = {
            'process_all': process_all,
            'force_tables': force_tables,
            'triggered_by': 'api',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message_id = publish_to_topic(Config.PUBSUB_TOPIC, message_data)
        
        if message_id:
            return jsonify({
                'status': 'success',
                'message': 'Ingestion triggered successfully',
                'message_id': message_id
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to trigger ingestion'
            }), 500
            
    except Exception as e:
        logger.error(f"Error triggering ingestion: {str(e)}")
        report_error(e)
        return jsonify({'error': str(e)}), 500

@api_blueprint.route('/admin/analyze', methods=['POST'])
@limiter.limit("5 per minute")
@csrf_exempt
@require_api_key
def trigger_analysis():
    """Trigger data analysis."""
    try:
        req_data = request.get_json() or {}
        analyze_all = req_data.get('analyze_all', False)
        indicator_ids = req_data.get('indicator_ids', [])
        force_reanalysis = req_data.get('force_reanalysis', False)
        
        message_data = {
            'analyze_all': analyze_all,
            'indicator_ids': indicator_ids,
            'force_reanalysis': force_reanalysis,
            'triggered_by': 'api',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message_id = publish_to_topic(Config.PUBSUB_ANALYSIS_TOPIC, message_data)
        
        if message_id:
            return jsonify({
                'status': 'success',
                'message': 'Analysis triggered successfully',
                'message_id': message_id
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to trigger analysis'
            }), 500
            
    except Exception as e:
        logger.error(f"Error triggering analysis: {str(e)}")
        report_error(e)
        return jsonify({'error': str(e)}), 500

# Error handlers
@api_blueprint.errorhandler(400)
def bad_request(e):
    """Handle 400 errors."""
    return jsonify({"error": "Bad request", "message": str(e)}), 400

@api_blueprint.errorhandler(401)
def unauthorized(e):
    """Handle 401 errors."""
    return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401

@api_blueprint.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Not found", "message": "Resource not found"}), 404

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

# Register blueprint hooks
@api_blueprint.before_request
def before_api_request():
    """Update API service status."""
    service_manager = Config.get_service_manager()
    service_manager.update_status('api', ServiceStatus.READY)

@api_blueprint.teardown_request
def teardown_api_request(exception=None):
    """Handle API request teardown."""
    if exception:
        logger.error(f"API request failed with exception: {exception}")
        service_manager = Config.get_service_manager()
        service_manager.update_status('api', ServiceStatus.DEGRADED)
