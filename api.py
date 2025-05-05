import os
import json
import logging
import traceback
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
    """Decorator to require API key for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from request
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        # For internal requests, check if user is logged in
        if request.remote_addr in ['127.0.0.1', '::1'] or request.headers.get('X-Forwarded-For', '').startswith('127.0.0.1'):
            # Internal request from frontend
            from flask import session
            if session.get('logged_in'):
                return f(*args, **kwargs)
        
        # Check if API key is valid
        if not api_key or api_key != Config.API_KEY:
            logger.warning(f"Invalid API key attempt from IP: {get_remote_address()}")
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

# -------------------- Debug Endpoints --------------------

@api_blueprint.route('/debug/auth', methods=['GET'])
@require_api_key
def debug_auth():
    """Debug authentication and permissions."""
    try:
        import google.auth
        import json
        from google.cloud import storage, bigquery, pubsub_v1
        from google.cloud.exceptions import NotFound
        
        # Get current credentials
        credentials, project_id = google.auth.default()
        service_account_email = getattr(credentials, 'service_account_email', 'Not available')
        
        # Test various services
        results = {
            "service_account": service_account_email,
            "project_id": project_id,
            "tests": {}
        }
        
        # Test BigQuery
        try:
            bq_client = bigquery.Client()
            dataset = f"{project_id}.threat_intelligence"
            try:
                bq_client.get_dataset(dataset)
                results["tests"]["bigquery"] = "Success: Dataset exists"
            except NotFound:
                results["tests"]["bigquery"] = "Error: Dataset not found"
        except Exception as e:
            results["tests"]["bigquery"] = f"Error: {str(e)}"
            
        # Test Storage
        try:
            storage_client = storage.Client()
            bucket_name = f"{project_id}-threat-data"
            try:
                bucket = storage_client.get_bucket(bucket_name)
                results["tests"]["storage"] = "Success: Bucket exists"
            except NotFound:
                results["tests"]["storage"] = "Error: Bucket not found"
        except Exception as e:
            results["tests"]["storage"] = f"Error: {str(e)}"
            
        # Test Pub/Sub
        try:
            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(project_id, "threat-data-ingestion")
            try:
                publisher.get_topic(request={"topic": topic_path})
                results["tests"]["pubsub"] = "Success: Topic exists"
            except NotFound:
                results["tests"]["pubsub"] = "Error: Topic not found"
        except Exception as e:
            results["tests"]["pubsub"] = f"Error: {str(e)}"
            
        # Test Secret Manager
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/feed-config"
            try:
                client.get_secret(request={"name": name})
                results["tests"]["secretmanager"] = "Success: Secret exists"
            except Exception as e:
                results["tests"]["secretmanager"] = f"Error: {str(e)}"
        except Exception as e:
            results["tests"]["secretmanager"] = f"Error: {str(e)}"
            
        return jsonify(results)
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

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

def execute_bq_query(query: str, params: Optional[Dict] = None) -> List[Dict]:
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

# -------------------- Mock Data Endpoints for Development --------------------

@api_blueprint.route('/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get platform statistics."""
    try:
        days = int(request.args.get('days', 30))
        
        # Mock data for development
        stats = {
            'feeds': {
                'total_sources': 12,
                'growth_rate': 15.3
            },
            'iocs': {
                'total': 24389,
                'growth_rate': 8.7,
                'types': [
                    {'type': 'domain', 'count': 10250},
                    {'type': 'ip', 'count': 8150},
                    {'type': 'url', 'count': 4500},
                    {'type': 'hash', 'count': 1489}
                ]
            },
            'campaigns': {
                'total_campaigns': 47,
                'growth_rate': 5.2
            },
            'analyses': {
                'total_analyses': 1234,
                'growth_rate': 12.5
            },
            'timestamp': datetime.utcnow().isoformat(),
            'visualization_data': {
                'daily_counts': [
                    {'date': (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d'), 'count': 100 + i * 5}
                    for i in range(days)
                ]
            }
        }
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/feeds', methods=['GET'])
@require_api_key
def get_feeds():
    """Get feed information."""
    try:
        # Mock feed data
        feeds = [
            {
                'id': 'phishtank',
                'name': 'PhishTank',
                'description': 'Phishing URLs database',
                'record_count': 15420,
                'last_updated': datetime.utcnow().isoformat(),
                'enabled': True
            },
            {
                'id': 'urlhaus',
                'name': 'URLhaus',
                'description': 'Malware URL database',
                'record_count': 8960,
                'last_updated': datetime.utcnow().isoformat(),
                'enabled': True
            },
            {
                'id': 'threatfox',
                'name': 'ThreatFox',
                'description': 'IOC database',
                'record_count': 12400,
                'last_updated': datetime.utcnow().isoformat(),
                'enabled': True
            }
        ]
        
        return jsonify({
            'feeds': feeds,
            'count': len(feeds),
            'feed_details': feeds
        })
    except Exception as e:
        logger.error(f"Error getting feeds: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/iocs', methods=['GET'])
@require_api_key
def get_iocs():
    """Get IOC data."""
    try:
        days = int(request.args.get('days', 30))
        
        # Mock IOC data
        iocs = [
            {
                'id': '1',
                'type': 'domain',
                'value': 'malicious-domain.com',
                'source': 'PhishTank',
                'sources': 3,
                'first_seen': (datetime.utcnow() - timedelta(days=5)).isoformat(),
                'confidence': 85
            },
            {
                'id': '2',
                'type': 'ip',
                'value': '192.168.1.100',
                'source': 'URLhaus',
                'sources': 1,
                'first_seen': (datetime.utcnow() - timedelta(days=3)).isoformat(),
                'confidence': 75
            },
            {
                'id': '3',
                'type': 'url',
                'value': 'http://malicious-site.com/phish',
                'source': 'ThreatFox',
                'sources': 2,
                'first_seen': (datetime.utcnow() - timedelta(days=1)).isoformat(),
                'confidence': 95
            },
            {
                'id': '4',
                'type': 'hash',
                'value': 'a1b2c3d4e5f6...',
                'source': 'PhishTank',
                'sources': 4,
                'first_seen': (datetime.utcnow() - timedelta(days=7)).isoformat(),
                'confidence': 90
            }
        ]
        
        return jsonify({
            'records': iocs,
            'count': len(iocs),
            'total_count': 24389
        })
    except Exception as e:
        logger.error(f"Error getting IOCs: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/campaigns', methods=['GET'])
@require_api_key
def get_campaigns():
    """Get campaign data."""
    try:
        days = int(request.args.get('days', 30))
        
        # Mock campaign data
        campaigns = [
            {
                'campaign_id': 'campaign-001',
                'campaign_name': 'Operation Phishing Storm',
                'threat_actor': 'APT-29',
                'source_count': 15,
                'severity': 'high',
                'first_seen': (datetime.utcnow() - timedelta(days=10)).isoformat(),
                'last_seen': (datetime.utcnow() - timedelta(days=1)).isoformat()
            },
            {
                'campaign_id': 'campaign-002',
                'campaign_name': 'Crypto Mining Botnet',
                'threat_actor': 'Unknown',
                'source_count': 8,
                'severity': 'medium',
                'first_seen': (datetime.utcnow() - timedelta(days=5)).isoformat(),
                'last_seen': (datetime.utcnow() - timedelta(days=2)).isoformat()
            },
            {
                'campaign_id': 'campaign-003',
                'campaign_name': 'Ransomware Wave',
                'threat_actor': 'REvil',
                'source_count': 22,
                'severity': 'critical',
                'first_seen': (datetime.utcnow() - timedelta(days=3)).isoformat(),
                'last_seen': datetime.utcnow().isoformat()
            }
        ]
        
        return jsonify({
            'campaigns': campaigns,
            'count': len(campaigns),
            'total_campaigns': 47
        })
    except Exception as e:
        logger.error(f"Error getting campaigns: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/threat_summary', methods=['GET'])
@require_api_key
def get_threat_summary():
    """Get threat summary data."""
    try:
        # Mock threat summary
        summary = {
            'high_risk_indicators': 156,
            'active_campaigns': 3,
            'recent_detections': 47,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting threat summary: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/iocs/geo', methods=['GET'])
@require_api_key
def get_geo_stats():
    """Get geographical IOC distribution."""
    try:
        # Mock geographical data
        geo_stats = {
            'countries': [
                {'country': 'USA', 'count': 850},
                {'country': 'RUS', 'count': 620},
                {'country': 'CHN', 'count': 450},
                {'country': 'IND', 'count': 380},
                {'country': 'BRA', 'count': 250}
            ]
        }
        
        return jsonify(geo_stats)
    except Exception as e:
        logger.error(f"Error getting geo stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

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
            {'path': '/api/indicators', 'method': 'GET', 'description': 'Get indicators of compromise'},
            {'path': '/api/vulnerabilities', 'method': 'GET', 'description': 'Get vulnerability information'},
            {'path': '/api/threat_actors', 'method': 'GET', 'description': 'Get threat actor information'},
            {'path': '/api/campaigns', 'method': 'GET', 'description': 'Get campaign information'},
            {'path': '/api/malware', 'method': 'GET', 'description': 'Get malware information'},
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
