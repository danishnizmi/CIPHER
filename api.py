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

@api_blueprint.route('/feeds', methods=['GET'])
def get_feed_info():
    """Get information about available threat feeds."""
    feeds = []
    
    for feed in Config.FEEDS:
        feeds.append({
            'id': feed.get('id'),
            'name': feed.get('name'),
            'description': feed.get('description'),
            'type': feed.get('type'),
            'update_frequency': feed.get('update_frequency')
        })
    
    return jsonify({
        'feeds': feeds,
        'count': len(feeds),
        'update_interval': Config.FEED_UPDATE_INTERVAL
    })

# -------------------- Data Access Endpoints --------------------

@api_blueprint.route('/indicators', methods=['GET'])
@require_api_key
@limiter.limit(Config.API_RATE_LIMIT)
def get_indicators():
    """Get indicators of compromise."""
    try:
        # Get query parameters with defaults
        limit = min(int(request.args.get('limit', Config.API_DEFAULT_PAGE_SIZE)), Config.API_MAX_PAGE_SIZE)
        offset = int(request.args.get('offset', 0))
        type_filter = request.args.get('type')
        value_filter = request.args.get('value')
        feed_filter = request.args.get('feed_id')
        min_confidence = request.args.get('min_confidence')
        max_age_days = request.args.get('max_age_days')
        
        # Build query filters
        filters = []
        query_params = []
        
        if type_filter:
            filters.append("type = @type_filter")
            query_params.append(bigquery.ScalarQueryParameter("type_filter", "STRING", type_filter))
            
        if value_filter:
            filters.append("value LIKE @value_filter")
            query_params.append(bigquery.ScalarQueryParameter("value_filter", "STRING", f"%{value_filter}%"))
            
        if feed_filter:
            filters.append("feed_id = @feed_filter")
            query_params.append(bigquery.ScalarQueryParameter("feed_filter", "STRING", feed_filter))
            
        if min_confidence:
            filters.append("confidence >= @min_confidence")
            query_params.append(bigquery.ScalarQueryParameter("min_confidence", "INT64", int(min_confidence)))
            
        if max_age_days:
            date_threshold = datetime.utcnow() - timedelta(days=int(max_age_days))
            filters.append("created_at >= @date_threshold")
            query_params.append(bigquery.ScalarQueryParameter("date_threshold", "TIMESTAMP", date_threshold))
        
        # Build query
        query = f"""
            SELECT * FROM `{Config.get_table_name('indicators')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
            ORDER BY created_at DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        # Get count query
        count_query = f"""
            SELECT COUNT(*) as count FROM `{Config.get_table_name('indicators')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
        """
        
        # Execute queries
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        count_job = bq_client.query(count_query, job_config=job_config)
        count_result = list(count_job)[0]
        total_count = count_result['count']
        
        results_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in results_job]
        
        return jsonify({
            'indicators': results,
            'count': len(results),
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error querying indicators: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve indicators: {str(e)}"}), 500

@api_blueprint.route('/vulnerabilities', methods=['GET'])
@require_api_key
@limiter.limit(Config.API_RATE_LIMIT)
def get_vulnerabilities():
    """Get vulnerability information."""
    try:
        # Get query parameters with defaults
        limit = min(int(request.args.get('limit', Config.API_DEFAULT_PAGE_SIZE)), Config.API_MAX_PAGE_SIZE)
        offset = int(request.args.get('offset', 0))
        cve_filter = request.args.get('cve')
        min_cvss = request.args.get('min_cvss')
        product_filter = request.args.get('product')
        
        # Build query filters
        filters = []
        query_params = []
        
        if cve_filter:
            filters.append("cve_id = @cve_filter")
            query_params.append(bigquery.ScalarQueryParameter("cve_filter", "STRING", cve_filter))
            
        if min_cvss:
            filters.append("cvss_score >= @min_cvss")
            query_params.append(bigquery.ScalarQueryParameter("min_cvss", "FLOAT64", float(min_cvss)))
            
        if product_filter:
            filters.append("(product LIKE @product_filter OR vendor LIKE @product_filter)")
            query_params.append(bigquery.ScalarQueryParameter("product_filter", "STRING", f"%{product_filter}%"))
        
        # Build query
        query = f"""
            SELECT * FROM `{Config.get_table_name('vulnerabilities')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
            ORDER BY cvss_score DESC, created_at DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        # Get count query
        count_query = f"""
            SELECT COUNT(*) as count FROM `{Config.get_table_name('vulnerabilities')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
        """
        
        # Execute queries
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        count_job = bq_client.query(count_query, job_config=job_config)
        count_result = list(count_job)[0]
        total_count = count_result['count']
        
        results_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in results_job]
        
        return jsonify({
            'vulnerabilities': results,
            'count': len(results),
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error querying vulnerabilities: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve vulnerabilities: {str(e)}"}), 500

@api_blueprint.route('/threat_actors', methods=['GET'])
@require_api_key
@limiter.limit(Config.API_RATE_LIMIT)
def get_threat_actors():
    """Get threat actor information."""
    try:
        # Get query parameters with defaults
        limit = min(int(request.args.get('limit', Config.API_DEFAULT_PAGE_SIZE)), Config.API_MAX_PAGE_SIZE)
        offset = int(request.args.get('offset', 0))
        name_filter = request.args.get('name')
        target_filter = request.args.get('target')
        
        # Build query filters
        filters = []
        query_params = []
        
        if name_filter:
            filters.append("(name LIKE @name_filter OR aliases LIKE @name_filter)")
            query_params.append(bigquery.ScalarQueryParameter("name_filter", "STRING", f"%{name_filter}%"))
            
        if target_filter:
            filters.append("targets LIKE @target_filter")
            query_params.append(bigquery.ScalarQueryParameter("target_filter", "STRING", f"%{target_filter}%"))
        
        # Build query
        query = f"""
            SELECT * FROM `{Config.get_table_name('threat_actors')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
            ORDER BY last_updated DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        # Get count query
        count_query = f"""
            SELECT COUNT(*) as count FROM `{Config.get_table_name('threat_actors')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
        """
        
        # Execute queries
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        count_job = bq_client.query(count_query, job_config=job_config)
        count_result = list(count_job)[0]
        total_count = count_result['count']
        
        results_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in results_job]
        
        return jsonify({
            'threat_actors': results,
            'count': len(results),
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error querying threat actors: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve threat actors: {str(e)}"}), 500

@api_blueprint.route('/campaigns', methods=['GET'])
@require_api_key
@limiter.limit(Config.API_RATE_LIMIT)
def get_campaigns():
    """Get campaign information."""
    try:
        # Get query parameters with defaults
        limit = min(int(request.args.get('limit', Config.API_DEFAULT_PAGE_SIZE)), Config.API_MAX_PAGE_SIZE)
        offset = int(request.args.get('offset', 0))
        name_filter = request.args.get('name')
        actor_filter = request.args.get('actor')
        
        # Build query filters
        filters = []
        query_params = []
        
        if name_filter:
            filters.append("name LIKE @name_filter")
            query_params.append(bigquery.ScalarQueryParameter("name_filter", "STRING", f"%{name_filter}%"))
            
        if actor_filter:
            filters.append("threat_actor_ids LIKE @actor_filter")
            query_params.append(bigquery.ScalarQueryParameter("actor_filter", "STRING", f"%{actor_filter}%"))
        
        # Build query
        query = f"""
            SELECT * FROM `{Config.get_table_name('campaigns')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
            ORDER BY first_seen DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        # Get count query
        count_query = f"""
            SELECT COUNT(*) as count FROM `{Config.get_table_name('campaigns')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
        """
        
        # Execute queries
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        count_job = bq_client.query(count_query, job_config=job_config)
        count_result = list(count_job)[0]
        total_count = count_result['count']
        
        results_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in results_job]
        
        return jsonify({
            'campaigns': results,
            'count': len(results),
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error querying campaigns: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve campaigns: {str(e)}"}), 500

@api_blueprint.route('/malware', methods=['GET'])
@require_api_key
@limiter.limit(Config.API_RATE_LIMIT)
def get_malware():
    """Get malware information."""
    try:
        # Get query parameters with defaults
        limit = min(int(request.args.get('limit', Config.API_DEFAULT_PAGE_SIZE)), Config.API_MAX_PAGE_SIZE)
        offset = int(request.args.get('offset', 0))
        name_filter = request.args.get('name')
        type_filter = request.args.get('type')
        hash_filter = request.args.get('hash')
        
        # Build query filters
        filters = []
        query_params = []
        
        if name_filter:
            filters.append("(name LIKE @name_filter OR aliases LIKE @name_filter)")
            query_params.append(bigquery.ScalarQueryParameter("name_filter", "STRING", f"%{name_filter}%"))
            
        if type_filter:
            filters.append("malware_type = @type_filter")
            query_params.append(bigquery.ScalarQueryParameter("type_filter", "STRING", type_filter))
            
        if hash_filter:
            filters.append("(md5 = @hash_filter OR sha1 = @hash_filter OR sha256 = @hash_filter)")
            query_params.append(bigquery.ScalarQueryParameter("hash_filter", "STRING", hash_filter))
        
        # Build query
        query = f"""
            SELECT * FROM `{Config.get_table_name('malware')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
            ORDER BY first_seen DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        # Get count query
        count_query = f"""
            SELECT COUNT(*) as count FROM `{Config.get_table_name('malware')}`
            {f"WHERE {' AND '.join(filters)}" if filters else ""}
        """
        
        # Execute queries
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        count_job = bq_client.query(count_query, job_config=job_config)
        count_result = list(count_job)[0]
        total_count = count_result['count']
        
        results_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in results_job]
        
        return jsonify({
            'malware': results,
            'count': len(results),
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error querying malware: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve malware: {str(e)}"}), 500

# -------------------- Detail Endpoints --------------------

@api_blueprint.route('/indicators/<indicator_id>', methods=['GET'])
@require_api_key
def get_indicator_detail(indicator_id):
    """Get detailed information about a specific indicator."""
    try:
        query = f"""
            SELECT * FROM `{Config.get_table_name('indicators')}`
            WHERE id = @indicator_id
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator_id", "STRING", indicator_id)
            ]
        )
        
        query_job = bq_client.query(query, job_config=job_config)
        results = list(query_job)
        
        if not results:
            return jsonify({"error": "Indicator not found"}), 404
            
        indicator = format_bq_row(results[0])
        
        # Get related entities
        related_malware_query = f"""
            SELECT m.* FROM `{Config.get_table_name('malware')}` m
            JOIN `{Config.get_table_name('indicators')}` i
            ON REGEXP_CONTAINS(i.related_malware_ids, m.id)
            WHERE i.id = @indicator_id
        """
        
        related_malware_job = bq_client.query(related_malware_query, job_config=job_config)
        related_malware = [format_bq_row(row) for row in related_malware_job]
        
        indicator['related_malware'] = related_malware
        
        return jsonify(indicator)
    
    except Exception as e:
        logger.error(f"Error getting indicator detail: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve indicator detail: {str(e)}"}), 500

@api_blueprint.route('/vulnerabilities/<cve_id>', methods=['GET'])
@require_api_key
def get_vulnerability_detail(cve_id):
    """Get detailed information about a specific vulnerability."""
    try:
        query = f"""
            SELECT * FROM `{Config.get_table_name('vulnerabilities')}`
            WHERE cve_id = @cve_id
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("cve_id", "STRING", cve_id)
            ]
        )
        
        query_job = bq_client.query(query, job_config=job_config)
        results = list(query_job)
        
        if not results:
            return jsonify({"error": "Vulnerability not found"}), 404
            
        vulnerability = format_bq_row(results[0])
        
        # Get related indicators
        related_indicators_query = f"""
            SELECT * FROM `{Config.get_table_name('indicators')}`
            WHERE related_vulnerabilities LIKE @vuln_pattern
            LIMIT 100
        """
        
        related_indicators_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("vuln_pattern", "STRING", f"%{cve_id}%")
            ]
        )
        
        related_indicators_job = bq_client.query(related_indicators_query, job_config=related_indicators_config)
        related_indicators = [format_bq_row(row) for row in related_indicators_job]
        
        vulnerability['related_indicators'] = related_indicators
        
        return jsonify(vulnerability)
    
    except Exception as e:
        logger.error(f"Error getting vulnerability detail: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to retrieve vulnerability detail: {str(e)}"}), 500

# -------------------- Admin API Endpoints --------------------

@api_blueprint.route('/admin/ingest', methods=['POST'])
@require_api_key
def trigger_ingest():
    """Trigger data ingestion process."""
    try:
        data = request.get_json() or {}
        process_all = data.get('process_all', False)
        feed_id = data.get('feed_id')
        
        # Validate feed_id if provided
        if feed_id and not Config.get_feed_by_id(feed_id):
            return jsonify({"error": f"Invalid feed_id: {feed_id}"}), 400
        
        # Import ingestion module
        try:
            import ingestion
            
            # Start ingestion in background thread for better responsiveness
            if process_all:
                # Process all feeds
                thread = ingestion.trigger_ingestion_in_background()
                return jsonify({
                    "message": "Ingestion process triggered for all feeds",
                    "status": "running"
                })
            elif feed_id:
                # Process specific feed
                result = ingestion.ingest_feed(feed_id)
                return jsonify({
                    "message": f"Processed feed {feed_id}",
                    "status": result["status"],
                    "details": result
                })
            else:
                return jsonify({"error": "Must specify feed_id or set process_all=true"}), 400
                
        except ImportError:
            # Fall back to Pub/Sub if ingestion module can't be imported directly
            # Prepare message for Pub/Sub
            message = {
                "operation": "ingest",
                "timestamp": datetime.utcnow().isoformat(),
                "process_all": process_all,
                "feed_id": feed_id
            }
            
            # Publish message to trigger Cloud Function
            message_id = publish_to_topic(Config.PUBSUB_TOPIC, message)
            
            return jsonify({
                "message": "Ingestion process triggered",
                "message_id": message_id,
                "process_all": process_all,
                "feed_id": feed_id
            })
    
    except Exception as e:
        logger.error(f"Error triggering ingestion: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to trigger ingestion: {str(e)}"}), 500

@api_blueprint.route('/admin/analyze', methods=['POST'])
@require_api_key
def trigger_analysis():
    """Trigger threat data analysis process."""
    try:
        data = request.get_json() or {}
        indicator_ids = data.get('indicator_ids', [])
        analyze_all = data.get('analyze_all', False)
        force_reanalysis = data.get('force_reanalysis', False)
        
        if not analyze_all and not indicator_ids:
            return jsonify({"error": "Must provide indicator_ids or set analyze_all=true"}), 400
            
        # Limit the number of indicators that can be analyzed at once
        if len(indicator_ids) > Config.ANALYSIS_MAX_INDICATORS_PER_BATCH:
            return jsonify({
                "error": f"Too many indicators to analyze at once. Maximum is {Config.ANALYSIS_MAX_INDICATORS_PER_BATCH}"
            }), 400
        
        # Try to import analysis module directly
        try:
            import analysis
            
            if analyze_all:
                # Find indicators for analysis
                indicators_to_analyze = analysis.find_indicators_for_analysis(
                    limit=min(1000, Config.ANALYSIS_MAX_INDICATORS_PER_BATCH)
                )
                
                if not indicators_to_analyze:
                    return jsonify({
                        "message": "No indicators found that need analysis",
                        "status": "skipped"
                    })
                    
                # Start analysis in background
                thread = threading.Thread(
                    target=analysis.analyze_threat_data,
                    args=({
                        "indicator_ids": indicators_to_analyze,
                        "force_reanalysis": force_reanalysis
                    },)
                )
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    "message": f"Analysis process triggered for {len(indicators_to_analyze)} indicators",
                    "status": "running"
                })
                
            else:
                # Analyze specific indicators
                result = analysis.analyze_threat_data({
                    "indicator_ids": indicator_ids,
                    "force_reanalysis": force_reanalysis
                })
                
                return jsonify({
                    "message": "Analysis process completed",
                    "status": "success", 
                    "results": result
                })
                
        except ImportError:
            # Fall back to Pub/Sub if analysis module can't be imported directly
            # Prepare message for Pub/Sub
            message = {
                "operation": "analyze",
                "timestamp": datetime.utcnow().isoformat(),
                "analyze_all": analyze_all,
                "force_reanalysis": force_reanalysis,
                "indicator_ids": indicator_ids
            }
            
            # Publish message to trigger Cloud Function
            message_id = publish_to_topic(Config.PUBSUB_ANALYSIS_TOPIC, message)
            
            return jsonify({
                "message": "Analysis process triggered",
                "message_id": message_id,
                "analyze_all": analyze_all,
                "indicator_count": len(indicator_ids) if not analyze_all else "all"
            })
    
    except Exception as e:
        logger.error(f"Error triggering analysis: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to trigger analysis: {str(e)}"}), 500

@api_blueprint.route('/admin/export', methods=['POST'])
@require_api_key
def export_data():
    """Export threat intelligence data."""
    try:
        data = request.get_json() or {}
        export_type = data.get('type', 'indicators')
        export_format = data.get('format', 'json')
        filters = data.get('filters', {})
        
        if export_format not in Config.EXPORT_FORMATS:
            return jsonify({"error": f"Invalid export format. Supported formats: {', '.join(Config.EXPORT_FORMATS)}"}), 400
            
        if export_type not in Config.BIGQUERY_TABLES:
            return jsonify({"error": f"Invalid export type. Supported types: {', '.join(Config.BIGQUERY_TABLES.keys())}"}), 400
            
        # Prepare message for Pub/Sub to trigger export
        message = {
            "operation": "export",
            "timestamp": datetime.utcnow().isoformat(),
            "export_type": export_type,
            "export_format": export_format,
            "filters": filters
        }
        
        # Publish message
        message_id = publish_to_topic(Config.PUBSUB_TOPIC, message)
        
        # For immediate exports of small datasets, we could implement direct export logic here
        
        return jsonify({
            "message": "Export process triggered",
            "message_id": message_id,
            "export_type": export_type,
            "export_format": export_format
        })
    
    except Exception as e:
        logger.error(f"Error triggering export: {str(e)}")
        report_error(e)
        return jsonify({"error": f"Failed to trigger export: {str(e)}"}), 500

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
