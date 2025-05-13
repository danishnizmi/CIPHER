"""
Production-ready API module for threat intelligence platform.
Provides RESTful endpoints for accessing threat intelligence data and analysis results.
Public-facing endpoints only.
"""

import os
import json
import logging
import traceback
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from functools import wraps
from cachetools import TTLCache
import hashlib

from flask import Blueprint, jsonify, request, current_app, abort, Response, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound, TooManyRequests
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound as GCPNotFound
import google.auth

# Import configuration
from config import Config, ServiceManager, ServiceStatus, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Create API blueprint
api_blueprint = Blueprint('api', __name__)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=current_app,
    default_limits=["2000 per day", "200 per hour"],  # More generous for public
    storage_uri="memory://",
    swallow_errors=True
)

# Cache for expensive queries
query_cache = TTLCache(maxsize=1000, ttl=300)  # 5-minute TTL
cache_stats = {"hits": 0, "misses": 0, "size": 0}

# Public read-only endpoints - no admin functionality
PUBLIC_ENDPOINTS = [
    '/health', 
    '/stats', 
    '/feeds', 
    '/iocs', 
    '/ai/analyses', 
    '/ai/summary', 
    '/threat_summary', 
    '/iocs/geo'
]

# API Key Authentication decorator
def require_api_key(f):
    """Decorator to require valid API key for endpoint access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Handle CORS preflight requests
        if request.method == 'OPTIONS':
            return '', 200
            
        # Check if this is a public endpoint
        is_public_endpoint = any(request.path.endswith(endpoint) for endpoint in PUBLIC_ENDPOINTS)
        
        # Get API key from header
        api_key = request.headers.get('X-API-Key')
        
        # For public endpoints, use default key if none provided
        if not api_key and is_public_endpoint:
            api_key = 'default-api-key'
            
        if not api_key:
            logger.warning(f"API request without key from {get_remote_address()}")
            return jsonify({'error': 'No API key provided'}), 401
        
        # Clean the API key
        api_key = api_key.strip().strip('"\'')
        
        # Get expected key from config
        expected_key = Config.API_KEY
        if expected_key:
            expected_key = expected_key.strip()
        
        # Allow default key for public endpoints
        if is_public_endpoint and (api_key == 'default-api-key' or not expected_key):
            return f(*args, **kwargs)
        
        # Special handling for development/testing
        if Config.ENVIRONMENT != 'production':
            if api_key in ['default-api-key', 'test-key']:
                return f(*args, **kwargs)
        
        # Validate API key for protected endpoints (none in this public API)
        if api_key != expected_key and expected_key and not is_public_endpoint:
            logger.warning(f"Invalid API key attempt from {get_remote_address()}")
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Cache decorator for expensive operations
def cache_response(ttl=300):
    """Decorator to cache API responses."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate cache key
            cache_key = f"{f.__name__}:{hash(str(sorted(request.args.items())))}"
            
            # Check cache
            if cache_key in query_cache:
                cache_stats["hits"] += 1
                logger.debug(f"Cache hit for {f.__name__}")
                return query_cache[cache_key]
            
            # Execute function
            result = f(*args, **kwargs)
            
            # Cache successful responses only
            if isinstance(result, tuple):
                response, status_code = result
                if status_code == 200:
                    query_cache[cache_key] = result
                    cache_stats["misses"] += 1
            elif not isinstance(result, Response) or result.status_code == 200:
                query_cache[cache_key] = result
                cache_stats["misses"] += 1
            
            cache_stats["size"] = len(query_cache)
            return result
        return decorated_function
    return decorator

# Validation helpers
def validate_days_parameter(days_str: str, max_days: int = 365) -> int:
    """Validate and return days parameter."""
    try:
        days = int(days_str)
        if days < 1:
            raise ValueError("Days must be positive")
        if days > max_days:
            raise ValueError(f"Days cannot exceed {max_days}")
        return days
    except (ValueError, TypeError) as e:
        raise BadRequest(f"Invalid days parameter: {e}")

def validate_limit_parameter(limit_str: str, max_limit: int = 10000) -> int:
    """Validate and return limit parameter."""
    try:
        limit = int(limit_str)
        if limit < 1:
            raise ValueError("Limit must be positive")
        if limit > max_limit:
            raise ValueError(f"Limit cannot exceed {max_limit}")
        return limit
    except (ValueError, TypeError) as e:
        raise BadRequest(f"Invalid limit parameter: {e}")

# Helper Functions
def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    return (
        service_manager.get_client('bigquery'),
        service_manager.get_client('storage'),
        service_manager.get_client('publisher'),
        service_manager.get_client('subscriber')
    )

def format_bq_row(row: Dict) -> Dict:
    """Format BigQuery row for JSON response."""
    formatted = {}
    for key, value in dict(row).items():
        if isinstance(value, datetime):
            formatted[key] = value.isoformat()
        elif hasattr(value, 'isoformat'):
            formatted[key] = value.isoformat()
        elif value is None:
            formatted[key] = None
        else:
            formatted[key] = value
    return formatted

def execute_bq_query(query: str, params: Optional[List] = None, cache_ttl: int = 300) -> List[Dict]:
    """Execute BigQuery query with caching and return formatted results."""
    # Generate cache key for query
    cache_key = hashlib.sha256(f"{query}:{str(params)}".encode()).hexdigest()
    
    # Check cache first
    if cache_key in query_cache:
        cache_stats["hits"] += 1
        return query_cache[cache_key]
    
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        raise Exception("BigQuery client not initialized")
    
    job_config = bigquery.QueryJobConfig(
        query_parameters=params if params else [],
        use_query_cache=True,
        maximum_bytes_billed=Config.BIGQUERY_MAX_BYTES_BILLED
    )
    
    try:
        start_time = time.time()
        query_job = bq_client.query(query, job_config=job_config)
        results = [format_bq_row(row) for row in query_job]
        
        # Log slow queries
        execution_time = time.time() - start_time
        if execution_time > 5:
            logger.warning(f"Slow query executed in {execution_time:.2f}s: {query[:100]}...")
        
        # Cache successful results
        query_cache[cache_key] = results
        cache_stats["misses"] += 1
        cache_stats["size"] = len(query_cache)
        
        return results
    except Exception as e:
        logger.error(f"Error executing BigQuery query: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(f"Query: {query}")
            logger.error(traceback.format_exc())
        report_error(e)
        raise

def check_table_exists(table_name: str) -> bool:
    """Check if BigQuery table exists and is accessible."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        return False
    
    try:
        full_table_id = Config.get_table_name(table_name)
        if not full_table_id:
            return False
        
        # Try to get table info
        table = bq_client.get_table(full_table_id)
        
        # Try a simple query to verify access
        test_query = f"SELECT COUNT(*) as count FROM `{full_table_id}` LIMIT 1"
        bq_client.query(test_query).result()
        
        return True
    except (GCPNotFound, Exception) as e:
        logger.debug(f"Table check failed for {table_name}: {e}")
        return False

# ==================== API Endpoints ====================

@api_blueprint.route('/health', methods=['GET'])
def api_health_check():
    """Comprehensive API health check."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    # Check critical tables
    tables_status = {}
    critical_tables = ['indicators', 'batch_analysis']
    
    for table in critical_tables:
        tables_status[table] = check_table_exists(table)
    
    health_data = {
        'status': status['overall'],
        'timestamp': datetime.utcnow().isoformat(),
        'api_version': Config.VERSION,
        'services': {
            'bigquery': status['services'].get('bigquery', 'unknown'),
            'storage': status['services'].get('storage', 'unknown'),
            'pubsub': status['services'].get('pubsub', 'unknown'),
            'ai_models': status['services'].get('ai_models', 'unknown'),
            'analysis': status['services'].get('analysis', 'unknown')
        },
        'tables': tables_status,
        'cache_stats': dict(cache_stats),
        'environment': Config.ENVIRONMENT
    }
    
    # Determine HTTP status code
    if status['overall'] == ServiceStatus.READY.value and all(tables_status.values()):
        return jsonify(health_data), 200
    elif status['overall'] == ServiceStatus.ERROR.value:
        return jsonify(health_data), 503
    else:
        return jsonify(health_data), 206  # Partial content

@api_blueprint.route('/stats', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=600)  # 10-minute cache
def get_stats():
    """Get comprehensive platform statistics."""
    try:
        days = validate_days_parameter(request.args.get('days', '30'))
        
        # Default response structure
        stats = {
            'feeds': {'total_sources': 0, 'growth_rate': 0},
            'iocs': {'total': 0, 'growth_rate': 0, 'types': []},
            'analyses': {'total_analyses': 0, 'growth_rate': 0},
            'batch_analyses': {'total': 0, 'growth_rate': 0},
            'timestamp': datetime.utcnow().isoformat(),
            'visualization_data': {'daily_counts': []},
            'period_days': days
        }
        
        # Check if tables exist
        if not check_table_exists('indicators'):
            logger.warning("Indicators table not ready, returning default stats")
            return jsonify(stats)
        
        # Feeds count query
        feeds_query = f"""
        SELECT COUNT(DISTINCT feed_id) as total_sources
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        try:
            feed_results = execute_bq_query(feeds_query)
            if feed_results:
                stats['feeds']['total_sources'] = feed_results[0].get('total_sources', 0)
        except Exception as e:
            logger.error(f"Error querying feeds: {e}")
        
        # IOCs count and types
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
        
        try:
            ioc_results = execute_bq_query(ioc_query)
            if ioc_results:
                stats['iocs']['total'] = sum(row.get('count', 0) for row in ioc_results)
                stats['iocs']['types'] = [
                    {'type': row['type'], 'count': row['count']} 
                    for row in ioc_results
                ]
        except Exception as e:
            logger.error(f"Error querying IOCs: {e}")
        
        # Batch analyses count
        if check_table_exists('batch_analysis'):
            batch_query = f"""
            SELECT COUNT(*) as total_analyses
            FROM `{Config.get_table_name('batch_analysis')}`
            WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            """
            
            try:
                batch_results = execute_bq_query(batch_query)
                if batch_results:
                    stats['batch_analyses']['total'] = batch_results[0].get('total_analyses', 0)
                    stats['analyses']['total_analyses'] = batch_results[0].get('total_analyses', 0)
            except Exception as e:
                logger.error(f"Error querying batch analyses: {e}")
        
        # Daily activity visualization data
        daily_query = f"""
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY date
        ORDER BY date
        """
        
        try:
            daily_results = execute_bq_query(daily_query)
            if daily_results:
                stats['visualization_data']['daily_counts'] = [
                    {'date': str(row['date']), 'count': row['count']}
                    for row in daily_results
                ]
        except Exception as e:
            logger.error(f"Error querying daily activity: {e}")
        
        return jsonify(stats)
        
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/feeds', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=300)
def get_feeds():
    """Get feed information with statistics."""
    try:
        feed_details = []
        
        # Get configured feeds
        feeds = getattr(Config, 'FEEDS', [])
        
        for feed in feeds:
            feed_detail = {
                'id': feed.get('id'),
                'name': feed.get('name'),
                'description': feed.get('description'),
                'record_count': 0,
                'last_updated': None,
                'enabled': feed.get('enabled', True),
                'format': feed.get('format', 'json'),
                'update_frequency': feed.get('update_frequency', 'daily'),
                'type': feed.get('type', 'mixed')
            }
            
            # Get statistics for each feed
            if check_table_exists('indicators'):
                feed_query = f"""
                SELECT 
                    COUNT(*) as count,
                    MAX(created_at) as last_updated
                FROM `{Config.get_table_name('indicators')}`
                WHERE feed_id = @feed_id
                """
                
                params = [bigquery.ScalarQueryParameter("feed_id", "STRING", feed.get('id'))]
                
                try:
                    feed_results = execute_bq_query(feed_query, params)
                    if feed_results:
                        feed_detail['record_count'] = feed_results[0].get('count', 0)
                        feed_detail['last_updated'] = feed_results[0].get('last_updated')
                except Exception as e:
                    logger.error(f"Error querying feed {feed.get('id')}: {e}")
            
            feed_details.append(feed_detail)
        
        return jsonify({
            'feeds': feed_details,
            'count': len(feed_details),
            'feed_details': feed_details
        })
        
    except Exception as e:
        logger.error(f"Error getting feeds: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/iocs', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=300)
def get_iocs():
    """Get IOC data with filtering and pagination."""
    try:
        # Validate parameters
        days = validate_days_parameter(request.args.get('days', '30'))
        limit = validate_limit_parameter(request.args.get('limit', '100'))
        offset = int(request.args.get('offset', '0'))
        ioc_type = request.args.get('type', '').strip()
        ioc_value = request.args.get('value', '').strip()
        
        # Default response
        default_response = {
            'records': [],
            'count': 0,
            'total_count': 0,
            'offset': offset,
            'limit': limit
        }
        
        if not check_table_exists('indicators'):
            logger.warning("Indicators table not ready")
            return jsonify(default_response)
        
        # Build query conditions
        where_conditions = [
            f"created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)"
        ]
        params = []
        
        if ioc_type:
            where_conditions.append("type = @ioc_type")
            params.append(bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type))
        
        if ioc_value:
            where_conditions.append("value LIKE @ioc_value")
            params.append(bigquery.ScalarQueryParameter("ioc_value", "STRING", f"%{ioc_value}%"))
        
        # Main query
        ioc_query = f"""
        SELECT *
        FROM `{Config.get_table_name('indicators')}`
        WHERE {" AND ".join(where_conditions)}
        ORDER BY risk_score DESC, created_at DESC
        LIMIT {limit}
        OFFSET {offset}
        """
        
        iocs = execute_bq_query(ioc_query, params)
        
        # Process IOCs for frontend display
        for ioc in iocs:
            # Ensure required fields
            if 'risk_score' not in ioc or ioc['risk_score'] is None:
                ioc['risk_score'] = 50
            
            if 'confidence' not in ioc or ioc['confidence'] is None:
                ioc['confidence'] = 50
            
            # Add computed fields
            ioc['ai_analyzed'] = bool(ioc.get('last_analyzed'))
            
            # Format tags if needed
            if 'tags' in ioc and isinstance(ioc['tags'], str):
                try:
                    ioc['tags'] = json.loads(ioc['tags'])
                except:
                    ioc['tags'] = []
        
        # Get total count for pagination
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
            'total_count': total_count,
            'offset': offset,
            'limit': limit,
            'filters': {
                'days': days,
                'type': ioc_type,
                'value': ioc_value
            }
        })
        
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error getting IOCs: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/ai/analyses', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=300)
def get_ai_analyses():
    """Get batch AI analysis data."""
    try:
        days = validate_days_parameter(request.args.get('days', '30'))
        
        # Import the analysis function
        from analysis import get_batch_analysis_summary
        
        batch_summary = get_batch_analysis_summary(days)
        
        if batch_summary.get('error'):
            return jsonify({
                'overall_threat_level': 'Medium',
                'total_feeds_analyzed': 0,
                'batch_analyses': [],
                'threat_level_distribution': [],
                'last_run_time': None,
                'error': batch_summary['error']
            })
        
        # Transform for frontend compatibility
        ai_analyses = {
            'overall_threat_level': 'Medium',
            'total_feeds_analyzed': batch_summary.get('total_feeds_analyzed', 0),
            'batch_analyses': batch_summary.get('feeds', []),
            'threat_level_distribution': batch_summary.get('threat_level_distribution', []),
            'analysis_trends': batch_summary.get('analysis_trends', []),
            'summary_stats': batch_summary.get('summary_stats', {}),
            'last_run_time': None,
            'is_batch_analysis': True,
            'period_days': days
        }
        
        # Determine overall threat level from distribution
        threat_counts = {
            item['threat_level']: item['count'] 
            for item in batch_summary.get('threat_level_distribution', [])
        }
        
        total_analyses = sum(threat_counts.values())
        if total_analyses > 0:
            critical_pct = (threat_counts.get('critical', 0) / total_analyses) * 100
            high_pct = (threat_counts.get('high', 0) / total_analyses) * 100
            
            if critical_pct > 20:
                ai_analyses['overall_threat_level'] = 'Critical'
            elif high_pct > 40 or critical_pct > 5:
                ai_analyses['overall_threat_level'] = 'High'
            elif threat_counts.get('low', 0) > threat_counts.get('medium', 0):
                ai_analyses['overall_threat_level'] = 'Low'
        
        # Get most recent analysis timestamp
        if ai_analyses['batch_analyses']:
            most_recent_list = [
                analysis['last_analysis'] 
                for analysis in ai_analyses['batch_analyses'] 
                if analysis.get('last_analysis')
            ]
            if most_recent_list:
                ai_analyses['last_run_time'] = max(most_recent_list)
        
        return jsonify(ai_analyses)
        
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error getting AI analyses: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/threat_summary', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=300)
def get_threat_summary():
    """Get comprehensive threat summary."""
    try:
        days = validate_days_parameter(request.args.get('days', '30'))
        
        threat_summary = {
            'overall_score': 50,
            'threat_level': 'Medium',
            'active_threats': 0,
            'critical_indicators': 0,
            'trending_ioc_types': [],
            'top_threat_actors': [],
            'top_malware_families': [],
            'risk_trend': 'stable',
            'period_days': days
        }
        
        if not check_table_exists('indicators'):
            return jsonify(threat_summary)
        
        # Calculate threat metrics
        summary_query = f"""
        SELECT 
            AVG(risk_score) as avg_risk_score,
            COUNT(CASE WHEN risk_score > 80 THEN 1 END) as critical_count,
            COUNT(DISTINCT CASE WHEN threat_actor IS NOT NULL THEN threat_actor END) as active_threat_actors,
            COUNT(DISTINCT CASE WHEN malware IS NOT NULL THEN malware END) as malware_families
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        try:
            results = execute_bq_query(summary_query)
            if results:
                row = results[0]
                threat_summary['overall_score'] = int(row.get('avg_risk_score', 50))
                threat_summary['critical_indicators'] = row.get('critical_count', 0)
                threat_summary['active_threats'] = (
                    row.get('active_threat_actors', 0) + row.get('malware_families', 0)
                )
        except Exception as e:
            logger.error(f"Error querying threat metrics: {e}")
        
        # Determine threat level
        score = threat_summary['overall_score']
        if score > 85:
            threat_summary['threat_level'] = 'Critical'
        elif score > 70:
            threat_summary['threat_level'] = 'High'
        elif score > 40:
            threat_summary['threat_level'] = 'Medium'
        else:
            threat_summary['threat_level'] = 'Low'
        
        # Get trending IOC types
        trending_query = f"""
        SELECT 
            type,
            COUNT(*) as count,
            AVG(risk_score) as avg_risk_score
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY type
        ORDER BY count DESC
        LIMIT 5
        """
        
        try:
            trending_results = execute_bq_query(trending_query)
            threat_summary['trending_ioc_types'] = trending_results
        except Exception as e:
            logger.error(f"Error querying trending IOCs: {e}")
        
        # Get top threat actors
        actors_query = f"""
        SELECT threat_actor, COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND threat_actor IS NOT NULL
        GROUP BY threat_actor
        ORDER BY count DESC
        LIMIT 5
        """
        
        try:
            actors_results = execute_bq_query(actors_query)
            threat_summary['top_threat_actors'] = actors_results
        except Exception as e:
            logger.error(f"Error querying threat actors: {e}")
        
        # Get top malware families
        malware_query = f"""
        SELECT malware, COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND malware IS NOT NULL
        GROUP BY malware
        ORDER BY count DESC
        LIMIT 5
        """
        
        try:
            malware_results = execute_bq_query(malware_query)
            threat_summary['top_malware_families'] = malware_results
        except Exception as e:
            logger.error(f"Error querying malware families: {e}")
        
        return jsonify(threat_summary)
        
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error getting threat summary: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/ai/summary', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=300)
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
        
        if not check_table_exists('indicators'):
            return jsonify(ai_summary)
        
        # Get critical indicators count
        critical_query = f"""
        SELECT COUNT(*) as critical_count
        FROM `{Config.get_table_name('indicators')}`
        WHERE risk_score > 80
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        """
        
        try:
            results = execute_bq_query(critical_query)
            if results:
                ai_summary['critical_indicators'] = results[0].get('critical_count', 0)
        except Exception as e:
            logger.error(f"Error querying critical indicators: {e}")
        
        # Determine risk level
        if ai_summary['critical_indicators'] > 100:
            ai_summary['risk_level'] = 'Critical'
        elif ai_summary['critical_indicators'] > 50:
            ai_summary['risk_level'] = 'High'
        elif ai_summary['critical_indicators'] > 10:
            ai_summary['risk_level'] = 'Medium'
        else:
            ai_summary['risk_level'] = 'Low'
        
        # Get trending threats
        threats_query = f"""
        SELECT malware, threat_type, COUNT(*) as count
        FROM `{Config.get_table_name('indicators')}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        AND (malware IS NOT NULL OR threat_type IS NOT NULL)
        GROUP BY malware, threat_type
        ORDER BY count DESC
        LIMIT 3
        """
        
        try:
            threat_results = execute_bq_query(threats_query)
            if threat_results:
                threats = []
                for threat in threat_results:
                    name = threat.get('malware') or threat.get('threat_type')
                    if name:
                        threats.append(name)
                
                if threats:
                    ai_summary['trending_threats'] = ', '.join(threats[:3])
        except Exception as e:
            logger.error(f"Error querying trending threats: {e}")
        
        # Generate key findings
        if ai_summary['critical_indicators'] > 50:
            ai_summary['key_findings'].append(
                f"High volume of critical indicators detected ({ai_summary['critical_indicators']})"
            )
        
        if ai_summary['trending_threats'] != 'None detected':
            ai_summary['key_findings'].append(
                f"Active malware families: {ai_summary['trending_threats']}"
            )
        
        if not ai_summary['key_findings']:
            ai_summary['key_findings'].append("No significant threats detected")
        
        return jsonify(ai_summary)
        
    except Exception as e:
        logger.error(f"Error getting AI summary: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/iocs/geo', methods=['GET'])
@limiter.limit("60 per minute")
@require_api_key
@cache_response(ttl=600)
def get_iocs_geo():
    """Get geographical statistics for IOCs."""
    try:
        days = validate_days_parameter(request.args.get('days', '30'))
        
        # Mock geographic data for demonstration
        # In production, this would require IP geolocation enrichment
        geo_stats = {
            'countries': [
                {'country': 'US', 'count': 150, 'risk_level': 'high'},
                {'country': 'RU', 'count': 120, 'risk_level': 'critical'},
                {'country': 'CN', 'count': 100, 'risk_level': 'high'},
                {'country': 'DE', 'count': 50, 'risk_level': 'medium'},
                {'country': 'GB', 'count': 45, 'risk_level': 'medium'}
            ],
            'top_sources': [],
            'threat_map_data': []
        }
        
        return jsonify(geo_stats)
        
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error getting geo stats: {str(e)}")
        report_error(e)
        return jsonify({"error": "Internal server error"}), 500

# ==================== Error Handlers ====================

@api_blueprint.errorhandler(400)
def bad_request(e):
    """Handle 400 errors."""
    logger.warning(f"Bad request: {e}")
    return jsonify({"error": "Bad request", "message": str(e)}), 400

@api_blueprint.errorhandler(401)
def unauthorized(e):
    """Handle 401 errors."""
    logger.warning(f"Unauthorized access attempt: {get_remote_address()}")
    return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401

@api_blueprint.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    logger.info(f"Resource not found: {request.path}")
    return jsonify({"error": "Not found", "message": "Resource not found"}), 404

@api_blueprint.errorhandler(429)
def too_many_requests(e):
    """Handle 429 errors."""
    logger.warning(f"Rate limit exceeded: {get_remote_address()}")
    return jsonify({
        "error": "Too many requests", 
        "message": "Rate limit exceeded. Please try again later.",
        "retry_after": 60
    }), 429

@api_blueprint.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(e)}")
    logger.error(traceback.format_exc())
    report_error(e)
    return jsonify({
        "error": "Internal server error", 
        "message": "An unexpected error occurred"
    }), 500

# ==================== Blueprint Hooks ====================

@api_blueprint.before_request
def before_api_request():
    """Update API service status before each request."""
    service_manager = Config.get_service_manager()
    service_manager.update_status('api', ServiceStatus.READY)
    
    # Log requests in development
    if Config.ENVIRONMENT != 'production':
        logger.debug(f"API request: {request.method} {request.path}")

@api_blueprint.after_request
def after_api_request(response):
    """Add CORS headers and log responses."""
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    
    # Add cache headers for GET requests
    if request.method == 'GET' and response.status_code == 200:
        response.headers['Cache-Control'] = 'public, max-age=300'
    
    return response

@api_blueprint.teardown_request
def teardown_api_request(exception=None):
    """Handle API request teardown."""
    if exception:
        logger.error(f"API request failed with exception: {exception}")
        service_manager = Config.get_service_manager()
        service_manager.update_status('api', ServiceStatus.DEGRADED)

# Initialize rate limiter with the blueprint
limiter.init_app(current_app)
