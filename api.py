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

# Initialize rate limiter for cost efficiency
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"]
)

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
    """Execute BigQuery query and return formatted results with improved error handling."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        raise Exception("Database connection unavailable")
    
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
        # Return empty result instead of raising, to prevent API errors
        return []

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
    """Check if BigQuery table exists with improved reliability."""
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
        table = bq_client.get_table(table_ref)
        
        # Try a simple query to verify the table can be queried
        test_query = f"SELECT COUNT(*) as count FROM `{full_table_id}` LIMIT 1"
        bq_client.query(test_query).result()
        
        return True
    except NotFound:
        return False
    except Exception as e:
        logger.error(f"Error checking table {table_name}: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        return False

def verify_bigquery_tables() -> bool:
    """Verify that all required BigQuery tables exist and are queryable."""
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    required_tables = ['indicators', 'vulnerabilities', 'threat_actors', 'campaigns', 'malware']
    missing_tables = []
    
    for table_name in required_tables:
        if not check_table_exists(table_name):
            missing_tables.append(table_name)
    
    if missing_tables:
        logger.warning(f"The following tables are missing or not accessible: {', '.join(missing_tables)}")
        return False
    
    return True

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
@limiter.limit("30 per minute")
def get_stats():
    """Get platform statistics."""
    try:
        days = int(request.args.get('days', 30))
        
        # First verify BigQuery tables exist
        if not verify_bigquery_tables():
            # Try to trigger initialization through ingestion module
            try:
                from ingestion import initialize_bigquery_tables
                initialize_bigquery_tables()
            except Exception as import_err:
                logger.error(f"Error importing initialization function: {str(import_err)}")
        
        # Get actual stats from BigQuery
        stats = {
            'feeds': {'total_sources': 0, 'growth_rate': 0},
            'iocs': {'total': 0, 'growth_rate': 0, 'types': []},
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
        
        # Query for AI analyses count
        analyses_query = """
        SELECT COUNT(*) as total_analyses
        FROM `{table_id}`
        WHERE last_analyzed IS NOT NULL
        AND last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        analyses_results = execute_bq_query(analyses_query)
        if analyses_results:
            stats['analyses']['total_analyses'] = analyses_results[0].get('total_analyses', 0)
        
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
        
        # Calculate growth rates
        if days > 7:
            growth_query = """
            WITH recent AS (
                SELECT COUNT(*) as recent_count
                FROM `{table_id}`
                WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
            ),
            previous AS (
                SELECT COUNT(*) as previous_count
                FROM `{table_id}`
                WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 14 DAY)
                AND created_at < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
            )
            SELECT 
                recent.recent_count,
                previous.previous_count,
                CASE 
                    WHEN previous.previous_count > 0 THEN 
                        ROUND((recent.recent_count - previous.previous_count) * 100.0 / previous.previous_count, 1)
                    ELSE 0
                END as growth_rate
            FROM recent, previous
            """.format(table_id=Config.get_table_name('indicators'))
            
            growth_results = execute_bq_query(growth_query)
            if growth_results:
                stats['iocs']['growth_rate'] = growth_results[0].get('growth_rate', 0)
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Feeds Endpoint --------------------

@api_blueprint.route('/feeds', methods=['GET'])
@limiter.limit("30 per minute")
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
                'enabled': feed.get('enabled', True),
                'format': feed.get('format', 'json'),
                'update_frequency': feed.get('update_frequency', 'daily')
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

# -------------------- IOCs Endpoints --------------------

@api_blueprint.route('/iocs', methods=['GET'])
@limiter.limit("30 per minute")
def get_iocs():
    """Get IOC data."""
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        ioc_type = request.args.get('type', '')
        
        # Build where clause
        where_conditions = ["created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {} DAY)".format(days)]
        params = []
        
        if ioc_type:
            where_conditions.append("type = @ioc_type")
            params.append(bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type))
        
        # Query for IOCs
        ioc_query = """
        SELECT *
        FROM `{table_id}`
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT {limit}
        OFFSET {offset}
        """.format(
            table_id=Config.get_table_name('indicators'),
            where_clause=" AND ".join(where_conditions),
            limit=limit,
            offset=offset
        )
        
        iocs = execute_bq_query(ioc_query, params)
        
        # Query for total count
        count_query = """
        SELECT COUNT(*) as total
        FROM `{table_id}`
        WHERE {where_clause}
        """.format(
            table_id=Config.get_table_name('indicators'),
            where_clause=" AND ".join(where_conditions)
        )
        
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

@api_blueprint.route('/iocs/<ioc_id>', methods=['GET'])
def get_ioc_detail(ioc_id):
    """Get detailed information about a specific IOC."""
    try:
        query = """
        SELECT *
        FROM `{table_id}`
        WHERE id = @ioc_id
        LIMIT 1
        """.format(table_id=Config.get_table_name('indicators'))
        
        params = [bigquery.ScalarQueryParameter("ioc_id", "STRING", ioc_id)]
        results = execute_bq_query(query, params)
        
        if not results:
            return jsonify({"error": "IOC not found"}), 404
        
        ioc = results[0]
        
        # Get AI analysis if available
        if ioc.get('last_analyzed'):
            ioc['ai_analysis'] = {
                'timestamp': ioc.get('last_analyzed'),
                'risk_score': ioc.get('risk_score'),
                'summary': ioc.get('analysis_summary'),
                'confidence': ioc.get('confidence')
            }
        
        return jsonify(ioc)
    except Exception as e:
        logger.error(f"Error getting IOC detail: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/iocs/<ioc_id>/related', methods=['GET'])
def get_related_iocs(ioc_id):
    """Get IOCs related to a specific IOC."""
    try:
        # First get the IOC details
        ioc_query = """
        SELECT *
        FROM `{table_id}`
        WHERE id = @ioc_id
        LIMIT 1
        """.format(table_id=Config.get_table_name('indicators'))
        
        params = [bigquery.ScalarQueryParameter("ioc_id", "STRING", ioc_id)]
        ioc_results = execute_bq_query(ioc_query, params)
        
        if not ioc_results:
            return jsonify({"error": "IOC not found"}), 404
        
        ioc = ioc_results[0]
        
        # Find related IOCs based on shared attributes
        related_query = """
        WITH original AS (
            SELECT * FROM `{table_id}` WHERE id = @ioc_id
        )
        SELECT DISTINCT i.*
        FROM `{table_id}` i
        JOIN original o ON (
            (i.source = o.source AND i.id != o.id) OR
            (i.campaign_id = o.campaign_id AND o.campaign_id IS NOT NULL) OR
            (i.threat_actor = o.threat_actor AND o.threat_actor IS NOT NULL) OR
            (ARRAY_LENGTH(
                ARRAY(SELECT x FROM UNNEST(i.tags) x 
                      WHERE x IN (SELECT y FROM UNNEST(o.tags) y))
            ) > 0)
        )
        WHERE i.id != @ioc_id
        ORDER BY i.confidence DESC
        LIMIT 10
        """.format(table_id=Config.get_table_name('indicators'))
        
        related_results = execute_bq_query(related_query, params)
        
        return jsonify({
            'ioc': ioc,
            'items': related_results,
            'count': len(related_results)
        })
    except Exception as e:
        logger.error(f"Error getting related IOCs: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/iocs/export', methods=['GET'])
@limiter.limit("10 per minute")
def export_iocs():
    """Export IOCs in bulk."""
    try:
        days = int(request.args.get('days', 30))
        ioc_type = request.args.get('type', '')
        limit = int(request.args.get('limit', 10000))
        
        # Build query
        where_conditions = ["created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {} DAY)".format(days)]
        params = []
        
        if ioc_type:
            where_conditions.append("type = @ioc_type")
            params.append(bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type))
        
        query = """
        SELECT *
        FROM `{table_id}`
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT {limit}
        """.format(
            table_id=Config.get_table_name('indicators'),
            where_clause=" AND ".join(where_conditions),
            limit=limit
        )
        
        results = execute_bq_query(query, params)
        
        return jsonify({
            'records': results,
            'count': len(results)
        })
    except Exception as e:
        logger.error(f"Error exporting IOCs: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- AI Analysis Endpoints --------------------

@api_blueprint.route('/ai/analyses', methods=['GET'])
@limiter.limit("20 per minute")
def get_ai_analyses():
    """Get AI analysis results."""
    try:
        days = int(request.args.get('days', 30))
        
        # Query for recent analyses
        query = """
        SELECT 
            id,
            type,
            value,
            last_analyzed as timestamp,
            risk_score,
            confidence,
            analysis_summary as result,
            CASE 
                WHEN risk_score >= 80 THEN 'critical'
                WHEN risk_score >= 60 THEN 'high'
                WHEN risk_score >= 40 THEN 'medium'
                ELSE 'low'
            END as result_severity
        FROM `{table_id}`
        WHERE last_analyzed IS NOT NULL
        AND last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        ORDER BY last_analyzed DESC
        LIMIT 100
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        results = execute_bq_query(query)
        
        # Calculate summary statistics
        summary = {
            'overall_threat_level': 'Medium',
            'total_indicators': len(results),
            'critical_indicators': sum(1 for r in results if r.get('result_severity') == 'critical'),
            'emerging_threats_count': 0,  # Would need more complex analysis
            'threat_patterns': [],  # Would need pattern analysis
            'recommendations': [
                {
                    'text': 'Review critical severity indicators immediately',
                    'priority': 'High'
                },
                {
                    'text': 'Update security controls based on latest threat patterns',
                    'priority': 'Medium'
                }
            ],
            'recent_analyses': results[:20]
        }
        
        # Determine overall threat level
        critical_ratio = summary['critical_indicators'] / max(1, summary['total_indicators'])
        if critical_ratio > 0.3:
            summary['overall_threat_level'] = 'Critical'
        elif critical_ratio > 0.1:
            summary['overall_threat_level'] = 'High'
        elif critical_ratio > 0.05:
            summary['overall_threat_level'] = 'Medium'
        else:
            summary['overall_threat_level'] = 'Low'
        
        # Get last run time
        last_run_query = """
        SELECT MAX(last_analyzed) as last_run
        FROM `{table_id}`
        WHERE last_analyzed IS NOT NULL
        """.format(table_id=Config.get_table_name('indicators'))
        
        last_run_results = execute_bq_query(last_run_query)
        if last_run_results:
            summary['last_run_time'] = last_run_results[0].get('last_run')
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting AI analyses: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/ai/analyses/<analysis_id>', methods=['GET'])
def get_ai_analysis_detail(analysis_id):
    """Get detailed AI analysis result."""
    try:
        # For this implementation, analysis_id is the IOC id
        query = """
        SELECT *
        FROM `{table_id}`
        WHERE id = @analysis_id
        AND last_analyzed IS NOT NULL
        LIMIT 1
        """.format(table_id=Config.get_table_name('indicators'))
        
        params = [bigquery.ScalarQueryParameter("analysis_id", "STRING", analysis_id)]
        results = execute_bq_query(query, params)
        
        if not results:
            return jsonify({"error": "Analysis not found"}), 404
        
        analysis = results[0]
        
        # Format as analysis result
        formatted_analysis = {
            'id': analysis['id'],
            'type': 'IOC Analysis',
            'target': f"{analysis['type']}:{analysis['value']}",
            'timestamp': analysis['last_analyzed'],
            'model': 'Vertex AI',
            'result': analysis.get('analysis_summary', 'No summary available'),
            'result_severity': 'critical' if analysis.get('risk_score', 0) > 80 else 'high' if analysis.get('risk_score', 0) > 60 else 'medium' if analysis.get('risk_score', 0) > 40 else 'low',
            'confidence': analysis.get('confidence', 0),
            'findings': {
                'risk_score': analysis.get('risk_score', 0),
                'indicators': [],  # Would be populated from enrichment data
                'mitre_mapping': []  # Would need to parse from tags
            }
        }
        
        return jsonify(formatted_analysis)
    except Exception as e:
        logger.error(f"Error getting AI analysis detail: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/ai/summary', methods=['GET'])
def get_ai_summary():
    """Get AI analysis summary for dashboard."""
    try:
        # Get recent high-risk indicators
        summary_query = """
        SELECT 
            CASE 
                WHEN AVG(risk_score) >= 80 THEN 'Critical'
                WHEN AVG(risk_score) >= 60 THEN 'High'
                WHEN AVG(risk_score) >= 40 THEN 'Medium'
                ELSE 'Low'
            END as risk_level,
            COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_indicators,
            STRING_AGG(DISTINCT type ORDER BY type LIMIT 3) as trending_threats
        FROM `{table_id}`
        WHERE last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        AND risk_score IS NOT NULL
        """.format(table_id=Config.get_table_name('indicators'))
        
        results = execute_bq_query(summary_query)
        
        if results:
            return jsonify(results[0])
        else:
            return jsonify({
                'risk_level': 'Unknown',
                'critical_indicators': 0,
                'trending_threats': 'None detected'
            })
    except Exception as e:
        logger.error(f"Error getting AI summary: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

@api_blueprint.route('/ai/generate_report', methods=['POST'])
@limiter.limit("5 per minute")
def generate_ai_report():
    """Generate AI analysis report."""
    try:
        req_data = request.get_json() or {}
        report_type = req_data.get('report_type', 'summary')
        period = req_data.get('period', 'monthly')
        
        # Determine time range
        if period == 'daily':
            days = 1
        elif period == 'weekly':
            days = 7
        elif period == 'monthly':
            days = 30
        else:
            days = int(req_data.get('days', 30))
        
        # Generate report data
        report = {
            'title': f"Threat Intelligence Report - {report_type.title()}",
            'generated_at': datetime.utcnow().isoformat(),
            'period': period,
            'sections': []
        }
        
        # Executive Summary
        exec_summary_query = """
        SELECT 
            COUNT(*) as total_indicators,
            COUNT(DISTINCT source) as total_sources,
            AVG(risk_score) as avg_risk_score,
            COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_count,
            COUNT(CASE WHEN risk_score >= 60 THEN 1 END) as high_count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        summary_results = execute_bq_query(exec_summary_query)
        if summary_results:
            report['sections'].append({
                'title': 'Executive Summary',
                'content': summary_results[0]
            })
        
        # Top Threats
        threats_query = """
        SELECT 
            type,
            COUNT(*) as count,
            AVG(risk_score) as avg_risk_score,
            MAX(risk_score) as max_risk_score
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY type
        ORDER BY count DESC
        LIMIT 10
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        threats_results = execute_bq_query(threats_query)
        if threats_results:
            report['sections'].append({
                'title': 'Top Threat Types',
                'content': threats_results
            })
        
        # AI Analysis Summary
        ai_query = """
        SELECT 
            COUNT(*) as analyzed_count,
            AVG(confidence) as avg_confidence,
            STRING_AGG(DISTINCT analysis_summary ORDER BY analysis_summary LIMIT 5) as key_findings
        FROM `{table_id}`
        WHERE last_analyzed >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND analysis_summary IS NOT NULL
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        ai_results = execute_bq_query(ai_query)
        if ai_results:
            report['sections'].append({
                'title': 'AI Analysis Summary',
                'content': ai_results[0]
            })
        
        return jsonify({'report': report})
    except Exception as e:
        logger.error(f"Error generating AI report: {str(e)}")
        report_error(e)
        return jsonify({'error': str(e)}), 500

# -------------------- Threat Summary Endpoint --------------------

@api_blueprint.route('/threat_summary', methods=['GET'])
@limiter.limit("30 per minute")
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
        
        # Query for recent detections
        recent_query = """
        SELECT COUNT(*) as count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        """.format(table_id=Config.get_table_name('indicators'))
        
        recent_results = execute_bq_query(recent_query)
        recent_detections = recent_results[0].get('count', 0) if recent_results else 0
        
        # Calculate overall threat score
        score_query = """
        SELECT 
            AVG(risk_score) as avg_risk,
            MAX(risk_score) as max_risk,
            COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_count
        FROM `{table_id}`
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND risk_score IS NOT NULL
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        score_results = execute_bq_query(score_query)
        overall_score = 50  # Default score
        
        if score_results and score_results[0].get('avg_risk'):
            avg_risk = score_results[0]['avg_risk']
            critical_count = score_results[0]['critical_count']
            
            # Calculate weighted score
            overall_score = min(100, int(avg_risk + (critical_count * 2)))
        
        summary = {
            'high_risk_indicators': high_risk_indicators,
            'recent_detections': recent_detections,
            'overall_score': overall_score,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting threat summary: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Geo Stats Endpoint --------------------

@api_blueprint.route('/iocs/geo', methods=['GET'])
@limiter.limit("30 per minute")
def get_geo_stats():
    """Get geographical IOC distribution."""
    try:
        days = int(request.args.get('days', 30))
        
        # Query for geographical distribution
        geo_query = """
        SELECT 
            enrichment_geo as country,
            COUNT(*) as count
        FROM `{table_id}`
        WHERE enrichment_geo IS NOT NULL
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY enrichment_geo
        ORDER BY count DESC
        LIMIT 10
        """.format(table_id=Config.get_table_name('indicators'), days=days)
        
        geo_results = execute_bq_query(geo_query)
        
        countries = []
        for row in geo_results:
            # Parse geo data if it's JSON
            try:
                if isinstance(row['country'], str) and row['country'].startswith('{'):
                    geo_data = json.loads(row['country'])
                    country = geo_data.get('country', 'Unknown')
                else:
                    country = row['country']
                
                countries.append({
                    'country': country,
                    'count': row['count']
                })
            except:
                countries.append({
                    'country': row['country'],
                    'count': row['count']
                })
        
        return jsonify({'countries': countries})
    except Exception as e:
        logger.error(f"Error getting geo stats: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Search Endpoint --------------------

@api_blueprint.route('/search', methods=['GET'])
@limiter.limit("20 per minute")
def search():
    """Search across all threat intelligence data."""
    try:
        query_string = request.args.get('query', '')
        if not query_string:
            return jsonify({"error": "Query parameter required"}), 400
        
        # Search across indicators
        search_query = """
        SELECT 
            id,
            type,
            value,
            source,
            description,
            created_at,
            risk_score,
            CASE 
                WHEN risk_score >= 80 THEN 'critical'
                WHEN risk_score >= 60 THEN 'high'
                WHEN risk_score >= 40 THEN 'medium'
                ELSE 'low'
            END as severity
        FROM `{table_id}`
        WHERE (
            LOWER(value) LIKE LOWER(@query) OR
            LOWER(description) LIKE LOWER(@query) OR
            LOWER(source) LIKE LOWER(@query) OR
            LOWER(type) LIKE LOWER(@query)
        )
        ORDER BY created_at DESC
        LIMIT 50
        """.format(table_id=Config.get_table_name('indicators'))
        
        params = [bigquery.ScalarQueryParameter("query", "STRING", f"%{query_string}%")]
        results = execute_bq_query(search_query, params)
        
        return jsonify({
            'query': query_string,
            'results': results,
            'count': len(results)
        })
    except Exception as e:
        logger.error(f"Error in search: {str(e)}")
        report_error(e)
        return jsonify({"error": str(e)}), 500

# -------------------- Admin Endpoints --------------------

@api_blueprint.route('/admin/ingest', methods=['POST'])
@limiter.limit("5 per minute")
def trigger_ingest():
    """Trigger data ingestion."""
    try:
        # Get request data
        req_data = request.get_json() or {}
        process_all = req_data.get('process_all', True)
        force_tables = req_data.get('force_tables', False)
        
        # Trigger ingestion via Pub/Sub
        message_data = {
            'process_all': process_all,
            'force_tables': force_tables,
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
@limiter.limit("5 per minute")
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

@api_blueprint.route('/admin/initialize_tables', methods=['POST'])
@limiter.limit("1 per minute")
def initialize_tables():
    """Manually trigger BigQuery table initialization."""
    try:
        # Import from ingestion module
        from ingestion import initialize_bigquery_tables, force_update_bigquery_tables
        
        # First try normal initialization
        logger.info("Attempting to initialize BigQuery tables via API request")
        result = initialize_bigquery_tables()
        
        if not result:
            # If normal initialization fails, try forced update
            logger.warning("Normal table initialization failed, trying forced update")
            result = force_update_bigquery_tables()
        
        if result:
            logger.info("Successfully initialized BigQuery tables via API request")
            return jsonify({
                'status': 'success',
                'message': 'BigQuery tables initialized successfully'
            })
        else:
            logger.error("Failed to initialize BigQuery tables via API request")
            return jsonify({
                'status': 'error',
                'message': 'Failed to initialize BigQuery tables'
            }), 500
    except ImportError:
        logger.error("Could not import initialization functions from ingestion module")
        # Alternative approach - use Pub/Sub to trigger initialization
        try:
            message_data = {
                'process_all': False,
                'force_tables': True,
                'triggered_by': 'api',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            message_id = publish_to_topic(Config.PUBSUB_TOPIC, message_data)
            
            return jsonify({
                'status': 'success',
                'message': 'BigQuery tables initialization triggered via Pub/Sub',
                'message_id': message_id
            })
        except Exception as pub_err:
            logger.error(f"Error triggering table initialization via Pub/Sub: {str(pub_err)}")
            return jsonify({'error': f"Failed to initialize tables: {str(pub_err)}"}), 500
    except Exception as e:
        logger.error(f"Error initializing tables: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
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
            {'path': '/api/iocs/<id>', 'method': 'GET', 'description': 'Get IOC details'},
            {'path': '/api/iocs/<id>/related', 'method': 'GET', 'description': 'Get related IOCs'},
            {'path': '/api/iocs/export', 'method': 'GET', 'description': 'Export IOCs'},
            {'path': '/api/threat_summary', 'method': 'GET', 'description': 'Get threat summary'},
            {'path': '/api/iocs/geo', 'method': 'GET', 'description': 'Get geographical distribution'},
            {'path': '/api/ai/analyses', 'method': 'GET', 'description': 'Get AI analysis results'},
            {'path': '/api/ai/analyses/<id>', 'method': 'GET', 'description': 'Get AI analysis details'},
            {'path': '/api/ai/summary', 'method': 'GET', 'description': 'Get AI summary'},
            {'path': '/api/ai/generate_report', 'method': 'POST', 'description': 'Generate AI report'},
            {'path': '/api/search', 'method': 'GET', 'description': 'Search threat intelligence'},
            {'path': '/api/admin/ingest', 'method': 'POST', 'description': 'Trigger data ingestion'},
            {'path': '/api/admin/analyze', 'method': 'POST', 'description': 'Trigger data analysis'},
            {'path': '/api/admin/initialize_tables', 'method': 'POST', 'description': 'Initialize BigQuery tables'}
        ]
    })

# -------------------- Error Handlers --------------------

@api_blueprint.errorhandler(400)
def bad_request(e):
    """Handle 400 errors."""
    return jsonify({"error": "Bad request", "message": str(e)}), 400

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
