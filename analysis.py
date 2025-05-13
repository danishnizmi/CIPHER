"""
Production-ready analysis module for threat intelligence platform.
Implements batch analysis to optimize costs and performance.
"""

import os
import json
import logging
import hashlib
import re
import ipaddress
import socket
import time
import threading
import uuid
import statistics
from typing import Dict, List, Any, Union, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import traceback

import requests
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound
from google.api_core.exceptions import GoogleAPIError

# Import configuration
from config import Config, ServiceManager, ServiceStatus, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Global analysis state
analysis_status = {
    "last_run": None,
    "running": False,
    "feeds_analyzed": 0,
    "feeds_failed": 0,
    "total_samples": 0,
    "errors": [],
    "batch_analyses": {},
    "ai_model_status": "initializing"
}

# Lock for thread-safe operations
_analysis_lock = threading.Lock()

# AI models - initialized lazily
text_model = None
generative_model = None
_ai_models_initialized = False
_ai_models_lock = threading.Lock()

# ==================== Helper Functions ====================

def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    return (
        service_manager.get_client('bigquery'),
        service_manager.get_client('storage'),
        service_manager.get_client('publisher'),
        service_manager.get_client('subscriber')
    )

def publish_event(event_type: str, data: dict = None):
    """Publish event through event bus if available."""
    try:
        from flask import g
        if hasattr(g, 'event_bus'):
            g.event_bus.publish(event_type, data)
            logger.debug(f"Published event: {event_type}")
    except Exception as e:
        logger.debug(f"Not in Flask context, skipping event publish: {e}")

def update_service_status(status: ServiceStatus, error: str = None):
    """Update analysis service status."""
    service_manager = Config.get_service_manager()
    service_manager.update_status('analysis', status, error)

def validate_feed_id(feed_id: str) -> bool:
    """Validate feed ID format."""
    if not feed_id or not isinstance(feed_id, str):
        return False
    # Allow alphanumeric, hyphens, and underscores
    return re.match(r'^[a-zA-Z0-9_-]+$', feed_id) is not None

# ==================== AI Model Initialization ====================

def initialize_ai_models_background():
    """Initialize AI models in background thread without blocking service startup."""
    global text_model, generative_model, _ai_models_initialized
    
    def _init_models():
        global text_model, generative_model, _ai_models_initialized
        
        with _ai_models_lock:
            if _ai_models_initialized:
                return
                
            service_manager = Config.get_service_manager()
            
            try:
                logger.info("Starting background AI model initialization...")
                service_manager.update_status('ai_models', ServiceStatus.INITIALIZING)
                
                # Update global status
                with _analysis_lock:
                    analysis_status["ai_model_status"] = "initializing"
                
                import vertexai
                from vertexai.language_models import TextGenerationModel
                from vertexai.preview.generative_models import GenerativeModel
                
                vertexai.init(project=Config.GCP_PROJECT, location=Config.VERTEXAI_LOCATION)
                
                # Initialize text model with fallback
                try:
                    text_model = TextGenerationModel.from_pretrained(Config.VERTEXAI_MODEL)
                    logger.info(f"Initialized text model: {Config.VERTEXAI_MODEL}")
                except Exception as e:
                    logger.warning(f"Could not load specified model: {str(e)}")
                    try:
                        text_model = TextGenerationModel.from_pretrained("text-bison@latest")
                        logger.info("Initialized fallback text-bison model")
                    except Exception:
                        logger.error("Could not load fallback text model")
                        text_model = None
                
                # Initialize generative model
                try:
                    generative_model = GenerativeModel("gemini-1.0-pro")
                    logger.info("Initialized Gemini model for advanced analysis")
                except Exception as e:
                    logger.warning(f"Could not load Gemini model: {str(e)}")
                    generative_model = None
                
                # Update status
                if text_model or generative_model:
                    service_manager.update_status('ai_models', ServiceStatus.READY)
                    _ai_models_initialized = True
                    with _analysis_lock:
                        analysis_status["ai_model_status"] = "ready"
                    logger.info("AI models initialization completed successfully")
                else:
                    service_manager.update_status('ai_models', ServiceStatus.DEGRADED, "No AI models available")
                    with _analysis_lock:
                        analysis_status["ai_model_status"] = "degraded"
                    logger.warning("No AI models available - will use statistical analysis only")
                    
            except Exception as e:
                logger.error(f"Error initializing Vertex AI: {str(e)}")
                service_manager.update_status('ai_models', ServiceStatus.ERROR, str(e))
                with _analysis_lock:
                    analysis_status["ai_model_status"] = "error"
                    analysis_status["errors"].append(f"AI initialization failed: {str(e)}")
    
    # Start initialization in background thread
    if Config.NLP_ENABLED:
        thread = threading.Thread(target=_init_models, daemon=True)
        thread.start()
        logger.info("Started AI model initialization in background")
    else:
        logger.info("NLP analysis is disabled in configuration")
        service_manager = Config.get_service_manager()
        service_manager.update_status('ai_models', ServiceStatus.READY)
        with _analysis_lock:
            analysis_status["ai_model_status"] = "disabled"

def ensure_ai_models() -> bool:
    """Ensure AI models are initialized before use."""
    global _ai_models_initialized
    
    if not Config.NLP_ENABLED:
        return False
    
    if _ai_models_initialized:
        return text_model is not None or generative_model is not None
    
    # If not initialized, wait a bit
    with _ai_models_lock:
        if not _ai_models_initialized:
            logger.info("AI models not ready, waiting...")
            return False
    
    return text_model is not None or generative_model is not None

# ==================== Analysis Functions ====================

def analyze_feed_batch(feed_id: str, sample_size: int = 100, force_analyze: bool = False) -> Dict[str, Any]:
    """
    Analyze a sample of recent indicators from a specific feed.
    
    Args:
        feed_id: The ID of the feed to analyze
        sample_size: Number of recent indicators to sample
        force_analyze: Force analysis even if recently analyzed
    
    Returns:
        Dictionary containing analysis results
    """
    if not validate_feed_id(feed_id):
        return {"error": "Invalid feed ID format"}
    
    logger.info(f"Starting batch analysis for feed {feed_id} (sample size: {sample_size})")
    
    # Check if feed was recently analyzed (unless forced)
    if not force_analyze:
        recent_analysis = get_recent_analysis(feed_id, hours=4)
        if recent_analysis:
            logger.info(f"Feed {feed_id} was recently analyzed, skipping")
            return {"status": "skipped", "reason": "recently_analyzed", "data": recent_analysis}
    
    bq_client, _, _, _ = get_clients()
    if not bq_client:
        return {"error": "BigQuery client not initialized"}
    
    try:
        # Get recent indicators from the feed
        table_id = Config.get_table_name('indicators')
        if not table_id:
            return {"error": "Indicators table not configured"}
        
        query = f"""
        SELECT * FROM `{table_id}`
        WHERE feed_id = @feed_id 
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        ORDER BY created_at DESC
        LIMIT @sample_size
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("feed_id", "STRING", feed_id),
                bigquery.ScalarQueryParameter("sample_size", "INT64", sample_size)
            ]
        )
        
        results = list(bq_client.query(query, job_config=job_config))
        
        if not results:
            logger.warning(f"No recent data found for feed {feed_id}")
            return {"error": "No recent data found for feed", "feed_id": feed_id}
        
        # Convert to dictionary format
        indicators = []
        for row in results:
            indicator = dict(row)
            # Convert datetime objects to ISO strings
            for key, value in indicator.items():
                if isinstance(value, datetime):
                    indicator[key] = value.isoformat()
            indicators.append(indicator)
        
        logger.info(f"Retrieved {len(indicators)} indicators for analysis")
        
        # Perform batch analysis
        analysis_result = perform_batch_analysis(indicators, feed_id)
        
        # Store batch analysis results
        if analysis_result and not analysis_result.get('error'):
            storage_success = store_batch_analysis_result(feed_id, analysis_result)
            analysis_result['stored'] = storage_success
            
            # Update global status
            with _analysis_lock:
                analysis_status["batch_analyses"][feed_id] = {
                    "last_analysis": analysis_result['timestamp'],
                    "threat_level": analysis_result['threat_summary']['level'],
                    "sample_size": analysis_result['sample_size']
                }
        
        logger.info(f"Completed batch analysis for feed {feed_id}")
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error analyzing feed batch: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {"error": str(e), "feed_id": feed_id}

def perform_batch_analysis(indicators: List[Dict], feed_id: str) -> Dict[str, Any]:
    """
    Perform AI or statistical analysis on a batch of indicators.
    
    Args:
        indicators: List of indicator dictionaries
        feed_id: Feed identifier
    
    Returns:
        Analysis results dictionary
    """
    analysis_result = {
        "feed_id": feed_id,
        "timestamp": datetime.utcnow().isoformat(),
        "sample_size": len(indicators),
        "analysis_type": "batch",
        "threat_summary": {"level": "medium", "confidence": 50, "rationale": ""},
        "patterns": {},
        "recommendations": [],
        "metrics": {},
        "ai_insights": None
    }
    
    try:
        # Basic statistical analysis (always performed)
        stats_result = perform_statistical_analysis(indicators, feed_id)
        analysis_result["metrics"] = stats_result["metrics"]
        analysis_result["patterns"] = stats_result["patterns"]
        
        # Determine base threat level from statistics
        avg_risk = stats_result["metrics"].get("average_risk_score", 50)
        analysis_result["threat_summary"] = determine_threat_level(avg_risk, stats_result)
        
        # Generate basic recommendations
        analysis_result["recommendations"] = generate_recommendations(stats_result)
        
        # Perform AI analysis if available
        if Config.NLP_ENABLED and ensure_ai_models():
            logger.info("Performing AI analysis on batch")
            ai_result = perform_ai_batch_analysis(indicators, stats_result, feed_id)
            
            if ai_result and not ai_result.get('error'):
                analysis_result["ai_insights"] = ai_result
                # Update threat summary with AI insights
                if ai_result.get('threat_assessment'):
                    ai_threat = ai_result['threat_assessment']
                    analysis_result["threat_summary"] = {
                        "level": ai_threat.get('level', analysis_result["threat_summary"]["level"]),
                        "confidence": ai_threat.get('confidence', analysis_result["threat_summary"]["confidence"]),
                        "rationale": ai_threat.get('rationale', '')
                    }
                # Add AI recommendations
                if ai_result.get('recommendations'):
                    analysis_result["recommendations"].extend(ai_result['recommendations'])
        else:
            logger.info("AI models not available, using statistical analysis only")
            analysis_result["analysis_type"] = "statistical"
        
        # Add execution metadata
        analysis_result["execution_time"] = time.time()
        analysis_result["system_status"] = {
            "ai_available": _ai_models_initialized,
            "model_type": "ai+statistical" if _ai_models_initialized else "statistical"
        }
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}")
        return {"error": str(e), "feed_id": feed_id}

def perform_statistical_analysis(indicators: List[Dict], feed_id: str) -> Dict[str, Any]:
    """
    Perform comprehensive statistical analysis on indicators.
    
    Args:
        indicators: List of indicator dictionaries
        feed_id: Feed identifier
    
    Returns:
        Statistical analysis results
    """
    stats = {
        "metrics": {},
        "patterns": {},
        "temporal_analysis": {}
    }
    
    # Type distribution
    type_counts = Counter()
    malware_families = Counter()
    threat_types = Counter()
    risk_scores = []
    confidence_scores = []
    
    # Temporal patterns
    hourly_distribution = defaultdict(int)
    daily_trend = []
    
    for indicator in indicators:
        # Count types
        ioc_type = indicator.get('type', 'unknown')
        type_counts[ioc_type] += 1
        
        # Track malware
        malware = indicator.get('malware')
        if malware:
            malware_families[malware] += 1
        
        # Track threat types
        threat_type = indicator.get('threat_type')
        if threat_type:
            threat_types[threat_type] += 1
        
        # Collect scores
        if indicator.get('risk_score') is not None:
            risk_scores.append(indicator['risk_score'])
        if indicator.get('confidence') is not None:
            confidence_scores.append(indicator['confidence'])
        
        # Temporal analysis
        created_at = indicator.get('created_at')
        if created_at:
            try:
                if isinstance(created_at, str):
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                else:
                    dt = created_at
                hourly_distribution[dt.hour] += 1
                daily_trend.append(dt.date())
            except:
                pass
    
    # Calculate metrics
    stats["metrics"] = {
        "total_indicators": len(indicators),
        "type_distribution": dict(type_counts.most_common()),
        "top_malware_families": dict(malware_families.most_common(5)),
        "threat_type_distribution": dict(threat_types.most_common()),
        "average_risk_score": statistics.mean(risk_scores) if risk_scores else 50,
        "risk_score_stddev": statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0,
        "average_confidence": statistics.mean(confidence_scores) if confidence_scores else 50,
        "confidence_stddev": statistics.stdev(confidence_scores) if len(confidence_scores) > 1 else 0
    }
    
    # Pattern analysis
    dominant_type = type_counts.most_common(1)[0] if type_counts else ('unknown', 0)
    total_indicators = len(indicators)
    
    stats["patterns"] = {
        "dominant_ioc_type": {
            "type": dominant_type[0],
            "percentage": (dominant_type[1] / total_indicators * 100) if total_indicators > 0 else 0
        },
        "malware_diversity": len(malware_families),
        "threat_concentration": len(threat_types),
        "temporal_patterns": {
            "peak_hours": sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)[:3],
            "activity_distribution": dict(hourly_distribution)
        }
    }
    
    # Risk assessment
    high_risk_count = sum(1 for score in risk_scores if score > 75)
    stats["risk_assessment"] = {
        "high_risk_percentage": (high_risk_count / len(risk_scores) * 100) if risk_scores else 0,
        "risk_distribution": {
            "critical": sum(1 for s in risk_scores if s > 85),
            "high": sum(1 for s in risk_scores if 65 < s <= 85),
            "medium": sum(1 for s in risk_scores if 35 < s <= 65),
            "low": sum(1 for s in risk_scores if s <= 35)
        }
    }
    
    return stats

def perform_ai_batch_analysis(indicators: List[Dict], stats_result: Dict, feed_id: str) -> Optional[Dict[str, Any]]:
    """
    Perform AI analysis on a batch of indicators.
    
    Args:
        indicators: List of indicators
        stats_result: Statistical analysis results
        feed_id: Feed identifier
    
    Returns:
        AI analysis results or None if failed
    """
    if not (text_model or generative_model):
        return None
    
    try:
        # Prepare analysis prompt
        metrics = stats_result["metrics"]
        patterns = stats_result["patterns"]
        
        # Create sample indicators for AI analysis (limit to prevent token overflow)
        sample_indicators = indicators[:10]
        
        analysis_prompt = f"""
        Analyze this threat intelligence batch from feed '{feed_id}':
        
        Sample Data:
        - Total indicators in batch: {metrics['total_indicators']}
        - Average risk score: {metrics['average_risk_score']:.1f}
        - Dominant IOC type: {patterns['dominant_ioc_type']['type']} ({patterns['dominant_ioc_type']['percentage']:.1f}%)
        - Top malware families: {list(metrics['top_malware_families'].keys())[:3]}
        - Threat types: {list(metrics['threat_type_distribution'].keys())}
        
        Sample indicators:
        {json.dumps(sample_indicators[:5], indent=2)}
        
        Provide analysis in JSON format:
        {{
            "threat_assessment": {{
                "level": "low|medium|high|critical",
                "confidence": 0-100,
                "rationale": "explanation of threat level"
            }},
            "key_findings": ["finding1", "finding2", ...],
            "emerging_patterns": ["pattern1", "pattern2", ...],
            "recommendations": ["recommendation1", "recommendation2", ...],
            "mitre_tactics": ["tactic1", "tactic2", ...],
            "threat_actors": ["actor1", "actor2", ...] if identifiable
        }}
        """
        
        # Use AI model to analyze
        if generative_model:
            response = generative_model.generate_content(analysis_prompt)
            response_text = response.text
        elif text_model:
            response = text_model.predict(
                prompt=analysis_prompt,
                temperature=0.2,
                max_output_tokens=1024,
                top_p=0.8,
                top_k=40
            )
            response_text = response.text
        else:
            return None
        
        # Parse JSON response
        json_match = re.search(r'({[\s\S]*})', response_text)
        if json_match:
            ai_result = json.loads(json_match.group(0))
            ai_result['raw_response'] = response_text
            ai_result['model_used'] = 'gemini' if generative_model else 'text-bison'
            return ai_result
        else:
            logger.warning("Could not parse JSON from AI response")
            return {"error": "Invalid AI response format", "raw_response": response_text}
            
    except Exception as e:
        logger.error(f"Error in AI batch analysis: {str(e)}")
        return {"error": str(e)}

def determine_threat_level(avg_risk: float, stats_result: Dict) -> Dict[str, Any]:
    """
    Determine threat level based on statistical analysis.
    
    Args:
        avg_risk: Average risk score
        stats_result: Statistical analysis results
    
    Returns:
        Threat assessment dictionary
    """
    threat_summary = {"level": "medium", "confidence": 50, "rationale": ""}
    
    # Base assessment on average risk
    if avg_risk > 85:
        threat_summary["level"] = "critical"
        threat_summary["confidence"] = 90
    elif avg_risk > 70:
        threat_summary["level"] = "high"
        threat_summary["confidence"] = 80
    elif avg_risk > 40:
        threat_summary["level"] = "medium"
        threat_summary["confidence"] = 70
    else:
        threat_summary["level"] = "low"
        threat_summary["confidence"] = 60
    
    # Adjust based on patterns
    risk_assessment = stats_result.get("risk_assessment", {})
    high_risk_percentage = risk_assessment.get("high_risk_percentage", 0)
    
    if high_risk_percentage > 50:
        threat_summary["confidence"] += 10
        threat_summary["rationale"] = f"High concentration of risky indicators ({high_risk_percentage:.1f}%)"
    elif high_risk_percentage < 10:
        threat_summary["confidence"] -= 10
        threat_summary["rationale"] = f"Low concentration of risky indicators ({high_risk_percentage:.1f}%)"
    
    # Consider malware diversity
    malware_diversity = stats_result.get("patterns", {}).get("malware_diversity", 0)
    if malware_diversity > 10:
        if threat_summary["level"] in ["medium", "high"]:
            threat_summary["level"] = "high" if threat_summary["level"] == "medium" else "critical"
        threat_summary["rationale"] += f" Multiple malware families detected ({malware_diversity})"
    
    threat_summary["confidence"] = min(95, max(30, threat_summary["confidence"]))
    return threat_summary

def generate_recommendations(stats_result: Dict) -> List[str]:
    """
    Generate security recommendations based on analysis.
    
    Args:
        stats_result: Statistical analysis results
    
    Returns:
        List of recommendations
    """
    recommendations = []
    metrics = stats_result["metrics"]
    patterns = stats_result["patterns"]
    
    # Type-based recommendations
    type_dist = metrics.get("type_distribution", {})
    total = sum(type_dist.values())
    
    if type_dist.get('ip:port', 0) / total > 0.3 if total > 0 else False:
        recommendations.append("High volume of C2 infrastructure detected. Strengthen network monitoring and implement port-based filtering.")
    
    if type_dist.get('url', 0) / total > 0.3 if total > 0 else False:
        recommendations.append("Significant malicious URL activity detected. Update web filtering policies and user awareness training.")
    
    if type_dist.get('domain', 0) / total > 0.4 if total > 0 else False:
        recommendations.append("High domain-based activity. Implement DNS monitoring and consider DNS filtering solutions.")
    
    # Risk-based recommendations
    avg_risk = metrics.get("average_risk_score", 50)
    if avg_risk > 70:
        recommendations.append("Above-average risk scores detected. Immediate threat hunting recommended.")
        recommendations.append("Consider implementing additional security controls for high-risk indicators.")
    
    # Malware family recommendations
    top_malware = list(metrics.get("top_malware_families", {}).keys())[:3]
    if top_malware:
        recommendations.append(f"Monitor for specific malware families: {', '.join(top_malware)}")
    
    # Temporal recommendations
    temporal_patterns = patterns.get("temporal_patterns", {})
    if temporal_patterns.get("peak_hours"):
        peak_hours = [str(hour) for hour, _ in temporal_patterns["peak_hours"]]
        recommendations.append(f"Increase monitoring during peak activity hours: {', '.join(peak_hours)}")
    
    # Default recommendations if none generated
    if not recommendations:
        recommendations.extend([
            "Continue monitoring threat landscape for emerging patterns",
            "Regularly update threat intelligence feeds",
            "Maintain situational awareness of current threat environment"
        ])
    
    return recommendations

# ==================== Storage Functions ====================

def store_batch_analysis_result(feed_id: str, analysis_data: Dict) -> bool:
    """
    Store batch analysis results in BigQuery.
    
    Args:
        feed_id: Feed identifier
        analysis_data: Analysis results to store
    
    Returns:
        True if successful, False otherwise
    """
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.batch_analysis"
        
        # Create table if it doesn't exist
        schema = [
            bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("feed_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("sample_size", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("threat_level", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("confidence", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("analysis_type", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("analysis_data", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("ai_available", "BOOLEAN", mode="NULLABLE"),
        ]
        
        try:
            bq_client.get_table(table_id)
        except NotFound:
            table = bigquery.Table(table_id, schema=schema)
            bq_client.create_table(table)
            logger.info(f"Created batch_analysis table: {table_id}")
        
        # Prepare record
        record = {
            "id": hashlib.md5(f"{feed_id}:{analysis_data['timestamp']}".encode()).hexdigest(),
            "feed_id": feed_id,
            "timestamp": analysis_data['timestamp'],
            "sample_size": analysis_data['sample_size'],
            "threat_level": analysis_data['threat_summary']['level'],
            "confidence": analysis_data['threat_summary']['confidence'],
            "analysis_type": analysis_data['analysis_type'],
            "analysis_data": json.dumps(analysis_data),
            "ai_available": analysis_data.get('system_status', {}).get('ai_available', False)
        }
        
        # Insert with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                job = bq_client.load_table_from_json([record], table_id)
                job.result(timeout=30)
                
                if job.errors:
                    logger.error(f"BigQuery job errors: {job.errors}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    return False
                else:
                    logger.info(f"Successfully stored batch analysis for feed {feed_id}")
                    return True
                    
            except Exception as e:
                logger.error(f"Error inserting batch analysis (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    report_error(e)
                    return False
        
        return False
        
    except Exception as e:
        logger.error(f"Error storing batch analysis: {str(e)}")
        report_error(e)
        return False

def get_recent_analysis(feed_id: str, hours: int = 4) -> Optional[Dict]:
    """
    Check if feed has been analyzed recently.
    
    Args:
        feed_id: Feed identifier
        hours: Number of hours to check back
    
    Returns:
        Recent analysis data if found, None otherwise
    """
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        return None
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.batch_analysis"
        
        query = f"""
        SELECT analysis_data
        FROM `{table_id}`
        WHERE feed_id = @feed_id
        AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @hours HOUR)
        ORDER BY timestamp DESC
        LIMIT 1
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("feed_id", "STRING", feed_id),
                bigquery.ScalarQueryParameter("hours", "INT64", hours)
            ]
        )
        
        results = list(bq_client.query(query, job_config=job_config))
        
        if results:
            return json.loads(results[0].analysis_data)
        return None
        
    except Exception as e:
        logger.error(f"Error checking recent analysis: {str(e)}")
        return None

def get_batch_analysis_summary(days: int = 7) -> Dict[str, Any]:
    """
    Get comprehensive batch analysis summary.
    
    Args:
        days: Number of days to look back
    
    Returns:
        Summary of batch analyses
    """
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        return {"error": "BigQuery client not initialized"}
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.batch_analysis"
        
        # Check if table exists
        try:
            bq_client.get_table(table_id)
        except NotFound:
            return {
                "total_feeds_analyzed": 0,
                "feeds": [],
                "threat_level_distribution": [],
                "analysis_trends": []
            }
        
        # Get feed-level analysis summary
        query = f"""
        SELECT 
            feed_id,
            COUNT(*) as analysis_count,
            AVG(confidence) as avg_confidence,
            ARRAY_AGG(DISTINCT threat_level) as threat_levels,
            MAX(timestamp) as last_analysis,
            AVG(sample_size) as avg_sample_size
        FROM `{table_id}`
        WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY feed_id
        ORDER BY last_analysis DESC
        """
        
        results = list(bq_client.query(query))
        
        summary = {
            "total_feeds_analyzed": len(results),
            "feeds": [],
            "period_days": days
        }
        
        for row in results:
            feed_data = {
                "feed_id": row.feed_id,
                "analysis_count": row.analysis_count,
                "avg_confidence": round(row.avg_confidence, 1) if row.avg_confidence else 0,
                "threat_levels": row.threat_levels,
                "last_analysis": row.last_analysis.isoformat() if row.last_analysis else None,
                "avg_sample_size": int(row.avg_sample_size) if row.avg_sample_size else 0
            }
            summary['feeds'].append(feed_data)
        
        # Get threat level distribution
        threat_query = f"""
        SELECT 
            threat_level,
            COUNT(*) as count,
            AVG(confidence) as avg_confidence
        FROM `{table_id}`
        WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY threat_level
        ORDER BY 
            CASE threat_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        """
        
        threat_results = list(bq_client.query(threat_query))
        summary['threat_level_distribution'] = [
            {
                "threat_level": row.threat_level,
                "count": row.count,
                "avg_confidence": round(row.avg_confidence, 1) if row.avg_confidence else 0
            }
            for row in threat_results
        ]
        
        # Get analysis trends (daily)
        trends_query = f"""
        SELECT 
            DATE(timestamp) as analysis_date,
            COUNT(*) as analyses_count,
            AVG(confidence) as avg_confidence,
            MODE(threat_level) as most_common_threat_level
        FROM `{table_id}`
        WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        GROUP BY DATE(timestamp)
        ORDER BY analysis_date DESC
        """
        
        trends_results = list(bq_client.query(trends_query))
        summary['analysis_trends'] = [
            {
                "date": row.analysis_date.isoformat(),
                "analyses_count": row.analyses_count,
                "avg_confidence": round(row.avg_confidence, 1) if row.avg_confidence else 0,
                "most_common_threat_level": row.most_common_threat_level
            }
            for row in trends_results
        ]
        
        # Add summary statistics
        if summary['feeds']:
            summary['summary_stats'] = {
                "total_analyses": sum(feed['analysis_count'] for feed in summary['feeds']),
                "avg_confidence_all": round(
                    sum(feed['avg_confidence'] * feed['analysis_count'] for feed in summary['feeds']) / 
                    sum(feed['analysis_count'] for feed in summary['feeds']), 1
                ),
                "most_active_feed": max(summary['feeds'], key=lambda x: x['analysis_count'])['feed_id']
            }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error getting batch analysis summary: {str(e)}")
        return {"error": str(e)}

# ==================== Background Processing ====================

def start_background_batch_analysis(interval_hours: int = 4):
    """
    Start background batch analysis for feeds.
    
    Args:
        interval_hours: Interval between analysis runs
    
    Returns:
        Thread object
    """
    def batch_analysis_thread():
        service_manager = Config.get_service_manager()
        
        while True:
            try:
                logger.info("Starting background batch analysis cycle")
                
                # Update service status
                update_service_status(ServiceStatus.READY)
                
                with _analysis_lock:
                    analysis_status["running"] = True
                    analysis_status["last_run"] = datetime.utcnow().isoformat()
                    analysis_status["feeds_analyzed"] = 0
                    analysis_status["feeds_failed"] = 0
                    analysis_status["total_samples"] = 0
                    analysis_status["errors"] = []
                
                # Get enabled feeds
                try:
                    feeds = Config.get_enabled_feeds() if hasattr(Config, 'get_enabled_feeds') else Config.FEEDS
                except Exception as e:
                    logger.error(f"Error getting feeds configuration: {e}")
                    feeds = []
                
                if not feeds:
                    logger.warning("No feeds configured for analysis")
                    with _analysis_lock:
                        analysis_status["running"] = False
                    time.sleep(interval_hours * 3600)
                    continue
                
                logger.info(f"Analyzing {len(feeds)} feeds")
                
                # Process each feed
                for feed in feeds:
                    if not feed.get('enabled', True):
                        continue
                        
                    feed_id = feed.get('id')
                    if not feed_id:
                        logger.warning(f"Feed missing ID: {feed}")
                        continue
                    
                    try:
                        logger.info(f"Running batch analysis for feed: {feed_id}")
                        result = analyze_feed_batch(feed_id, sample_size=100)
                        
                        with _analysis_lock:
                            if result.get('error'):
                                analysis_status["feeds_failed"] += 1
                                error_msg = f"Feed {feed_id}: {result['error']}"
                                analysis_status["errors"].append(error_msg)
                                logger.error(error_msg)
                            elif result.get('status') != 'skipped':
                                analysis_status["feeds_analyzed"] += 1
                                analysis_status["total_samples"] += result.get('sample_size', 0)
                                logger.info(f"Completed batch analysis for {feed_id}")
                        
                        # Small delay between feeds to avoid overwhelming services
                        time.sleep(2)
                        
                    except Exception as e:
                        error_msg = f"Failed to analyze feed {feed_id}: {str(e)}"
                        logger.error(error_msg)
                        with _analysis_lock:
                            analysis_status["feeds_failed"] += 1
                            analysis_status["errors"].append(error_msg)
                
                with _analysis_lock:
                    analysis_status["running"] = False
                
                # Publish completion event
                publish_event('batch_analysis_completed', {
                    'feeds_analyzed': analysis_status["feeds_analyzed"],
                    'feeds_failed': analysis_status["feeds_failed"],
                    'total_samples': analysis_status["total_samples"]
                })
                
                success_count = analysis_status["feeds_analyzed"]
                total_feeds = len(feeds)
                logger.info(f"Background batch analysis completed: {success_count}/{total_feeds} feeds analyzed")
                
                # Sleep until next cycle
                time.sleep(interval_hours * 3600)
                
            except Exception as e:
                logger.error(f"Error in background batch analysis: {str(e)}")
                update_service_status(ServiceStatus.ERROR, str(e))
                with _analysis_lock:
                    analysis_status["running"] = False
                    analysis_status["errors"].append(f"Background analysis error: {str(e)}")
                time.sleep(300)  # Wait 5 minutes on error
    
    thread = threading.Thread(target=batch_analysis_thread, daemon=True)
    thread.start()
    logger.info(f"Started background batch analysis thread (interval: {interval_hours} hours)")
    return thread

def get_analysis_status() -> Dict:
    """
    Get current analysis status.
    
    Returns:
        Current analysis status dictionary
    """
    with _analysis_lock:
        status_copy = dict(analysis_status)
    
    # Add current timestamp
    status_copy["current_time"] = datetime.utcnow().isoformat()
    
    # Add service manager status
    service_manager = Config.get_service_manager()
    service_status = service_manager.get_status()
    
    status_copy["service_status"] = {
        "analysis": service_status['services'].get('analysis', 'unknown'),
        "ai_models": service_status['services'].get('ai_models', 'unknown'),
        "overall": service_status['overall']
    }
    
    return status_copy

# ==================== Initialization ====================

# Module initialization
if __name__ != "__main__":
    logger.info("Initializing analysis module")
    
    # Initialize AI models in background
    if Config.NLP_ENABLED:
        initialize_ai_models_background()
        
        # Start batch analysis if enabled
        if Config.AUTO_ANALYZE:
            # Delay start to allow services to initialize
            def delayed_start():
                time.sleep(30)
                start_background_batch_analysis(interval_hours=4)
            
            threading.Thread(target=delayed_start, daemon=True).start()
            logger.info("Scheduled background batch analysis to start in 30 seconds")
    else:
        logger.info("NLP analysis disabled in configuration")
        service_manager = Config.get_service_manager()
        service_manager.update_status('ai_models', ServiceStatus.READY)
    
    # Update analysis service status
    update_service_status(ServiceStatus.READY)
    logger.info("Analysis module initialization completed")

# CLI mode
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat Intelligence Batch Analysis Tool')
    parser.add_argument('--feed', type=str, help='Analyze specific feed by ID')
    parser.add_argument('--all', action='store_true', help='Analyze all enabled feeds')
    parser.add_argument('--status', action='store_true', help='Show analysis status')
    parser.add_argument('--summary', action='store_true', help='Show analysis summary')
    parser.add_argument('--days', type=int, default=7, help='Days to include in summary')
    parser.add_argument('--sample-size', type=int, default=100, help='Sample size for analysis')
    args = parser.parse_args()
    
    # Initialize configuration
    Config.init_app()
    
    # Initialize AI models if needed
    if Config.NLP_ENABLED:
        initialize_ai_models_background()
        time.sleep(5)  # Give models time to initialize
    
    if args.status:
        status = get_analysis_status()
        print(json.dumps(status, indent=2))
        
    elif args.summary:
        summary = get_batch_analysis_summary(days=args.days)
        print(json.dumps(summary, indent=2))
        
    elif args.feed:
        logger.info(f"Analyzing feed: {args.feed}")
        result = analyze_feed_batch(args.feed, sample_size=args.sample_size, force_analyze=True)
        print(json.dumps(result, indent=2))
        
    elif args.all:
        logger.info("Analyzing all enabled feeds...")
        
        # Get feeds
        feeds = Config.get_enabled_feeds() if hasattr(Config, 'get_enabled_feeds') else Config.FEEDS
        
        results = []
        for feed in feeds:
            if feed.get('enabled', True) and feed.get('id'):
                result = analyze_feed_batch(feed['id'], sample_size=args.sample_size, force_analyze=True)
                results.append(result)
        
        print(json.dumps(results, indent=2))
        
    else:
        logger.info("No action specified. Use --help for options.")
