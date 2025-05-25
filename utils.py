import os
import json
import logging
import time
import tempfile
import re
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from google.cloud import bigquery, secretmanager, storage
from google.api_core import exceptions as gcp_exceptions
from google.auth import default
import google.generativeai as genai

# Configure logging
logger = logging.getLogger(__name__)

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")
BUCKET_NAME = f"{PROJECT_ID}-telegram-sessions"

# CIPHER Cybersecurity Intelligence Channels
MONITORED_CHANNELS = [
    "@DarkfeedNews",        # Advanced Persistent Threats & Zero-days
    "@breachdetector",      # Data breach monitoring & credential dumps
    "@secharvester",        # CVE, patches, security advisories
]

# Enhanced channel metadata for threat intelligence
CHANNEL_METADATA = {
    "@DarkfeedNews": {
        "type": "cyber_threat_intelligence",
        "priority": "critical",
        "focus": "advanced_persistent_threats",
        "threat_multiplier": 1.5,
        "keywords": ["apt", "malware", "ransomware", "zero-day", "exploit", "breach", "attack"],
        "description": "Premium threat intelligence focusing on APTs and zero-day exploits"
    },
    "@breachdetector": {
        "type": "data_breach_monitor", 
        "priority": "high",
        "focus": "data_breaches",
        "threat_multiplier": 1.3,
        "keywords": ["breach", "leak", "database", "stolen", "credentials", "dump"],
        "description": "Real-time data breach and credential leak monitoring"
    },
    "@secharvester": {
        "type": "security_news",
        "priority": "medium", 
        "focus": "security_updates",
        "threat_multiplier": 1.0,
        "keywords": ["vulnerability", "cve", "patch", "security", "advisory"],
        "description": "Security news, CVE tracking, and patch information"
    }
}

# Global clients
_bq_client = None
_secret_client = None
_storage_client = None
_gemini_model = None
_telegram_client = None

# System state
_clients_initialized = False
_bigquery_available = False
_gemini_available = False
_telegram_connected = False
_monitoring_active = False
_initialization_lock = asyncio.Lock()

async def initialize_all_systems():
    """Initialize all Google Cloud and external systems"""
    global _clients_initialized
    
    async with _initialization_lock:
        if _clients_initialized:
            return True
        
        try:
            logger.info("🔧 Initializing all systems...")
            
            # Initialize Google Cloud clients
            await initialize_gcp_clients()
            
            # Setup BigQuery infrastructure
            await setup_bigquery_infrastructure()
            
            # Initialize Gemini AI
            await initialize_gemini_ai()
            
            # Initialize Telegram (optional, graceful failure)
            await initialize_telegram_client()
            
            _clients_initialized = True
            logger.info("✅ All systems initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            return False

async def initialize_gcp_clients():
    """Initialize Google Cloud Platform clients"""
    global _bq_client, _secret_client, _storage_client, _bigquery_available
    
    try:
        # Initialize BigQuery client
        try:
            credentials, project = default()
            _bq_client = bigquery.Client(project=project, credentials=credentials)
            
            # Test connection
            test_query = "SELECT 1 as test"
            query_job = _bq_client.query(test_query)
            list(query_job.result(timeout=10))
            
            _bigquery_available = True
            logger.info("✅ BigQuery client initialized")
        except Exception as e:
            logger.error(f"BigQuery initialization failed: {e}")
            _bigquery_available = False
        
        # Initialize Secret Manager client
        try:
            _secret_client = secretmanager.SecretManagerServiceClient()
            logger.info("✅ Secret Manager client initialized")
        except Exception as e:
            logger.error(f"Secret Manager initialization failed: {e}")
        
        # Initialize Storage client
        try:
            _storage_client = storage.Client(project=PROJECT_ID)
            logger.info("✅ Storage client initialized")
        except Exception as e:
            logger.error(f"Storage initialization failed: {e}")
            
    except Exception as e:
        logger.error(f"GCP clients initialization failed: {e}")
        raise

async def setup_bigquery_infrastructure():
    """Setup BigQuery dataset and tables with enhanced schema"""
    if not _bigquery_available:
        logger.warning("BigQuery not available, skipping infrastructure setup")
        return
    
    try:
        logger.info("📊 Setting up BigQuery infrastructure...")
        
        # Create dataset if not exists
        dataset_ref = _bq_client.dataset(DATASET_ID)
        try:
            _bq_client.get_dataset(dataset_ref)
            logger.info(f"BigQuery dataset '{DATASET_ID}' exists")
        except gcp_exceptions.NotFound:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "CIPHER Cybersecurity Intelligence Platform - Threat Intelligence Data"
            _bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset '{DATASET_ID}'")

        # Enhanced cybersecurity schema
        schema = [
            # Core message fields
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("chat_username", "STRING"),
            bigquery.SchemaField("user_id", "STRING"),
            bigquery.SchemaField("username", "STRING"),
            bigquery.SchemaField("message_text", "STRING"),
            bigquery.SchemaField("message_date", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("processed_date", "TIMESTAMP", mode="REQUIRED"),
            
            # AI Analysis fields
            bigquery.SchemaField("gemini_analysis", "STRING"),
            bigquery.SchemaField("sentiment", "STRING"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED"),
            bigquery.SchemaField("urgency_score", "FLOAT"),
            bigquery.SchemaField("category", "STRING"),
            
            # Cybersecurity fields
            bigquery.SchemaField("threat_level", "STRING"),
            bigquery.SchemaField("threat_type", "STRING"),
            bigquery.SchemaField("channel_type", "STRING"),
            bigquery.SchemaField("channel_priority", "STRING"),
            bigquery.SchemaField("iocs_detected", "STRING", mode="REPEATED"),
            bigquery.SchemaField("cve_references", "STRING", mode="REPEATED"),
            bigquery.SchemaField("malware_families", "STRING", mode="REPEATED"),
            bigquery.SchemaField("affected_systems", "STRING", mode="REPEATED"),
            bigquery.SchemaField("attack_vectors", "STRING", mode="REPEATED"),
            bigquery.SchemaField("threat_actors", "STRING", mode="REPEATED"),
            bigquery.SchemaField("campaign_names", "STRING", mode="REPEATED"),
            bigquery.SchemaField("geographical_targets", "STRING", mode="REPEATED"),
            bigquery.SchemaField("industry_targets", "STRING", mode="REPEATED"),
        ]

        # Create table with partitioning and clustering
        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = _bq_client.get_table(table_ref)
            logger.info(f"BigQuery table '{TABLE_ID}' exists")
        except gcp_exceptions.NotFound:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "CIPHER Cybersecurity Intelligence Messages"
            
            # Add partitioning and clustering for performance
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="processed_date"
            )
            table.clustering_fields = ["threat_level", "channel_type", "category"]
            
            _bq_client.create_table(table, timeout=30)
            logger.info(f"Created partitioned BigQuery table '{TABLE_ID}'")

        logger.info("✅ BigQuery infrastructure ready")
        
    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def get_secret(secret_id: str) -> Optional[str]:
    """Get secret from Secret Manager"""
    try:
        if not _secret_client:
            logger.warning("Secret Manager client not available")
            return None
        
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = _secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        
        if not secret_value or secret_value.startswith("REPLACE_WITH"):
            logger.error(f"Secret {secret_id} contains placeholder value")
            return None
            
        logger.info(f"Retrieved secret: {secret_id}")
        return secret_value
        
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        return None

async def initialize_gemini_ai():
    """Initialize Gemini AI for cybersecurity analysis"""
    global _gemini_model, _gemini_available
    
    try:
        logger.info("🤖 Initializing Gemini AI...")
        
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            logger.warning("Gemini API key not available")
            return False
        
        genai.configure(api_key=api_key)
        _gemini_model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                top_p=0.8,
                max_output_tokens=1000
            )
        )
        
        # Test the model
        test_response = await asyncio.to_thread(
            _gemini_model.generate_content, 
            "Analyze this test message for cybersecurity threats: 'This is a test message.'"
        )
        
        if test_response.text:
            _gemini_available = True
            logger.info("✅ Gemini AI initialized and tested")
            return True
        else:
            raise Exception("Gemini test failed")
            
    except Exception as e:
        logger.error(f"Gemini AI initialization failed: {e}")
        _gemini_available = False
        return False

async def initialize_telegram_client():
    """Initialize Telegram client (optional)"""
    global _telegram_client, _telegram_connected
    
    try:
        logger.info("📱 Initializing Telegram client...")
        
        # For production, we'll set this up later when secrets are properly configured
        # This is a placeholder for the full Telegram integration
        _telegram_connected = False
        logger.info("⚠️ Telegram client setup deferred (secrets configuration needed)")
        
        return False
        
    except Exception as e:
        logger.error(f"Telegram initialization failed: {e}")
        _telegram_connected = False
        return False

async def start_monitoring_system():
    """Start the cybersecurity monitoring system"""
    global _monitoring_active
    
    try:
        logger.info("🛡️ Starting CIPHER monitoring system...")
        
        if not _clients_initialized:
            await initialize_all_systems()
        
        # For now, we'll run in data-only mode
        # Full monitoring requires Telegram authentication
        _monitoring_active = _bigquery_available
        
        if _monitoring_active:
            logger.info("✅ CIPHER monitoring active (data-only mode)")
        else:
            logger.warning("⚠️ CIPHER monitoring limited (BigQuery unavailable)")
        
        return _monitoring_active
        
    except Exception as e:
        logger.error(f"Monitoring system start failed: {e}")
        _monitoring_active = False
        return False

async def stop_monitoring_system():
    """Stop the monitoring system"""
    global _monitoring_active, _telegram_client
    
    try:
        if _telegram_client:
            await _telegram_client.disconnect()
            _telegram_client = None
        
        _monitoring_active = False
        logger.info("🛑 CIPHER monitoring stopped")
        
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")

async def get_comprehensive_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics"""
    try:
        if not _bigquery_available:
            return _get_default_stats()
        
        # Base query for essential stats
        base_query = f"""
        SELECT 
            COUNT(*) as total_messages,
            COUNTIF(DATE(processed_date) = CURRENT_DATE()) as processed_today,
            COUNT(DISTINCT chat_username) as unique_channels,
            AVG(COALESCE(urgency_score, 0)) as avg_urgency
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        try:
            query_job = _bq_client.query(base_query)
            row = next(iter(query_job.result(timeout=30)), None)
            
            if row:
                stats = {
                    "total_messages": int(row.total_messages) if row.total_messages else 0,
                    "processed_today": int(row.processed_today) if row.processed_today else 0,
                    "unique_channels": int(row.unique_channels) if row.unique_channels else 3,
                    "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
                    "monitoring_active": _monitoring_active,
                    "data_source": "bigquery"
                }
                
                # Try to get threat-specific stats
                try:
                    threat_query = f"""
                    SELECT 
                        COUNTIF(threat_level IN ('high', 'critical')) as high_threats,
                        COUNTIF(threat_level = 'critical') as critical_threats,
                        COUNTIF(category = 'data_breach') as data_breaches,
                        COUNTIF(category = 'malware') as malware_alerts,
                        COUNTIF(category = 'vulnerability') as vulnerabilities,
                        COUNTIF(ARRAY_LENGTH(cve_references) > 0) as cve_mentions,
                        COUNTIF(category = 'apt') as apt_activity,
                        COUNTIF(category = 'ransomware') as ransomware_alerts
                    FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
                    WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
                    """
                    
                    threat_job = _bq_client.query(threat_query)
                    threat_row = next(iter(threat_job.result(timeout=15)), None)
                    
                    if threat_row:
                        stats.update({
                            "high_threats": int(threat_row.high_threats) if threat_row.high_threats else 0,
                            "critical_threats": int(threat_row.critical_threats) if threat_row.critical_threats else 0,
                            "data_breaches": int(threat_row.data_breaches) if threat_row.data_breaches else 0,
                            "malware_alerts": int(threat_row.malware_alerts) if threat_row.malware_alerts else 0,
                            "vulnerabilities": int(threat_row.vulnerabilities) if threat_row.vulnerabilities else 0,
                            "cve_mentions": int(threat_row.cve_mentions) if threat_row.cve_mentions else 0,
                            "apt_activity": int(threat_row.apt_activity) if threat_row.apt_activity else 0,
                            "ransomware_alerts": int(threat_row.ransomware_alerts) if threat_row.ransomware_alerts else 0
                        })
                        
                except Exception:
                    # Threat columns don't exist yet, add defaults
                    stats.update({
                        "high_threats": 0,
                        "critical_threats": 0,
                        "data_breaches": 0,
                        "malware_alerts": 0,
                        "vulnerabilities": 0,
                        "cve_mentions": 0,
                        "apt_activity": 0,
                        "ransomware_alerts": 0
                    })
                
                return stats
            else:
                return _get_default_stats()
                
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            return _get_default_stats()
        
    except Exception as e:
        logger.error(f"Failed to get comprehensive stats: {e}")
        return _get_default_stats()

async def get_threat_insights() -> Dict[str, Any]:
    """Get latest threat intelligence insights"""
    try:
        if not _bigquery_available:
            return {"insights": [], "total": 0, "source": "bigquery_unavailable"}
        
        # Query for recent insights
        query = f"""
        SELECT 
            message_id,
            chat_username,
            message_text,
            message_date,
            processed_date,
            gemini_analysis,
            sentiment,
            urgency_score,
            COALESCE(threat_level, 'low') as threat_level,
            COALESCE(category, 'other') as category,
            COALESCE(threat_type, 'unknown') as threat_type
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC, urgency_score DESC
        LIMIT 50
        """
        
        query_job = _bq_client.query(query)
        results = query_job.result(timeout=30)
        
        insights = []
        for row in results:
            insight = {
                "message_id": row.message_id,
                "chat_username": row.chat_username or "@Unknown",
                "message_text": (row.message_text or "")[:1000],
                "message_date": row.message_date.isoformat() if row.message_date else None,
                "processed_date": row.processed_date.isoformat() if row.processed_date else None,
                "gemini_analysis": row.gemini_analysis or "No analysis available",
                "sentiment": row.sentiment or "neutral",
                "urgency_score": float(row.urgency_score) if row.urgency_score is not None else 0.0,
                "threat_level": row.threat_level,
                "category": row.category,
                "threat_type": row.threat_type,
                "key_topics": [],  # Default empty, will be filled if available
                "cve_references": [],
                "malware_families": [],
                "threat_actors": []
            }
            insights.append(insight)
        
        logger.info(f"Retrieved {len(insights)} threat insights")
        return {
            "insights": insights,
            "total": len(insights),
            "source": "bigquery"
        }
        
    except Exception as e:
        logger.error(f"Failed to get threat insights: {e}")
        return {"insights": [], "total": 0, "source": "error", "error": str(e)}

async def get_monitoring_status() -> Dict[str, Any]:
    """Get detailed monitoring system status"""
    try:
        status = {
            "active": _monitoring_active,
            "subsystems": {
                "bigquery": _bigquery_available,
                "gemini": _gemini_available,
                "telegram": _telegram_connected
            },
            "channels": {
                "monitored": MONITORED_CHANNELS,
                "metadata": CHANNEL_METADATA,
                "count": len(MONITORED_CHANNELS)
            },
            "last_check": datetime.now().isoformat(),
            "system_health": "operational" if _monitoring_active else "limited"
        }
        
        # Add detailed channel status
        channel_status = []
        for channel in MONITORED_CHANNELS:
            metadata = CHANNEL_METADATA.get(channel, {})
            channel_status.append({
                "username": channel,
                "type": metadata.get("type", "unknown"),
                "priority": metadata.get("priority", "medium"),
                "status": "monitoring" if _monitoring_active else "standby",
                "description": metadata.get("description", "")
            })
        
        status["channel_status"] = channel_status
        return status
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return {"active": False, "error": str(e)}

async def get_threat_analytics() -> Dict[str, Any]:
    """Get comprehensive threat analytics"""
    try:
        insights_data = await get_threat_insights()
        insights = insights_data["insights"]
        
        analytics = {
            "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "categories": {
                "threat_intel": 0, "data_breach": 0, "vulnerability": 0, 
                "malware": 0, "ransomware": 0, "apt": 0, "other": 0
            },
            "top_threats": [],
            "urgency_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "channel_activity": {},
            "time_analysis": {},
            "summary": {}
        }
        
        if not insights:
            return analytics
        
        # Process insights for analytics
        threat_types = {}
        urgency_scores = []
        
        for insight in insights:
            # Threat level distribution
            threat_level = insight.get("threat_level", "low")
            if threat_level in analytics["threat_levels"]:
                analytics["threat_levels"][threat_level] += 1
            
            # Category distribution
            category = insight.get("category", "other")
            if category in analytics["categories"]:
                analytics["categories"][category] += 1
            
            # Urgency analysis
            urgency = insight.get("urgency_score", 0.0)
            urgency_scores.append(urgency)
            if urgency >= 0.8:
                analytics["urgency_distribution"]["critical"] += 1
            elif urgency >= 0.6:
                analytics["urgency_distribution"]["high"] += 1
            elif urgency >= 0.4:
                analytics["urgency_distribution"]["medium"] += 1
            else:
                analytics["urgency_distribution"]["low"] += 1
            
            # Track threat types
            threat_type = insight.get("threat_type", "unknown")
            if threat_type != "unknown":
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Channel activity
            channel = insight.get("chat_username", "Unknown")
            if channel not in analytics["channel_activity"]:
                analytics["channel_activity"][channel] = {"count": 0, "avg_urgency": 0.0}
            analytics["channel_activity"][channel]["count"] += 1
        
        # Calculate top threats
        analytics["top_threats"] = [
            {"type": t_type, "count": count, "percentage": round((count/len(insights))*100, 1)}
            for t_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Calculate summary
        analytics["summary"] = {
            "total_threats": len(insights),
            "high_priority": analytics["threat_levels"]["critical"] + analytics["threat_levels"]["high"],
            "avg_urgency": sum(urgency_scores) / len(urgency_scores) if urgency_scores else 0.0,
            "active_channels": len(analytics["channel_activity"]),
            "threat_categories": len([c for c, count in analytics["categories"].items() if count > 0])
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Error calculating threat analytics: {e}")
        return {"error": str(e), "status": "error"}

def _get_default_stats() -> Dict[str, Any]:
    """Return default statistics when systems unavailable"""
    return {
        "total_messages": 0,
        "processed_today": 0,
        "unique_channels": len(MONITORED_CHANNELS),
        "avg_urgency": 0.0,
        "high_threats": 0,
        "critical_threats": 0,
        "data_breaches": 0,
        "malware_alerts": 0,
        "vulnerabilities": 0,
        "cve_mentions": 0,
        "apt_activity": 0,
        "ransomware_alerts": 0,
        "monitoring_active": _monitoring_active,
        "data_source": "system_default"
    }

# System state checkers
def is_bigquery_available() -> bool:
    """Check if BigQuery is available"""
    return _bigquery_available

def is_gemini_available() -> bool:
    """Check if Gemini AI is available"""
    return _gemini_available

def is_telegram_connected() -> bool:
    """Check if Telegram is connected"""
    return _telegram_connected

def is_monitoring_active() -> bool:
    """Check if monitoring is active"""
    return _monitoring_active

# Export main functions
__all__ = [
    'initialize_all_systems',
    'start_monitoring_system',
    'stop_monitoring_system',
    'get_comprehensive_stats',
    'get_threat_insights',
    'get_monitoring_status',
    'get_threat_analytics',
    'is_bigquery_available',
    'is_gemini_available',
    'is_telegram_connected',
    'is_monitoring_active',
    'MONITORED_CHANNELS',
    'CHANNEL_METADATA'
]
