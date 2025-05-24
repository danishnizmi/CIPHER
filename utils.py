import os
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
import re
import time
from google.cloud import bigquery
from google.cloud import secretmanager
from google.cloud import storage
import google.generativeai as genai

logger = logging.getLogger(__name__)

# Initialize clients with error handling
try:
    bq_client = bigquery.Client()
except Exception as e:
    logger.warning(f"BigQuery client init delayed: {e}")
    bq_client = None

try:
    secret_client = secretmanager.SecretManagerServiceClient()
except Exception as e:
    logger.warning(f"Secret Manager client init delayed: {e}")
    secret_client = None

try:
    storage_client = storage.Client()
except Exception as e:
    logger.warning(f"Storage client init delayed: {e}")
    storage_client = None

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")

# Session configuration
BUCKET_NAME = f"{PROJECT_ID}-telegram-sessions"
SESSION_NAME = "cipher_session"

# Global state variables
telegram_client = None
gemini_model = None
_monitoring_task = None
_initialization_lock = asyncio.Lock()
_clients_initialized = False

# CIPHER Cybersecurity Channels
MONITORED_CHANNELS = [
    "@DarkfeedNews",        # DARKFEED - Advanced Persistent Threats
    "@breachdetector",      # Breach Detection - Data leak monitoring
    "@secharvester",        # Security Harvester - Cybersecurity news
]

# Enhanced channel metadata for threat intelligence
CHANNEL_METADATA = {
    "@DarkfeedNews": {
        "type": "cyber_threat_intelligence",
        "priority": "critical",
        "focus": "advanced_persistent_threats",
        "threat_multiplier": 1.5,
        "keywords": ["apt", "malware", "ransomware", "zero-day", "exploit", "breach", "attack"]
    },
    "@breachdetector": {
        "type": "data_breach_monitor", 
        "priority": "high",
        "focus": "data_breaches",
        "threat_multiplier": 1.3,
        "keywords": ["breach", "leak", "database", "stolen", "credentials", "dump", "exposure"]
    },
    "@secharvester": {
        "type": "security_news",
        "priority": "medium", 
        "focus": "security_updates",
        "threat_multiplier": 1.0,
        "keywords": ["vulnerability", "cve", "patch", "security", "advisory", "update"]
    }
}

# Configuration
MESSAGE_DATE_LIMIT = timedelta(days=30)
_last_api_call = {}
_api_call_delay = 1.0

async def rate_limit_check(operation: str) -> None:
    """Implement rate limiting for API calls"""
    now = datetime.now()
    if operation in _last_api_call:
        time_diff = (now - _last_api_call[operation]).total_seconds()
        if time_diff < _api_call_delay:
            await asyncio.sleep(_api_call_delay - time_diff)
    _last_api_call[operation] = now

async def initialize_clients():
    """Initialize Google Cloud clients with retry logic"""
    global bq_client, secret_client, storage_client, _clients_initialized
    
    async with _initialization_lock:
        if _clients_initialized:
            return True
        
        try:
            logger.info("Initializing Google Cloud clients...")
            
            # Initialize BigQuery client
            if not bq_client:
                bq_client = bigquery.Client(project=PROJECT_ID)
            
            # Initialize Secret Manager client
            if not secret_client:
                secret_client = secretmanager.SecretManagerServiceClient()
            
            # Initialize Storage client
            if not storage_client:
                storage_client = storage.Client(project=PROJECT_ID)
            
            _clients_initialized = True
            logger.info("Google Cloud clients initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Cloud clients: {e}")
            return False

async def get_secret(secret_id: str) -> Optional[str]:
    """Get secret from Secret Manager with retries"""
    try:
        if not secret_client:
            await initialize_clients()
        
        if not secret_client:
            logger.error("Secret Manager client not available")
            return None
        
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        
        if not secret_value or secret_value.startswith("REPLACE_WITH"):
            logger.error(f"Secret {secret_id} contains placeholder value")
            return None
            
        logger.info(f"Successfully retrieved secret: {secret_id}")
        return secret_value
        
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        return None

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables with error handling"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            raise Exception("BigQuery client not available")
        
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            dataset = bq_client.get_dataset(dataset_ref)
            logger.info(f"BigQuery dataset {DATASET_ID} already exists")
        except Exception:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "CIPHER Cybersecurity Intelligence Platform"
            dataset = bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset {DATASET_ID}")

        # Enhanced cybersecurity schema
        schema = [
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
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info(f"BigQuery table {TABLE_ID} already exists")
        except Exception:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "CIPHER Cybersecurity Intelligence Messages"
            
            # Add partitioning and clustering for performance
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="processed_date"
            )
            table.clustering_fields = ["threat_level", "channel_type", "category"]
            
            table = bq_client.create_table(table, timeout=30)
            logger.info(f"Created BigQuery table {TABLE_ID}")

        logger.info("BigQuery setup completed successfully")

    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def initialize_gemini():
    """Initialize Gemini AI with error handling"""
    global gemini_model
    try:
        # Get Gemini API key
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            raise Exception("Gemini API key not available")
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                top_p=0.8,
                max_output_tokens=800,
                candidate_count=1,
            )
        )
        
        # Test the model
        test_response = await asyncio.to_thread(
            gemini_model.generate_content, 
            "Test cybersecurity analysis. Return: {'status': 'ok'}"
        )
        
        if test_response.text:
            logger.info("Gemini AI initialized successfully")
            return True
        else:
            raise Exception("Gemini test failed")
            
    except Exception as e:
        logger.error(f"Failed to initialize Gemini AI: {e}")
        return False

async def download_session_from_storage() -> Optional[bytes]:
    """Download Telegram session from Cloud Storage"""
    try:
        if not storage_client:
            await initialize_clients()
        
        if not storage_client:
            raise Exception("Storage client not available")
        
        logger.info(f"Downloading session from gs://{BUCKET_NAME}/{SESSION_NAME}.session")
        
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{SESSION_NAME}.session")
        
        if not blob.exists():
            logger.error("Session file not found in Cloud Storage")
            return None
        
        session_data = blob.download_as_bytes()
        if not session_data:
            logger.error("Downloaded session file is empty")
            return None
        
        logger.info("Session downloaded successfully")
        return session_data
        
    except Exception as e:
        logger.error(f"Failed to download session: {e}")
        return None

async def initialize_telegram_client():
    """Initialize Telegram client with session from Cloud Storage"""
    global telegram_client
    
    try:
        logger.info("Initializing Telegram client...")
        
        # Import Telethon here to avoid startup delay
        from telethon import TelegramClient, events
        from telethon.errors import (
            AuthKeyUnregisteredError, UserDeactivatedError, UnauthorizedError
        )
        import tempfile
        
        # Get credentials
        api_id_str = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        
        if not api_id_str or not api_hash:
            raise Exception("Telegram credentials not available")
        
        api_id = int(api_id_str)
        
        # Download session
        session_data = await download_session_from_storage()
        if not session_data:
            raise Exception("No session available")
        
        # Create temporary session file
        temp_dir = tempfile.gettempdir()
        session_path = os.path.join(temp_dir, f"{SESSION_NAME}.session")
        
        with open(session_path, 'wb') as f:
            f.write(session_data)
        
        # Create client
        telegram_client = TelegramClient(
            session_path,
            api_id, 
            api_hash,
            timeout=30,
            retry_delay=2,
            auto_reconnect=True,
            connection_retries=3
        )
        
        # Connect with timeout
        await asyncio.wait_for(telegram_client.connect(), timeout=30)
        
        # Verify authorization
        is_authorized = await telegram_client.is_user_authorized()
        if not is_authorized:
            raise Exception("Session not authorized")
        
        # Get user info
        me = await telegram_client.get_me()
        logger.info(f"Telegram client initialized: {me.username or me.first_name}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize Telegram client: {e}")
        if telegram_client:
            try:
                await telegram_client.disconnect()
            except:
                pass
        return False

async def get_recent_insights(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent cybersecurity insights with error handling"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            logger.warning("BigQuery not available")
            return []
        
        query = f"""
        SELECT 
            message_id,
            chat_username,
            chat_id,
            username,
            message_text,
            message_date,
            gemini_analysis,
            sentiment,
            key_topics,
            urgency_score,
            category,
            threat_level,
            threat_type,
            channel_type,
            channel_priority,
            iocs_detected,
            cve_references,
            malware_families,
            affected_systems
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC, urgency_score DESC
        LIMIT {limit}
        OFFSET {offset}
        """
        
        query_job = bq_client.query(query, timeout=30)
        results = []
        
        for row in query_job:
            results.append({
                "message_id": row.message_id,
                "chat_username": row.chat_username or "Unknown",
                "chat_id": row.chat_id,
                "username": row.username or "Unknown",
                "message_text": row.message_text,
                "message_date": row.message_date.isoformat() if row.message_date else None,
                "gemini_analysis": row.gemini_analysis,
                "sentiment": row.sentiment,
                "key_topics": list(row.key_topics) if row.key_topics else [],
                "urgency_score": float(row.urgency_score) if row.urgency_score is not None else 0.0,
                "category": row.category,
                "threat_level": getattr(row, 'threat_level', 'low'),
                "threat_type": getattr(row, 'threat_type', 'unknown'),
                "channel_type": getattr(row, 'channel_type', 'unknown'),
                "channel_priority": getattr(row, 'channel_priority', 'medium'),
                "iocs_detected": list(getattr(row, 'iocs_detected', [])),
                "cve_references": list(getattr(row, 'cve_references', [])),
                "malware_families": list(getattr(row, 'malware_families', [])),
                "affected_systems": list(getattr(row, 'affected_systems', []))
            })
        
        logger.info(f"Retrieved {len(results)} cybersecurity insights")
        return results

    except Exception as e:
        logger.error(f"Failed to get insights: {e}")
        return []

async def get_message_stats() -> Dict[str, Any]:
    """Get message statistics with error handling"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            # Return default stats if BigQuery not available
            logger.warning("BigQuery client not available - returning default stats")
            return _get_default_stats()
        
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        
        query = f"""
        SELECT 
            COUNT(*) as total_messages,
            COUNT(CASE WHEN DATE(processed_date) = '{today}' THEN 1 END) as processed_today,
            AVG(urgency_score) as avg_urgency,
            COUNT(DISTINCT chat_id) as unique_channels,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(CASE WHEN threat_level IN ('critical', 'high') THEN 1 END) as high_threats,
            COUNT(CASE WHEN threat_level = 'critical' THEN 1 END) as critical_threats,
            COUNT(CASE WHEN category = 'data_breach' THEN 1 END) as data_breaches,
            COUNT(CASE WHEN category = 'malware' THEN 1 END) as malware_alerts,
            COUNT(CASE WHEN category = 'vulnerability' THEN 1 END) as vulnerabilities,
            COUNT(CASE WHEN array_length(cve_references) > 0 THEN 1 END) as cve_mentions
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE DATE(processed_date) >= '{week_ago}'
        """
        
        try:
            query_job = bq_client.query(query, timeout=30)
            row = next(iter(query_job), None)
            
            if row:
                stats = {
                    "total_messages": int(row.total_messages) if row.total_messages else 0,
                    "processed_today": int(row.processed_today) if row.processed_today else 0,
                    "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
                    "unique_channels": int(row.unique_channels) if row.unique_channels else 0,
                    "unique_users": int(row.unique_users) if row.unique_users else 0,
                    "high_threats": int(row.high_threats) if row.high_threats else 0,
                    "critical_threats": int(row.critical_threats) if row.critical_threats else 0,
                    "data_breaches": int(row.data_breaches) if row.data_breaches else 0,
                    "malware_alerts": int(row.malware_alerts) if row.malware_alerts else 0,
                    "vulnerabilities": int(row.vulnerabilities) if row.vulnerabilities else 0,
                    "cve_mentions": int(row.cve_mentions) if row.cve_mentions else 0,
                }
            else:
                stats = _get_default_stats()
                
        except Exception as query_error:
            # Log the specific BigQuery error but don't fail
            logger.error(f"BigQuery query failed: {query_error}")
            stats = _get_default_stats()
            stats["bigquery_error"] = "Query failed - using defaults"
        
        # Add monitoring status
        stats["monitoring_active"] = (
            telegram_client is not None and 
            telegram_client.is_connected() if telegram_client else False
        )
        
        return stats

    except Exception as e:
        logger.error(f"Failed to get cybersecurity stats: {e}")
        return _get_default_stats()

def _get_default_stats() -> Dict[str, Any]:
    """Return default stats when BigQuery unavailable"""
    return {
        "total_messages": 0,
        "processed_today": 0,
        "avg_urgency": 0.0,
        "unique_channels": len(MONITORED_CHANNELS),
        "unique_users": 0,
        "high_threats": 0,
        "critical_threats": 0,
        "data_breaches": 0,
        "malware_alerts": 0,
        "vulnerabilities": 0,
        "cve_mentions": 0,
        "monitoring_active": False,
        "note": "Statistics will be available after BigQuery initialization"
    }

async def start_background_monitoring():
    """Start background monitoring with error handling"""
    global _monitoring_task
    
    try:
        logger.info("Starting CIPHER cybersecurity monitoring...")
        
        # Initialize Gemini AI
        gemini_success = await initialize_gemini()
        if not gemini_success:
            logger.warning("Gemini AI initialization failed - using fallback analysis")
        
        # Initialize Telegram client
        telegram_success = await initialize_telegram_client()
        if not telegram_success:
            logger.error("Telegram client initialization failed")
            return False
        
        logger.info("CIPHER monitoring system started successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return False

async def stop_background_monitoring():
    """Stop background monitoring"""
    global _monitoring_task, telegram_client
    
    try:
        if telegram_client:
            await telegram_client.disconnect()
            telegram_client = None
        
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
            try:
                await _monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("CIPHER monitoring stopped")
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")

# Export main functions
__all__ = [
    'setup_bigquery_tables',
    'start_background_monitoring', 
    'stop_background_monitoring',
    'get_recent_insights',
    'get_message_stats',
    'MONITORED_CHANNELS',
    'CHANNEL_METADATA',
    'telegram_client'
]
