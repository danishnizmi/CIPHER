import os
import json
import logging
import time
import tempfile
import re
import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
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
        "keywords": ["apt", "malware", "ransomware", "zero-day", "exploit", "breach", "attack", "darkfeed", "leak"],
        "description": "Premium threat intelligence focusing on APTs and zero-day exploits",
        "color": "#ff4444",
        "icon": "🔴"
    },
    "@breachdetector": {
        "type": "data_breach_monitor", 
        "priority": "high",
        "focus": "data_breaches",
        "threat_multiplier": 1.3,
        "keywords": ["breach", "leak", "database", "stolen", "credentials", "dump", "hacked", "compromised"],
        "description": "Real-time data breach and credential leak monitoring",
        "color": "#ffaa00",
        "icon": "🟠"
    },
    "@secharvester": {
        "type": "security_news",
        "priority": "medium", 
        "focus": "security_updates",
        "threat_multiplier": 1.0,
        "keywords": ["vulnerability", "cve", "patch", "security", "advisory", "update", "fix"],
        "description": "Security news, CVE tracking, and patch information",
        "color": "#6366f1",
        "icon": "🔵"
    }
}

# Enhanced cybersecurity patterns for better data extraction
CYBERSEC_PATTERNS = {
    "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
    "ip_address": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    "domain": re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
}

# Threat actor groups and malware families
THREAT_ACTORS = [
    "lazarus", "apt1", "apt28", "apt29", "apt30", "apt32", "apt34", "apt40", "apt41",
    "carbanak", "fin7", "fin8", "sandworm", "turla", "kimsuky", "darkhydrus", "muddywater",
    "oceanlotus", "machete", "gallmaker", "leafy", "scarlet mimic", "naikon", "lotus blossom",
    "comment crew", "elderwood", "aurora", "nitro", "shady rat", "ghostnet", "red october"
]

MALWARE_FAMILIES = [
    "wannacry", "petya", "notpetya", "ryuk", "maze", "lockbit", "conti", "ragnar",
    "emotet", "trickbot", "qakbot", "danabot", "formbook", "remcos", "njrat", "darkcomet",
    "cobalt strike", "metasploit", "mimikatz", "powershell empire", "covenant", "sliver",
    "stuxnet", "duqu", "flame", "gauss", "miniflame", "regin", "equation", "carbanak"
]

VULNERABILITY_KEYWORDS = [
    "zero-day", "0day", "rce", "remote code execution", "privilege escalation", "buffer overflow",
    "sql injection", "xss", "csrf", "directory traversal", "file inclusion", "deserialization"
]

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
_session_string = None
_monitoring_task = None
_table_schema_cache = None

async def get_table_schema() -> Dict[str, str]:
    """Get actual table schema and cache it"""
    global _table_schema_cache
    
    if _table_schema_cache:
        return _table_schema_cache
    
    try:
        if not _bigquery_available:
            return {}
        
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        
        schema_dict = {}
        for field in table.schema:
            schema_dict[field.name] = field.field_type
        
        _table_schema_cache = schema_dict
        logger.info(f"Cached table schema with {len(schema_dict)} fields")
        return schema_dict
        
    except Exception as e:
        logger.error(f"Failed to get table schema: {e}")
        return {}

def build_safe_select_clause(requested_fields: List[str]) -> str:
    """Build a safe SELECT clause using only fields that exist in the table"""
    schema = _table_schema_cache or {}
    
    safe_fields = []
    for field in requested_fields:
        if field in schema:
            safe_fields.append(field)
        elif '(' in field:  # Handle expressions like COALESCE
            safe_fields.append(field)
        else:
            # Provide safe defaults for missing fields
            if field in ['urgency_score', 'confidence_score']:
                safe_fields.append(f"0.0 as {field}")
            elif field in ['threat_level']:
                safe_fields.append(f"'low' as {field}")
            elif field in ['category']:
                safe_fields.append(f"'other' as {field}")
            elif field in ['subcategory', 'threat_type', 'attack_stage', 'kill_chain_phase']:
                safe_fields.append(f"'unknown' as {field}")
            elif field.endswith('_references') or field.endswith('_detected') or field.endswith('_families'):
                safe_fields.append(f"ARRAY<STRING>[] as {field}")
            else:
                safe_fields.append(f"NULL as {field}")
    
    return ', '.join(safe_fields)

async def initialize_all_systems():
    """Initialize all Google Cloud and external systems with comprehensive error handling"""
    global _clients_initialized
    
    async with _initialization_lock:
        if _clients_initialized:
            return True
        
        try:
            logger.info("🔧 Initializing CIPHER cybersecurity intelligence systems...")
            
            # Initialize Google Cloud clients
            await initialize_gcp_clients()
            
            # Setup BigQuery infrastructure with enhanced schema
            await setup_enhanced_bigquery_infrastructure()
            
            # Initialize Gemini AI for cybersecurity analysis
            await initialize_gemini_ai()
            
            # Initialize Telegram monitoring (graceful failure)
            await initialize_telegram_client()
            
            _clients_initialized = True
            logger.info("✅ All CIPHER systems initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            return False

async def initialize_gcp_clients():
    """Initialize Google Cloud Platform clients with enhanced error handling"""
    global _bq_client, _secret_client, _storage_client, _bigquery_available
    
    try:
        # Initialize BigQuery client with enhanced configuration
        try:
            credentials, project = default()
            _bq_client = bigquery.Client(project=project, credentials=credentials)
            
            # Test connection with cybersecurity-specific query
            test_query = """
            SELECT 
                'CIPHER_TEST' as system,
                CURRENT_TIMESTAMP() as test_time,
                'BigQuery connection successful' as status
            """
            query_job = _bq_client.query(test_query)
            result = list(query_job.result(timeout=10))
            
            _bigquery_available = True
            logger.info("✅ BigQuery client initialized and tested")
        except Exception as e:
            logger.error(f"BigQuery initialization failed: {e}")
            _bigquery_available = False
        
        # Initialize Secret Manager client
        try:
            _secret_client = secretmanager.SecretManagerServiceClient()
            logger.info("✅ Secret Manager client initialized")
        except Exception as e:
            logger.error(f"Secret Manager initialization failed: {e}")
        
        # Initialize Storage client for Telegram sessions
        try:
            _storage_client = storage.Client(project=PROJECT_ID)
            logger.info("✅ Storage client initialized")
        except Exception as e:
            logger.error(f"Storage initialization failed: {e}")
            
    except Exception as e:
        logger.error(f"GCP clients initialization failed: {e}")
        raise

async def setup_enhanced_bigquery_infrastructure():
    """Setup BigQuery with enhanced cybersecurity schema"""
    if not _bigquery_available:
        logger.warning("BigQuery not available, skipping infrastructure setup")
        return
    
    try:
        logger.info("📊 Setting up enhanced BigQuery cybersecurity infrastructure...")
        
        # Create dataset if not exists
        dataset_ref = _bq_client.dataset(DATASET_ID)
        try:
            _bq_client.get_dataset(dataset_ref)
            logger.info(f"BigQuery dataset '{DATASET_ID}' exists")
        except gcp_exceptions.NotFound:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "CIPHER Cybersecurity Intelligence Platform - Enhanced Threat Intelligence Data"
            dataset.labels = {"platform": "cipher", "type": "cybersecurity", "version": "v1"}
            _bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset '{DATASET_ID}'")

        # Enhanced cybersecurity schema with comprehensive fields
        schema = [
            # Core message fields
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED", description="Unique message identifier"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED", description="Telegram chat/channel ID"),
            bigquery.SchemaField("chat_username", "STRING", description="Channel username (e.g., @DarkfeedNews)"),
            bigquery.SchemaField("user_id", "STRING", description="Telegram user ID"),
            bigquery.SchemaField("username", "STRING", description="Username without @ symbol"),
            bigquery.SchemaField("message_text", "STRING", description="Original message content"),
            bigquery.SchemaField("message_date", "TIMESTAMP", mode="REQUIRED", description="When message was sent"),
            bigquery.SchemaField("processed_date", "TIMESTAMP", mode="REQUIRED", description="When message was processed"),
            
            # AI Analysis fields
            bigquery.SchemaField("gemini_analysis", "STRING", description="Gemini AI comprehensive threat analysis"),
            bigquery.SchemaField("sentiment", "STRING", description="Message sentiment: positive/negative/neutral"),
            bigquery.SchemaField("confidence_score", "FLOAT", description="AI analysis confidence (0.0-1.0)"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED", description="Key cybersecurity topics identified"),
            bigquery.SchemaField("urgency_score", "FLOAT", description="Threat urgency score (0.0-1.0)"),
            bigquery.SchemaField("category", "STRING", description="Primary threat category"),
            bigquery.SchemaField("subcategory", "STRING", description="Specific threat subcategory"),
            
            # Threat Classification
            bigquery.SchemaField("threat_level", "STRING", description="Threat level: critical/high/medium/low/info"),
            bigquery.SchemaField("threat_type", "STRING", description="Specific threat type (e.g., APT, ransomware)"),
            bigquery.SchemaField("attack_stage", "STRING", description="Attack lifecycle stage"),
            bigquery.SchemaField("kill_chain_phase", "STRING", description="MITRE ATT&CK kill chain phase"),
            
            # Channel Metadata
            bigquery.SchemaField("channel_type", "STRING", description="Source channel type"),
            bigquery.SchemaField("channel_priority", "STRING", description="Channel priority level"),
            bigquery.SchemaField("channel_focus", "STRING", description="Channel focus area"),
            
            # Indicators of Compromise (IOCs)
            bigquery.SchemaField("iocs_detected", "STRING", mode="REPEATED", description="All IOCs found"),
            bigquery.SchemaField("ip_addresses", "STRING", mode="REPEATED", description="IP addresses found"),
            bigquery.SchemaField("domains", "STRING", mode="REPEATED", description="Domains found"),
            bigquery.SchemaField("urls", "STRING", mode="REPEATED", description="URLs found"),
            bigquery.SchemaField("file_hashes", "STRING", mode="REPEATED", description="File hashes (MD5, SHA1, SHA256)"),
            bigquery.SchemaField("email_addresses", "STRING", mode="REPEATED", description="Email addresses found"),
            
            # Threat Intelligence
            bigquery.SchemaField("cve_references", "STRING", mode="REPEATED", description="CVE references mentioned"),
            bigquery.SchemaField("cwe_references", "STRING", mode="REPEATED", description="CWE references mentioned"),
            bigquery.SchemaField("mitre_techniques", "STRING", mode="REPEATED", description="MITRE ATT&CK techniques"),
            bigquery.SchemaField("malware_families", "STRING", mode="REPEATED", description="Malware families identified"),
            bigquery.SchemaField("threat_actors", "STRING", mode="REPEATED", description="Threat actors/groups mentioned"),
            bigquery.SchemaField("campaign_names", "STRING", mode="REPEATED", description="Campaign or operation names"),
            
            # Impact Assessment
            bigquery.SchemaField("affected_systems", "STRING", mode="REPEATED", description="Systems/platforms affected"),
            bigquery.SchemaField("affected_vendors", "STRING", mode="REPEATED", description="Vendors/companies affected"),
            bigquery.SchemaField("attack_vectors", "STRING", mode="REPEATED", description="Attack vectors mentioned"),
            bigquery.SchemaField("vulnerabilities", "STRING", mode="REPEATED", description="Vulnerability types"),
            bigquery.SchemaField("geographical_targets", "STRING", mode="REPEATED", description="Geographic regions targeted"),
            bigquery.SchemaField("industry_targets", "STRING", mode="REPEATED", description="Industries targeted"),
            
            # Additional Context
            bigquery.SchemaField("source_reliability", "STRING", description="Source reliability assessment"),
            bigquery.SchemaField("information_type", "STRING", description="Type of intelligence information"),
            bigquery.SchemaField("sharing_level", "STRING", description="Information sharing level (TLP)"),
            bigquery.SchemaField("tags", "STRING", mode="REPEATED", description="Custom tags for categorization"),
            
            # Quality Metrics
            bigquery.SchemaField("processing_time_ms", "INTEGER", description="Processing time in milliseconds"),
            bigquery.SchemaField("data_quality_score", "FLOAT", description="Data quality assessment (0.0-1.0)"),
            bigquery.SchemaField("false_positive_risk", "STRING", description="False positive risk assessment"),
        ]

        # Create table with enhanced partitioning and clustering
        table_ref = dataset_ref.table(TABLE_ID)
        table_exists = False
        try:
            table = _bq_client.get_table(table_ref)
            table_exists = True
            logger.info(f"BigQuery table '{TABLE_ID}' exists with {len(table.schema)} fields")
            
            # Update schema cache
            await get_table_schema()
            
        except gcp_exceptions.NotFound:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "CIPHER Cybersecurity Intelligence Messages - Enhanced Schema"
            
            # Enhanced partitioning and clustering for performance
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="processed_date",
                expiration_ms=None  # Keep all data
            )
            
            # Optimized clustering for cybersecurity queries
            table.clustering_fields = [
                "threat_level", 
                "channel_type", 
                "category", 
                "threat_type"
            ]
            
            # Add labels for better organization
            table.labels = {
                "platform": "cipher",
                "type": "threat_intelligence",
                "version": "enhanced_v1"
            }
            
            _bq_client.create_table(table, timeout=60)
            logger.info(f"Created enhanced BigQuery table '{TABLE_ID}' with {len(schema)} fields")
            
            # Update schema cache
            await get_table_schema()

        logger.info("✅ Enhanced BigQuery cybersecurity infrastructure ready")
        
    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def get_secret(secret_id: str) -> Optional[str]:
    """Get secret from Secret Manager with enhanced error handling"""
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
            
        logger.info(f"Retrieved secret: {secret_id} ({len(secret_value)} chars)")
        return secret_value
        
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        return None

async def initialize_gemini_ai():
    """Initialize Gemini AI for enhanced cybersecurity analysis"""
    global _gemini_model, _gemini_available
    
    try:
        logger.info("🤖 Initializing Gemini AI for cybersecurity analysis...")
        
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            logger.error("Gemini API key not available in Secret Manager")
            return False
        
        try:
            genai.configure(api_key=api_key)
            
            # Enhanced model configuration for cybersecurity analysis
            _gemini_model = genai.GenerativeModel(
                'gemini-1.5-flash',
                generation_config=genai.GenerationConfig(
                    temperature=0.1,  # Low temperature for consistent analysis
                    top_p=0.8,
                    max_output_tokens=2000,  # Increased for detailed analysis
                    candidate_count=1
                ),
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            )
            
            # Test with comprehensive cybersecurity prompt
            test_prompt = """
            Analyze this cybersecurity threat intelligence and respond in JSON format:
            "Critical vulnerability CVE-2024-0001 discovered in Apache servers. Immediate patching required. 
            Exploit code released by threat actor Lazarus. Affects Apache 2.4.x versions. 
            IOCs: 192.168.1.100, malicious-domain.com, hash: d41d8cd98f00b204e9800998ecf8427e"
            """
            
            test_response = await asyncio.to_thread(_gemini_model.generate_content, test_prompt)
            
            if test_response and test_response.text:
                _gemini_available = True
                logger.info("✅ Gemini AI initialized and tested for cybersecurity analysis")
                return True
            else:
                logger.error("Gemini test failed - no response generated")
                return False
                
        except Exception as api_error:
            logger.error(f"Gemini API configuration failed: {api_error}")
            return False
            
    except Exception as e:
        logger.error(f"Gemini AI initialization failed: {e}")
        _gemini_available = False
        return False

async def initialize_telegram_client():
    """Initialize Telegram client with session management"""
    global _telegram_client, _telegram_connected
    
    try:
        logger.info("📱 Initializing Telegram client for CIPHER monitoring...")
        
        # Get credentials from Secret Manager
        api_id = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        phone = await get_secret("telegram-phone-number")
        
        if not all([api_id, api_hash, phone]):
            logger.error("Telegram credentials not available in Secret Manager")
            _telegram_connected = False
            return False
        
        # Get session from Cloud Storage
        session_data = await get_telegram_session_from_storage()
        if not session_data:
            logger.error("No Telegram session available")
            _telegram_connected = False
            return False
        
        try:
            from telethon import TelegramClient
            from telethon.sessions import StringSession
            
            session = StringSession(session_data)
            _telegram_client = TelegramClient(
                session,
                int(api_id),
                api_hash,
                system_version="CIPHER v1.0.0",
                device_model="CIPHER Intelligence Platform",
                app_version="1.0.0",
                lang_code="en",
                system_lang_code="en"
            )
            
            await _telegram_client.connect()
            
            if await _telegram_client.is_user_authorized():
                me = await _telegram_client.get_me()
                logger.info(f"✅ Telegram authenticated as: {me.first_name} (@{me.username or 'no_username'})")
                
                # Test channel access
                accessible_channels = await test_channel_access()
                
                if accessible_channels:
                    _telegram_connected = True
                    logger.info(f"✅ Telegram ready - {len(accessible_channels)}/{len(MONITORED_CHANNELS)} channels accessible")
                    return True
                else:
                    logger.warning("⚠️ Telegram connected but no channels accessible")
                    _telegram_connected = False
                    return False
            else:
                logger.error("Telegram session is not authorized")
                _telegram_connected = False
                return False
                
        except ImportError:
            logger.error("Telethon not installed. Install with: pip install telethon")
            _telegram_connected = False
            return False
        except Exception as e:
            logger.error(f"Telegram client initialization failed: {e}")
            _telegram_connected = False
            return False
            
    except Exception as e:
        logger.error(f"Telegram initialization failed: {e}")
        _telegram_connected = False
        return False

async def get_telegram_session_from_storage() -> Optional[str]:
    """Retrieve Telegram session from Cloud Storage"""
    global _session_string
    
    if _session_string:
        return _session_string
    
    try:
        if not _storage_client:
            logger.error("Storage client not available")
            return None
        
        bucket = _storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob("cipher_session.session")
        
        if not blob.exists():
            logger.error("Telegram session not found in Cloud Storage")
            return None
        
        session_data = blob.download_as_bytes()
        if not session_data:
            logger.error("Empty session data in Cloud Storage")
            return None
        
        if isinstance(session_data, bytes):
            try:
                _session_string = session_data.decode('utf-8')
            except UnicodeDecodeError:
                import base64
                try:
                    _session_string = base64.b64encode(session_data).decode('utf-8')
                except:
                    logger.error("Unable to decode session data")
                    return None
        else:
            _session_string = str(session_data)
        
        logger.info(f"Retrieved Telegram session from Cloud Storage ({len(_session_string)} chars)")
        return _session_string
        
    except Exception as e:
        logger.error(f"Failed to retrieve Telegram session: {e}")
        return None

async def test_channel_access() -> List[str]:
    """Test access to monitored cybersecurity channels"""
    if not _telegram_client:
        return []
    
    accessible = []
    for channel in MONITORED_CHANNELS:
        try:
            entity = await _telegram_client.get_entity(channel)
            messages = await _telegram_client.get_messages(entity, limit=1)
            accessible.append(channel)
            logger.info(f"✅ Channel access confirmed: {channel}")
        except Exception as e:
            logger.warning(f"⚠️ Channel access limited: {channel} - {str(e)[:50]}...")
    
    return accessible

async def start_monitoring_system():
    """Start the CIPHER cybersecurity monitoring system"""
    global _monitoring_active, _monitoring_task
    
    try:
        logger.info("🛡️ Starting CIPHER cybersecurity monitoring system...")
        
        if not _clients_initialized:
            await initialize_all_systems()
        
        if _telegram_connected and _bigquery_available:
            _monitoring_active = True
            logger.info("✅ CIPHER monitoring active (full intelligence mode)")
            
            # Start background monitoring task
            _monitoring_task = asyncio.create_task(monitoring_loop())
            
        elif _bigquery_available:
            _monitoring_active = True
            logger.info("✅ CIPHER monitoring active (data-only mode)")
        else:
            _monitoring_active = False
            logger.warning("⚠️ CIPHER monitoring limited (no data storage)")
        
        return _monitoring_active
        
    except Exception as e:
        logger.error(f"Monitoring system start failed: {e}")
        _monitoring_active = False
        return False

async def monitoring_loop():
    """Enhanced monitoring loop for processing cybersecurity intelligence"""
    if not _telegram_client or not _bigquery_available:
        logger.warning("Monitoring loop disabled - missing required components")
        return
    
    logger.info("📡 Starting enhanced cybersecurity intelligence monitoring loop...")
    
    try:
        while _monitoring_active and _telegram_connected:
            try:
                logger.info("🔍 Processing cybersecurity intelligence from all channels...")
                
                # Process messages from each monitored channel
                for channel in MONITORED_CHANNELS:
                    try:
                        processed_count = await process_channel_messages(channel)
                        if processed_count > 0:
                            logger.info(f"📊 Processed {processed_count} new messages from {channel}")
                    except Exception as e:
                        logger.error(f"Error processing {channel}: {e}")
                
                # Wait before next iteration (configurable interval)
                await asyncio.sleep(300)  # Check every 5 minutes for production
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(600)  # Wait 10 minutes on error
                
    except Exception as e:
        logger.error(f"Monitoring loop failed: {e}")

async def process_channel_messages(channel: str) -> int:
    """Process new messages from a specific cybersecurity channel"""
    try:
        if not _telegram_client:
            return 0
        
        entity = await _telegram_client.get_entity(channel)
        
        # Get messages from last 2 hours (configurable)
        cutoff_time = datetime.now() - timedelta(hours=2)
        messages = await _telegram_client.get_messages(
            entity, 
            limit=50,  # Increased limit for better coverage
            offset_date=cutoff_time
        )
        
        processed_count = 0
        for message in messages:
            if message.text and len(message.text.strip()) > 10:  # Filter out very short messages
                try:
                    await process_message(message, channel)
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing individual message: {e}")
                    
                # Small delay to avoid overwhelming the AI API
                await asyncio.sleep(0.5)
                
        return processed_count
                
    except Exception as e:
        logger.error(f"Error processing channel {channel}: {e}")
        return 0

async def process_message(message, channel: str):
    """Process and analyze a single cybersecurity message with comprehensive intelligence extraction"""
    try:
        # Convert Telegram datetime to Python datetime
        message_date = message.date
        if hasattr(message_date, 'timestamp'):
            message_date = datetime.fromtimestamp(message_date.timestamp())
        elif not isinstance(message_date, datetime):
            message_date = datetime.now()
            
        processed_date = datetime.now()
        
        # Extract basic message information
        message_data = {
            "message_id": str(message.id),
            "chat_id": str(message.peer_id.channel_id if hasattr(message.peer_id, 'channel_id') else message.chat_id),
            "chat_username": channel,
            "user_id": str(message.from_id.user_id if message.from_id else ""),
            "username": "",
            "message_text": message.text,
            "message_date": message_date,
            "processed_date": processed_date,
            "channel_type": CHANNEL_METADATA.get(channel, {}).get("type", "unknown"),
            "channel_priority": CHANNEL_METADATA.get(channel, {}).get("priority", "medium"),
            "channel_focus": CHANNEL_METADATA.get(channel, {}).get("focus", "general"),
            "processing_time_ms": 0,  # Will be calculated
        }
        
        start_time = time.time()
        
        # Comprehensive cybersecurity analysis
        if _gemini_available:
            ai_analysis = await analyze_message_with_gemini(message.text, channel)
            message_data.update(ai_analysis)
        else:
            # Enhanced fallback analysis
            fallback_analysis = get_enhanced_fallback_analysis(message.text, channel)
            message_data.update(fallback_analysis)
        
        # Extract comprehensive cybersecurity data
        cybersec_data = extract_comprehensive_cybersec_data(message.text)
        message_data.update(cybersec_data)
        
        # Calculate processing metrics
        processing_time = int((time.time() - start_time) * 1000)
        message_data["processing_time_ms"] = processing_time
        message_data["data_quality_score"] = calculate_data_quality_score(message_data)
        
        # Store in BigQuery with enhanced schema
        await store_enhanced_message_in_bigquery(message_data)
        
        # Log comprehensive processing result
        threat_info = f"{message_data.get('threat_level', 'low')}/{message_data.get('category', 'other')}"
        ioc_count = len(message_data.get('iocs_detected', []))
        cve_count = len(message_data.get('cve_references', []))
        
        logger.info(f"✅ Processed {channel} message: {threat_info} threat (IOCs: {ioc_count}, CVEs: {cve_count}) in {processing_time}ms")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")
        logger.error(f"Message preview: {getattr(message, 'text', 'No text')[:100]}...")

async def analyze_message_with_gemini(text: str, channel: str) -> Dict[str, Any]:
    """Enhanced Gemini AI analysis for comprehensive cybersecurity intelligence"""
    try:
        if not _gemini_model:
            logger.warning("Gemini AI not available, using enhanced fallback analysis")
            return get_enhanced_fallback_analysis(text, channel)
        
        channel_context = CHANNEL_METADATA.get(channel, {})
        
        # Comprehensive cybersecurity analysis prompt
        prompt = f"""
        You are CIPHER, an advanced cybersecurity threat intelligence analyst. Analyze this message from {channel} and provide a comprehensive JSON response.

        Channel Context: {channel_context.get('description', 'Unknown')}
        Channel Focus: {channel_context.get('focus', 'general')}
        
        Message: "{text}"

        Provide analysis in this EXACT JSON format (ensure valid JSON):
        {{
            "threat_level": "critical|high|medium|low|info",
            "category": "apt|malware|ransomware|data_breach|vulnerability|phishing|ddos|insider_threat|supply_chain|other",
            "subcategory": "specific threat subtype",
            "threat_type": "detailed threat description",
            "urgency_score": 0.85,
            "confidence_score": 0.90,
            "sentiment": "negative|neutral|positive",
            "gemini_analysis": "Comprehensive 2-3 sentence threat intelligence analysis for cybersecurity professionals",
            "key_topics": ["topic1", "topic2", "topic3"],
            "attack_stage": "reconnaissance|weaponization|delivery|exploitation|installation|command_control|actions_objectives|unknown",
            "kill_chain_phase": "MITRE ATT&CK tactic",
            "mitre_techniques": ["T1566", "T1204"],
            "affected_systems": ["Windows", "Linux", "Cloud"],
            "affected_vendors": ["Microsoft", "Apache"],
            "vulnerabilities": ["RCE", "Privilege Escalation"],
            "attack_vectors": ["Email", "Web", "Network"],
            "geographical_targets": ["Global", "US", "Europe"],
            "industry_targets": ["Healthcare", "Finance", "Government"],
            "information_type": "tactical|operational|strategic",
            "source_reliability": "A|B|C|D|F",
            "sharing_level": "TLP:RED|TLP:AMBER|TLP:GREEN|TLP:WHITE",
            "false_positive_risk": "low|medium|high",
            "tags": ["custom", "categorization", "tags"]
        }}

        Guidelines:
        - Focus on actionable cybersecurity intelligence
        - Be precise about threat levels and categories
        - Extract all relevant technical details
        - Consider the source channel's specialty
        - If no specific threats, mark as appropriate level (info/low)
        - Ensure JSON is valid and complete
        """
        
        try:
            response = await asyncio.to_thread(_gemini_model.generate_content, prompt)
            
            if response and response.text:
                response_text = response.text.strip()
                
                # Clean JSON response
                if response_text.startswith('```'):
                    response_text = response_text.split('\n', 1)[1]
                if response_text.endswith('```'):
                    response_text = response_text.rsplit('\n', 1)[0]
                if response_text.startswith('json'):
                    response_text = response_text[4:].strip()
                
                try:
                    analysis = json.loads(response_text)
                    
                    # Validate and enhance the analysis
                    analysis = validate_and_enhance_gemini_analysis(analysis, text, channel)
                    
                    logger.info(f"✅ Gemini analysis: {analysis.get('threat_level', 'unknown')} - {analysis.get('category', 'other')} (confidence: {analysis.get('confidence_score', 0.0):.2f})")
                    return analysis
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Gemini response not valid JSON: {e}")
                    return parse_text_response_enhanced(response_text, text, channel)
            else:
                logger.warning("Gemini returned empty response")
                return get_enhanced_fallback_analysis(text, channel)
                
        except Exception as api_error:
            logger.error(f"Gemini API call failed: {api_error}")
            return get_enhanced_fallback_analysis(text, channel)
        
    except Exception as e:
        logger.error(f"Message analysis failed: {e}")
        return get_enhanced_fallback_analysis(text, channel)

def validate_and_enhance_gemini_analysis(analysis: Dict[str, Any], text: str, channel: str) -> Dict[str, Any]:
    """Validate and enhance Gemini analysis with extracted cybersecurity data"""
    
    # Ensure required fields with defaults
    enhanced = {
        "threat_level": analysis.get("threat_level", "low"),
        "category": analysis.get("category", "other"),
        "subcategory": analysis.get("subcategory", "unknown"),
        "threat_type": analysis.get("threat_type", "unknown"),
        "urgency_score": float(analysis.get("urgency_score", 0.1)),
        "confidence_score": float(analysis.get("confidence_score", 0.5)),
        "sentiment": analysis.get("sentiment", "neutral"),
        "gemini_analysis": analysis.get("gemini_analysis", "Analysis generated by Gemini AI"),
        "key_topics": analysis.get("key_topics", []),
        "attack_stage": analysis.get("attack_stage", "unknown"),
        "kill_chain_phase": analysis.get("kill_chain_phase", "unknown"),
        "mitre_techniques": analysis.get("mitre_techniques", []),
        "affected_systems": analysis.get("affected_systems", []),
        "affected_vendors": analysis.get("affected_vendors", []),
        "vulnerabilities": analysis.get("vulnerabilities", []),
        "attack_vectors": analysis.get("attack_vectors", []),
        "geographical_targets": analysis.get("geographical_targets", []),
        "industry_targets": analysis.get("industry_targets", []),
        "information_type": analysis.get("information_type", "tactical"),
        "source_reliability": analysis.get("source_reliability", "C"),
        "sharing_level": analysis.get("sharing_level", "TLP:GREEN"),
        "false_positive_risk": analysis.get("false_positive_risk", "medium"),
        "tags": analysis.get("tags", [])
    }
    
    # Validate score ranges
    enhanced["urgency_score"] = max(0.0, min(1.0, enhanced["urgency_score"]))
    enhanced["confidence_score"] = max(0.0, min(1.0, enhanced["confidence_score"]))
    
    # Add channel-specific enhancements
    channel_meta = CHANNEL_METADATA.get(channel, {})
    enhanced["tags"].extend([channel_meta.get("focus", ""), channel_meta.get("type", "")])
    enhanced["tags"] = [tag for tag in enhanced["tags"] if tag]  # Remove empty tags
    
    return enhanced

def parse_text_response_enhanced(response_text: str, text: str, channel: str) -> Dict[str, Any]:
    """Parse non-JSON Gemini responses for cybersecurity intelligence"""
    
    analysis = get_enhanced_fallback_analysis(text, channel)
    
    response_lower = response_text.lower()
    
    # Extract threat level from text
    if any(word in response_lower for word in ['critical', 'severe', 'urgent', 'emergency']):
        analysis["threat_level"] = "critical"
        analysis["urgency_score"] = 0.9
    elif any(word in response_lower for word in ['high', 'important', 'significant']):
        analysis["threat_level"] = "high"
        analysis["urgency_score"] = 0.7
    elif any(word in response_lower for word in ['medium', 'moderate']):
        analysis["threat_level"] = "medium"
        analysis["urgency_score"] = 0.5
    
    # Use text response as analysis
    analysis["gemini_analysis"] = response_text[:1000] + "..." if len(response_text) > 1000 else response_text
    analysis["confidence_score"] = 0.6  # Lower confidence for parsed text
    
    return analysis

def get_enhanced_fallback_analysis(text: str, channel: str) -> Dict[str, Any]:
    """Enhanced fallback analysis with comprehensive cybersecurity intelligence extraction"""
    
    # Extract all cybersecurity data
    cybersec_data = extract_comprehensive_cybersec_data(text)
    
    # Generate comprehensive analysis
    analysis = {
        "gemini_analysis": generate_enhanced_analysis_text(text, channel, cybersec_data),
        "threat_level": detect_threat_level_enhanced(text, channel),
        "category": detect_category_enhanced(text, channel),
        "subcategory": detect_subcategory(text, channel),
        "threat_type": detect_threat_type_enhanced(text, channel),
        "urgency_score": calculate_urgency_enhanced(text, channel),
        "confidence_score": 0.7,  # Good confidence for rule-based analysis
        "sentiment": detect_sentiment_enhanced(text),
        "key_topics": extract_keywords_enhanced(text, channel),
        "attack_stage": detect_attack_stage(text),
        "kill_chain_phase": detect_kill_chain_phase(text),
        "information_type": "tactical",
        "source_reliability": get_source_reliability(channel),
        "sharing_level": "TLP:GREEN",
        "false_positive_risk": "medium"
    }
    
    # Add extracted cybersecurity data
    analysis.update(cybersec_data)
    
    return analysis

def extract_comprehensive_cybersec_data(text: str) -> Dict[str, List[str]]:
    """Extract comprehensive cybersecurity data using enhanced patterns and techniques"""
    
    extracted = {
        "cve_references": [],
        "cwe_references": [],
        "iocs_detected": [],
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "file_hashes": [],
        "email_addresses": [],
        "malware_families": [],
        "threat_actors": [],
        "affected_systems": [],
        "affected_vendors": [],
        "vulnerabilities": [],
        "attack_vectors": [],
        "mitre_techniques": [],
        "geographical_targets": [],
        "industry_targets": []
    }
    
    text_lower = text.lower()
    
    # CVE and CWE references
    extracted["cve_references"] = CYBERSEC_PATTERNS["cve"].findall(text)
    extracted["cwe_references"] = re.findall(r'CWE-\d{1,4}', text, re.IGNORECASE)
    
    # Network indicators
    extracted["ip_addresses"] = [ip for ip in CYBERSEC_PATTERNS["ip_address"].findall(text) 
                                if not ip.startswith(('0.', '127.', '255.', '224.', '240.'))]
    extracted["urls"] = CYBERSEC_PATTERNS["url"].findall(text)
    extracted["email_addresses"] = CYBERSEC_PATTERNS["email"].findall(text)
    
    # Domain extraction with filtering
    domain_matches = CYBERSEC_PATTERNS["domain"].findall(text)
    excluded_domains = {'google.com', 'microsoft.com', 'apple.com', 'github.com', 'twitter.com', 'facebook.com', 'linkedin.com'}
    extracted["domains"] = ['.'.join(domain) for domain in domain_matches 
                           if '.'.join(domain).lower() not in excluded_domains][:10]
    
    # File hashes
    for hash_type, pattern in [("md5", CYBERSEC_PATTERNS["md5"]), 
                              ("sha1", CYBERSEC_PATTERNS["sha1"]), 
                              ("sha256", CYBERSEC_PATTERNS["sha256"])]:
        hashes = pattern.findall(text)
        extracted["file_hashes"].extend(hashes)
    
    # Malware families
    extracted["malware_families"] = [malware for malware in MALWARE_FAMILIES 
                                   if malware in text_lower]
    
    # Threat actors
    extracted["threat_actors"] = [actor for actor in THREAT_ACTORS 
                                if actor in text_lower]
    
    # Systems and vendors
    systems = ['windows', 'linux', 'macos', 'android', 'ios', 'docker', 'kubernetes', 'aws', 'azure', 'gcp']
    extracted["affected_systems"] = [system for system in systems if system in text_lower]
    
    vendors = ['microsoft', 'apple', 'google', 'amazon', 'oracle', 'adobe', 'cisco', 'vmware', 'citrix']
    extracted["affected_vendors"] = [vendor for vendor in vendors if vendor in text_lower]
    
    # Vulnerabilities
    extracted["vulnerabilities"] = [vuln for vuln in VULNERABILITY_KEYWORDS if vuln in text_lower]
    
    # Attack vectors
    attack_vectors = ['email', 'web', 'network', 'usb', 'social engineering', 'supply chain', 'insider', 'physical']
    extracted["attack_vectors"] = [vector for vector in attack_vectors if vector in text_lower]
    
    # MITRE techniques (basic pattern matching)
    mitre_pattern = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)
    extracted["mitre_techniques"] = mitre_pattern.findall(text)
    
    # Geographical and industry targets
    countries = ['usa', 'us', 'united states', 'china', 'russia', 'ukraine', 'iran', 'north korea', 'israel']
    extracted["geographical_targets"] = [country for country in countries if country in text_lower]
    
    industries = ['healthcare', 'finance', 'government', 'education', 'energy', 'manufacturing', 'retail', 'technology']
    extracted["industry_targets"] = [industry for industry in industries if industry in text_lower]
    
    # Combine all IOCs
    extracted["iocs_detected"] = (extracted["ip_addresses"] + 
                                extracted["domains"] + 
                                extracted["file_hashes"][:5] +  # Limit hashes
                                extracted["email_addresses"])[:15]  # Total limit
    
    return extracted

def generate_enhanced_analysis_text(text: str, channel: str, cybersec_data: Dict) -> str:
    """Generate enhanced threat analysis summary with comprehensive intelligence"""
    
    threat_level = detect_threat_level_enhanced(text, channel)
    category = detect_category_enhanced(text, channel)
    
    analysis_parts = []
    
    # Main threat assessment
    if threat_level == "critical":
        analysis_parts.append(f"Critical {category} threat detected requiring immediate security response.")
    elif threat_level == "high":
        analysis_parts.append(f"High-priority {category} identified with significant security implications.")
    elif threat_level == "medium":
        analysis_parts.append(f"Medium-level {category} requiring monitoring and assessment.")
    else:
        analysis_parts.append(f"{category.title()} intelligence from {channel} for situational awareness.")
    
    # Add technical details
    if cybersec_data["cve_references"]:
        cve_count = len(cybersec_data['cve_references'])
        analysis_parts.append(f"References {cve_count} CVE vulnerabilities requiring patch management attention.")
    
    if cybersec_data["malware_families"]:
        families = ", ".join(cybersec_data["malware_families"][:2])
        analysis_parts.append(f"Associated with {families} malware families.")
    
    if cybersec_data["threat_actors"]:
        actors = ", ".join(cybersec_data["threat_actors"][:2])
        analysis_parts.append(f"Attributed to {actors} threat groups.")
    
    if cybersec_data["affected_systems"]:
        systems = ", ".join(cybersec_data["affected_systems"][:3])
        analysis_parts.append(f"Affects {systems} systems and infrastructure.")
    
    if cybersec_data["iocs_detected"]:
        ioc_count = len(cybersec_data["iocs_detected"])
        analysis_parts.append(f"Contains {ioc_count} indicators of compromise for threat hunting.")
    
    # Add context based on content
    text_lower = text.lower()
    if any(word in text_lower for word in ['patch', 'update', 'fix', 'remediation']):
        analysis_parts.append("Includes remediation guidance and security recommendations.")
    
    if any(word in text_lower for word in ['exploit', 'proof of concept', 'poc', 'weaponized']):
        analysis_parts.append("Contains exploitation details requiring immediate defensive measures.")
    
    return " ".join(analysis_parts)

# Enhanced detection functions
def detect_threat_level_enhanced(text: str, channel: str) -> str:
    """Enhanced threat level detection with channel-specific weighting"""
    text_lower = text.lower()
    score = 0
    
    # Critical indicators
    critical_indicators = ['critical', 'urgent', 'immediate', 'emergency', 'zero-day', '0day', 'exploit', 'ransomware', 'breach', 'compromised']
    for indicator in critical_indicators:
        if indicator in text_lower:
            score += 4
    
    # High indicators
    high_indicators = ['high', 'severe', 'important', 'vulnerability', 'malware', 'attack', 'threat', 'suspicious']
    for indicator in high_indicators:
        if indicator in text_lower:
            score += 2
    
    # Medium indicators
    medium_indicators = ['medium', 'moderate', 'warning', 'advisory', 'patch', 'update']
    for indicator in medium_indicators:
        if indicator in text_lower:
            score += 1
    
    # Channel-specific adjustments
    channel_meta = CHANNEL_METADATA.get(channel, {})
    multiplier = channel_meta.get('threat_multiplier', 1.0)
    score = int(score * multiplier)
    
    if score >= 8:
        return "critical"
    elif score >= 4:
        return "high"
    elif score >= 2:
        return "medium"
    else:
        return "low"

def detect_category_enhanced(text: str, channel: str) -> str:
    """Enhanced category detection with better keyword matching"""
    text_lower = text.lower()
    
    category_keywords = {
        "apt": ["apt", "advanced persistent", "nation state", "state sponsored", "targeted attack"],
        "ransomware": ["ransomware", "crypto", "encrypt", "ransom", "lockbit", "maze", "ryuk"],
        "data_breach": ["breach", "leak", "stolen", "database", "credential", "dump", "exposed", "compromised"],
        "malware": ["malware", "trojan", "virus", "backdoor", "rat", "stealer", "loader"],
        "vulnerability": ["vulnerability", "cve-", "patch", "exploit", "rce", "privilege escalation"],
        "phishing": ["phishing", "scam", "social engineering", "credential harvesting", "business email compromise"],
        "ddos": ["ddos", "denial of service", "botnet", "amplification"],
        "insider_threat": ["insider", "employee", "privileged access", "data exfiltration"],
        "supply_chain": ["supply chain", "third party", "vendor", "dependency", "package"]
    }
    
    # Score each category
    category_scores = {}
    for category, keywords in category_keywords.items():
        score = sum(1 for keyword in keywords if keyword in text_lower)
        if score > 0:
            category_scores[category] = score
    
    # Channel-specific category bias
    channel_meta = CHANNEL_METADATA.get(channel, {})
    channel_focus = channel_meta.get('focus', '')
    
    if channel_focus == 'data_breaches' and 'data_breach' in category_scores:
        category_scores['data_breach'] += 1
    elif channel_focus == 'advanced_persistent_threats' and 'apt' in category_scores:
        category_scores['apt'] += 1
    elif channel_focus == 'security_updates' and 'vulnerability' in category_scores:
        category_scores['vulnerability'] += 1
    
    if category_scores:
        return max(category_scores, key=category_scores.get)
    
    return "other"

def detect_subcategory(text: str, channel: str) -> str:
    """Detect specific threat subcategory"""
    text_lower = text.lower()
    
    subcategories = {
        "banking_trojan": ["banking", "financial", "credential theft"],
        "ransomware_as_a_service": ["raas", "affiliate", "ransomware service"],
        "supply_chain_compromise": ["supply chain", "software update", "dependency"],
        "zero_day_exploit": ["zero-day", "0day", "unknown vulnerability"],
        "credential_stuffing": ["credential stuffing", "password reuse", "combo list"],
        "business_email_compromise": ["bec", "ceo fraud", "wire transfer"],
        "cryptojacking": ["cryptojacking", "cryptocurrency mining", "monero"],
        "watering_hole": ["watering hole", "strategic web compromise"],
        "living_off_the_land": ["lolbins", "legitimate tools", "powershell"]
    }
    
    for subcategory, keywords in subcategories.items():
        if any(keyword in text_lower for keyword in keywords):
            return subcategory
    
    return "unknown"

def detect_threat_type_enhanced(text: str, channel: str) -> str:
    """Enhanced threat type detection with more specificity"""
    text_lower = text.lower()
    
    threat_types = {
        'ransomware_attack': ['ransomware attack', 'encryption attack', 'ransom demand'],
        'apt_campaign': ['apt campaign', 'targeted attack', 'espionage'],
        'malware_distribution': ['malware distribution', 'trojan deployment', 'payload delivery'],
        'phishing_campaign': ['phishing campaign', 'credential harvesting', 'email attack'],
        'ddos_attack': ['ddos attack', 'denial of service', 'traffic flooding'],
        'data_exfiltration': ['data exfiltration', 'information theft', 'sensitive data'],
        'vulnerability_exploitation': ['vulnerability exploitation', 'exploit development', 'code execution'],
        'insider_threat': ['insider threat', 'privileged abuse', 'employee misconduct'],
        'supply_chain_attack': ['supply chain attack', 'third party compromise', 'vendor breach'],
        'cryptojacking': ['cryptojacking', 'unauthorized mining', 'cryptocurrency theft'],
        'business_email_compromise': ['business email compromise', 'ceo fraud', 'financial fraud']
    }
    
    for threat_type, keywords in threat_types.items():
        if any(keyword in text_lower for keyword in keywords):
            return threat_type.replace('_', ' ')
    
    return "unknown threat type"

def calculate_urgency_enhanced(text: str, channel: str) -> float:
    """Enhanced urgency calculation with multiple factors"""
    score = 0.1  # Base score
    
    text_lower = text.lower()
    
    # Urgency keywords with weighted scores
    urgency_weights = {
        'critical': 0.4, 'urgent': 0.3, 'immediate': 0.3, 'emergency': 0.4,
        'zero-day': 0.5, '0day': 0.5, 'exploit': 0.3, 'active': 0.2,
        'widespread': 0.2, 'severe': 0.2, 'ongoing': 0.2, 'massive': 0.3
    }
    
    for keyword, weight in urgency_weights.items():
        if keyword in text_lower:
            score += weight
    
    # CVE and IOC presence increases urgency
    if re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE):
        score += 0.2
    
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
        score += 0.1
    
    # Channel multiplier
    channel_meta = CHANNEL_METADATA.get(channel, {})
    channel_multiplier = channel_meta.get('threat_multiplier', 1.0)
    score *= channel_multiplier
    
    return min(score, 1.0)  # Cap at 1.0

def detect_sentiment_enhanced(text: str) -> str:
    """Enhanced sentiment detection for cybersecurity context"""
    text_lower = text.lower()
    
    negative_indicators = ['critical', 'severe', 'dangerous', 'urgent', 'threat', 'attack', 'breach', 'compromised', 'exploit', 'malicious']
    positive_indicators = ['fixed', 'patched', 'resolved', 'secured', 'protected', 'mitigated', 'blocked', 'prevented']
    neutral_indicators = ['advisory', 'notification', 'update', 'information', 'analysis', 'report']
    
    negative_count = sum(1 for word in negative_indicators if word in text_lower)
    positive_count = sum(1 for word in positive_indicators if word in text_lower)
    neutral_count = sum(1 for word in neutral_indicators if word in text_lower)
    
    if negative_count > positive_count and negative_count > neutral_count:
        return "negative"
    elif positive_count > negative_count and positive_count > neutral_count:
        return "positive"
    else:
        return "neutral"

def extract_keywords_enhanced(text: str, channel: str) -> List[str]:
    """Enhanced keyword extraction for cybersecurity intelligence"""
    keywords = set()
    text_lower = text.lower()
    
    # Cybersecurity keywords
    cyber_keywords = [
        'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing', 'apt', 'breach', 'leak',
        'patch', 'update', 'threat', 'attack', 'compromise', 'backdoor', 'trojan', 'virus',
        'ddos', 'botnet', 'cryptocurrency', 'blockchain', 'supply chain', 'zero-day', 'rce',
        'privilege escalation', 'lateral movement', 'persistence', 'evasion', 'reconnaissance'
    ]
    
    for keyword in cyber_keywords:
        if keyword in text_lower:
            keywords.add(keyword)
    
    # Extract technical terms
    technical_patterns = [
        r'\b[A-Z]{2,}[-_]?\d+\b',  # Technical IDs like CVE-2024-1234
        r'\b[A-Za-z]+\d+\b',       # Version numbers
        r'\b\d+\.\d+\.\d+\b'       # Version numbers
    ]
    
    for pattern in technical_patterns:
        matches = re.findall(pattern, text)
        keywords.update([match.lower() for match in matches[:3]])  # Limit to 3
    
    return list(keywords)[:10]  # Return top 10

def detect_attack_stage(text: str) -> str:
    """Detect attack stage based on content"""
    text_lower = text.lower()
    
    stages = {
        "reconnaissance": ["reconnaissance", "recon", "scanning", "enumeration", "osint"],
        "weaponization": ["weaponization", "exploit development", "payload creation"],
        "delivery": ["delivery", "distribution", "email attachment", "malicious link"],
        "exploitation": ["exploitation", "exploit", "vulnerability", "code execution"],
        "installation": ["installation", "persistence", "backdoor", "implant"],
        "command_control": ["command and control", "c2", "c&c", "communication"],
        "actions_objectives": ["data exfiltration", "lateral movement", "privilege escalation", "destruction"]
    }
    
    for stage, keywords in stages.items():
        if any(keyword in text_lower for keyword in keywords):
            return stage
    
    return "unknown"

def detect_kill_chain_phase(text: str) -> str:
    """Detect MITRE ATT&CK kill chain phase"""
    text_lower = text.lower()
    
    phases = {
        "Initial Access": ["initial access", "phishing", "exploit", "drive-by"],
        "Execution": ["execution", "powershell", "command line", "script"],
        "Persistence": ["persistence", "startup", "registry", "scheduled task"],
        "Privilege Escalation": ["privilege escalation", "uac bypass", "token manipulation"],
        "Defense Evasion": ["defense evasion", "obfuscation", "masquerading", "anti-analysis"],
        "Credential Access": ["credential access", "credential dumping", "brute force"],
        "Discovery": ["discovery", "system information", "network discovery"],
        "Lateral Movement": ["lateral movement", "remote services", "admin shares"],
        "Collection": ["collection", "data staged", "screen capture", "clipboard"],
        "Command and Control": ["command and control", "c2", "application layer protocol"],
        "Exfiltration": ["exfiltration", "data transfer", "automated exfiltration"],
        "Impact": ["impact", "data destruction", "ransomware", "denial of service"]
    }
    
    for phase, keywords in phases.items():
        if any(keyword in text_lower for keyword in keywords):
            return phase
    
    return "unknown"

def get_source_reliability(channel: str) -> str:
    """Get source reliability rating based on channel"""
    reliability_ratings = {
        "@DarkfeedNews": "B",      # Good reliability for APT intelligence
        "@breachdetector": "B",    # Good reliability for breach data
        "@secharvester": "A",      # Excellent reliability for CVE data
    }
    
    return reliability_ratings.get(channel, "C")

def calculate_data_quality_score(message_data: Dict[str, Any]) -> float:
    """Calculate data quality score based on completeness and accuracy"""
    score = 0.5  # Base score
    
    # IOCs presence increases quality
    if message_data.get('iocs_detected'):
        score += 0.2
    
    # CVE references increase quality
    if message_data.get('cve_references'):
        score += 0.2
    
    # Detailed analysis increases quality
    if message_data.get('gemini_analysis') and len(message_data['gemini_analysis']) > 100:
        score += 0.1
    
    # Multiple threat indicators increase quality
    threat_indicators = sum([
        len(message_data.get('malware_families', [])),
        len(message_data.get('threat_actors', [])),
        len(message_data.get('affected_systems', []))
    ])
    
    if threat_indicators > 0:
        score += min(0.1 * threat_indicators, 0.2)
    
    return min(score, 1.0)

async def store_enhanced_message_in_bigquery(message_data: Dict[str, Any]):
    """Store processed message in BigQuery with safe field handling"""
    try:
        if not _bigquery_available:
            logger.warning("BigQuery not available for storing message")
            return
        
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        
        # Get current schema
        schema = await get_table_schema()
        
        # Helper function to convert datetime objects
        def convert_datetime(dt):
            if dt is None:
                return None
            if isinstance(dt, datetime):
                return dt.isoformat()
            if hasattr(dt, 'timestamp'):
                return datetime.fromtimestamp(dt.timestamp()).isoformat()
            return str(dt)
        
        # Build row with only fields that exist in the table
        row = {}
        
        # Core required fields
        core_fields = {
            "message_id": str(message_data.get("message_id", "")),
            "chat_id": str(message_data.get("chat_id", "")),
            "processed_date": convert_datetime(message_data.get("processed_date")),
        }
        
        # Add only fields that exist in the schema
        for field_name, field_value in message_data.items():
            if field_name in schema:
                if field_name.endswith('_date') or field_name in ['first_seen', 'last_updated']:
                    row[field_name] = convert_datetime(field_value)
                elif isinstance(field_value, list):
                    # Ensure list fields are properly formatted
                    row[field_name] = [str(item) for item in field_value if item]
                elif isinstance(field_value, (int, float)):
                    row[field_name] = field_value
                else:
                    row[field_name] = str(field_value) if field_value is not None else ""
        
        # Ensure core fields are set
        row.update(core_fields)
        
        # Insert with error handling
        errors = _bq_client.insert_rows_json(table, [row])
        if errors:
            logger.error(f"BigQuery insert failed: {errors}")
            logger.error(f"Row fields: {list(row.keys())}")
        else:
            # Enhanced success logging with intelligence summary
            threat_level = row.get('threat_level', 'low')
            category = row.get('category', 'other')
            ioc_count = len(message_data.get("iocs_detected", []))
            cve_count = len(message_data.get("cve_references", []))
            urgency = message_data.get("urgency_score", 0.0)
            
            intelligence_summary = f"{threat_level}/{category}"
            if cve_count > 0:
                intelligence_summary += f" [{cve_count} CVEs]"
            if ioc_count > 0:
                intelligence_summary += f" [{ioc_count} IOCs]"
            intelligence_summary += f" (urgency: {urgency:.2f})"
            
            logger.info(f"✅ Stored: {row.get('chat_username', 'unknown')} - {intelligence_summary}")
            
    except Exception as e:
        logger.error(f"Enhanced BigQuery storage failed: {e}")
        logger.error(f"Available schema fields: {len(await get_table_schema())}")

async def stop_monitoring_system():
    """Stop the CIPHER monitoring system with cleanup"""
    global _monitoring_active, _telegram_client, _monitoring_task
    
    try:
        _monitoring_active = False
        
        # Cancel monitoring task
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
            try:
                await _monitoring_task
            except asyncio.CancelledError:
                logger.info("Monitoring task cancelled")
        
        # Disconnect Telegram
        if _telegram_client:
            await _telegram_client.disconnect()
            _telegram_client = None
            _telegram_connected = False
        
        logger.info("🛑 CIPHER monitoring system stopped")
        
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")

# FIXED: Enhanced API functions with defensive BigQuery queries

async def get_comprehensive_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics with defensive field checking"""
    try:
        if not _bigquery_available:
            return _get_default_stats()
        
        # Get available schema first
        schema = await get_table_schema()
        
        # Build defensive query with only existing fields
        available_fields = []
        if 'urgency_score' in schema:
            available_fields.append('AVG(COALESCE(urgency_score, 0)) as avg_urgency')
        else:
            available_fields.append('0.0 as avg_urgency')
            
        if 'threat_level' in schema:
            available_fields.extend([
                "COUNTIF(threat_level IN ('high', 'critical')) as high_threats",
                "COUNTIF(threat_level = 'critical') as critical_threats"
            ])
        else:
            available_fields.extend([
                "0 as high_threats",
                "0 as critical_threats"
            ])
            
        if 'category' in schema:
            available_fields.extend([
                "COUNTIF(category = 'data_breach') as data_breaches",
                "COUNTIF(category = 'malware') as malware_alerts",
                "COUNTIF(category = 'vulnerability') as vulnerabilities",
                "COUNTIF(category = 'apt') as apt_activity"
            ])
        else:
            available_fields.extend([
                "0 as data_breaches",
                "0 as malware_alerts", 
                "0 as vulnerabilities",
                "0 as apt_activity"
            ])
            
        if 'cve_references' in schema:
            available_fields.append("COUNTIF(ARRAY_LENGTH(cve_references) > 0) as cve_mentions")
        else:
            available_fields.append("0 as cve_mentions")
        
        # Core stats query with defensive field handling
        stats_query = f"""
        SELECT 
            COUNT(*) as total_messages,
            COUNTIF(DATE(processed_date) = CURRENT_DATE()) as processed_today,
            COUNT(DISTINCT chat_username) as unique_channels,
            {', '.join(available_fields)}
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        try:
            query_job = _bq_client.query(stats_query)
            row = next(iter(query_job.result(timeout=30)), None)
            
            if row:
                return {
                    "total_messages": int(row.total_messages) if row.total_messages else 0,
                    "processed_today": int(row.processed_today) if row.processed_today else 0,
                    "unique_channels": int(row.unique_channels) if row.unique_channels else 3,
                    "avg_urgency": float(row.avg_urgency) if hasattr(row, 'avg_urgency') and row.avg_urgency else 0.0,
                    "high_threats": int(row.high_threats) if hasattr(row, 'high_threats') and row.high_threats else 0,
                    "critical_threats": int(row.critical_threats) if hasattr(row, 'critical_threats') and row.critical_threats else 0,
                    "data_breaches": int(row.data_breaches) if hasattr(row, 'data_breaches') and row.data_breaches else 0,
                    "malware_alerts": int(row.malware_alerts) if hasattr(row, 'malware_alerts') and row.malware_alerts else 0,
                    "vulnerabilities": int(row.vulnerabilities) if hasattr(row, 'vulnerabilities') and row.vulnerabilities else 0,
                    "apt_activity": int(row.apt_activity) if hasattr(row, 'apt_activity') and row.apt_activity else 0,
                    "cve_mentions": int(row.cve_mentions) if hasattr(row, 'cve_mentions') and row.cve_mentions else 0,
                    "monitoring_active": _monitoring_active,
                    "data_source": "bigquery",
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            else:
                return _get_default_stats()
                
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            return _get_default_stats()
        
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return _get_default_stats()

async def get_threat_insights() -> Dict[str, Any]:
    """Get threat intelligence insights with defensive field handling"""
    try:
        if not _bigquery_available:
            return {"insights": [], "total": 0, "source": "bigquery_unavailable"}
        
        # Get available schema
        schema = await get_table_schema()
        
        # Build defensive field list
        core_fields = [
            "message_id",
            "chat_username", 
            "message_text",
            "message_date",
            "processed_date"
        ]
        
        optional_fields = [
            "gemini_analysis",
            "sentiment", 
            "urgency_score",
            "threat_level",
            "category", 
            "threat_type",
            "key_topics",
            "cve_references",
            "iocs_detected",
            "malware_families",
            "threat_actors",
            "affected_systems"
        ]
        
        # Only include fields that exist
        select_fields = core_fields.copy()
        for field in optional_fields:
            if field in schema:
                select_fields.append(field)
            else:
                # Provide defaults for missing fields
                if field in ['urgency_score']:
                    select_fields.append(f"0.0 as {field}")
                elif field in ['threat_level']:
                    select_fields.append(f"'low' as {field}")
                elif field in ['category', 'threat_type']:
                    select_fields.append(f"'other' as {field}")
                elif field.endswith('_references') or field.endswith('_detected') or field.endswith('_families') or field in ['key_topics', 'threat_actors', 'affected_systems']:
                    select_fields.append(f"ARRAY<STRING>[] as {field}")
                else:
                    select_fields.append(f"'' as {field}")
        
        insights_query = f"""
        SELECT {', '.join(select_fields)}
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC
        LIMIT 50
        """
        
        query_job = _bq_client.query(insights_query)
        results = query_job.result(timeout=30)
        
        insights = []
        for row in results:
            insight = {
                "message_id": row.message_id,
                "chat_username": row.chat_username or "@Unknown",
                "message_text": (row.message_text or "")[:1000],
                "message_date": row.message_date.isoformat() if row.message_date else None,
                "processed_date": row.processed_date.isoformat() if row.processed_date else None,
                "gemini_analysis": getattr(row, 'gemini_analysis', '') or "No analysis available",
                "sentiment": getattr(row, 'sentiment', '') or "neutral",
                "urgency_score": float(getattr(row, 'urgency_score', 0)) if hasattr(row, 'urgency_score') else 0.0,
                "threat_level": getattr(row, 'threat_level', '') or "low",
                "category": getattr(row, 'category', '') or "other",
                "threat_type": getattr(row, 'threat_type', '') or "unknown",
                "key_topics": getattr(row, 'key_topics', []) or [],
                "cve_references": getattr(row, 'cve_references', []) or [],
                "iocs_detected": getattr(row, 'iocs_detected', []) or [],
                "malware_families": getattr(row, 'malware_families', []) or [],
                "threat_actors": getattr(row, 'threat_actors', []) or [],
                "affected_systems": getattr(row, 'affected_systems', []) or []
            }
            insights.append(insight)
        
        logger.info(f"Retrieved {len(insights)} threat insights with defensive queries")
        return {
            "insights": insights,
            "total": len(insights),
            "source": "bigquery_defensive",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get threat insights: {e}")
        return {"insights": [], "total": 0, "source": "error", "error": str(e)}

async def get_monitoring_status() -> Dict[str, Any]:
    """Get detailed monitoring system status with enhanced metrics"""
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
                "count": len(MONITORED_CHANNELS),
                "accessible": await test_channel_access() if _telegram_connected else []
            },
            "last_check": datetime.now(timezone.utc).isoformat(),
            "system_health": "operational" if _monitoring_active else "limited",
            "monitoring_task_active": _monitoring_task is not None and not _monitoring_task.done() if _monitoring_task else False
        }
        
        # Add detailed channel status with metadata
        channel_status = []
        for channel in MONITORED_CHANNELS:
            metadata = CHANNEL_METADATA.get(channel, {})
            channel_status.append({
                "username": channel,
                "type": metadata.get("type", "unknown"),
                "priority": metadata.get("priority", "medium"),
                "focus": metadata.get("focus", "general"),
                "threat_multiplier": metadata.get("threat_multiplier", 1.0),
                "status": "monitoring" if _monitoring_active else "standby",
                "description": metadata.get("description", ""),
                "color": metadata.get("color", "#6366f1"),
                "icon": metadata.get("icon", "📡")
            })
        
        status["channel_details"] = channel_status
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return {"active": False, "error": str(e)}

async def get_threat_analytics() -> Dict[str, Any]:
    """Get threat analytics with defensive field handling"""
    try:
        if not _bigquery_available:
            return _get_empty_analytics()
        
        # Get available schema
        schema = await get_table_schema()
        
        # Build defensive analytics query
        threat_level_fields = []
        category_fields = []
        
        if 'threat_level' in schema:
            threat_level_fields = [
                "COUNTIF(threat_level = 'critical') as critical_count",
                "COUNTIF(threat_level = 'high') as high_count", 
                "COUNTIF(threat_level = 'medium') as medium_count",
                "COUNTIF(threat_level = 'low') as low_count"
            ]
        else:
            threat_level_fields = [
                "0 as critical_count",
                "0 as high_count",
                "0 as medium_count", 
                "0 as low_count"
            ]
            
        if 'category' in schema:
            category_fields = [
                "COUNTIF(category = 'apt') as apt_count",
                "COUNTIF(category = 'malware') as malware_count",
                "COUNTIF(category = 'data_breach') as breach_count",
                "COUNTIF(category = 'vulnerability') as vuln_count"
            ]
        else:
            category_fields = [
                "0 as apt_count",
                "0 as malware_count", 
                "0 as breach_count",
                "0 as vuln_count"
            ]
        
        urgency_field = "AVG(urgency_score)" if 'urgency_score' in schema else "0.0"
        
        analytics_query = f"""
        SELECT 
            {', '.join(threat_level_fields)},
            {', '.join(category_fields)},
            {urgency_field} as avg_urgency,
            COUNT(*) as total_threats
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        query_job = _bq_client.query(analytics_query)
        row = next(iter(query_job.result(timeout=30)), None)
        
        if not row:
            return _get_empty_analytics()
        
        analytics = {
            "threat_levels": {
                "critical": int(getattr(row, 'critical_count', 0)) if hasattr(row, 'critical_count') else 0,
                "high": int(getattr(row, 'high_count', 0)) if hasattr(row, 'high_count') else 0,
                "medium": int(getattr(row, 'medium_count', 0)) if hasattr(row, 'medium_count') else 0,
                "low": int(getattr(row, 'low_count', 0)) if hasattr(row, 'low_count') else 0
            },
            "categories": {
                "apt": int(getattr(row, 'apt_count', 0)) if hasattr(row, 'apt_count') else 0,
                "malware": int(getattr(row, 'malware_count', 0)) if hasattr(row, 'malware_count') else 0,
                "data_breach": int(getattr(row, 'breach_count', 0)) if hasattr(row, 'breach_count') else 0,
                "vulnerability": int(getattr(row, 'vuln_count', 0)) if hasattr(row, 'vuln_count') else 0
            },
            "summary": {
                "total_threats": int(getattr(row, 'total_threats', 0)) if hasattr(row, 'total_threats') else 0,
                "high_priority": (int(getattr(row, 'critical_count', 0)) if hasattr(row, 'critical_count') else 0) + 
                               (int(getattr(row, 'high_count', 0)) if hasattr(row, 'high_count') else 0),
                "avg_urgency": float(getattr(row, 'avg_urgency', 0.0)) if hasattr(row, 'avg_urgency') else 0.0
            },
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "data_period": "30_days"
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Error calculating threat analytics: {e}")
        return {"error": str(e), "status": "error"}

def _get_default_stats() -> Dict[str, Any]:
    """Return enhanced default statistics structure"""
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
        "apt_activity": 0,
        "cve_mentions": 0,
        "monitoring_active": _monitoring_active,
        "data_source": "system_default"
    }

def _get_empty_analytics() -> Dict[str, Any]:
    """Enhanced empty analytics structure"""
    return {
        "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "categories": {"apt": 0, "malware": 0, "data_breach": 0, "vulnerability": 0},
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0}
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
