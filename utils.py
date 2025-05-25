import os
import json
import logging
import time
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
        "threat_multiplier": 1.8,
        "keywords": ["apt", "malware", "ransomware", "zero-day", "exploit", "breach", "attack", "darkfeed", "leak", "campaign", "threat actor"],
        "description": "Premium threat intelligence focusing on APTs and zero-day exploits",
        "color": "#ff4444",
        "icon": "🔴"
    },
    "@breachdetector": {
        "type": "data_breach_monitor", 
        "priority": "high",
        "focus": "data_breaches",
        "threat_multiplier": 1.5,
        "keywords": ["breach", "leak", "database", "stolen", "credentials", "dump", "hacked", "compromised", "exposed", "data"],
        "description": "Real-time data breach and credential leak monitoring",
        "color": "#ffaa00",
        "icon": "🟠"
    },
    "@secharvester": {
        "type": "security_news",
        "priority": "medium", 
        "focus": "security_updates",
        "threat_multiplier": 1.2,
        "keywords": ["vulnerability", "cve", "patch", "security", "advisory", "update", "fix", "exploit"],
        "description": "Security news, CVE tracking, and patch information",
        "color": "#6366f1",
        "icon": "🔵"
    }
}

# Production-grade cybersecurity patterns
CYBERSEC_PATTERNS = {
    "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
    "cwe": re.compile(r'CWE-\d{1,4}', re.IGNORECASE),
    "ip_address": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    "domain": re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha512": re.compile(r'\b[a-fA-F0-9]{128}\b'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "bitcoin": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "mitre_technique": re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE),
}

# Enhanced threat intelligence databases
THREAT_ACTORS = [
    "lazarus", "apt1", "apt28", "apt29", "apt30", "apt32", "apt34", "apt40", "apt41",
    "carbanak", "fin7", "fin8", "sandworm", "turla", "kimsuky", "darkhydrus", "muddywater",
    "oceanlotus", "machete", "gallmaker", "leafy", "scarlet mimic", "naikon", "lotus blossom",
    "comment crew", "elderwood", "aurora", "nitro", "shady rat", "ghostnet", "red october",
    "imncrew", "secp0", "apipn", "blacktech", "winnti", "bronze butler", "stone panda"
]

MALWARE_FAMILIES = [
    "wannacry", "petya", "notpetya", "ryuk", "maze", "lockbit", "conti", "ragnar",
    "emotet", "trickbot", "qakbot", "danabot", "formbook", "remcos", "njrat", "darkcomet",
    "cobalt strike", "metasploit", "mimikatz", "powershell empire", "covenant", "sliver",
    "stuxnet", "duqu", "flame", "gauss", "miniflame", "regin", "equation", "carbanak",
    "novas", "blackcat", "alphv", "revil", "sodinokibi", "darkside", "babuk", "hive",
    "blackmatter", "grief", "egregor", "netwalker", "dharma", "phobos", "stop", "djvu"
]

VULNERABILITY_KEYWORDS = [
    "zero-day", "0day", "rce", "remote code execution", "privilege escalation", "buffer overflow",
    "sql injection", "xss", "csrf", "directory traversal", "file inclusion", "deserialization",
    "use after free", "double free", "heap overflow", "stack overflow", "format string",
    "authentication bypass", "authorization bypass", "session hijacking", "clickjacking"
]

ATTACK_VECTORS = [
    "email", "phishing", "spearphishing", "web", "browser", "javascript", "network",
    "lateral movement", "smb", "rdp", "ssh", "usb", "removable media", "supply chain",
    "third party", "vendor", "social engineering", "watering hole", "drive by"
]

# Private/internal IP ranges to exclude
PRIVATE_IP_RANGES = [
    r'^10\.',
    r'^172\.(1[6-9]|2[0-9]|3[01])\.',
    r'^192\.168\.',
    r'^127\.',
    r'^169\.254\.',
    r'^224\.',
    r'^240\.',
    r'^255\.',
    r'^0\.',
    r'^localhost$'
]

# Common domains to exclude from IOCs
EXCLUDED_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'github.com', 'twitter.com', 'facebook.com',
    'linkedin.com', 'youtube.com', 'amazon.com', 'cloudflare.com', 'telegram.org', 't.me',
    'blackhatworld.com', 'reddit.com', 'stackoverflow.com', 'medium.com', 'wordpress.com',
    'blogger.com', 'tumblr.com', 'instagram.com', 'tiktok.com', 'snapchat.com'
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
_session_string = None
_monitoring_task = None

async def initialize_all_systems():
    """Initialize all Google Cloud and external systems"""
    global _clients_initialized
    
    async with _initialization_lock:
        if _clients_initialized:
            return True
        
        try:
            logger.info("🔧 Initializing CIPHER cybersecurity intelligence systems...")
            
            # Initialize Google Cloud clients
            await initialize_gcp_clients()
            
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
    """Initialize Google Cloud Platform clients"""
    global _bq_client, _secret_client, _storage_client, _bigquery_available
    
    try:
        # Initialize BigQuery client
        try:
            credentials, project = default()
            _bq_client = bigquery.Client(project=project, credentials=credentials)
            
            # Test connection
            test_query = "SELECT CURRENT_TIMESTAMP() as test_time"
            query_job = _bq_client.query(test_query)
            list(query_job.result(timeout=10))
            
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
        
        # Initialize Storage client
        try:
            _storage_client = storage.Client(project=PROJECT_ID)
            logger.info("✅ Storage client initialized")
        except Exception as e:
            logger.error(f"Storage initialization failed: {e}")
            
    except Exception as e:
        logger.error(f"GCP clients initialization failed: {e}")
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
        logger.info("🤖 Initializing Gemini AI for cybersecurity analysis...")
        
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            logger.error("Gemini API key not available")
            _gemini_available = False
            return False
        
        try:
            genai.configure(api_key=api_key)
            
            _gemini_model = genai.GenerativeModel(
                'gemini-1.5-flash',
                generation_config=genai.GenerationConfig(
                    temperature=0.1,
                    top_p=0.8,
                    max_output_tokens=1500,
                    candidate_count=1
                ),
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            )
            
            # Test API
            test_response = await asyncio.to_thread(
                _gemini_model.generate_content,
                "Test cybersecurity analysis capability. Respond with: OK"
            )
            
            if test_response and test_response.text and "OK" in test_response.text:
                _gemini_available = True
                logger.info("✅ Gemini AI initialized and tested")
                return True
            else:
                logger.error("Gemini test failed")
                _gemini_available = False
                return False
                
        except Exception as api_error:
            logger.error(f"Gemini API configuration failed: {api_error}")
            _gemini_available = False
            return False
            
    except Exception as e:
        logger.error(f"Gemini AI initialization failed: {e}")
        _gemini_available = False
        return False

async def initialize_telegram_client():
    """Initialize Telegram client"""
    global _telegram_client, _telegram_connected
    
    try:
        logger.info("📱 Initializing Telegram client...")
        
        # Get credentials
        api_id = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        
        if not all([api_id, api_hash]):
            logger.error("Telegram credentials not available")
            _telegram_connected = False
            return False
        
        # Get session from storage
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
                logger.info(f"✅ Telegram authenticated as: {me.first_name}")
                
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
                logger.error("Telegram session not authorized")
                _telegram_connected = False
                return False
                
        except ImportError:
            logger.error("Telethon not installed")
            _telegram_connected = False
            return False
        except Exception as e:
            logger.error(f"Telegram client failed: {e}")
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
            logger.error("Empty session data")
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
        
        logger.info("Retrieved Telegram session from Cloud Storage")
        return _session_string
        
    except Exception as e:
        logger.error(f"Failed to retrieve Telegram session: {e}")
        return None

async def test_channel_access() -> List[str]:
    """Test access to monitored channels"""
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
    """Start the CIPHER monitoring system"""
    global _monitoring_active, _monitoring_task
    
    try:
        logger.info("🛡️ Starting CIPHER monitoring system...")
        
        if not _clients_initialized:
            await initialize_all_systems()
        
        if _telegram_connected and _bigquery_available:
            _monitoring_active = True
            logger.info("✅ CIPHER monitoring active (full intelligence mode)")
            
            # Start background monitoring
            _monitoring_task = asyncio.create_task(monitoring_loop())
            
        elif _bigquery_available:
            _monitoring_active = True
            logger.info("✅ CIPHER monitoring active (data-only mode)")
        else:
            _monitoring_active = False
            logger.warning("⚠️ CIPHER monitoring limited")
        
        return _monitoring_active
        
    except Exception as e:
        logger.error(f"Monitoring system start failed: {e}")
        _monitoring_active = False
        return False

async def monitoring_loop():
    """Enhanced monitoring loop"""
    if not _telegram_client or not _bigquery_available:
        logger.warning("Monitoring loop disabled - missing components")
        return
    
    logger.info("📡 Starting cybersecurity intelligence monitoring loop...")
    
    try:
        while _monitoring_active and _telegram_connected:
            try:
                logger.info("🔍 Processing cybersecurity intelligence...")
                
                for channel in MONITORED_CHANNELS:
                    try:
                        processed_count = await process_channel_messages(channel)
                        if processed_count > 0:
                            logger.info(f"📊 Processed {processed_count} new messages from {channel}")
                    except Exception as e:
                        logger.error(f"Error processing {channel}: {e}")
                
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(600)  # 10 minutes on error
                
    except Exception as e:
        logger.error(f"Monitoring loop failed: {e}")

async def process_channel_messages(channel: str) -> int:
    """Process new messages from channel"""
    try:
        if not _telegram_client:
            return 0
        
        entity = await _telegram_client.get_entity(channel)
        
        # Get recent messages
        cutoff_time = datetime.now() - timedelta(hours=2)
        messages = await _telegram_client.get_messages(
            entity, 
            limit=50,
            offset_date=cutoff_time
        )
        
        processed_count = 0
        for message in messages:
            if message.text and len(message.text.strip()) > 10:
                try:
                    await process_message(message, channel)
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
                await asyncio.sleep(0.5)  # Rate limiting
                
        return processed_count
                
    except Exception as e:
        logger.error(f"Error processing channel {channel}: {e}")
        return 0

async def process_message(message, channel: str):
    """Process and analyze a cybersecurity message"""
    try:
        # Convert message date
        message_date = message.date
        if hasattr(message_date, 'timestamp'):
            message_date = datetime.fromtimestamp(message_date.timestamp())
        elif not isinstance(message_date, datetime):
            message_date = datetime.now()
            
        processed_date = datetime.now()
        
        # Extract basic message info
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
            "processing_time_ms": 0,
        }
        
        start_time = time.time()
        
        # Comprehensive analysis
        if _gemini_available:
            ai_analysis = await analyze_message_with_gemini(message.text, channel)
            message_data.update(ai_analysis)
        else:
            # Enhanced analysis without Gemini
            analysis = analyze_message_content_enhanced(message.text, channel)
            message_data.update(analysis)
        
        # Extract cybersecurity data
        cybersec_data = extract_cybersecurity_data_enhanced(message.text)
        message_data.update(cybersec_data)
        
        # Calculate metrics
        processing_time = int((time.time() - start_time) * 1000)
        message_data["processing_time_ms"] = processing_time
        
        # Store in BigQuery
        await store_message_in_bigquery(message_data)
        
        logger.info(f"✅ Processed {channel}: {message_data.get('threat_level', 'low')}/{message_data.get('category', 'other')} in {processing_time}ms")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")

async def analyze_message_with_gemini(text: str, channel: str) -> Dict[str, Any]:
    """Analyze message with Gemini AI"""
    try:
        if not _gemini_model:
            logger.warning("Gemini AI not available")
            return analyze_message_content_enhanced(text, channel)
        
        channel_context = CHANNEL_METADATA.get(channel, {})
        
        prompt = f"""
        Analyze this cybersecurity threat intelligence from {channel} and respond with valid JSON only:

        Channel Focus: {channel_context.get('focus', 'general')}
        Channel Type: {channel_context.get('type', 'security')}
        Message: "{text[:2000]}"

        Respond with this exact JSON structure (no other text):
        {{
            "threat_level": "critical|high|medium|low|info",
            "category": "apt|malware|ransomware|data_breach|vulnerability|phishing|ddos|insider_threat|supply_chain|other",
            "threat_type": "specific threat description",
            "urgency_score": 0.85,
            "sentiment": "negative|neutral|positive",
            "gemini_analysis": "2-3 sentence professional threat intelligence analysis",
            "key_topics": ["topic1", "topic2"],
            "mitre_techniques": ["T1566"],
            "affected_systems": ["Windows", "Linux"],
            "vulnerabilities": ["RCE"],
            "attack_vectors": ["Email", "Web"],
            "geographical_targets": ["Global"],
            "industry_targets": ["Finance"]
        }}

        Guidelines:
        - Be precise about threat levels based on actual content
        - Extract real technical details only
        - No speculation or fake IOCs
        - Consider channel context and reputation
        - Return only valid JSON
        """
        
        try:
            response = await asyncio.to_thread(_gemini_model.generate_content, prompt)
            
            if response and response.text:
                response_text = response.text.strip()
                
                # Clean response
                if response_text.startswith('```'):
                    start = response_text.find('{')
                    end = response_text.rfind('}') + 1
                    if start != -1 and end != 0:
                        response_text = response_text[start:end]
                
                try:
                    analysis = json.loads(response_text)
                    
                    # Validate required fields
                    analysis["threat_level"] = analysis.get("threat_level", "low")
                    analysis["category"] = analysis.get("category", "other")
                    analysis["urgency_score"] = max(0.0, min(1.0, float(analysis.get("urgency_score", 0.1))))
                    analysis["sentiment"] = analysis.get("sentiment", "neutral")
                    analysis["gemini_analysis"] = analysis.get("gemini_analysis", "Analysis completed")
                    
                    # Ensure arrays exist
                    for field in ["key_topics", "mitre_techniques", "affected_systems", "vulnerabilities", "attack_vectors", "geographical_targets", "industry_targets"]:
                        if field not in analysis or not isinstance(analysis[field], list):
                            analysis[field] = []
                    
                    logger.info(f"✅ Gemini analysis: {analysis['threat_level']} - {analysis['category']}")
                    return analysis
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from Gemini: {e}")
                    return analyze_message_content_enhanced(text, channel)
            else:
                logger.warning("Empty Gemini response")
                return analyze_message_content_enhanced(text, channel)
                
        except Exception as api_error:
            logger.error(f"Gemini API error: {api_error}")
            return analyze_message_content_enhanced(text, channel)
        
    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return analyze_message_content_enhanced(text, channel)

def analyze_message_content_enhanced(text: str, channel: str) -> Dict[str, Any]:
    """ENHANCED analyze message content without AI - PRODUCTION VERSION"""
    text_lower = text.lower()
    
    # Enhanced threat level detection with proper scoring
    threat_level = "low"
    urgency_score = 0.1
    
    # COMPREHENSIVE cybersecurity threat scoring
    threat_score = 0.0
    
    # Critical cybersecurity indicators with realistic weights
    critical_keywords = {
        # Zero-day and critical exploits
        "zero-day": 1.0, "0day": 1.0, "zero day": 1.0,
        "critical": 0.8, "urgent": 0.7, "emergency": 0.8,
        
        # Active threats and attacks
        "exploit": 0.9, "attack": 0.7, "compromise": 0.8,
        "breach": 0.9, "hacked": 0.8, "compromised": 0.8,
        
        # Ransomware and malware families
        "ransomware": 0.9, "lockbit": 0.9, "maze": 0.9, "conti": 0.9, "ryuk": 0.9,
        "blackcat": 0.9, "alphv": 0.9, "revil": 0.9, "darkside": 0.9,
        
        # APT and nation-state threats
        "apt": 0.8, "advanced persistent": 0.8, "nation state": 0.8,
        "lazarus": 0.9, "kimsuky": 0.8, "turla": 0.8, "carbanak": 0.8,
        
        # Malware and backdoors
        "malware": 0.7, "trojan": 0.7, "backdoor": 0.7, "rat": 0.7,
        "stealer": 0.7, "loader": 0.7, "cryptominer": 0.6,
        
        # Active IOCs and threat intel
        "ioc": 0.6, "indicator": 0.6, "hash": 0.5, "c2": 0.7, "command and control": 0.7,
        
        # Special threat actor indicators
        "darkfeed": 0.8, "threat actor": 0.7, "campaign": 0.6, "operation": 0.6
    }
    
    high_keywords = {
        # Vulnerabilities and exploits
        "vulnerability": 0.6, "rce": 0.7, "remote code execution": 0.7,
        "privilege escalation": 0.6, "buffer overflow": 0.6, "sql injection": 0.5,
        
        # Security incidents
        "incident": 0.5, "suspicious": 0.5, "threat": 0.5,
        "phishing": 0.5, "scam": 0.5, "fraud": 0.5,
        
        # Data breaches and leaks
        "leak": 0.6, "stolen": 0.6, "database": 0.5, "credentials": 0.5,
        "dump": 0.6, "exposed": 0.5,
        
        # DDoS and disruption
        "ddos": 0.5, "dos": 0.5, "disruption": 0.4, "outage": 0.4,
        
        # Additional high-priority terms
        "botnet": 0.6, "c2 server": 0.6, "payload": 0.5, "dropper": 0.5
    }
    
    medium_keywords = {
        # General security terms
        "security": 0.3, "patch": 0.4, "update": 0.3, "fix": 0.3,
        "advisory": 0.4, "alert": 0.4, "warning": 0.4,
        
        # CVE and vulnerability tracking
        "cve-": 0.5, "cwe-": 0.4, "nvd": 0.4,
        
        # General monitoring
        "monitoring": 0.3, "detection": 0.3, "analysis": 0.3,
        "intelligence": 0.3, "report": 0.2
    }
    
    # Calculate weighted threat score
    keywords_found = []
    for keyword, weight in critical_keywords.items():
        if keyword in text_lower:
            threat_score += weight
            keywords_found.append(f"{keyword}(+{weight})")
    
    for keyword, weight in high_keywords.items():
        if keyword in text_lower:
            threat_score += weight
            keywords_found.append(f"{keyword}(+{weight})")
    
    for keyword, weight in medium_keywords.items():
        if keyword in text_lower:
            threat_score += weight
    
    if keywords_found:
        logger.info(f"Keywords found: {', '.join(keywords_found[:5])}")
    
    # Apply channel-specific multipliers and context
    channel_meta = CHANNEL_METADATA.get(channel, {})
    multiplier = channel_meta.get('threat_multiplier', 1.0)
    channel_keywords = channel_meta.get('keywords', [])
    
    # Bonus for channel-specific keywords
    channel_bonus = 0.0
    for keyword in channel_keywords:
        if keyword in text_lower:
            channel_bonus += 0.2
    
    # Apply multipliers
    threat_score = (threat_score + channel_bonus) * multiplier
    
    # Special handling for DarkfeedNews (premium threat intel)
    if channel == "@DarkfeedNews":
        threat_score += 0.4  # Base boost for premium intel
        
        # Extra boost for darkfeed-specific indicators
        if any(word in text_lower for word in ["darkfeed", "threat actor", "campaign", "operation"]):
            threat_score += 0.3
            
        # DarkfeedNews content is inherently higher threat
        if threat_score < 0.4:
            threat_score = 0.4
    
    # Special handling for breach detector
    if channel == "@breachdetector":
        if any(word in text_lower for word in ["breach", "leak", "stolen", "dump", "database"]):
            threat_score += 0.3
            
        # Breach detector content is inherently medium+ threat
        if threat_score < 0.3:
            threat_score = 0.3
    
    # Special handling for SecHarvester
    if channel == "@secharvester":
        if any(word in text_lower for word in ["cve-", "vulnerability", "exploit"]):
            threat_score += 0.2
    
    # Determine threat level and urgency with realistic thresholds
    if threat_score >= 1.8:
        threat_level = "critical"
        urgency_score = min(0.95, 0.5 + (threat_score * 0.2))
    elif threat_score >= 1.0:
        threat_level = "high"
        urgency_score = min(0.85, 0.4 + (threat_score * 0.2))
    elif threat_score >= 0.5:
        threat_level = "medium"
        urgency_score = min(0.65, 0.3 + (threat_score * 0.2))
    elif threat_score >= 0.2:
        threat_level = "low"
        urgency_score = min(0.45, 0.2 + (threat_score * 0.2))
    else:
        threat_level = "low"
        urgency_score = max(0.05, threat_score * 0.3)
    
    # ENHANCED category detection with cybersecurity context
    category = "other"
    category_scores = {}
    
    # Comprehensive category mapping
    category_patterns = {
        "ransomware": [
            "ransomware", "crypto", "encrypt", "lockbit", "maze", "ryuk", "conti", 
            "blackcat", "alphv", "revil", "darkside", "babuk", "novas", "ragnar",
            "hive", "blackmatter", "grief", "egregor", "netwalker"
        ],
        "apt": [
            "apt", "advanced persistent", "nation state", "lazarus", "kimsuky", 
            "turla", "carbanak", "fin7", "sandworm", "equation", "darkhydrus",
            "muddywater", "oceanlotus", "machete", "bronze butler", "stone panda"
        ],
        "data_breach": [
            "breach", "leak", "stolen", "database", "credential", "dump", "exposed",
            "hacked", "compromised", "data theft", "exfiltration", "personal data"
        ],
        "malware": [
            "malware", "trojan", "virus", "backdoor", "rat", "stealer", "loader",
            "botnet", "cryptominer", "keylogger", "spyware", "adware", "worm"
        ],
        "vulnerability": [
            "vulnerability", "cve-", "exploit", "rce", "remote code execution",
            "privilege escalation", "buffer overflow", "sql injection", "xss",
            "csrf", "directory traversal", "deserialization"
        ],
        "phishing": [
            "phishing", "scam", "social engineering", "credential harvesting",
            "fake", "spoofed", "impersonation", "bec", "business email compromise"
        ],
        "ddos": [
            "ddos", "dos", "denial of service", "amplification", "reflection",
            "volumetric", "network attack", "bandwidth"
        ],
        "insider_threat": [
            "insider", "rogue employee", "privilege abuse", "data theft employee",
            "internal threat", "malicious insider"
        ],
        "supply_chain": [
            "supply chain", "third party", "vendor", "software supply chain",
            "dependency", "compromised library", "backdoored"
        ]
    }
    
    # Score each category
    for cat, patterns in category_patterns.items():
        score = 0
        for pattern in patterns:
            if pattern in text_lower:
                score += 1
                if pattern in ["lockbit", "maze", "ryuk", "conti"]:  # High-profile ransomware
                    score += 2
                elif pattern in ["lazarus", "apt28", "apt29"]:  # High-profile APTs
                    score += 2
        if score > 0:
            category_scores[cat] = score
    
    # Apply channel context to category detection
    if channel == "@DarkfeedNews":
        # DarkfeedNews tends toward APT and advanced threats
        if 'apt' in category_scores:
            category_scores['apt'] += 2
        if 'ransomware' in category_scores:
            category_scores['ransomware'] += 2
        # If no clear category but DarkfeedNews, likely APT/advanced
        if not category_scores and threat_score > 0.3:
            category_scores['apt'] = 1
            
    elif channel == "@breachdetector":
        # Breach detector focuses on data breaches
        if 'data_breach' in category_scores:
            category_scores['data_breach'] += 3
        # If no clear category but breach detector, likely breach
        if not category_scores:
            category_scores['data_breach'] = 1
            
    elif channel == "@secharvester":
        # SecHarvester focuses on vulnerabilities and general security
        if 'vulnerability' in category_scores:
            category_scores['vulnerability'] += 2
        if 'malware' in category_scores:
            category_scores['malware'] += 1
    
    # Select highest scoring category
    if category_scores:
        category = max(category_scores, key=category_scores.get)
        logger.info(f"Category detected: {category} (score: {category_scores[category]})")
    
    # Enhanced sentiment detection
    sentiment = "neutral"
    negative_indicators = [
        "critical", "severe", "dangerous", "urgent", "threat", "attack", "breach",
        "compromised", "exploit", "malicious", "vulnerable", "exposed", "stolen",
        "emergency", "warning", "alert", "suspicious"
    ]
    positive_indicators = [
        "fixed", "patched", "resolved", "secured", "protected", "mitigated",
        "blocked", "prevented", "detected", "stopped", "quarantined", "updated"
    ]
    
    negative_count = sum(1 for word in negative_indicators if word in text_lower)
    positive_count = sum(1 for word in positive_indicators if word in text_lower)
    
    if negative_count > positive_count and negative_count >= 2:
        sentiment = "negative"
    elif positive_count > negative_count and positive_count >= 2:
        sentiment = "positive"
    
    # Generate ENHANCED analysis based on content and context
    analysis_parts = []
    
    # Main threat assessment with channel context
    channel_name = channel.replace("@", "")
    if threat_level == "critical":
        analysis_parts.append(f"Critical {category} threat detected from {channel_name} requiring immediate security response and containment measures.")
    elif threat_level == "high":
        analysis_parts.append(f"High-priority {category} identified from {channel_name} with significant security implications requiring prompt action.")
    elif threat_level == "medium":
        analysis_parts.append(f"Medium-level {category} from {channel_name} requiring security monitoring and assessment.")
    else:
        analysis_parts.append(f"{category.title()} intelligence from {channel_name} providing valuable situational awareness.")
    
    # Add specific context based on detected content
    context_added = False
    
    if any(word in text_lower for word in ["cve-", "vulnerability", "exploit"]):
        analysis_parts.append("Contains vulnerability information requiring immediate patch management review and remediation.")
        context_added = True
    
    if any(word in text_lower for word in ["zero-day", "0day", "zero day"]):
        analysis_parts.append("Involves zero-day exploitation requiring emergency response and advanced detection measures.")
        context_added = True
    
    if any(word in text_lower for word in ["ransomware", "encrypt", "lockbit", "maze"]):
        analysis_parts.append("Ransomware activity detected requiring backup verification and endpoint protection review.")
        context_added = True
    
    if any(word in text_lower for word in ["breach", "leak", "stolen", "dump"]):
        analysis_parts.append("Data exposure incident requiring impact assessment and incident response activation.")
        context_added = True
    
    if any(word in text_lower for word in ["apt", "nation state", "advanced persistent"]):
        analysis_parts.append("Advanced persistent threat activity requiring enhanced monitoring and threat hunting.")
        context_added = True
    
    if any(word in text_lower for word in ["ioc", "indicator", "hash", "c2"]):
        analysis_parts.append("Contains threat indicators requiring integration into security tools and hunting operations.")
        context_added = True
    
    # Add channel-specific context if no specific context was added
    if not context_added:
        if channel == "@DarkfeedNews":
            analysis_parts.append("Premium threat intelligence requiring security team review and threat landscape assessment.")
        elif channel == "@breachdetector":
            analysis_parts.append("Data security incident requiring breach response team evaluation.")
        elif channel == "@secharvester":
            analysis_parts.append("Security advisory requiring vulnerability management team review.")
    
    analysis_text = " ".join(analysis_parts)
    
    # Extract comprehensive key topics
    key_topics = []
    topic_keywords = [
        "vulnerability", "exploit", "malware", "ransomware", "breach", "apt", 
        "phishing", "patch", "zero-day", "trojan", "backdoor", "stealer",
        "ddos", "c2", "botnet", "campaign", "threat actor", "ioc"
    ]
    
    for keyword in topic_keywords:
        if keyword in text_lower:
            key_topics.append(keyword)
    
    # Add channel-specific topics
    if channel == "@DarkfeedNews":
        key_topics.extend(["threat-intelligence", "darkfeed"])
    elif channel == "@breachdetector":
        key_topics.extend(["data-breach", "breach-monitoring"])
    elif channel == "@secharvester":
        key_topics.extend(["security-news", "vulnerability-tracking"])
    
    # Extract MITRE techniques from content
    mitre_techniques = []
    if any(word in text_lower for word in ["phishing", "spearphishing"]):
        mitre_techniques.append("T1566")  # Phishing
    if any(word in text_lower for word in ["powershell", "command line"]):
        mitre_techniques.append("T1059")  # Command and Scripting Interpreter
    if any(word in text_lower for word in ["credential", "password", "hash"]):
        mitre_techniques.append("T1003")  # OS Credential Dumping
    if any(word in text_lower for word in ["lateral movement", "network"]):
        mitre_techniques.append("T1021")  # Remote Services
    if any(word in text_lower for word in ["persistence", "startup"]):
        mitre_techniques.append("T1547")  # Boot or Logon Autostart Execution
    
    # Determine affected systems
    affected_systems = []
    system_keywords = {
        "windows": ["windows", "microsoft", "powershell", "cmd", "exe", "dll"],
        "linux": ["linux", "unix", "bash", "shell", "root", "sudo"],
        "macos": ["macos", "mac", "apple", "osx", "darwin"],
        "cloud": ["aws", "azure", "gcp", "cloud", "kubernetes", "docker"],
        "mobile": ["android", "ios", "mobile", "phone", "app"],
        "web": ["web", "browser", "javascript", "html", "php", "apache", "nginx"]
    }
    
    for system, keywords in system_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            affected_systems.append(system)
    
    logger.info(f"Enhanced analysis complete: {threat_level}/{category} - score: {threat_score:.2f} - urgency: {urgency_score:.2f}")
    
    return {
        "threat_level": threat_level,
        "category": category,
        "threat_type": f"{category} threat intelligence",
        "urgency_score": urgency_score,
        "sentiment": sentiment,
        "gemini_analysis": analysis_text,
        "key_topics": key_topics[:8],  # Limit to top 8 topics
        "mitre_techniques": mitre_techniques,
        "affected_systems": affected_systems,
        "vulnerabilities": [],  # Will be populated by extract_cybersecurity_data
        "attack_vectors": [],
        "geographical_targets": [],
        "industry_targets": [],
        # Additional metadata
        "analysis_confidence": min(0.95, 0.5 + (threat_score * 0.3)),
        "processing_method": "enhanced_rule_based",
        "threat_score_raw": threat_score
    }

def extract_cybersecurity_data_enhanced(text: str) -> Dict[str, List[str]]:
    """Enhanced cybersecurity indicator extraction"""
    extracted = {
        "cve_references": [],
        "cwe_references": [],
        "iocs_detected": [],
        "malware_families": [],
        "threat_actors": [],
        "affected_systems": [],
        "attack_vectors": [],
        "vulnerabilities": [],
        "campaign_names": [],
        "geographical_targets": [],
        "industry_targets": []
    }
    
    text_lower = text.lower()
    
    # Extract CVEs with enhanced pattern
    cve_matches = CYBERSEC_PATTERNS["cve"].findall(text)
    extracted["cve_references"] = list(set(cve_matches))[:5]  # Limit to 5 most relevant
    
    # Extract CWEs
    cwe_matches = CYBERSEC_PATTERNS["cwe"].findall(text)
    extracted["cwe_references"] = list(set(cwe_matches))[:3]
    
    # Extract IOCs with better filtering
    # IPs (excluding private ranges)
    ip_matches = CYBERSEC_PATTERNS["ip_address"].findall(text)
    real_ips = []
    for ip in ip_matches:
        is_private = any(re.match(pattern, ip) for pattern in PRIVATE_IP_RANGES)
        if not is_private and ip not in ["0.0.0.0", "127.0.0.1", "255.255.255.255"]:
            real_ips.append(ip)
    
    # Domains (excluding common ones)
    domain_matches = CYBERSEC_PATTERNS["domain"].findall(text)
    real_domains = []
    for domain_parts in domain_matches:
        domain = '.'.join(domain_parts) if isinstance(domain_parts, tuple) else domain_parts
        domain_lower = domain.lower()
        
        # Exclude common domains and obviously false positives
        if (domain_lower not in EXCLUDED_DOMAINS and 
            not any(excluded in domain_lower for excluded in EXCLUDED_DOMAINS) and
            len(domain) > 4 and '.' in domain):
            real_domains.append(domain)
    
    # File hashes
    hashes = []
    for hash_type in ["md5", "sha1", "sha256", "sha512"]:
        if hash_type in CYBERSEC_PATTERNS:
            hash_matches = CYBERSEC_PATTERNS[hash_type].findall(text)
            hashes.extend(hash_matches)
    
    # Combine IOCs with reasonable limits
    all_iocs = real_ips[:5] + real_domains[:8] + hashes[:5]
    extracted["iocs_detected"] = all_iocs
    
    # Enhanced malware family detection
    detected_malware = []
    for malware in MALWARE_FAMILIES:
        if malware in text_lower:
            detected_malware.append(malware)
    
    # Add common malware patterns not in the main list
    additional_malware = ["emotet", "trickbot", "qakbot", "cobalt strike", "metasploit"]
    for malware in additional_malware:
        if malware in text_lower and malware not in detected_malware:
            detected_malware.append(malware)
    
    extracted["malware_families"] = detected_malware[:5]
    
    # Enhanced threat actor detection
    detected_actors = []
    for actor in THREAT_ACTORS:
        if actor in text_lower:
            detected_actors.append(actor)
    
    extracted["threat_actors"] = detected_actors[:3]
    
    # Attack vector detection
    attack_vectors = []
    vector_patterns = {
        "email": ["email", "phishing", "spearphishing", "attachment"],
        "web": ["web", "browser", "javascript", "xss", "sql injection"],
        "network": ["network", "lateral movement", "smb", "rdp", "ssh"],
        "usb": ["usb", "removable media", "autorun"],
        "supply_chain": ["supply chain", "third party", "vendor", "dependency"]
    }
    
    for vector, keywords in vector_patterns.items():
        if any(keyword in text_lower for keyword in keywords):
            attack_vectors.append(vector)
    
    extracted["attack_vectors"] = attack_vectors[:4]
    
    # Vulnerability types
    vuln_types = []
    vuln_patterns = [
        "rce", "remote code execution", "privilege escalation", "buffer overflow",
        "sql injection", "xss", "csrf", "deserialization", "directory traversal"
    ]
    
    for vuln in vuln_patterns:
        if vuln in text_lower:
            vuln_types.append(vuln.replace(" ", "_"))
    
    extracted["vulnerabilities"] = vuln_types[:4]
    
    # Campaign names (look for operation/campaign keywords)
    campaign_keywords = ["operation", "campaign", "apt", "group"]
    campaigns = []
    
    for keyword in campaign_keywords:
        # Look for "Operation/Campaign [Name]" patterns
        pattern = rf'{keyword}\s+([a-zA-Z][a-zA-Z0-9\s]{{2,20}})'
        matches = re.findall(pattern, text, re.IGNORECASE)
        campaigns.extend(matches)
    
    extracted["campaign_names"] = campaigns[:3]
    
    # Geographic targets
    countries = [
        "united states", "usa", "china", "russia", "ukraine", "israel", "iran",
        "north korea", "south korea", "japan", "germany", "france", "uk", "india"
    ]
    
    geo_targets = []
    for country in countries:
        if country in text_lower:
            geo_targets.append(country)
    
    extracted["geographical_targets"] = geo_targets[:4]
    
    # Industry targets
    industries = [
        "healthcare", "finance", "banking", "government", "education", "manufacturing",
        "energy", "utilities", "telecommunications", "retail", "technology"
    ]
    
    industry_targets = []
    for industry in industries:
        if industry in text_lower:
            industry_targets.append(industry)
    
    extracted["industry_targets"] = industry_targets[:4]
    
    # Affected systems (enhanced)
    systems = []
    system_indicators = {
        "windows": ["windows", "microsoft", "powershell", "cmd", "exe", "dll"],
        "linux": ["linux", "unix", "bash", "shell", "root", "sudo"],
        "macos": ["macos", "mac", "apple", "osx", "darwin"],
        "android": ["android", "apk", "mobile"],
        "ios": ["ios", "iphone", "ipad", "mobile"],
        "docker": ["docker", "container", "kubernetes"],
        "cloud": ["aws", "azure", "gcp", "cloud", "s3", "ec2"]
    }
    
    for system, indicators in system_indicators.items():
        if any(indicator in text_lower for indicator in indicators):
            systems.append(system)
    
    extracted["affected_systems"] = systems[:5]
    
    return extracted

# Use the enhanced function instead of the original
def extract_cybersecurity_data(text: str) -> Dict[str, List[str]]:
    """Extract cybersecurity indicators from text - Enhanced Version"""
    return extract_cybersecurity_data_enhanced(text)

# Use the enhanced function instead of the original
def analyze_message_content(text: str, channel: str) -> Dict[str, Any]:
    """Analyze message content without AI - Enhanced Version"""
    return analyze_message_content_enhanced(text, channel)

async def store_message_in_bigquery(message_data: Dict[str, Any]):
    """Store processed message in BigQuery - DEFENSIVE VERSION"""
    try:
        if not _bigquery_available:
            logger.warning("BigQuery not available")
            return
        
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        
        # Get existing schema fields
        existing_fields = {field.name for field in table.schema}
        logger.info(f"Available fields for storage: {sorted(existing_fields)}")
        
        # Convert datetime objects
        def convert_datetime(dt):
            if dt is None:
                return None
            if isinstance(dt, datetime):
                return dt.isoformat()
            if hasattr(dt, 'timestamp'):
                return datetime.fromtimestamp(dt.timestamp()).isoformat()
            return str(dt)
        
        # Build row data with ONLY existing fields
        row = {}
        for field_name, field_value in message_data.items():
            # Only include fields that exist in the schema
            if field_name in existing_fields:
                if field_name.endswith('_date'):
                    row[field_name] = convert_datetime(field_value)
                elif isinstance(field_value, list):
                    row[field_name] = [str(item) for item in field_value if item]
                elif isinstance(field_value, (int, float)):
                    row[field_name] = field_value
                else:
                    row[field_name] = str(field_value) if field_value is not None else ""
            else:
                logger.debug(f"Skipping field not in schema: {field_name}")
        
        # Ensure required core fields exist
        core_fields = {
            "message_id": str(message_data.get("message_id", "")),
            "chat_id": str(message_data.get("chat_id", "")),
            "processed_date": convert_datetime(message_data.get("processed_date", datetime.now()))
        }
        
        for field, value in core_fields.items():
            if field in existing_fields:
                row[field] = value
        
        # Insert row
        if row:  # Only insert if we have data
            errors = _bq_client.insert_rows_json(table, [row])
            if errors:
                logger.error(f"BigQuery insert failed: {errors}")
                logger.error(f"Attempted to insert fields: {list(row.keys())}")
            else:
                stored_fields = len(row)
                threat_level = row.get('threat_level', 'unknown')
                category = row.get('category', 'unknown')
                logger.info(f"✅ Stored message: {row.get('chat_username')} - {threat_level}/{category} ({stored_fields} fields)")
        else:
            logger.warning("No valid fields to store in BigQuery")
            
    except Exception as e:
        logger.error(f"BigQuery storage failed: {e}")
        logger.error(f"Available schema fields: {len(existing_fields) if 'existing_fields' in locals() else 'unknown'}")

async def stop_monitoring_system():
    """Stop monitoring system"""
    global _monitoring_active, _telegram_client, _monitoring_task
    
    try:
        _monitoring_active = False
        
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
            try:
                await _monitoring_task
            except asyncio.CancelledError:
                logger.info("Monitoring task cancelled")
        
        if _telegram_client:
            await _telegram_client.disconnect()
            _telegram_client = None
            
        logger.info("🛑 CIPHER monitoring stopped")
        
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")

# API Functions

async def get_comprehensive_stats() -> Dict[str, Any]:
    """Get real system statistics from BigQuery - DEFENSIVE VERSION"""
    try:
        if not _bigquery_available:
            return {
                "total_messages": 0,
                "processed_today": 0,
                "high_threats": 0,
                "critical_threats": 0,
                "monitoring_active": _monitoring_active,
                "data_source": "bigquery_unavailable"
            }
        
        # Check available fields first
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        existing_fields = {field.name for field in table.schema}
        
        logger.info(f"Available fields for stats: {sorted(existing_fields)}")
        
        # Build defensive query based on available fields
        base_stats = [
            "COUNT(*) as total_messages",
            "COUNTIF(DATE(processed_date) = CURRENT_DATE()) as processed_today",
            "COUNT(DISTINCT chat_username) as unique_channels"
        ]
        
        # Add conditional fields
        additional_stats = []
        
        if 'urgency_score' in existing_fields:
            additional_stats.append("AVG(COALESCE(urgency_score, 0)) as avg_urgency")
        else:
            additional_stats.append("0.0 as avg_urgency")
            
        if 'threat_level' in existing_fields:
            additional_stats.extend([
                "COUNTIF(threat_level IN ('high', 'critical')) as high_threats",
                "COUNTIF(threat_level = 'critical') as critical_threats"
            ])
        else:
            additional_stats.extend([
                "0 as high_threats",
                "0 as critical_threats"
            ])
            
        if 'category' in existing_fields:
            additional_stats.extend([
                "COUNTIF(category = 'data_breach') as data_breaches",
                "COUNTIF(category = 'malware') as malware_alerts",
                "COUNTIF(category = 'vulnerability') as vulnerabilities",
                "COUNTIF(category = 'apt') as apt_activity"
            ])
        else:
            additional_stats.extend([
                "0 as data_breaches",
                "0 as malware_alerts", 
                "0 as vulnerabilities",
                "0 as apt_activity"
            ])
            
        if 'cve_references' in existing_fields:
            additional_stats.append("COUNTIF(ARRAY_LENGTH(cve_references) > 0) as cve_mentions")
        else:
            additional_stats.append("0 as cve_mentions")
        
        all_stats = base_stats + additional_stats
        
        stats_query = f"""
        SELECT {', '.join(all_stats)}
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        logger.info("Executing defensive stats query")
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
                "data_source": "bigquery_defensive",
                "available_fields": sorted(existing_fields),
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
        else:
            return {
                "total_messages": 0,
                "processed_today": 0,
                "monitoring_active": _monitoring_active,
                "data_source": "bigquery_no_data"
            }
                
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {
            "total_messages": 0,
            "processed_today": 0,
            "monitoring_active": _monitoring_active,
            "data_source": "error",
            "error": str(e)
        }

async def get_threat_insights() -> Dict[str, Any]:
    """Get real threat intelligence insights - DEFENSIVE VERSION"""
    try:
        if not _bigquery_available:
            return {"insights": [], "total": 0, "source": "bigquery_unavailable"}
        
        # First, check what fields actually exist in the table
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        existing_fields = {field.name for field in table.schema}
        
        logger.info(f"Available BigQuery fields: {sorted(existing_fields)}")
        
        # Build query with only existing fields
        core_fields = ["message_id", "chat_username", "message_text", "message_date", "processed_date"]
        optional_fields = ["gemini_analysis", "sentiment", "urgency_score", "threat_level", "category", 
                          "threat_type", "key_topics", "cve_references", "iocs_detected", 
                          "malware_families", "threat_actors", "affected_systems"]
        
        # Only select fields that exist
        select_fields = []
        for field in core_fields:
            if field in existing_fields:
                select_fields.append(field)
        
        for field in optional_fields:
            if field in existing_fields:
                select_fields.append(field)
        
        if not select_fields:
            logger.error("No valid fields found in BigQuery table")
            return {"insights": [], "total": 0, "source": "schema_error"}
        
        # Build defensive query
        insights_query = f"""
        SELECT {', '.join(select_fields)}
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC
        LIMIT 100
        """
        
        logger.info(f"Executing defensive query with {len(select_fields)} fields")
        query_job = _bq_client.query(insights_query)
        results = query_job.result(timeout=30)
        
        insights = []
        for row in results:
            # Build insight with defensive field access
            insight = {
                "message_id": getattr(row, 'message_id', 'unknown'),
                "chat_username": getattr(row, 'chat_username', '@Unknown'),
                "message_text": (getattr(row, 'message_text', '') or '')[:1000],
                "message_date": getattr(row, 'message_date', None),
                "processed_date": getattr(row, 'processed_date', None),
                "gemini_analysis": getattr(row, 'gemini_analysis', None) or "Analysis not available",
                "sentiment": getattr(row, 'sentiment', None) or "neutral",
                "urgency_score": float(getattr(row, 'urgency_score', 0) or 0),
                "threat_level": getattr(row, 'threat_level', None) or "low",
                "category": getattr(row, 'category', None) or "other",
                "threat_type": getattr(row, 'threat_type', None) or "unknown",
                "key_topics": getattr(row, 'key_topics', []) or [],
                "cve_references": getattr(row, 'cve_references', []) or [],
                "iocs_detected": getattr(row, 'iocs_detected', []) or [],
                "malware_families": getattr(row, 'malware_families', []) or [],
                "threat_actors": getattr(row, 'threat_actors', []) or [],
                "affected_systems": getattr(row, 'affected_systems', []) or []
            }
            
            # Convert dates to ISO format
            if insight["message_date"]:
                if hasattr(insight["message_date"], 'isoformat'):
                    insight["message_date"] = insight["message_date"].isoformat()
                else:
                    insight["message_date"] = str(insight["message_date"])
            
            if insight["processed_date"]:
                if hasattr(insight["processed_date"], 'isoformat'):
                    insight["processed_date"] = insight["processed_date"].isoformat()
                else:
                    insight["processed_date"] = str(insight["processed_date"])
            
            # If we have real message text but poor analysis, do real-time analysis
            if (insight["message_text"] and len(insight["message_text"]) > 20 and 
                (not insight["gemini_analysis"] or insight["gemini_analysis"] == "Analysis not available" or
                 insight["urgency_score"] == 0.0)):
                
                logger.info(f"Re-analyzing message {insight['message_id']} with poor analysis")
                enhanced_analysis = analyze_message_content_enhanced(insight["message_text"], insight["chat_username"])
                
                # Update with better analysis
                insight.update(enhanced_analysis)
                insight["gemini_analysis"] = enhanced_analysis.get("gemini_analysis", insight["gemini_analysis"])
            
            insights.append(insight)
        
        logger.info(f"Retrieved {len(insights)} real threat insights (defensive mode)")
        return {
            "insights": insights,
            "total": len(insights),
            "source": "bigquery_defensive",
            "available_fields": sorted(existing_fields),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get threat insights: {e}")
        return {"insights": [], "total": 0, "source": "error", "error": str(e)}

async def get_monitoring_status() -> Dict[str, Any]:
    """Get monitoring system status"""
    try:
        return {
            "active": _monitoring_active,
            "subsystems": {
                "bigquery": _bigquery_available,
                "gemini": _gemini_available,
                "telegram": _telegram_connected
            },
            "channels": {
                "monitored": MONITORED_CHANNELS,
                "count": len(MONITORED_CHANNELS),
                "accessible": await test_channel_access() if _telegram_connected else []
            },
            "last_check": datetime.now(timezone.utc).isoformat(),
            "system_health": "operational" if _monitoring_active else "limited",
            "monitoring_task_active": _monitoring_task is not None and not _monitoring_task.done() if _monitoring_task else False
        }
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return {"active": False, "error": str(e)}

async def get_threat_analytics() -> Dict[str, Any]:
    """Get real threat analytics - DEFENSIVE VERSION"""
    try:
        if not _bigquery_available:
            return {
                "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "summary": {"total_threats": 0, "high_priority": 0}
            }
        
        # Check available fields first
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        existing_fields = {field.name for field in table.schema}
        
        # Build defensive analytics query
        base_analytics = ["COUNT(*) as total_threats"]
        
        threat_level_fields = []
        if 'threat_level' in existing_fields:
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
            
        category_fields = []
        if 'category' in existing_fields:
            category_fields = [
                "COUNTIF(category = 'apt') as apt_count",
                "COUNTIF(category = 'malware') as malware_count",
                "COUNTIF(category = 'data_breach') as breach_count",
                "COUNTIF(category = 'vulnerability') as vuln_count",
                "COUNTIF(category = 'ransomware') as ransomware_count",
                "COUNTIF(category = 'phishing') as phishing_count"
            ]
        else:
            category_fields = [
                "0 as apt_count",
                "0 as malware_count", 
                "0 as breach_count",
                "0 as vuln_count",
                "0 as ransomware_count",
                "0 as phishing_count"
            ]
        
        urgency_field = "AVG(COALESCE(urgency_score, 0))" if 'urgency_score' in existing_fields else "0.0"
        urgency_field += " as avg_urgency"
        
        all_analytics = base_analytics + threat_level_fields + category_fields + [urgency_field]
        
        analytics_query = f"""
        SELECT {', '.join(all_analytics)}
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        logger.info("Executing defensive analytics query")
        query_job = _bq_client.query(analytics_query)
        row = next(iter(query_job.result(timeout=30)), None)
        
        if not row:
            return {
                "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "summary": {"total_threats": 0, "high_priority": 0}
            }
        
        return {
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
                "vulnerability": int(getattr(row, 'vuln_count', 0)) if hasattr(row, 'vuln_count') else 0,
                "ransomware": int(getattr(row, 'ransomware_count', 0)) if hasattr(row, 'ransomware_count') else 0,
                "phishing": int(getattr(row, 'phishing_count', 0)) if hasattr(row, 'phishing_count') else 0
            },
            "summary": {
                "total_threats": int(getattr(row, 'total_threats', 0)) if hasattr(row, 'total_threats') else 0,
                "high_priority": (int(getattr(row, 'critical_count', 0)) if hasattr(row, 'critical_count') else 0) + 
                               (int(getattr(row, 'high_count', 0)) if hasattr(row, 'high_count') else 0),
                "avg_urgency": float(getattr(row, 'avg_urgency', 0.0)) if hasattr(row, 'avg_urgency') else 0.0
            },
            "available_fields": sorted(existing_fields),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error calculating threat analytics: {e}")
        return {"error": str(e), "status": "error"}

# System state checkers
def is_bigquery_available() -> bool:
    return _bigquery_available

def is_gemini_available() -> bool:
    return _gemini_available

def is_telegram_connected() -> bool:
    return _telegram_connected

def is_monitoring_active() -> bool:
    return _monitoring_active

# Export functions
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
