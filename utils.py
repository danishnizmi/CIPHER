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
_session_string = None

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
            logger.error("Please run the authentication script first: python local_auth.py")
            return None
        
        session_data = blob.download_as_bytes()
        if not session_data:
            logger.error("Empty session data in Cloud Storage")
            return None
        
        # Convert bytes to string if needed
        if isinstance(session_data, bytes):
            try:
                _session_string = session_data.decode('utf-8')
            except UnicodeDecodeError:
                # If it's binary data, treat as base64 or raw bytes
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

async def initialize_gemini_ai():
    """Initialize Gemini AI for cybersecurity analysis with enhanced error handling"""
    global _gemini_model, _gemini_available
    
    try:
        logger.info("🤖 Initializing Gemini AI...")
        
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            logger.error("Gemini API key not available in Secret Manager")
            logger.error("Please set up Gemini API key at: https://makersuite.google.com/app/apikey")
            return False
        
        # Validate API key format
        if len(api_key) < 20:
            logger.error(f"Gemini API key appears invalid (length: {len(api_key)})")
            return False
        
        logger.info(f"Found Gemini API key (length: {len(api_key)} chars)")
        
        try:
            genai.configure(api_key=api_key)
            
            _gemini_model = genai.GenerativeModel(
                'gemini-1.5-flash',
                generation_config=genai.GenerationConfig(
                    temperature=0.1,
                    top_p=0.8,
                    max_output_tokens=1000
                )
            )
            
            # Test the model with a simple cybersecurity prompt
            test_prompt = "Analyze this cybersecurity message for threats: 'New critical vulnerability CVE-2024-0001 discovered in Apache servers. Immediate patching required.'"
            
            logger.info("Testing Gemini AI with cybersecurity prompt...")
            test_response = await asyncio.to_thread(
                _gemini_model.generate_content, 
                test_prompt
            )
            
            if test_response and test_response.text:
                _gemini_available = True
                logger.info("✅ Gemini AI initialized and tested successfully")
                logger.info(f"Test response preview: {test_response.text[:100]}...")
                return True
            else:
                logger.error("Gemini test failed - no response generated")
                return False
                
        except Exception as api_error:
            logger.error(f"Gemini API configuration failed: {api_error}")
            
            # Check for common API errors
            error_str = str(api_error).lower()
            if "api key" in error_str or "authentication" in error_str:
                logger.error("❌ Gemini API key is invalid or expired")
                logger.error("🔑 Get a new API key from: https://makersuite.google.com/app/apikey")
            elif "quota" in error_str or "limit" in error_str:
                logger.error("❌ Gemini API quota exceeded or billing issue")
                logger.error("💳 Check your Google AI Studio billing and quotas")
            elif "permission" in error_str:
                logger.error("❌ Gemini API access denied")
                logger.error("🔐 Ensure the API key has proper permissions")
            else:
                logger.error(f"❌ Unknown Gemini API error: {api_error}")
            
            return False
            
    except Exception as e:
        logger.error(f"Gemini AI initialization failed: {e}")
        _gemini_available = False
        return False

async def initialize_telegram_client():
    """Initialize Telegram client with proper session handling"""
    global _telegram_client, _telegram_connected
    
    try:
        logger.info("📱 Initializing Telegram client...")
        
        # Get credentials from Secret Manager
        api_id = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        phone = await get_secret("telegram-phone-number")
        
        if not all([api_id, api_hash, phone]):
            logger.error("Telegram credentials not available in Secret Manager")
            logger.error("Required secrets: telegram-api-id, telegram-api-hash, telegram-phone-number")
            logger.error("Please run authentication script: python local_auth.py")
            _telegram_connected = False
            return False
        
        # Get session from Cloud Storage
        session_data = await get_telegram_session_from_storage()
        if not session_data:
            logger.error("No Telegram session available")
            logger.error("Please run authentication script to create session")
            _telegram_connected = False
            return False
        
        # Initialize Telethon client
        try:
            from telethon import TelegramClient
            from telethon.sessions import StringSession
            
            # Create client with session string
            session = StringSession(session_data)
            _telegram_client = TelegramClient(
                session,
                int(api_id),
                api_hash,
                system_version="CIPHER v1.0.0",
                device_model="CIPHER Intelligence Platform",
                app_version="1.0.0"
            )
            
            # Connect and verify
            await _telegram_client.connect()
            
            if await _telegram_client.is_user_authorized():
                # Get user info
                me = await _telegram_client.get_me()
                logger.info(f"✅ Telegram authenticated as: {me.first_name} (@{me.username or 'no_username'})")
                
                # Test channel access
                accessible_channels = await test_channel_access()
                
                if accessible_channels:
                    _telegram_connected = True
                    logger.info(f"✅ Telegram client ready - {len(accessible_channels)}/{len(MONITORED_CHANNELS)} channels accessible")
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

async def test_channel_access() -> List[str]:
    """Test access to monitored channels"""
    if not _telegram_client:
        return []
    
    accessible = []
    for channel in MONITORED_CHANNELS:
        try:
            entity = await _telegram_client.get_entity(channel)
            # Try to get recent messages to test read access
            messages = await _telegram_client.get_messages(entity, limit=1)
            accessible.append(channel)
            logger.info(f"✅ Channel access confirmed: {channel}")
        except Exception as e:
            logger.warning(f"⚠️ Channel access limited: {channel} - {str(e)[:50]}...")
    
    return accessible

async def start_monitoring_system():
    """Start the cybersecurity monitoring system"""
    global _monitoring_active
    
    try:
        logger.info("🛡️ Starting CIPHER monitoring system...")
        
        if not _clients_initialized:
            await initialize_all_systems()
        
        # Determine monitoring mode
        if _telegram_connected and _bigquery_available:
            _monitoring_active = True
            logger.info("✅ CIPHER monitoring active (full mode)")
            
            # Start background monitoring task
            asyncio.create_task(monitoring_loop())
            
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
    """Main monitoring loop for processing messages"""
    if not _telegram_client or not _bigquery_available:
        logger.warning("Monitoring loop disabled - missing required components")
        return
    
    logger.info("📡 Starting message monitoring loop...")
    
    try:
        # This is a basic monitoring loop - in production you'd want more sophisticated handling
        while _monitoring_active and _telegram_connected:
            try:
                # Process messages from each channel
                for channel in MONITORED_CHANNELS:
                    try:
                        await process_channel_messages(channel)
                    except Exception as e:
                        logger.error(f"Error processing {channel}: {e}")
                
                # Wait before next iteration
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
                
    except Exception as e:
        logger.error(f"Monitoring loop failed: {e}")

async def process_channel_messages(channel: str):
    """Process messages from a specific channel"""
    try:
        if not _telegram_client:
            return
        
        entity = await _telegram_client.get_entity(channel)
        
        # Get recent messages (last hour)
        messages = await _telegram_client.get_messages(
            entity, 
            limit=10,
            offset_date=datetime.now() - timedelta(hours=1)
        )
        
        for message in messages:
            if message.text:
                await process_message(message, channel)
                
    except Exception as e:
        logger.error(f"Error processing channel {channel}: {e}")

async def process_message(message, channel: str):
    """Process and analyze a single message with proper datetime handling"""
    try:
        # Convert Telegram datetime to Python datetime
        message_date = message.date
        if hasattr(message_date, 'timestamp'):
            message_date = datetime.fromtimestamp(message_date.timestamp())
        elif not isinstance(message_date, datetime):
            message_date = datetime.now()
            
        processed_date = datetime.now()
        
        # Basic message processing
        message_data = {
            "message_id": str(message.id),
            "chat_id": str(message.peer_id.channel_id if hasattr(message.peer_id, 'channel_id') else message.chat_id),
            "chat_username": channel,
            "user_id": str(message.from_id.user_id if message.from_id else ""),
            "username": "",
            "message_text": message.text,
            "message_date": message_date,  # Python datetime object
            "processed_date": processed_date,  # Python datetime object
            "channel_type": CHANNEL_METADATA.get(channel, {}).get("type", "unknown"),
            "channel_priority": CHANNEL_METADATA.get(channel, {}).get("priority", "medium")
        }
        
        # AI Analysis (if Gemini available)
        if _gemini_available:
            analysis = await analyze_message_with_gemini(message.text, channel)
            message_data.update(analysis)
        
        # Store in BigQuery
        await store_message_in_bigquery(message_data)
        
        logger.info(f"Processed message from {channel}: {message_data.get('threat_level', 'low')} threat")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")
        logger.error(f"Message: {getattr(message, 'text', 'No text')[:50]}...")

async def analyze_message_with_gemini(text: str, channel: str) -> Dict[str, Any]:
    """Analyze message with Gemini AI for cybersecurity threats with enhanced data extraction"""
    try:
        if not _gemini_model:
            logger.warning("Gemini AI not available, using fallback analysis")
            return _get_enhanced_fallback_analysis(text, channel)
        
        channel_context = CHANNEL_METADATA.get(channel, {})
        
        # Enhanced prompt for better structured analysis
        prompt = f"""
        Analyze this cybersecurity message from {channel} and provide a JSON response:

        Message: "{text}"

        Return ONLY valid JSON in this exact format:
        {{
            "threat_level": "critical|high|medium|low|info",
            "category": "apt|malware|ransomware|data_breach|vulnerability|phishing|other",
            "threat_type": "brief description",
            "urgency_score": 0.9,
            "sentiment": "positive|negative|neutral",
            "gemini_analysis": "2-3 sentence professional threat analysis summary without technical jargon",
            "key_topics": ["topic1", "topic2", "topic3"],
            "cve_references": ["CVE-2024-1234"],
            "iocs_detected": ["malicious-domain.com", "192.168.1.1"],
            "threat_actors": ["actor_name"],
            "affected_systems": ["Windows", "Linux"],
            "references": ["https://example.com/report"],
            "mitigation": "Brief mitigation advice"
        }}

        Focus on actionable cybersecurity intelligence. If no specific threats, mark as "info" level.
        """
        
        try:
            response = await asyncio.to_thread(_gemini_model.generate_content, prompt)
            
            if response and response.text:
                # Clean and parse JSON response
                response_text = response.text.strip()
                
                # Remove markdown code blocks if present
                if response_text.startswith('```'):
                    response_text = response_text.split('\n', 1)[1]
                if response_text.endswith('```'):
                    response_text = response_text.rsplit('\n', 1)[0]
                
                # Remove any "json" prefix
                if response_text.startswith('json'):
                    response_text = response_text[4:].strip()
                
                try:
                    analysis = json.loads(response_text)
                    
                    # Validate and enhance the analysis
                    analysis = _validate_and_enhance_analysis(analysis, text, channel)
                    
                    logger.info(f"✅ Gemini analysis: {analysis.get('threat_level', 'unknown')} - {analysis.get('category', 'other')}")
                    return analysis
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Gemini response not valid JSON: {e}")
                    logger.warning(f"Response: {response_text[:200]}...")
                    
                    # Extract useful information from text response
                    return _parse_text_response(response_text, text, channel)
            else:
                logger.warning("Gemini returned empty response")
                return _get_enhanced_fallback_analysis(text, channel)
                
        except Exception as api_error:
            logger.error(f"Gemini API call failed: {api_error}")
            return _get_enhanced_fallback_analysis(text, channel)
        
    except Exception as e:
        logger.error(f"Message analysis failed: {e}")
        return _get_enhanced_fallback_analysis(text, channel)

def _validate_and_enhance_analysis(analysis: Dict[str, Any], text: str, channel: str) -> Dict[str, Any]:
    """Validate and enhance Gemini analysis with extracted data"""
    
    # Ensure required fields exist with defaults
    enhanced = {
        "threat_level": analysis.get("threat_level", "low"),
        "category": analysis.get("category", "other"),
        "threat_type": analysis.get("threat_type", "unknown"),
        "urgency_score": float(analysis.get("urgency_score", 0.1)),
        "sentiment": analysis.get("sentiment", "neutral"),
        "gemini_analysis": analysis.get("gemini_analysis", "Analysis generated by Gemini AI"),
        "key_topics": analysis.get("key_topics", []),
        "cve_references": analysis.get("cve_references", []),
        "iocs_detected": analysis.get("iocs_detected", []),
        "threat_actors": analysis.get("threat_actors", []),
        "affected_systems": analysis.get("affected_systems", []),
        "references": analysis.get("references", []),
        "mitigation": analysis.get("mitigation", "")
    }
    
    # Enhance with extracted data from text
    extracted_data = _extract_enhanced_data(text)
    
    # Merge extracted data with Gemini analysis
    if extracted_data["cve_references"] and not enhanced["cve_references"]:
        enhanced["cve_references"] = extracted_data["cve_references"]
    
    if extracted_data["urls"] and not enhanced["references"]:
        enhanced["references"] = extracted_data["urls"]
    
    if extracted_data["iocs"] and not enhanced["iocs_detected"]:
        enhanced["iocs_detected"] = extracted_data["iocs"]
    
    # Add extracted data fields
    enhanced.update({
        "urls_extracted": extracted_data["urls"],
        "domains_extracted": extracted_data["domains"],
        "ip_addresses": extracted_data["ip_addresses"],
        "file_hashes": extracted_data["file_hashes"],
        "malware_families": extracted_data["malware_families"]
    })
    
    # Validate urgency score
    if enhanced["urgency_score"] > 1.0:
        enhanced["urgency_score"] = 1.0
    elif enhanced["urgency_score"] < 0.0:
        enhanced["urgency_score"] = 0.0
    
    return enhanced

def _parse_text_response(response_text: str, text: str, channel: str) -> Dict[str, Any]:
    """Parse non-JSON Gemini responses and extract useful information"""
    
    # Get basic analysis
    analysis = _get_enhanced_fallback_analysis(text, channel)
    
    # Try to extract information from the text response
    response_lower = response_text.lower()
    
    # Extract threat level from text
    if any(word in response_lower for word in ['critical', 'severe', 'urgent']):
        analysis["threat_level"] = "critical"
    elif any(word in response_lower for word in ['high', 'important', 'significant']):
        analysis["threat_level"] = "high"
    elif any(word in response_lower for word in ['medium', 'moderate']):
        analysis["threat_level"] = "medium"
    
    # Use text response as analysis
    analysis["gemini_analysis"] = response_text[:500] + "..." if len(response_text) > 500 else response_text
    
    return analysis

def _get_enhanced_fallback_analysis(text: str, channel: str) -> Dict[str, Any]:
    """Enhanced fallback analysis with comprehensive data extraction"""
    
    # Extract comprehensive data
    extracted_data = _extract_enhanced_data(text)
    
    # Generate analysis
    analysis = {
        "gemini_analysis": _generate_enhanced_analysis(text, channel, extracted_data),
        "threat_level": _detect_threat_level(text, channel),
        "category": _detect_category(text, channel),
        "threat_type": _detect_threat_type(text, channel),
        "urgency_score": _calculate_urgency(text, channel),
        "sentiment": _detect_sentiment(text),
        "key_topics": _extract_keywords(text, channel),
        
        # Enhanced extracted data
        "cve_references": extracted_data["cve_references"],
        "iocs_detected": extracted_data["iocs"],
        "urls_extracted": extracted_data["urls"],
        "domains_extracted": extracted_data["domains"],
        "ip_addresses": extracted_data["ip_addresses"],
        "file_hashes": extracted_data["file_hashes"],
        "malware_families": extracted_data["malware_families"],
        "threat_actors": extracted_data["threat_actors"],
        "affected_systems": extracted_data["affected_systems"],
        "references": extracted_data["urls"][:3],  # Top 3 URLs as references
        "mitigation": _generate_mitigation_advice(text, channel)
    }
    
    return analysis

def _extract_enhanced_data(text: str) -> Dict[str, List[str]]:
    """Extract comprehensive cybersecurity data from text"""
    import re
    
    extracted = {
        "cve_references": [],
        "urls": [],
        "domains": [],
        "ip_addresses": [],
        "file_hashes": [],
        "malware_families": [],
        "threat_actors": [],
        "affected_systems": [],
        "iocs": []
    }
    
    # CVE references
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    extracted["cve_references"] = re.findall(cve_pattern, text, re.IGNORECASE)
    
    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    extracted["urls"] = re.findall(url_pattern, text)
    
    # IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    # Filter out obviously invalid IPs
    extracted["ip_addresses"] = [ip for ip in ips if not ip.startswith(('0.', '255.', '127.'))]
    
    # Domain names
    domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
    domains = re.findall(domain_pattern, text)
    # Filter common legitimate domains
    excluded_domains = ['google.com', 'microsoft.com', 'apple.com', 'github.com', 'twitter.com', 'facebook.com']
    extracted["domains"] = ['.'.join(domain) for domain in domains 
                           if '.'.join(domain) not in excluded_domains][:5]
    
    # File hashes (MD5, SHA1, SHA256)
    hash_patterns = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }
    
    for hash_type, pattern in hash_patterns.items():
        hashes = re.findall(pattern, text)
        extracted["file_hashes"].extend(hashes)
    
    # Malware families (common ones)
    malware_keywords = [
        'wannacry', 'petya', 'notpetya', 'ryuk', 'maze', 'lockbit', 'conti',
        'emotet', 'trickbot', 'qakbot', 'danabot', 'formbook', 'remcos',
        'cobalt strike', 'metasploit', 'mimikatz', 'powershell empire'
    ]
    
    text_lower = text.lower()
    extracted["malware_families"] = [malware for malware in malware_keywords 
                                   if malware in text_lower]
    
    # Threat actors/groups
    threat_actor_keywords = [
        'lazarus', 'apt1', 'apt28', 'apt29', 'apt40', 'carbanak', 'fin7',
        'sandworm', 'turla', 'kimsuky', 'darkhydrus', 'muddywater'
    ]
    
    extracted["threat_actors"] = [actor for actor in threat_actor_keywords 
                                if actor in text_lower]
    
    # Affected systems
    system_keywords = [
        'windows', 'linux', 'macos', 'android', 'ios', 'docker', 'kubernetes',
        'apache', 'nginx', 'iis', 'mysql', 'postgresql', 'mongodb'
    ]
    
    extracted["affected_systems"] = [system for system in system_keywords 
                                   if system in text_lower]
    
    # Combine IOCs
    extracted["iocs"] = (extracted["ip_addresses"] + 
                        extracted["domains"] + 
                        extracted["file_hashes"][:3])[:10]  # Limit to 10 total
    
    return extracted

def _generate_enhanced_analysis(text: str, channel: str, extracted_data: Dict) -> str:
    """Generate enhanced threat analysis summary"""
    
    threat_level = _detect_threat_level(text, channel)
    category = _detect_category(text, channel)
    
    analysis_parts = []
    
    # Main threat assessment
    if threat_level == "critical":
        analysis_parts.append(f"Critical {category} threat detected requiring immediate attention.")
    elif threat_level == "high":
        analysis_parts.append(f"High-priority {category} identified.")
    else:
        analysis_parts.append(f"{category.title()} intelligence from {channel}.")
    
    # Add specific details based on extracted data
    if extracted_data["cve_references"]:
        analysis_parts.append(f"References {len(extracted_data['cve_references'])} CVE vulnerabilities.")
    
    if extracted_data["malware_families"]:
        families = ", ".join(extracted_data["malware_families"][:2])
        analysis_parts.append(f"Associated with {families} malware.")
    
    if extracted_data["threat_actors"]:
        actors = ", ".join(extracted_data["threat_actors"][:2])
        analysis_parts.append(f"Linked to {actors} threat groups.")
    
    if extracted_data["affected_systems"]:
        systems = ", ".join(extracted_data["affected_systems"][:3])
        analysis_parts.append(f"Affects {systems} systems.")
    
    # Add context based on content
    text_lower = text.lower()
    if any(word in text_lower for word in ['patch', 'update', 'fix']):
        analysis_parts.append("Remediation information available.")
    
    if any(word in text_lower for word in ['exploit', 'proof of concept', 'poc']):
        analysis_parts.append("Exploitation details present.")
    
    if extracted_data["urls"]:
        analysis_parts.append(f"Includes {len(extracted_data['urls'])} reference links.")
    
    return " ".join(analysis_parts)

def _generate_mitigation_advice(text: str, channel: str) -> str:
    """Generate basic mitigation advice based on content"""
    
    text_lower = text.lower()
    advice = []
    
    if 'vulnerability' in text_lower or 'cve-' in text_lower:
        advice.append("Apply security patches immediately.")
    
    if any(word in text_lower for word in ['malware', 'trojan', 'backdoor']):
        advice.append("Update antivirus signatures and scan systems.")
    
    if 'breach' in text_lower or 'leak' in text_lower:
        advice.append("Monitor for credential exposure and reset passwords.")
    
    if 'phishing' in text_lower:
        advice.append("Increase user awareness and email filtering.")
    
    if 'ransomware' in text_lower:
        advice.append("Verify backup integrity and network segmentation.")
    
    if not advice:
        advice.append("Follow standard security best practices.")
    
    return " ".join(advice)

def _get_fallback_analysis(text: str, channel: str) -> Dict[str, Any]:
    """Provide basic cybersecurity analysis when Gemini AI is unavailable (legacy compatibility)"""
    return _get_enhanced_fallback_analysis(text, channel)

def _detect_threat_level(text: str, channel: str) -> str:
    """Detect threat level based on keywords"""
    text_lower = text.lower()
    
    # Critical indicators
    critical_words = ['critical', 'urgent', 'immediate', 'emergency', 'zero-day', 'exploit', 'ransomware', 'breach']
    if any(word in text_lower for word in critical_words):
        return "critical"
    
    # High indicators
    high_words = ['high', 'severe', 'important', 'vulnerability', 'malware', 'attack', 'compromise']
    if any(word in text_lower for word in high_words):
        return "high"
    
    # Medium indicators
    medium_words = ['medium', 'moderate', 'warning', 'advisory', 'patch', 'update']
    if any(word in text_lower for word in medium_words):
        return "medium"
    
    return "low"

def _detect_category(text: str, channel: str) -> str:
    """Detect threat category based on content and channel"""
    text_lower = text.lower()
    
    # Category detection based on keywords
    if any(word in text_lower for word in ['apt', 'advanced persistent', 'nation state']):
        return "apt"
    elif any(word in text_lower for word in ['ransomware', 'crypto', 'encrypt']):
        return "ransomware"
    elif any(word in text_lower for word in ['breach', 'leak', 'stolen', 'database', 'credential']):
        return "data_breach"
    elif any(word in text_lower for word in ['malware', 'trojan', 'virus', 'backdoor']):
        return "malware"
    elif any(word in text_lower for word in ['vulnerability', 'cve-', 'patch', 'exploit']):
        return "vulnerability"
    elif any(word in text_lower for word in ['phishing', 'scam', 'social engineering']):
        return "phishing"
    
    # Category based on channel
    channel_meta = CHANNEL_METADATA.get(channel, {})
    if channel_meta.get('focus') == 'data_breaches':
        return "data_breach"
    elif channel_meta.get('focus') == 'advanced_persistent_threats':
        return "apt"
    elif channel_meta.get('focus') == 'security_updates':
        return "vulnerability"
    
    return "other"

def _detect_threat_type(text: str, channel: str) -> str:
    """Detect specific threat type"""
    text_lower = text.lower()
    
    threat_types = {
        'ransomware': ['ransomware', 'crypto locker', 'encrypt'],
        'apt': ['apt', 'advanced persistent', 'nation state'],
        'malware': ['malware', 'trojan', 'virus', 'backdoor'],
        'phishing': ['phishing', 'spear phishing', 'social engineering'],
        'ddos': ['ddos', 'denial of service', 'botnet'],
        'data_breach': ['data breach', 'data leak', 'stolen database'],
        'vulnerability': ['vulnerability', 'exploit', 'zero-day']
    }
    
    for threat_type, keywords in threat_types.items():
        if any(keyword in text_lower for keyword in keywords):
            return threat_type
    
    return "unknown"

def _calculate_urgency(text: str, channel: str) -> float:
    """Calculate urgency score based on content and channel"""
    score = 0.1  # Base score
    
    text_lower = text.lower()
    
    # Urgency keywords
    urgency_multipliers = {
        'critical': 0.4,
        'urgent': 0.3,
        'immediate': 0.3,
        'emergency': 0.4,
        'zero-day': 0.5,
        'exploit': 0.3,
        'active': 0.2,
        'widespread': 0.2,
        'severe': 0.2
    }
    
    for word, multiplier in urgency_multipliers.items():
        if word in text_lower:
            score += multiplier
    
    # Channel multiplier
    channel_meta = CHANNEL_METADATA.get(channel, {})
    channel_multiplier = channel_meta.get('threat_multiplier', 1.0)
    score *= channel_multiplier
    
    return min(score, 1.0)  # Cap at 1.0

def _detect_sentiment(text: str) -> str:
    """Basic sentiment detection"""
    text_lower = text.lower()
    
    negative_words = ['critical', 'severe', 'dangerous', 'urgent', 'threat', 'attack', 'breach']
    positive_words = ['fixed', 'patched', 'resolved', 'secured', 'protected']
    
    negative_count = sum(1 for word in negative_words if word in text_lower)
    positive_count = sum(1 for word in positive_words if word in text_lower)
    
    if negative_count > positive_count:
        return "negative"
    elif positive_count > negative_count:
        return "positive"
    
    return "neutral"

def _extract_keywords(text: str, channel: str) -> List[str]:
    """Extract cybersecurity keywords"""
    keywords = []
    text_lower = text.lower()
    
    cyber_keywords = [
        'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing',
        'apt', 'breach', 'leak', 'patch', 'update', 'threat', 'attack'
    ]
    
    for keyword in cyber_keywords:
        if keyword in text_lower:
            keywords.append(keyword)
    
    return keywords[:5]  # Return top 5

def _extract_cves(text: str) -> List[str]:
    """Extract CVE references from text (legacy compatibility)"""
    return _extract_enhanced_data(text)["cve_references"]

def _extract_iocs(text: str) -> List[str]:
    """Extract basic Indicators of Compromise (legacy compatibility)"""
    return _extract_enhanced_data(text)["iocs"]

def _extract_malware(text: str) -> List[str]:
    """Extract malware family names (legacy compatibility)"""
    return _extract_enhanced_data(text)["malware_families"]

async def store_message_in_bigquery(message_data: Dict[str, Any]):
    """Store processed message in BigQuery with enhanced data and proper schema handling"""
    try:
        if not _bigquery_available:
            return
        
        table_ref = _bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = _bq_client.get_table(table_ref)
        
        # Helper function to convert datetime objects
        def convert_datetime(dt):
            if dt is None:
                return None
            if isinstance(dt, datetime):
                return dt.isoformat()
            if hasattr(dt, 'timestamp'):  # Telegram date objects
                return datetime.fromtimestamp(dt.timestamp()).isoformat()
            return str(dt)
        
        # Get existing schema field names for compatibility
        existing_fields = {field.name for field in table.schema}
        
        # Base row with required fields
        row = {
            "message_id": str(message_data.get("message_id", "")),
            "chat_id": str(message_data.get("chat_id", "")),
            "chat_username": message_data.get("chat_username", ""),
            "user_id": str(message_data.get("user_id", "")),
            "username": message_data.get("username", ""),
            "message_text": message_data.get("message_text", ""),
            "message_date": convert_datetime(message_data.get("message_date")),
            "processed_date": convert_datetime(message_data.get("processed_date")),
        }
        
        # Enhanced analysis fields - only add if they exist in schema
        enhanced_fields = {
            "gemini_analysis": message_data.get("gemini_analysis", ""),
            "sentiment": message_data.get("sentiment", "neutral"),
            "key_topics": message_data.get("key_topics", []),
            "urgency_score": float(message_data.get("urgency_score", 0.0)),
            "category": message_data.get("category", "other"),
            "threat_level": message_data.get("threat_level", "low"),
            "threat_type": message_data.get("threat_type", "unknown"),
            "channel_type": message_data.get("channel_type", "unknown"),
            "channel_priority": message_data.get("channel_priority", "medium"),
            
            # Standard cybersecurity fields
            "iocs_detected": message_data.get("iocs_detected", message_data.get("iocs", [])),
            "cve_references": message_data.get("cve_references", []),
            "malware_families": message_data.get("malware_families", []),
            "affected_systems": message_data.get("affected_systems", []),
            
            # Extended fields (may not exist in older schemas)
            "attack_vectors": message_data.get("attack_vectors", []),
            "threat_actors": message_data.get("threat_actors", []),
            "campaign_names": message_data.get("campaign_names", []),
            "geographical_targets": message_data.get("geographical_targets", []),
            "industry_targets": message_data.get("industry_targets", []),
        }
        
        # Only add fields that exist in the table schema
        for field_name, field_value in enhanced_fields.items():
            if field_name in existing_fields:
                row[field_name] = field_value
        
        # Store enhanced extracted data in appropriate fields if they exist
        if "iocs_detected" in existing_fields and message_data.get("urls_extracted"):
            # Combine IOCs with URLs if there's room
            current_iocs = row.get("iocs_detected", [])
            urls = message_data.get("urls_extracted", [])[:2]  # Add up to 2 URLs
            row["iocs_detected"] = current_iocs + urls
        
        errors = _bq_client.insert_rows_json(table, [row])
        if errors:
            logger.error(f"BigQuery insert failed: {errors}")
            logger.error(f"Row data: {[(k, type(v).__name__) for k, v in row.items()]}")
        else:
            # Enhanced success logging
            cve_count = len(message_data.get("cve_references", []))
            ioc_count = len(message_data.get("iocs_detected", []))
            url_count = len(message_data.get("urls_extracted", []))
            
            extra_info = []
            if cve_count > 0:
                extra_info.append(f"{cve_count} CVEs")
            if ioc_count > 0:
                extra_info.append(f"{ioc_count} IOCs")
            if url_count > 0:
                extra_info.append(f"{url_count} URLs")
            
            extra_str = f" [{', '.join(extra_info)}]" if extra_info else ""
            
            logger.info(f"✅ Stored: {row['chat_username']} - {row.get('threat_level', 'low')} {row.get('category', 'other')}{extra_str}")
            
    except Exception as e:
        logger.error(f"BigQuery storage failed: {e}")
        logger.error(f"Available fields: {[field.name for field in table.schema] if 'table' in locals() else 'unknown'}")
        logger.error(f"Message data keys: {list(message_data.keys())}")

async def stop_monitoring_system():
    """Stop the monitoring system"""
    global _monitoring_active, _telegram_client
    
    try:
        _monitoring_active = False
        
        if _telegram_client:
            await _telegram_client.disconnect()
            _telegram_client = None
            _telegram_connected = False
        
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
        
        # Add authentication status
        if not _telegram_connected:
            status["authentication_required"] = True
            status["auth_message"] = "Run authentication script: python local_auth.py"
        
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
