import os
import json
import logging
import time
import tempfile
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
from google.cloud import bigquery
from google.cloud import secretmanager
from google.cloud import storage
from google.api_core import exceptions as gcp_exceptions
import google.generativeai as genai

# Configure logging
logger = logging.getLogger(__name__)

# Initialize clients with error handling
bq_client = None
secret_client = None
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

# CIPHER Cybersecurity Intelligence Channels
MONITORED_CHANNELS = [
    "@DarkfeedNews",        # DARKFEED - Advanced Persistent Threats & Zero-days
    "@breachdetector",      # Breach Detection - Data leak monitoring & credential dumps
    "@secharvester",        # Security Harvester - CVE, patches, security advisories
]

# Enhanced channel metadata for threat intelligence analysis
CHANNEL_METADATA = {
    "@DarkfeedNews": {
        "type": "cyber_threat_intelligence",
        "priority": "critical",
        "focus": "advanced_persistent_threats",
        "threat_multiplier": 1.5,
        "keywords": ["apt", "malware", "ransomware", "zero-day", "exploit", "breach", "attack", "campaign"],
        "description": "Premium threat intelligence feed focusing on APTs and zero-day exploits"
    },
    "@breachdetector": {
        "type": "data_breach_monitor", 
        "priority": "high",
        "focus": "data_breaches",
        "threat_multiplier": 1.3,
        "keywords": ["breach", "leak", "database", "stolen", "credentials", "dump", "exposure", "hack"],
        "description": "Real-time data breach and credential leak monitoring"
    },
    "@secharvester": {
        "type": "security_news",
        "priority": "medium", 
        "focus": "security_updates",
        "threat_multiplier": 1.0,
        "keywords": ["vulnerability", "cve", "patch", "security", "advisory", "update", "disclosure"],
        "description": "Security news, CVE tracking, and patch information"
    }
}

# Configuration constants
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
            try:
                bq_client = bigquery.Client(project=PROJECT_ID)
                # Test connection with a simple query
                query = f"SELECT 1 as test"
                query_job = bq_client.query(query)
                list(query_job.result())  # Force execution
                logger.info("BigQuery client initialized successfully")
            except Exception as e:
                logger.error(f"BigQuery client initialization failed: {e}")
                bq_client = None
            
            # Initialize Secret Manager client
            try:
                secret_client = secretmanager.SecretManagerServiceClient()
                logger.info("Secret Manager client initialized successfully")
            except Exception as e:
                logger.error(f"Secret Manager client initialization failed: {e}")
                secret_client = None
            
            # Initialize Storage client
            try:
                storage_client = storage.Client(project=PROJECT_ID)
                # Test connection
                list(storage_client.list_buckets(max_results=1))
                logger.info("Storage client initialized successfully")
            except Exception as e:
                logger.error(f"Storage client initialization failed: {e}")
                storage_client = None
            
            _clients_initialized = True
            logger.info("Google Cloud clients initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Cloud clients: {e}")
            return False

async def create_storage_bucket():
    """Create storage bucket if it doesn't exist"""
    try:
        if not storage_client:
            await initialize_clients()
        
        if not storage_client:
            logger.error("Storage client not available for bucket creation")
            return False
        
        try:
            # Check if bucket exists
            bucket = storage_client.bucket(BUCKET_NAME)
            bucket.reload()
            logger.info(f"Storage bucket {BUCKET_NAME} already exists")
            return True
        except gcp_exceptions.NotFound:
            # Create bucket
            logger.info(f"Creating storage bucket: {BUCKET_NAME}")
            bucket = storage_client.bucket(BUCKET_NAME)
            bucket.storage_class = "STANDARD"
            bucket.location = "US"
            
            bucket = storage_client.create_bucket(bucket, timeout=30)
            logger.info(f"Created storage bucket: {BUCKET_NAME}")
            return True
        except Exception as e:
            logger.error(f"Error checking/creating bucket: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create storage bucket: {e}")
        return False

async def get_secret(secret_id: str) -> Optional[str]:
    """Get secret from Secret Manager with retries and validation"""
    try:
        if not secret_client:
            await initialize_clients()
        
        if not secret_client:
            logger.error("Secret Manager client not available")
            return None
        
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        
        # Validate secret value
        if not secret_value or secret_value.startswith("REPLACE_WITH") or secret_value in ["YOUR_", "EXAMPLE_"]:
            logger.error(f"Secret {secret_id} contains invalid or placeholder value")
            return None
            
        logger.info(f"Successfully retrieved secret: {secret_id}")
        return secret_value
        
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        return None

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables with enhanced cybersecurity schema"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            raise Exception("BigQuery client not available")
        
        logger.info("Setting up BigQuery dataset and tables...")
        
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            dataset = bq_client.get_dataset(dataset_ref)
            logger.info(f"BigQuery dataset {DATASET_ID} already exists")
        except gcp_exceptions.NotFound:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "CIPHER Cybersecurity Intelligence Platform - Threat Intelligence Data"
            dataset = bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset {DATASET_ID}")

        # Enhanced cybersecurity schema for threat intelligence
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
            bigquery.SchemaField("gemini_analysis", "STRING", description="Gemini AI threat analysis summary"),
            bigquery.SchemaField("sentiment", "STRING", description="Message sentiment: positive/negative/neutral"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED", description="Key cybersecurity topics identified"),
            bigquery.SchemaField("urgency_score", "FLOAT", description="Threat urgency score (0.0-1.0)"),
            bigquery.SchemaField("category", "STRING", description="Threat category classification"),
            
            # Cybersecurity threat intelligence fields
            bigquery.SchemaField("threat_level", "STRING", description="Threat level: critical/high/medium/low/info"),
            bigquery.SchemaField("threat_type", "STRING", description="Specific threat type (e.g., APT, ransomware)"),
            bigquery.SchemaField("channel_type", "STRING", description="Source channel type"),
            bigquery.SchemaField("channel_priority", "STRING", description="Channel priority level"),
            bigquery.SchemaField("iocs_detected", "STRING", mode="REPEATED", description="Indicators of Compromise found"),
            bigquery.SchemaField("cve_references", "STRING", mode="REPEATED", description="CVE references mentioned"),
            bigquery.SchemaField("malware_families", "STRING", mode="REPEATED", description="Malware families identified"),
            bigquery.SchemaField("affected_systems", "STRING", mode="REPEATED", description="Systems/platforms affected"),
            
            # Advanced threat intelligence fields
            bigquery.SchemaField("attack_vectors", "STRING", mode="REPEATED", description="Attack vectors mentioned"),
            bigquery.SchemaField("threat_actors", "STRING", mode="REPEATED", description="Threat actors/groups mentioned"),
            bigquery.SchemaField("campaign_names", "STRING", mode="REPEATED", description="Campaign or operation names"),
            bigquery.SchemaField("geographical_targets", "STRING", mode="REPEATED", description="Geographic regions targeted"),
            bigquery.SchemaField("industry_targets", "STRING", mode="REPEATED", description="Industries targeted"),
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info(f"BigQuery table {TABLE_ID} already exists")
            
            # Check if schema needs updating
            existing_fields = {field.name for field in table.schema}
            new_fields = {field.name for field in schema}
            missing_fields = new_fields - existing_fields
            
            if missing_fields:
                logger.info(f"Table schema will be updated with new fields: {missing_fields}")
                
        except gcp_exceptions.NotFound:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "CIPHER Cybersecurity Intelligence Messages - Threat Intelligence Data"
            
            # Add partitioning and clustering for optimal performance
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="processed_date"
            )
            table.clustering_fields = ["threat_level", "channel_type", "category", "threat_type"]
            
            table = bq_client.create_table(table, timeout=30)
            logger.info(f"Created partitioned and clustered BigQuery table {TABLE_ID}")

        logger.info("BigQuery setup completed successfully")

    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def initialize_gemini():
    """Initialize Gemini AI for cybersecurity analysis"""
    global gemini_model
    try:
        logger.info("Initializing Gemini AI for cybersecurity analysis...")
        
        # Get Gemini API key
        api_key = await get_secret("gemini-api-key")
        if not api_key:
            raise Exception("Gemini API key not available")
        
        # Configure Gemini with optimized settings for cybersecurity
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=genai.GenerationConfig(
                temperature=0.1,  # Low temperature for consistent analysis
                top_p=0.8,
                max_output_tokens=1000,
                candidate_count=1,
            )
        )
        
        # Test the model with cybersecurity prompt
        test_prompt = "Analyze this cybersecurity test message and return JSON with threat_level: 'low'"
        test_response = await asyncio.to_thread(
            gemini_model.generate_content, 
            test_prompt
        )
        
        if test_response.text:
            logger.info("Gemini AI initialized and tested successfully")
            return True
        else:
            raise Exception("Gemini test failed - no response")
            
    except Exception as e:
        logger.error(f"Failed to initialize Gemini AI: {e}")
        return False

async def download_session_from_storage() -> Optional[bytes]:
    """Download pre-authenticated Telegram session from Cloud Storage"""
    try:
        if not storage_client:
            await initialize_clients()
        
        if not storage_client:
            raise Exception("Storage client not available")
        
        # Ensure bucket exists
        await create_storage_bucket()
        
        logger.info(f"Downloading Telegram session from gs://{BUCKET_NAME}/{SESSION_NAME}.session")
        
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{SESSION_NAME}.session")
        
        if not blob.exists():
            logger.error("Telegram session file not found in Cloud Storage")
            logger.error("Please run the local authentication script first to create a session")
            return None
        
        session_data = blob.download_as_bytes()
        if not session_data:
            logger.error("Downloaded session file is empty")
            return None
        
        # Get metadata
        blob.reload()
        metadata = blob.metadata or {}
        phone = metadata.get('phone_number', 'unknown')
        logger.info(f"Telegram session downloaded successfully (phone: {phone})")
        
        return session_data
        
    except Exception as e:
        logger.error(f"Failed to download Telegram session: {e}")
        return None

async def initialize_telegram_client():
    """Initialize Telegram MTProto client with pre-authenticated session"""
    global telegram_client
    
    try:
        logger.info("Initializing Telegram MTProto client...")
        
        # Import Telethon here to avoid startup delay
        from telethon import TelegramClient, events
        from telethon.errors import (
            AuthKeyUnregisteredError, UserDeactivatedError, UnauthorizedError,
            FloodWaitError, ChannelPrivateError, UsernameNotOccupiedError
        )
        
        # Get MTProto credentials
        api_id_str = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        
        if not api_id_str or not api_hash:
            raise Exception("Telegram API credentials not available")
        
        try:
            api_id = int(api_id_str)
        except ValueError:
            raise Exception(f"Invalid API ID format: {api_id_str}")
        
        logger.info(f"Using Telegram API ID: {api_id}")
        
        # Download pre-authenticated session
        session_data = await download_session_from_storage()
        if not session_data:
            raise Exception("No authenticated session available")
        
        # Create temporary session file
        temp_dir = tempfile.gettempdir()
        session_path = os.path.join(temp_dir, f"{SESSION_NAME}.session")
        
        with open(session_path, 'wb') as f:
            f.write(session_data)
        
        logger.info(f"Created temporary session file: {session_path}")
        
        # Create Telegram client
        telegram_client = TelegramClient(
            session_path,
            api_id, 
            api_hash,
            timeout=30,
            retry_delay=2,
            auto_reconnect=True,
            connection_retries=5
        )
        
        # Connect with timeout
        logger.info("Connecting to Telegram...")
        await asyncio.wait_for(telegram_client.connect(), timeout=30)
        
        # Verify authorization
        is_authorized = await telegram_client.is_user_authorized()
        if not is_authorized:
            raise Exception("Telegram session not authorized - may have expired")
        
        # Get user info
        me = await telegram_client.get_me()
        logger.info(f"Telegram client connected successfully: {me.username or me.first_name} (ID: {me.id})")
        
        # Start monitoring channels for new messages
        await start_channel_monitoring()
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize Telegram client: {e}")
        if telegram_client:
            try:
                await telegram_client.disconnect()
            except:
                pass
            telegram_client = None
        return False

async def start_channel_monitoring():
    """Start monitoring cybersecurity channels for new messages"""
    if not telegram_client:
        logger.error("Telegram client not available for monitoring")
        return False
    
    try:
        from telethon import events
        
        logger.info("Starting cybersecurity channel monitoring...")
        
        # Event handler for new messages
        @telegram_client.on(events.NewMessage)
        async def handle_new_message(event):
            try:
                # Check if message is from a monitored channel
                chat = await event.get_chat()
                if hasattr(chat, 'username') and f"@{chat.username}" in MONITORED_CHANNELS:
                    logger.info(f"New message from {chat.username}: processing...")
                    await process_message(event)
                    
            except Exception as e:
                logger.error(f"Error handling new message: {e}")
        
        # Get recent messages from monitored channels
        for channel_username in MONITORED_CHANNELS:
            try:
                logger.info(f"Fetching recent messages from {channel_username}...")
                
                # Get entity
                entity = await telegram_client.get_entity(channel_username)
                
                # Get recent messages (last 24 hours)
                async for message in telegram_client.iter_messages(entity, limit=50):
                    if message.date and (datetime.now() - message.date.replace(tzinfo=None)) < timedelta(hours=24):
                        await process_message(message, entity)
                    
                logger.info(f"Processed recent messages from {channel_username}")
                await asyncio.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error processing channel {channel_username}: {e}")
        
        logger.info("Channel monitoring initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to start channel monitoring: {e}")
        return False

async def process_message(message, entity=None):
    """Process a cybersecurity message with AI analysis"""
    try:
        if not message.text:
            return
        
        # Get chat info
        if entity:
            chat = entity
        else:
            chat = await message.get_chat()
        
        chat_username = f"@{chat.username}" if hasattr(chat, 'username') else "Unknown"
        
        # Skip if not from monitored channels
        if chat_username not in MONITORED_CHANNELS:
            return
        
        logger.info(f"Processing message from {chat_username}")
        
        # Get channel metadata
        channel_metadata = CHANNEL_METADATA.get(chat_username, {})
        
        # Analyze with Gemini AI
        analysis = await analyze_with_gemini(message.text, chat_username, channel_metadata)
        
        # Extract indicators
        indicators = extract_cybersecurity_indicators(message.text)
        
        # Prepare data for BigQuery
        processed_data = {
            "message_id": str(message.id),
            "chat_id": str(chat.id),
            "chat_username": chat_username,
            "user_id": str(message.sender_id) if message.sender_id else None,
            "username": None,  # Will be filled if available
            "message_text": message.text[:10000],  # Limit text length
            "message_date": message.date.isoformat() if message.date else datetime.now().isoformat(),
            "processed_date": datetime.now().isoformat(),
            
            # AI analysis
            "gemini_analysis": analysis.get("gemini_analysis", ""),
            "sentiment": analysis.get("sentiment", "neutral"),
            "key_topics": analysis.get("key_topics", []),
            "urgency_score": analysis.get("urgency_score", 0.0),
            "category": analysis.get("category", "other"),
            
            # Threat intelligence
            "threat_level": analysis.get("threat_level", "low"),
            "threat_type": analysis.get("threat_type", "unknown"),
            "channel_type": channel_metadata.get("type", "unknown"),
            "channel_priority": channel_metadata.get("priority", "medium"),
            "iocs_detected": indicators.get("ip_addresses", []) + indicators.get("domains", []) + indicators.get("file_hashes", []),
            "cve_references": indicators.get("cve_references", []),
            "malware_families": indicators.get("malware_families", []),
            "affected_systems": analysis.get("affected_systems", []),
            
            # Advanced fields
            "attack_vectors": indicators.get("attack_vectors", []) + analysis.get("attack_vectors", []),
            "threat_actors": indicators.get("threat_actors", []) + analysis.get("threat_actors", []),
            "campaign_names": indicators.get("campaign_names", []) + analysis.get("campaign_names", []),
            "geographical_targets": analysis.get("geographical_targets", []),
            "industry_targets": analysis.get("industry_targets", []),
        }
        
        # Insert into BigQuery
        await insert_to_bigquery(processed_data)
        
        logger.info(f"Successfully processed message from {chat_username} - Threat level: {analysis.get('threat_level', 'low')}")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")

async def insert_to_bigquery(data: Dict[str, Any]):
    """Insert processed message data into BigQuery"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            logger.error("BigQuery client not available")
            return False
        
        table_ref = bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = bq_client.get_table(table_ref)
        
        # Convert datetime strings to proper format
        if isinstance(data.get("message_date"), str):
            data["message_date"] = datetime.fromisoformat(data["message_date"].replace("Z", "+00:00"))
        if isinstance(data.get("processed_date"), str):
            data["processed_date"] = datetime.fromisoformat(data["processed_date"].replace("Z", "+00:00"))
        
        # Insert row
        errors = bq_client.insert_rows_json(table, [data])
        
        if errors:
            logger.error(f"BigQuery insert errors: {errors}")
            return False
        
        logger.info("Successfully inserted data into BigQuery")
        return True
        
    except Exception as e:
        logger.error(f"Failed to insert data into BigQuery: {e}")
        return False

def extract_cybersecurity_indicators(text: str) -> Dict[str, List[str]]:
    """Extract cybersecurity indicators and IOCs from message text"""
    indicators = {
        "cve_references": [],
        "ip_addresses": [],
        "domains": [],
        "file_hashes": [],
        "malware_families": [],
        "attack_vectors": [],
        "threat_actors": [],
        "campaign_names": []
    }
    
    try:
        # CVE pattern (CVE-YYYY-NNNN)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        indicators["cve_references"] = re.findall(cve_pattern, text, re.IGNORECASE)
        
        # IP addresses (IPv4)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        # Filter out obviously invalid IPs
        indicators["ip_addresses"] = [ip for ip in potential_ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
        
        # Domain names
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,6})\b'
        potential_domains = re.findall(domain_pattern, text)
        indicators["domains"] = [f"{domain[0]}.{domain[1]}" for domain in potential_domains]
        
        # File hashes (SHA256, MD5, SHA1)
        hash_patterns = [
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b'   # SHA1
        ]
        for pattern in hash_patterns:
            indicators["file_hashes"].extend(re.findall(pattern, text))
        
        # Common malware families and threat actors
        malware_keywords = [
            'ransomware', 'trojan', 'botnet', 'backdoor', 'rootkit', 'wiper', 'stealer', 
            'loader', 'dropper', 'rat', 'apt', 'lazarus', 'carbanak', 'fin7', 'conti',
            'lockbit', 'ryuk', 'emotet', 'trickbot', 'qakbot', 'cobalt strike'
        ]
        
        for keyword in malware_keywords:
            if keyword.lower() in text.lower():
                if 'apt' in keyword.lower() or any(actor in keyword.lower() for actor in ['lazarus', 'carbanak', 'fin']):
                    indicators["threat_actors"].append(keyword)
                else:
                    indicators["malware_families"].append(keyword)
        
        # Attack vectors
        attack_keywords = [
            'phishing', 'spear phishing', 'watering hole', 'supply chain', 'zero-day',
            'exploit kit', 'social engineering', 'brute force', 'credential stuffing',
            'sql injection', 'xss', 'rce', 'privilege escalation'
        ]
        
        for keyword in attack_keywords:
            if keyword.lower() in text.lower():
                indicators["attack_vectors"].append(keyword)
        
        # Campaign names (common patterns)
        campaign_patterns = [
            r'Operation\s+\w+',
            r'Campaign\s+\w+',
            r'\w+\s+Campaign',
            r'APT\d+',
            r'FIN\d+'
        ]
        
        for pattern in campaign_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["campaign_names"].extend(matches)
        
    except Exception as e:
        logger.error(f"Error extracting indicators: {e}")
    
    # Remove duplicates and return
    for key in indicators:
        indicators[key] = list(set(indicators[key]))
    
    return indicators

async def analyze_with_gemini(text: str, channel_username: str, channel_metadata: Dict) -> Dict[str, Any]:
    """Enhanced cybersecurity analysis using Gemini AI"""
    try:
        if not gemini_model:
            success = await initialize_gemini()
            if not success:
                return _get_fallback_analysis(text, channel_metadata)

        # Enhanced cybersecurity analysis prompt
        channel_type = channel_metadata.get("type", "unknown")
        channel_focus = channel_metadata.get("focus", "general")
        threat_multiplier = channel_metadata.get("threat_multiplier", 1.0)
        
        prompt = f"""
        You are an expert cybersecurity threat intelligence analyst. Analyze this message from {channel_username} ({channel_type}).

        Channel Context:
        - Type: {channel_type}
        - Focus: {channel_focus}
        - Trust Level: {threat_multiplier}

        Return analysis as valid JSON with these exact fields:
        {{
            "sentiment": "positive|negative|neutral",
            "key_topics": ["topic1", "topic2", "topic3"],
            "urgency_score": 0.7,
            "category": "threat_intel|data_breach|vulnerability|malware|ransomware|apt|phishing|other",
            "threat_level": "critical|high|medium|low|info",
            "threat_type": "specific_threat_description",
            "affected_systems": ["system1", "system2"],
            "attack_vectors": ["vector1", "vector2"],
            "threat_actors": ["actor1"],
            "campaign_names": ["campaign1"],
            "geographical_targets": ["region1"],
            "industry_targets": ["industry1"],
            "analysis": "Brief threat assessment in 2-3 sentences"
        }}

        Cybersecurity Analysis Guidelines:
        - threat_level: critical (active zero-days, major breaches), high (new vulns, active campaigns), medium (advisories, emerging threats), low (general info), info (educational)
        - urgency_score: 0.9-1.0 (immediate threats), 0.7-0.8 (critical vulns), 0.5-0.6 (medium threats), 0.1-0.4 (advisories), 0.0-0.1 (info)
        - category: Focus on cybersecurity - threat_intel for APT/campaigns, data_breach for breaches, vulnerability for CVEs, malware for malware analysis
        - Apply threat multiplier of {threat_multiplier} to urgency score
        - Extract specific threat actors, campaign names, affected regions/industries
        - Identify attack vectors and techniques

        Message to analyze: "{text[:2000]}"

        Return only valid JSON:
        """

        # Generate analysis with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                await rate_limit_check("gemini_analysis")
                
                response = await asyncio.to_thread(
                    gemini_model.generate_content, 
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        top_p=0.8,
                        max_output_tokens=1000,
                    )
                )
                
                if response.text:
                    break
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Gemini AI attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(2 ** attempt)
        
        # Parse JSON response
        response_text = response.text.strip()
        
        # Clean markdown formatting
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Parse and validate JSON
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Extract JSON from response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                result = json.loads(response_text[start:end])
            else:
                raise ValueError("No valid JSON found in Gemini response")
        
        # Validate and enhance the result
        analysis_result = {
            "gemini_analysis": str(result.get("analysis", "AI analysis completed"))[:1000],
            "sentiment": _validate_sentiment(result.get("sentiment", "neutral")),
            "key_topics": _validate_topics(result.get("key_topics", [])),
            "urgency_score": _validate_urgency(result.get("urgency_score", 0.0), threat_multiplier),
            "category": _validate_category(result.get("category", "other")),
            "threat_level": _validate_threat_level(result.get("threat_level", "low")),
            "threat_type": str(result.get("threat_type", "unknown"))[:200],
            "affected_systems": _validate_systems(result.get("affected_systems", [])),
            "attack_vectors": _validate_list_field(result.get("attack_vectors", []), 10),
            "threat_actors": _validate_list_field(result.get("threat_actors", []), 5),
            "campaign_names": _validate_list_field(result.get("campaign_names", []), 5),
            "geographical_targets": _validate_list_field(result.get("geographical_targets", []), 10),
            "industry_targets": _validate_list_field(result.get("industry_targets", []), 10)
        }
        
        logger.info(f"Gemini analysis completed: {analysis_result['threat_level']} threat, category: {analysis_result['category']}")
        return analysis_result

    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return _get_fallback_analysis(text, channel_metadata)

def _validate_sentiment(sentiment: str) -> str:
    """Validate sentiment value"""
    valid_sentiments = ["positive", "negative", "neutral"]
    sentiment = str(sentiment).lower().strip()
    return sentiment if sentiment in valid_sentiments else "neutral"

def _validate_topics(topics: List) -> List[str]:
    """Validate and clean topics"""
    if not isinstance(topics, list):
        return []
    cleaned_topics = []
    for topic in topics[:15]:  # Max 15 topics
        if isinstance(topic, str) and len(topic.strip()) > 0:
            cleaned_topics.append(str(topic).strip()[:100])
    return cleaned_topics

def _validate_urgency(urgency: Any, multiplier: float = 1.0) -> float:
    """Validate urgency score with channel multiplier"""
    try:
        score = float(urgency) * multiplier
        return max(0.0, min(1.0, score))
    except (ValueError, TypeError):
        return 0.0

def _validate_category(category: str) -> str:
    """Validate cybersecurity category"""
    valid_categories = [
        "threat_intel", "data_breach", "vulnerability", "malware", 
        "ransomware", "apt", "phishing", "other"
    ]
    category = str(category).lower().strip()
    return category if category in valid_categories else "other"

def _validate_threat_level(threat_level: str) -> str:
    """Validate threat level"""
    valid_levels = ["critical", "high", "medium", "low", "info"]
    threat_level = str(threat_level).lower().strip()
    return threat_level if threat_level in valid_levels else "low"

def _validate_systems(systems: List) -> List[str]:
    """Validate affected systems"""
    if not isinstance(systems, list):
        return []
    cleaned_systems = []
    for system in systems[:15]:
        if isinstance(system, str) and len(system.strip()) > 0:
            cleaned_systems.append(str(system).strip()[:100])
    return cleaned_systems

def _validate_list_field(field: List, max_items: int = 10) -> List[str]:
    """Validate list fields"""
    if not isinstance(field, list):
        return []
    cleaned_field = []
    for item in field[:max_items]:
        if isinstance(item, str) and len(item.strip()) > 0:
            cleaned_field.append(str(item).strip()[:100])
    return cleaned_field

def _get_fallback_analysis(text: str, channel_metadata: Dict) -> Dict[str, Any]:
    """Fallback analysis when Gemini fails"""
    text_lower = text.lower()
    
    # Enhanced keyword-based analysis
    threat_keywords = {
        "critical": ["zero-day", "0-day", "exploit", "breach", "ransomware", "apt", "critical"],
        "high": ["vulnerability", "malware", "attack", "compromise", "backdoor", "trojan"],
        "medium": ["security", "advisory", "patch", "update", "warning", "alert"],
        "low": ["information", "report", "analysis", "research", "news"]
    }
    
    threat_level = "low"
    urgency = 0.2
    category = "other"
    
    # Determine threat level and category
    for level, keywords in threat_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            threat_level = level
            if level == "critical":
                urgency = 0.9
                category = "threat_intel"
            elif level == "high":
                urgency = 0.7
                category = "malware"
            elif level == "medium":
                urgency = 0.5
                category = "vulnerability"
            break
    
    # Apply channel multiplier
    multiplier = channel_metadata.get("threat_multiplier", 1.0)
    urgency = min(1.0, urgency * multiplier)
    
    # Extract simple indicators
    indicators = extract_cybersecurity_indicators(text)
    
    return {
        "gemini_analysis": f"Fallback analysis: {len(text)} char message from {channel_metadata.get('type', 'unknown')} source. Automated threat assessment based on keywords.",
        "sentiment": "neutral",
        "key_topics": [],
        "urgency_score": urgency,
        "category": category,
        "threat_level": threat_level,
        "threat_type": f"Automated classification: {threat_level} threat",
        "affected_systems": [],
        "attack_vectors": indicators.get("attack_vectors", []),
        "threat_actors": indicators.get("threat_actors", []),
        "campaign_names": indicators.get("campaign_names", []),
        "geographical_targets": [],
        "industry_targets": []
    }

async def get_recent_insights(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent cybersecurity insights from BigQuery with enhanced error handling"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            logger.warning("BigQuery client not available for insights query")
            return []
        
        query = f"""
        SELECT 
            message_id,
            chat_username,
            chat_id,
            username,
            message_text,
            message_date,
            processed_date,
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
            affected_systems,
            attack_vectors,
            threat_actors,
            campaign_names,
            geographical_targets,
            industry_targets
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC, urgency_score DESC
        LIMIT {limit}
        OFFSET {offset}
        """
        
        query_job = bq_client.query(query, timeout=30)
        results = []
        
        for row in query_job:
            insight = {
                "message_id": row.message_id,
                "chat_username": row.chat_username or "Unknown",
                "chat_id": row.chat_id,
                "username": row.username or "Unknown",
                "message_text": row.message_text,
                "message_date": row.message_date.isoformat() if row.message_date else None,
                "processed_date": row.processed_date.isoformat() if row.processed_date else None,
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
                "affected_systems": list(getattr(row, 'affected_systems', [])),
                "attack_vectors": list(getattr(row, 'attack_vectors', [])),
                "threat_actors": list(getattr(row, 'threat_actors', [])),
                "campaign_names": list(getattr(row, 'campaign_names', [])),
                "geographical_targets": list(getattr(row, 'geographical_targets', [])),
                "industry_targets": list(getattr(row, 'industry_targets', []))
            }
            results.append(insight)
        
        logger.info(f"Retrieved {len(results)} cybersecurity insights from BigQuery")
        return results

    except Exception as e:
        logger.error(f"Failed to get cybersecurity insights: {e}")
        return []

async def get_message_stats() -> Dict[str, Any]:
    """Get comprehensive cybersecurity statistics with error handling"""
    try:
        if not bq_client:
            await initialize_clients()
        
        if not bq_client:
            logger.warning("BigQuery client not available for stats query")
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
            COUNT(CASE WHEN array_length(cve_references) > 0 THEN 1 END) as cve_mentions,
            COUNT(CASE WHEN category = 'apt' THEN 1 END) as apt_activity,
            COUNT(CASE WHEN category = 'ransomware' THEN 1 END) as ransomware_alerts,
            COUNT(CASE WHEN array_length(threat_actors) > 0 THEN 1 END) as attributed_threats
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
                    "apt_activity": int(getattr(row, 'apt_activity', 0)),
                    "ransomware_alerts": int(getattr(row, 'ransomware_alerts', 0)),
                    "attributed_threats": int(getattr(row, 'attributed_threats', 0)),
                }
            else:
                stats = _get_default_stats()
                
        except Exception as query_error:
            logger.error(f"BigQuery query failed: {query_error}")
            stats = _get_default_stats()
            stats["bigquery_error"] = "Query failed - using defaults"
        
        # Add monitoring status and metadata
        stats["monitoring_active"] = (
            telegram_client is not None and 
            telegram_client.is_connected() if telegram_client else False
        )
        stats["monitored_channels"] = len(MONITORED_CHANNELS)
        stats["last_updated"] = time.time()
        
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
        "apt_activity": 0,
        "ransomware_alerts": 0,
        "attributed_threats": 0,
        "monitoring_active": False,
        "monitored_channels": len(MONITORED_CHANNELS),
        "note": "Statistics will be available after BigQuery initialization"
    }

async def start_background_monitoring():
    """Start CIPHER cybersecurity monitoring system"""
    global _monitoring_task
    
    try:
        logger.info("🛡️ Starting CIPHER cybersecurity monitoring system...")
        
        # Initialize clients first
        await initialize_clients()
        
        # Create storage bucket if needed
        await create_storage_bucket()
        
        # Initialize Gemini AI
        gemini_success = await initialize_gemini()
        if not gemini_success:
            logger.warning("Gemini AI initialization failed - using fallback analysis")
        
        # Initialize Telegram client
        telegram_success = await initialize_telegram_client()
        if not telegram_success:
            logger.error("Telegram client initialization failed")
            return False
        
        logger.info("✅ CIPHER cybersecurity monitoring system started successfully")
        logger.info(f"📡 Monitoring channels: {', '.join(MONITORED_CHANNELS)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to start CIPHER monitoring: {e}")
        return False

async def stop_background_monitoring():
    """Stop CIPHER monitoring system"""
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
        
        logger.info("🛑 CIPHER cybersecurity monitoring stopped")
    except Exception as e:
        logger.error(f"Error stopping CIPHER monitoring: {e}")

# Export main functions for the application
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
