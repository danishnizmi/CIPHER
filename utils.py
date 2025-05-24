import os
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
import re
from google.cloud import bigquery
from google.cloud import secretmanager
from google.cloud import storage
import google.generativeai as genai
from telethon import TelegramClient, events, functions
from telethon.errors import (
    SessionPasswordNeededError, 
    PhoneCodeInvalidError, 
    FloodWaitError,
    ChannelPrivateError,
    UsernameNotOccupiedError,
    AuthKeyUnregisteredError,
    UserDeactivatedError,
    UnauthorizedError
)
from telethon.tl.types import Channel, Chat
import tempfile

logger = logging.getLogger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()
storage_client = storage.Client()

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")

# Session configuration
BUCKET_NAME = f"{PROJECT_ID}-telegram-sessions"
SESSION_NAME = "cipher_session"

# MTProto client
telegram_client = None
gemini_model = None
_monitoring_task = None

# Cybersecurity focused channels only
MONITORED_CHANNELS = [
    "@DarkfeedNews",        # DARKFEED - Cyber Threat Intelligence
    "@breachdetector",      # Data Leak Monitor - Threat detection
    "@secharvester",        # Security Harvester - Cybersecurity news
]

# Channel metadata for enhanced analysis
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

# Date limit - only process messages from the last 30 days
MESSAGE_DATE_LIMIT = timedelta(days=30)

# Rate limiting
_last_api_call = {}
_api_call_delay = 1.0  # Minimum delay between API calls

async def rate_limit_check(operation: str) -> None:
    """Implement rate limiting for API calls"""
    now = datetime.now()
    if operation in _last_api_call:
        time_diff = (now - _last_api_call[operation]).total_seconds()
        if time_diff < _api_call_delay:
            await asyncio.sleep(_api_call_delay - time_diff)
    _last_api_call[operation] = now

async def get_secret(secret_id: str) -> str:
    """Get secret from Secret Manager with validation"""
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        
        if not secret_value:
            raise ValueError(f"Secret {secret_id} is empty")
            
        logger.info(f"Successfully retrieved secret: {secret_id}")
        return secret_value
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        raise

async def download_session_from_storage() -> Optional[str]:
    """Download Telegram session from Cloud Storage"""
    try:
        logger.info(f"Downloading session from gs://{BUCKET_NAME}/{SESSION_NAME}.session")
        
        # Get bucket
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{SESSION_NAME}.session")
        
        # Check if session exists
        if not blob.exists():
            logger.error(f"Session file not found in Cloud Storage: gs://{BUCKET_NAME}/{SESSION_NAME}.session")
            logger.error("Please run the local authentication script first to upload a session")
            return None
        
        # Download session data
        session_data = blob.download_as_bytes()
        
        if not session_data:
            logger.error("Downloaded session file is empty")
            return None
        
        # Get metadata for logging
        blob.reload()
        metadata = blob.metadata or {}
        logger.info(f"Session downloaded successfully (created: {metadata.get('created_at', 'unknown')})")
        
        return session_data
        
    except Exception as e:
        logger.error(f"Failed to download session from Cloud Storage: {e}")
        return None

async def upload_session_to_storage(session_data: bytes) -> bool:
    """Upload updated session to Cloud Storage"""
    try:
        logger.info("Uploading updated session to Cloud Storage...")
        
        # Ensure bucket exists
        bucket = storage_client.bucket(BUCKET_NAME)
        try:
            bucket.reload()
        except:
            # Create bucket if it doesn't exist
            bucket = storage_client.create_bucket(BUCKET_NAME, location="US")
            logger.info(f"Created session storage bucket: {BUCKET_NAME}")
        
        # Upload session
        blob = bucket.blob(f"{SESSION_NAME}.session")
        blob.upload_from_string(session_data)
        
        # Update metadata
        blob.metadata = {
            "updated_by": "cipher_cloud_service",
            "updated_at": datetime.now().isoformat(),
            "session_type": "mtproto_authenticated"
        }
        blob.patch()
        
        logger.info("Session updated in Cloud Storage successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to upload session to Cloud Storage: {e}")
        return False

async def create_session_file(session_data: bytes) -> Optional[str]:
    """Create temporary session file from downloaded data"""
    try:
        # Create temporary file for session
        temp_dir = tempfile.gettempdir()
        session_path = os.path.join(temp_dir, f"{SESSION_NAME}.session")
        
        # Write session data to file
        with open(session_path, 'wb') as f:
            f.write(session_data)
        
        logger.info(f"Created temporary session file: {session_path}")
        return session_path
        
    except Exception as e:
        logger.error(f"Failed to create session file: {e}")
        return None

async def initialize_gemini():
    """Initialize Gemini AI with enhanced configuration for cybersecurity"""
    global gemini_model
    try:
        # Get Gemini API key from Secret Manager
        api_key = await get_secret("gemini-api-key")
        
        # Configure Gemini with optimized settings for cybersecurity analysis
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=genai.GenerationConfig(
                temperature=0.1,  # Low temperature for consistent analysis
                top_p=0.8,
                max_output_tokens=800,
                candidate_count=1,
            )
        )
        
        # Test the model with a cybersecurity prompt
        test_prompt = "Analyze this cybersecurity message and return JSON with threat_level: 'low'"
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

async def initialize_telegram_client():
    """Initialize Telegram MTProto client using pre-authenticated session from Cloud Storage"""
    global telegram_client
    
    try:
        logger.info("Initializing Telegram client with pre-authenticated session from Cloud Storage")
        
        # Get MTProto credentials from Secret Manager
        api_id_str = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        
        # Validate credentials
        try:
            api_id = int(api_id_str)
        except ValueError:
            raise ValueError(f"Invalid API ID format: {api_id_str}")
            
        if not api_hash or len(api_hash) < 10:
            raise ValueError("Invalid API hash format")
        
        logger.info(f"Using API ID: {api_id}")
        
        # Download session from Cloud Storage
        session_data = await download_session_from_storage()
        if not session_data:
            logger.error("Failed to download session from Cloud Storage")
            logger.error("Please run the local authentication script to create a session first")
            return False
        
        # Create temporary session file
        session_path = await create_session_file(session_data)
        if not session_path:
            logger.error("Failed to create session file")
            return False
        
        # Create client with the session file
        telegram_client = TelegramClient(
            session_path,  # Use the downloaded session file
            api_id, 
            api_hash,
            timeout=30,
            retry_delay=2,
            auto_reconnect=True,
            connection_retries=5
        )
        
        # Connect with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Connection attempt {attempt + 1}/{max_retries}")
                await telegram_client.connect()
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(5)
        
        # Check authorization status
        try:
            is_authorized = await telegram_client.is_user_authorized()
            if not is_authorized:
                logger.error("Session is not authorized - authentication may have expired")
                logger.error("Please run the local authentication script again to refresh the session")
                return False
            
            # Verify client is working by getting user info
            me = await telegram_client.get_me()
            logger.info(f"Successfully authenticated as: {me.username or me.first_name} (ID: {me.id})")
            
            # Update session in Cloud Storage if it changed
            try:
                updated_session = telegram_client.session.save()
                if updated_session and updated_session != session_data:
                    await upload_session_to_storage(updated_session)
            except Exception as e:
                logger.warning(f"Failed to update session in storage: {e}")
            
            logger.info("Telegram client initialized successfully")
            return True
            
        except (AuthKeyUnregisteredError, UserDeactivatedError, UnauthorizedError) as e:
            logger.error(f"Session authentication error: {e}")
            logger.error("The session may have expired or been revoked")
            logger.error("Please run the local authentication script again")
            return False
        
    except Exception as e:
        logger.error(f"Failed to initialize Telegram client: {e}")
        if telegram_client:
            try:
                await telegram_client.disconnect()
            except:
                pass
        return False

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables with cybersecurity schema"""
    try:
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            dataset = bq_client.get_dataset(dataset_ref)
            logger.info(f"Dataset {DATASET_ID} already exists")
        except Exception:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "CIPHER Cybersecurity Intelligence Platform"
            dataset = bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created dataset {DATASET_ID}")

        # Enhanced cybersecurity schema
        schema = [
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED", description="Unique message identifier"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED", description="Chat/channel identifier"), 
            bigquery.SchemaField("chat_username", "STRING", description="Channel username"),
            bigquery.SchemaField("user_id", "STRING", description="User identifier"),
            bigquery.SchemaField("username", "STRING", description="Username without @"),
            bigquery.SchemaField("message_text", "STRING", description="Original message text"),
            bigquery.SchemaField("message_date", "TIMESTAMP", mode="REQUIRED", description="When message was sent"),
            bigquery.SchemaField("processed_date", "TIMESTAMP", mode="REQUIRED", description="When message was processed"),
            
            # AI Analysis fields
            bigquery.SchemaField("gemini_analysis", "STRING", description="AI analysis summary"),
            bigquery.SchemaField("sentiment", "STRING", description="Sentiment: positive/negative/neutral"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED", description="Main topics identified"),
            bigquery.SchemaField("urgency_score", "FLOAT", description="Urgency score 0-1"),
            bigquery.SchemaField("category", "STRING", description="Message category"),
            
            # Cybersecurity specific fields
            bigquery.SchemaField("threat_level", "STRING", description="Threat level: critical/high/medium/low/info"),
            bigquery.SchemaField("threat_type", "STRING", description="Type of threat identified"),
            bigquery.SchemaField("channel_type", "STRING", description="Type of source channel"),
            bigquery.SchemaField("channel_priority", "STRING", description="Channel priority level"),
            bigquery.SchemaField("iocs_detected", "STRING", mode="REPEATED", description="Indicators of Compromise detected"),
            bigquery.SchemaField("cve_references", "STRING", mode="REPEATED", description="CVE references found"),
            bigquery.SchemaField("malware_families", "STRING", mode="REPEATED", description="Malware families mentioned"),
            bigquery.SchemaField("affected_systems", "STRING", mode="REPEATED", description="Systems/platforms affected"),
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info(f"Table {TABLE_ID} already exists")
            
            # Check if we need to add new columns
            existing_fields = {field.name for field in table.schema}
            new_fields = {field.name for field in schema}
            missing_fields = new_fields - existing_fields
            
            if missing_fields:
                logger.info(f"Table schema will be updated with new fields: {missing_fields}")
                
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
            logger.info(f"Created partitioned and clustered table {TABLE_ID}")

        logger.info("BigQuery setup completed successfully")

    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

def is_message_recent(message_date: datetime) -> bool:
    """Check if message is within our date limit (last 30 days)"""
    if not message_date:
        return False
    
    # Handle timezone-aware datetime
    if message_date.tzinfo is None:
        message_date = message_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
    
    cutoff_date = datetime.now().astimezone() - MESSAGE_DATE_LIMIT
    return message_date >= cutoff_date

def extract_cybersecurity_indicators(text: str) -> Dict[str, List[str]]:
    """Extract cybersecurity indicators from message text"""
    indicators = {
        "cve_references": [],
        "ip_addresses": [],
        "domains": [],
        "file_hashes": [],
        "malware_families": [],
        "attack_techniques": []
    }
    
    # CVE pattern
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    indicators["cve_references"] = re.findall(cve_pattern, text, re.IGNORECASE)
    
    # IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    indicators["ip_addresses"] = re.findall(ip_pattern, text)
    
    # Domain names (basic pattern)
    domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,6})\b'
    indicators["domains"] = re.findall(domain_pattern, text)
    
    # SHA256 hashes
    hash_pattern = r'\b[a-fA-F0-9]{64}\b'
    indicators["file_hashes"] = re.findall(hash_pattern, text)
    
    # Common malware families (expand as needed)
    malware_keywords = [
        'ransomware', 'trojan', 'botnet', 'backdoor', 'rootkit', 
        'wiper', 'stealer', 'loader', 'dropper', 'rat'
    ]
    for keyword in malware_keywords:
        if keyword.lower() in text.lower():
            indicators["malware_families"].append(keyword)
    
    return indicators

async def join_monitored_channels():
    """Join cybersecurity channels with enhanced error handling"""
    if not telegram_client:
        logger.error("Telegram client not initialized")
        return {"successful": 0, "failed": 0, "errors": []}
    
    successful_joins = 0
    failed_joins = 0
    errors = []
    
    for channel_username in MONITORED_CHANNELS:
        try:
            await rate_limit_check(f"get_entity_{channel_username}")
            
            # Try to get the channel entity
            entity = await telegram_client.get_entity(channel_username)
            
            if isinstance(entity, Channel):
                try:
                    # Try to join if not already joined
                    await rate_limit_check(f"join_{channel_username}")
                    await telegram_client(functions.channels.JoinChannelRequest(entity))
                    logger.info(f"Joined cybersecurity channel: {channel_username}")
                except Exception as join_error:
                    # Might already be joined or channel doesn't require joining
                    logger.info(f"Channel access confirmed: {channel_username} ({str(join_error)[:50]})")
            
            successful_joins += 1
            channel_info = CHANNEL_METADATA.get(channel_username, {})
            logger.info(f"Successfully accessing {channel_username} - Type: {channel_info.get('type', 'unknown')}")
            
        except FloodWaitError as e:
            wait_time = e.seconds
            logger.warning(f"Rate limited for {channel_username}, waiting {wait_time}s")
            await asyncio.sleep(wait_time + 1)
            errors.append(f"{channel_username}: Rate limited ({wait_time}s)")
            
        except (ChannelPrivateError, UsernameNotOccupiedError) as e:
            logger.error(f"Channel access error for {channel_username}: {e}")
            failed_joins += 1
            errors.append(f"{channel_username}: {type(e).__name__}")
            
        except Exception as e:
            logger.error(f"Unexpected error accessing {channel_username}: {e}")
            failed_joins += 1
            errors.append(f"{channel_username}: {str(e)[:50]}")
    
    result = {
        "successful": successful_joins,
        "failed": failed_joins, 
        "errors": errors
    }
    
    logger.info(f"Cybersecurity channel access summary: {successful_joins}/{len(MONITORED_CHANNELS)} successful")
    return result

@events.register(events.NewMessage)
async def handle_new_message(event):
    """Handle new messages from cybersecurity channels"""
    try:
        # Get message details
        message = event.message
        chat = await event.get_chat()
        sender = await event.get_sender()
        
        # Only process messages from monitored cybersecurity channels
        chat_username = getattr(chat, 'username', None)
        if chat_username:
            chat_username = f"@{chat_username}"
            if chat_username not in MONITORED_CHANNELS:
                return
        else:
            return
        
        # Check if message is recent (within last 30 days)
        if not is_message_recent(message.date):
            logger.debug(f"Skipping old message from {chat_username}")
            return
        
        # Extract message data
        message_id = str(message.id)
        chat_id = str(chat.id)
        user_id = str(sender.id) if sender else ""
        username = getattr(sender, 'username', '') if sender else ""
        text = message.text or ""
        message_date = message.date
        
        # Skip if no text content or too short
        if not text or len(text.strip()) < 10:
            logger.debug(f"Skipping message {message_id} - insufficient content")
            return

        logger.info(f"Processing cybersecurity message {message_id} from {chat_username}")

        # Extract cybersecurity indicators
        indicators = extract_cybersecurity_indicators(text)
        
        # Get channel metadata
        channel_metadata = CHANNEL_METADATA.get(chat_username, {})
        
        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text, chat_username, channel_metadata)
        
        # Prepare enhanced data for storage
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "chat_username": chat_username,
            "user_id": user_id,
            "username": username,
            "message_text": text[:4000],  # Limit length
            "message_date": message_date,
            "processed_date": datetime.now(),
            "channel_type": channel_metadata.get("type", "unknown"),
            "channel_priority": channel_metadata.get("priority", "medium"),
            "iocs_detected": indicators.get("ip_addresses", []) + indicators.get("domains", []) + indicators.get("file_hashes", []),
            "cve_references": indicators.get("cve_references", []),
            "malware_families": indicators.get("malware_families", []),
            "affected_systems": [],  # Will be populated by AI analysis
            **analysis_result
        }
        
        # Store in BigQuery
        await store_processed_message(message_data)
        
        logger.info(f"Successfully processed cybersecurity message {message_id} - Threat Level: {analysis_result.get('threat_level', 'unknown')}")

    except Exception as e:
        logger.error(f"Error handling cybersecurity message: {e}")

async def fetch_recent_cybersecurity_history():
    """Fetch recent messages from cybersecurity channels (last 30 days)"""
    if not telegram_client:
        logger.error("Telegram client not initialized")
        return 0
    
    cutoff_date = datetime.now() - MESSAGE_DATE_LIMIT
    processed_count = 0
    
    for channel_username in MONITORED_CHANNELS:
        try:
            logger.info(f"Fetching recent history from cybersecurity channel: {channel_username}")
            
            await rate_limit_check(f"history_{channel_username}")
            entity = await telegram_client.get_entity(channel_username)
            channel_metadata = CHANNEL_METADATA.get(channel_username, {})
            
            # Fetch messages with rate limiting
            message_count = 0
            async for message in telegram_client.iter_messages(
                entity, 
                offset_date=cutoff_date,
                limit=200  # Reasonable limit per channel
            ):
                # Check if message is too old
                if not is_message_recent(message.date):
                    break
                
                # Skip messages without text
                if not message.text or len(message.text.strip()) < 10:
                    continue
                
                try:
                    # Process the historical message
                    chat_id = str(entity.id)
                    message_id = str(message.id)
                    user_id = str(message.sender_id) if message.sender_id else ""
                    text = message.text
                    
                    logger.debug(f"Processing historical message {message_id} from {channel_username}")
                    
                    # Extract indicators
                    indicators = extract_cybersecurity_indicators(text)
                    
                    # Analyze with Gemini
                    analysis_result = await analyze_with_gemini(text, channel_username, channel_metadata)
                    
                    # Prepare data
                    message_data = {
                        "message_id": message_id,
                        "chat_id": chat_id,
                        "chat_username": channel_username,
                        "user_id": user_id,
                        "username": "",
                        "message_text": text[:4000],
                        "message_date": message.date,
                        "processed_date": datetime.now(),
                        "channel_type": channel_metadata.get("type", "unknown"),
                        "channel_priority": channel_metadata.get("priority", "medium"),
                        "iocs_detected": indicators.get("ip_addresses", []) + indicators.get("domains", []) + indicators.get("file_hashes", []),
                        "cve_references": indicators.get("cve_references", []),
                        "malware_families": indicators.get("malware_families", []),
                        "affected_systems": [],
                        **analysis_result
                    }
                    
                    # Store in BigQuery
                    await store_processed_message(message_data)
                    processed_count += 1
                    message_count += 1
                    
                    # Rate limiting between messages
                    if message_count % 10 == 0:
                        await asyncio.sleep(2)  # Pause every 10 messages
                    else:
                        await asyncio.sleep(0.5)  # Small delay between messages
                    
                except Exception as msg_error:
                    logger.error(f"Error processing historical message: {msg_error}")
                    continue
            
            logger.info(f"Processed {message_count} historical messages from {channel_username}")
            
        except Exception as e:
            logger.error(f"Error fetching history from {channel_username}: {e}")
            continue
    
    logger.info(f"Total processed {processed_count} historical cybersecurity messages")
    return processed_count

async def analyze_with_gemini(text: str, channel_username: str, channel_metadata: Dict) -> Dict[str, Any]:
    """Enhanced cybersecurity analysis with Gemini AI"""
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
        You are a cybersecurity threat intelligence analyst. Analyze this message from {channel_username} (type: {channel_type}, focus: {channel_focus}).

        Provide analysis as valid JSON with these exact fields:
        {{
            "sentiment": "positive|negative|neutral",
            "key_topics": ["topic1", "topic2", "topic3"],
            "urgency_score": 0.5,
            "category": "threat_intel|data_breach|vulnerability|malware|ransomware|apt|phishing|other",
            "threat_level": "critical|high|medium|low|info", 
            "threat_type": "specific_threat_type",
            "affected_systems": ["system1", "system2"],
            "analysis": "Brief 2-3 sentence threat assessment"
        }}

        Cybersecurity Analysis Guidelines:
        - threat_level: critical (active exploits, major breaches), high (new vulnerabilities, active campaigns), medium (advisories, emerging threats), low (general info), info (educational)
        - category: Focus on cybersecurity categories - threat_intel for APT/campaigns, data_breach for breaches/leaks, vulnerability for CVEs/patches, malware for malware analysis, etc.
        - threat_type: Specific threat like "ransomware campaign", "zero-day exploit", "data breach", "apt activity", etc.
        - affected_systems: Operating systems, software, or industries mentioned
        - urgency_score: 0.9-1.0 (zero-days, active attacks), 0.7-0.8 (critical vulns, major breaches), 0.5-0.6 (medium threats), 0.1-0.4 (advisories, patches), 0.0-0.1 (general info)

        Apply threat multiplier of {threat_multiplier} for this channel type.

        Key indicators to look for:
        - CVE references and CVSS scores
        - Malware family names and IOCs
        - Attack vectors and techniques
        - Affected organizations or sectors
        - Timeline and attribution information

        Message: "{text[:2000]}"

        Return only valid JSON:
        """

        # Generate content with retry logic
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
                        max_output_tokens=800,
                    )
                )
                
                if response.text:
                    break
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Gemini API attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # Clean and parse JSON response
        response_text = response.text.strip()
        
        # Remove markdown formatting
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Parse JSON
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                result = json.loads(response_text[start:end])
            else:
                raise ValueError("No valid JSON found in response")
        
        # Validate and enhance the result
        analysis_result = {
            "gemini_analysis": str(result.get("analysis", "Analysis completed"))[:1000],
            "sentiment": _validate_sentiment(result.get("sentiment", "neutral")),
            "key_topics": _validate_topics(result.get("key_topics", [])),
            "urgency_score": _validate_urgency(result.get("urgency_score", 0.0), threat_multiplier),
            "category": _validate_category(result.get("category", "other")),
            "threat_level": _validate_threat_level(result.get("threat_level", "low")),
            "threat_type": str(result.get("threat_type", "unknown"))[:100],
            "affected_systems": _validate_systems(result.get("affected_systems", []))
        }
        
        logger.info(f"Gemini analysis: {analysis_result['threat_level']} threat, category: {analysis_result['category']}")
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
    for topic in topics[:10]:  # Max 10 topics
        if isinstance(topic, str) and len(topic.strip()) > 0:
            cleaned_topics.append(str(topic).strip()[:50])
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
    for system in systems[:10]:  # Max 10 systems
        if isinstance(system, str) and len(system.strip()) > 0:
            cleaned_systems.append(str(system).strip()[:100])
    return cleaned_systems

def _get_fallback_analysis(text: str, channel_metadata: Dict) -> Dict[str, Any]:
    """Fallback analysis when Gemini fails"""
    text_lower = text.lower()
    
    # Basic cybersecurity keyword analysis
    threat_keywords = {
        "critical": ["zero-day", "exploit", "breach", "ransomware", "apt"],
        "high": ["vulnerability", "malware", "attack", "compromise", "backdoor"],
        "medium": ["security", "advisory", "patch", "update", "warning"],
        "low": ["information", "report", "analysis", "research"]
    }
    
    threat_level = "low"
    urgency = 0.2
    
    for level, keywords in threat_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            threat_level = level
            if level == "critical":
                urgency = 0.9
            elif level == "high":
                urgency = 0.7
            elif level == "medium":
                urgency = 0.5
            break
    
    # Apply channel multiplier
    multiplier = channel_metadata.get("threat_multiplier", 1.0)
    urgency = min(1.0, urgency * multiplier)
    
    return {
        "gemini_analysis": f"Fallback analysis: {len(text)} char message from {channel_metadata.get('type', 'unknown')} source",
        "sentiment": "neutral",
        "key_topics": [],
        "urgency_score": urgency,
        "category": "other",
        "threat_level": threat_level,
        "threat_type": "unknown",
        "affected_systems": []
    }

async def store_processed_message(data: Dict[str, Any]):
    """Store processed cybersecurity message in BigQuery with retry logic"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            table_ref = bq_client.dataset(DATASET_ID).table(TABLE_ID)
            table = bq_client.get_table(table_ref)
            
            # Convert datetime objects to strings for BigQuery
            if isinstance(data.get("message_date"), datetime):
                data["message_date"] = data["message_date"].isoformat()
            if isinstance(data.get("processed_date"), datetime):
                data["processed_date"] = data["processed_date"].isoformat()
            
            # Insert row with timeout
            errors = bq_client.insert_rows_json(table, [data], timeout=30)
            
            if errors:
                raise Exception(f"BigQuery insert failed: {errors}")
            
            logger.info(f"Stored cybersecurity message {data['message_id']} - {data.get('threat_level', 'unknown')} threat")
            return
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"BigQuery insert attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(retry_delay * (2 ** attempt))
            else:
                logger.error(f"BigQuery storage failed after {max_retries} attempts: {e}")
                raise

async def get_recent_insights(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent cybersecurity insights from BigQuery"""
    try:
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
        
        logger.info(f"Retrieved {len(results)} cybersecurity insights from BigQuery")
        return results

    except Exception as e:
        logger.error(f"Failed to get cybersecurity insights: {e}")
        return []

async def get_message_stats() -> Dict[str, Any]:
    """Get cybersecurity message statistics from BigQuery"""
    try:
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
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "unique_channels": 0,
                "unique_users": 0,
                "high_threats": 0,
                "critical_threats": 0,
                "data_breaches": 0,
                "malware_alerts": 0,
                "vulnerabilities": 0,
                "cve_mentions": 0,
            }
        
        # Add monitoring status
        stats["monitoring_active"] = (
            telegram_client is not None and 
            telegram_client.is_connected()
        )
        
        logger.info(f"Cybersecurity stats: {stats['total_messages']} total, {stats['high_threats']} high threats")
        return stats

    except Exception as e:
        logger.error(f"Failed to get cybersecurity stats: {e}")
        return {
            "total_messages": 0,
            "processed_today": 0,
            "avg_urgency": 0.0,
            "unique_channels": 0,
            "unique_users": 0,
            "high_threats": 0,
            "critical_threats": 0,
            "data_breaches": 0,
            "malware_alerts": 0,
            "vulnerabilities": 0,
            "cve_mentions": 0,
            "monitoring_active": False
        }

async def start_monitoring():
    """Start cybersecurity monitoring"""
    try:
        logger.info("Starting CIPHER cybersecurity monitoring system...")
        
        # Initialize Gemini AI
        gemini_success = await initialize_gemini()
        if not gemini_success:
            logger.error("Failed to initialize Gemini AI - continuing with fallback analysis")
        
        # Initialize Telegram client using Cloud Storage session
        telegram_success = await initialize_telegram_client()
        if not telegram_success:
            logger.error("Failed to initialize Telegram client")
            logger.error("Make sure you have run the local authentication script to create a session")
            return False
        
        # Join cybersecurity channels
        join_result = await join_monitored_channels()
        
        if join_result["successful"] == 0:
            logger.error("Failed to access any cybersecurity channels")
            return False
        
        # Fetch recent history from cybersecurity channels
        logger.info("Fetching recent cybersecurity intelligence...")
        history_count = await fetch_recent_cybersecurity_history()
        logger.info(f"Processed {history_count} historical cybersecurity messages")
        
        # Add event handler for new messages
        telegram_client.add_event_handler(handle_new_message)
        
        logger.info("CIPHER cybersecurity monitoring started successfully")
        logger.info(f"Monitoring {len(MONITORED_CHANNELS)} cybersecurity channels: {', '.join(MONITORED_CHANNELS)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to start cybersecurity monitoring: {e}")
        return False

async def stop_monitoring():
    """Stop cybersecurity monitoring and cleanup"""
    try:
        if telegram_client:
            # Try to save session before disconnecting
            try:
                session_data = telegram_client.session.save()
                if session_data:
                    await upload_session_to_storage(session_data)
            except Exception as e:
                logger.warning(f"Failed to save session during shutdown: {e}")
            
            await telegram_client.disconnect()
        logger.info("Stopped CIPHER cybersecurity monitoring")
    except Exception as e:
        logger.error(f"Error stopping cybersecurity monitoring: {e}")

async def start_background_monitoring():
    """Start cybersecurity monitoring in background task"""
    global _monitoring_task
    
    if _monitoring_task and not _monitoring_task.done():
        logger.info("Cybersecurity monitoring already running")
        return
    
    try:
        success = await start_monitoring()
        if not success:
            logger.error("Failed to start cybersecurity monitoring")
            return
        
        _monitoring_task = asyncio.create_task(telegram_client.run_until_disconnected())
        logger.info("Background cybersecurity monitoring started")
        
    except Exception as e:
        logger.error(f"Failed to start background cybersecurity monitoring: {e}")

async def stop_background_monitoring():
    """Stop background cybersecurity monitoring"""
    global _monitoring_task
    
    try:
        await stop_monitoring()
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
            try:
                await _monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Background cybersecurity monitoring stopped")
    except Exception as e:
        logger.error(f"Failed to stop background cybersecurity monitoring: {e}")

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
