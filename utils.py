import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from google.cloud import bigquery
from google.cloud import secretmanager
from google.cloud import storage
import google.generativeai as genai
from telethon import TelegramClient, events, functions
from telethon.errors import (
    SessionPasswordNeededError, 
    PhoneCodeInvalidError, 
    ApiIdInvalidError,
    PhoneNumberInvalidError,
    FloodWaitError
)
from telethon.tl.types import Channel, Chat
from cryptg import encrypt_ige, decrypt_ige
import structlog

# Configure structured logging
logger = structlog.get_logger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()
storage_client = storage.Client()

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")
BUCKET_NAME = os.environ.get("SESSION_BUCKET", f"{PROJECT_ID}-telegram-sessions")

# MTProto client
telegram_client = None
gemini_model = None
_monitoring_task = None
_last_activity = datetime.now()

# Monitored channels with metadata
MONITORED_CHANNELS = [
    {"username": "@bbcbreaking", "category": "news", "priority": "high"},
    {"username": "@cnn", "category": "news", "priority": "high"},
    {"username": "@bitcoin", "category": "crypto", "priority": "medium"},
    {"username": "@ethereum", "category": "crypto", "priority": "medium"},
    {"username": "@techcrunch", "category": "tech", "priority": "medium"},
    {"username": "@reuters", "category": "news", "priority": "high"},
]

# Rate limiting
_api_calls = {}
_rate_limit_window = timedelta(minutes=1)
_max_calls_per_window = 30

class TelegramSessionError(Exception):
    """Custom exception for Telegram session issues"""
    pass

class RateLimitError(Exception):
    """Custom exception for rate limiting"""
    pass

async def check_rate_limit(operation: str) -> bool:
    """Check if operation is within rate limits"""
    now = datetime.now()
    if operation not in _api_calls:
        _api_calls[operation] = []
    
    # Clean old calls
    _api_calls[operation] = [
        call_time for call_time in _api_calls[operation]
        if now - call_time < _rate_limit_window
    ]
    
    if len(_api_calls[operation]) >= _max_calls_per_window:
        raise RateLimitError(f"Rate limit exceeded for {operation}")
    
    _api_calls[operation].append(now)
    return True

async def get_secret(secret_id: str) -> str:
    """Get secret from Secret Manager"""
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        
        if not secret_value:
            raise ValueError(f"Secret {secret_id} is empty")
        
        logger.info("Successfully retrieved secret", secret_id=secret_id)
        return secret_value
    except Exception as e:
        logger.error("Failed to get secret", secret_id=secret_id, error=str(e))
        raise

async def save_session_to_storage(session_data: bytes, session_name: str = "telegram_session") -> bool:
    """Save Telegram session to Cloud Storage"""
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        
        # Create bucket if it doesn't exist
        try:
            bucket.reload()
        except Exception:
            bucket = storage_client.create_bucket(BUCKET_NAME, location="US")
            logger.info("Created session storage bucket", bucket=BUCKET_NAME)
        
        blob = bucket.blob(f"{session_name}.session")
        blob.upload_from_string(session_data)
        
        logger.info("Session saved to storage", session=session_name)
        return True
    except Exception as e:
        logger.error("Failed to save session", error=str(e))
        return False

async def load_session_from_storage(session_name: str = "telegram_session") -> Optional[bytes]:
    """Load Telegram session from Cloud Storage"""
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{session_name}.session")
        
        if blob.exists():
            session_data = blob.download_as_bytes()
            logger.info("Session loaded from storage", session=session_name)
            return session_data
        else:
            logger.info("No existing session found", session=session_name)
            return None
    except Exception as e:
        logger.error("Failed to load session", error=str(e))
        return None

async def initialize_gemini() -> bool:
    """Initialize Gemini AI with API key from Secret Manager"""
    global gemini_model
    try:
        api_key = await get_secret("gemini-api-key")
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                top_p=0.8,
                max_output_tokens=800,
                response_mime_type="application/json"
            )
        )
        
        # Test the model
        test_response = await asyncio.to_thread(
            gemini_model.generate_content, 
            'Return JSON with one field "status": "ok"'
        )
        
        logger.info("Gemini AI initialized and tested successfully")
        return True
    except Exception as e:
        logger.error("Failed to initialize Gemini AI", error=str(e))
        return False

async def initialize_telegram_client() -> bool:
    """Initialize Telegram MTProto client with session persistence"""
    global telegram_client
    
    try:
        # Get MTProto credentials
        api_id_str = await get_secret("telegram-api-id")
        api_hash = await get_secret("telegram-api-hash")
        phone_number = await get_secret("telegram-phone-number")
        
        # Validate API ID is numeric
        try:
            api_id = int(api_id_str)
        except ValueError:
            raise ValueError(f"Invalid API ID: {api_id_str}. Must be numeric.")
        
        # Validate phone number format
        if not phone_number.startswith('+') or len(phone_number) < 10:
            raise ValueError(f"Invalid phone number format: {phone_number}")
        
        logger.info("Retrieved Telegram credentials", api_id=api_id, phone=phone_number[:5]+"***")
        
        # Load existing session
        session_data = await load_session_from_storage()
        
        # Create client
        telegram_client = TelegramClient(
            session='memory_session', 
            api_id=api_id, 
            api_hash=api_hash,
            timeout=30,
            retry_delay=1,
            auto_reconnect=True
        )
        
        # Load session if exists
        if session_data:
            telegram_client.session.load(session_data)
        
        # Connect
        await telegram_client.connect()
        
        # Check authorization
        if not await telegram_client.is_user_authorized():
            logger.warning("Telegram client not authorized. Manual intervention required.")
            logger.warning("For production, implement proper 2FA flow or use bot token.")
            # In production, you would implement a proper auth flow
            # For now, we'll continue without full authorization
            return False
        
        # Save session after successful connection
        if telegram_client.session.save():
            session_string = telegram_client.session.save()
            await save_session_to_storage(session_string.encode())
        
        logger.info("Telegram client initialized successfully")
        return True
        
    except Exception as e:
        logger.error("Failed to initialize Telegram client", error=str(e))
        if telegram_client:
            try:
                await telegram_client.disconnect()
            except:
                pass
        return False

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables with correct schema"""
    try:
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            dataset = bq_client.get_dataset(dataset_ref)
            logger.info("Dataset already exists", dataset=DATASET_ID)
        except Exception:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "Telegram AI Processor data storage"
            dataset = bq_client.create_dataset(dataset, timeout=30)
            logger.info("Created dataset", dataset=DATASET_ID)

        # Updated table schema - matching the actual queries
        schema = [
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED", description="Unique message identifier"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED", description="Chat/channel identifier"),
            bigquery.SchemaField("chat_username", "STRING", description="Channel username"),
            bigquery.SchemaField("user_id", "STRING", description="User identifier"),
            bigquery.SchemaField("username", "STRING", description="Username without @"),
            bigquery.SchemaField("message_text", "STRING", description="Original message text"),
            bigquery.SchemaField("message_date", "TIMESTAMP", mode="REQUIRED", description="When message was sent"),
            bigquery.SchemaField("processed_date", "TIMESTAMP", mode="REQUIRED", description="When message was processed"),
            bigquery.SchemaField("gemini_analysis", "STRING", description="AI analysis summary"),
            bigquery.SchemaField("sentiment", "STRING", description="Sentiment: positive/negative/neutral"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED", description="Main topics identified"),
            bigquery.SchemaField("urgency_score", "FLOAT", description="Urgency score 0-1"),
            bigquery.SchemaField("category", "STRING", description="Message category"),
            bigquery.SchemaField("channel_priority", "STRING", description="Channel priority level"),
            bigquery.SchemaField("processing_version", "STRING", description="Processing pipeline version"),
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info("Table already exists", table=TABLE_ID)
            
            # Check if schema needs updates
            existing_fields = {field.name for field in table.schema}
            new_fields = {field.name for field in schema}
            
            if not new_fields.issubset(existing_fields):
                logger.warning("Table schema may need updates. Consider adding missing columns.")
                
        except Exception:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "Processed Telegram messages with AI analysis"
            table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field="processed_date"
            )
            table.clustering_fields = ["category", "chat_username"]
            table = bq_client.create_table(table, timeout=30)
            logger.info("Created table with partitioning and clustering", table=TABLE_ID)

        logger.info("BigQuery setup completed successfully")

    except Exception as e:
        logger.error("BigQuery setup failed", error=str(e))
        raise

async def join_monitored_channels():
    """Join all monitored channels with error handling"""
    if not telegram_client:
        logger.error("Telegram client not initialized")
        return {"successful": 0, "failed": 0, "errors": ["Client not initialized"]}
    
    successful_joins = 0
    failed_joins = 0
    errors = []
    
    for channel_info in MONITORED_CHANNELS:
        channel_username = channel_info["username"]
        try:
            await check_rate_limit("get_entity")
            
            # Try to get the channel entity
            entity = await telegram_client.get_entity(channel_username)
            
            if isinstance(entity, Channel):
                # For channels, try to join if not already joined
                try:
                    await check_rate_limit("join_channel")
                    await telegram_client(functions.channels.JoinChannelRequest(entity))
                    logger.info("Joined channel", channel=channel_username)
                except Exception as join_error:
                    # Might already be joined or can't join
                    logger.info("Channel access confirmed", 
                              channel=channel_username, 
                              note="Already joined or public channel")
            
            successful_joins += 1
            logger.info("Successfully accessed channel", 
                       channel=channel_username, 
                       category=channel_info["category"],
                       priority=channel_info["priority"])
            
        except FloodWaitError as e:
            wait_time = e.seconds
            logger.warning("Rate limited, waiting", 
                          channel=channel_username, 
                          wait_seconds=wait_time)
            await asyncio.sleep(wait_time)
            errors.append(f"{channel_username}: Rate limited (waited {wait_time}s)")
        except Exception as e:
            logger.error("Failed to access channel", 
                        channel=channel_username, 
                        error=str(e))
            failed_joins += 1
            errors.append(f"{channel_username}: {str(e)}")
    
    result = {
        "successful": successful_joins,
        "failed": failed_joins,
        "errors": errors
    }
    
    logger.info("Channel access summary", **result)
    return result

@events.register(events.NewMessage)
async def handle_new_message(event):
    """Handle new messages from monitored channels with comprehensive error handling"""
    global _last_activity
    _last_activity = datetime.now()
    
    try:
        # Get message details
        message = event.message
        chat = await event.get_chat()
        sender = await event.get_sender()
        
        # Only process messages from monitored channels
        chat_username = getattr(chat, 'username', None)
        if chat_username:
            chat_username = f"@{chat_username}"
            channel_info = next(
                (ch for ch in MONITORED_CHANNELS if ch["username"] == chat_username), 
                None
            )
            if not channel_info:
                return
        else:
            # Skip if we can't identify the channel
            return
        
        # Extract message data
        message_id = str(message.id)
        chat_id = str(chat.id)
        user_id = str(sender.id) if sender else ""
        username = getattr(sender, 'username', '') if sender else ""
        text = message.text or ""
        message_date = message.date

        if not text or len(text.strip()) < 10:
            logger.debug("Message too short or empty, skipping", 
                        message_id=message_id, 
                        length=len(text))
            return

        logger.info("Processing message", 
                   message_id=message_id, 
                   channel=chat_username,
                   text_length=len(text))

        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text, channel_info)
        
        # Prepare data for storage
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "chat_username": chat_username,
            "user_id": user_id,
            "username": username,
            "message_text": text[:4000],  # Limit text length
            "message_date": message_date.isoformat(),
            "processed_date": datetime.now().isoformat(),
            "channel_priority": channel_info["priority"],
            "processing_version": "1.0.0",
            **analysis_result
        }
        
        # Store in BigQuery
        await store_processed_message(message_data)
        
        logger.info("Successfully processed message", 
                   message_id=message_id, 
                   channel=chat_username,
                   sentiment=analysis_result.get("sentiment"),
                   urgency=analysis_result.get("urgency_score"))

    except Exception as e:
        logger.error("Error handling message", 
                    message_id=getattr(message, 'id', 'unknown'),
                    error=str(e))

async def analyze_with_gemini(text: str, channel_info: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze text with Gemini AI using structured prompts"""
    try:
        if not gemini_model:
            success = await initialize_gemini()
            if not success:
                return _get_fallback_analysis(text)

        # Enhanced prompt with channel context
        prompt = f"""
        Analyze this Telegram message from {channel_info['username']} (category: {channel_info['category']}, priority: {channel_info['priority']}).

        Provide analysis as JSON with these exact fields:
        {{
            "sentiment": "positive|negative|neutral",
            "key_topics": ["topic1", "topic2", "topic3"],
            "urgency_score": 0.5,
            "category": "breaking|news|market|tech|politics|crypto|other",
            "analysis": "Brief 1-2 sentence summary"
        }}

        Urgency scoring guidelines:
        - 0.9-1.0: BREAKING news, market crashes, emergencies
        - 0.7-0.8: Major announcements, significant events  
        - 0.4-0.6: Important updates, notable developments
        - 0.1-0.3: Regular news, general information
        - 0.0: Routine posts, advertisements

        Consider these urgency indicators:
        - Keywords: BREAKING, URGENT, ALERT, EMERGENCY
        - Market movements: price changes >5%, major partnerships
        - Time sensitivity: "just announced", "happening now"
        - Impact level: global vs local, major vs minor

        Message: "{text[:2000]}"
        """

        # Generate content
        response = await asyncio.to_thread(
            gemini_model.generate_content, 
            prompt
        )
        
        # Parse JSON response
        response_text = response.text.strip()
        
        # Clean markdown formatting
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                result = json.loads(response_text[start:end])
            else:
                raise
        
        # Validate and clean result
        analysis_result = {
            "gemini_analysis": str(result.get("analysis", "Analysis completed"))[:1000],
            "sentiment": _validate_sentiment(result.get("sentiment", "neutral")),
            "key_topics": _validate_topics(result.get("key_topics", [])),
            "urgency_score": _validate_urgency(result.get("urgency_score", 0.0)),
            "category": _validate_category(result.get("category", "other"))
        }
        
        logger.info("Gemini analysis completed", 
                   sentiment=analysis_result["sentiment"],
                   urgency=analysis_result["urgency_score"],
                   category=analysis_result["category"])
        
        return analysis_result

    except Exception as e:
        logger.error("Gemini analysis failed", error=str(e))
        return _get_fallback_analysis(text)

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

def _validate_urgency(urgency: Any) -> float:
    """Validate urgency score"""
    try:
        score = float(urgency)
        return max(0.0, min(1.0, score))
    except (ValueError, TypeError):
        return 0.0

def _validate_category(category: str) -> str:
    """Validate category"""
    valid_categories = ["breaking", "news", "market", "tech", "politics", "crypto", "other"]
    category = str(category).lower().strip()
    return category if category in valid_categories else "other"

def _get_fallback_analysis(text: str) -> Dict[str, Any]:
    """Fallback analysis when Gemini fails"""
    # Simple keyword-based analysis
    text_lower = text.lower()
    
    # Determine urgency based on keywords
    urgency = 0.0
    if any(word in text_lower for word in ["breaking", "urgent", "alert", "emergency"]):
        urgency = 0.9
    elif any(word in text_lower for word in ["announces", "launches", "major"]):
        urgency = 0.6
    elif any(word in text_lower for word in ["update", "news", "reports"]):
        urgency = 0.3
    
    # Simple sentiment
    positive_words = ["good", "great", "success", "up", "gain", "positive", "win"]
    negative_words = ["bad", "crash", "down", "loss", "negative", "fail", "drop"]
    
    pos_count = sum(1 for word in positive_words if word in text_lower)
    neg_count = sum(1 for word in negative_words if word in text_lower)
    
    if pos_count > neg_count:
        sentiment = "positive"
    elif neg_count > pos_count:
        sentiment = "negative"
    else:
        sentiment = "neutral"
    
    return {
        "gemini_analysis": f"Fallback analysis: {len(text)} character message processed",
        "sentiment": sentiment,
        "key_topics": [],
        "urgency_score": urgency,
        "category": "other"
    }

async def store_processed_message(data: Dict[str, Any]):
    """Store processed message in BigQuery with retry logic"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            table_ref = bq_client.dataset(DATASET_ID).table(TABLE_ID)
            table = bq_client.get_table(table_ref)
            
            # Insert row
            errors = bq_client.insert_rows_json(table, [data], timeout=30)
            
            if errors:
                raise Exception(f"BigQuery insert failed: {errors}")
            
            logger.info("Stored message in BigQuery", 
                       message_id=data["message_id"],
                       attempt=attempt + 1)
            return
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning("BigQuery insert failed, retrying", 
                             attempt=attempt + 1, 
                             error=str(e))
                await asyncio.sleep(retry_delay * (2 ** attempt))
            else:
                logger.error("BigQuery storage failed after retries", 
                           message_id=data.get("message_id"),
                           error=str(e))
                raise

async def get_recent_insights(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent processed insights from BigQuery with corrected schema"""
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
            channel_priority
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC
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
                "channel_priority": getattr(row, 'channel_priority', 'medium')
            })
        
        logger.info("Retrieved insights from BigQuery", count=len(results))
        return results

    except Exception as e:
        logger.error("Failed to get insights", error=str(e))
        return []

async def get_message_stats() -> Dict[str, Any]:
    """Get comprehensive message statistics from BigQuery"""
    try:
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        
        query = f"""
        WITH daily_stats AS (
            SELECT 
                DATE(processed_date) as processing_date,
                COUNT(*) as daily_count,
                AVG(urgency_score) as daily_avg_urgency,
                COUNT(DISTINCT chat_id) as daily_channels
            FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
            WHERE DATE(processed_date) >= '{week_ago}'
            GROUP BY DATE(processed_date)
        ),
        overall_stats AS (
            SELECT 
                COUNT(*) as total_messages,
                COUNT(CASE WHEN DATE(processed_date) = '{today}' THEN 1 END) as processed_today,
                AVG(urgency_score) as avg_urgency,
                COUNT(DISTINCT chat_id) as unique_channels,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(CASE WHEN urgency_score > 0.7 THEN 1 END) as high_urgency_count
            FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
            WHERE DATE(processed_date) >= '{week_ago}'
        )
        SELECT * FROM overall_stats
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
                "high_urgency_count": int(row.high_urgency_count) if row.high_urgency_count else 0,
            }
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "unique_channels": 0,
                "unique_users": 0,
                "high_urgency_count": 0,
            }
        
        # Add monitoring status
        stats["monitoring_active"] = (
            telegram_client is not None and 
            telegram_client.is_connected() and
            (datetime.now() - _last_activity).seconds < 300  # Active in last 5 minutes
        )
        
        logger.info("Retrieved comprehensive stats", **stats)
        return stats

    except Exception as e:
        logger.error("Failed to get stats", error=str(e))
        return {
            "total_messages": 0,
            "processed_today": 0,
            "avg_urgency": 0.0,
            "unique_channels": 0,
            "unique_users": 0,
            "high_urgency_count": 0,
            "monitoring_active": False
        }

async def start_monitoring() -> bool:
    """Start monitoring with comprehensive initialization"""
    try:
        # Initialize Gemini
        gemini_success = await initialize_gemini()
        if not gemini_success:
            logger.error("Failed to initialize Gemini AI")
            return False
        
        # Initialize Telegram client
        telegram_success = await initialize_telegram_client()
        if not telegram_success:
            logger.error("Failed to initialize Telegram client")
            return False
        
        # Join monitored channels
        join_result = await join_monitored_channels()
        
        if join_result["successful"] == 0:
            logger.error("Failed to access any monitored channels")
            return False
        
        # Add event handler
        telegram_client.add_event_handler(handle_new_message)
        
        logger.info("Started monitoring Telegram channels", 
                   successful_channels=join_result["successful"],
                   failed_channels=join_result["failed"],
                   monitored_channels=[ch["username"] for ch in MONITORED_CHANNELS])
        
        return True
        
    except Exception as e:
        logger.error("Failed to start monitoring", error=str(e))
        return False

async def stop_monitoring():
    """Stop monitoring and cleanup resources"""
    try:
        if telegram_client:
            # Save session before disconnecting
            try:
                session_string = telegram_client.session.save()
                if session_string:
                    await save_session_to_storage(session_string.encode())
            except Exception as e:
                logger.warning("Failed to save session", error=str(e))
            
            await telegram_client.disconnect()
        
        logger.info("Stopped monitoring Telegram channels")
    except Exception as e:
        logger.error("Error stopping monitoring", error=str(e))

async def start_background_monitoring():
    """Start monitoring in background task with health checks"""
    global _monitoring_task
    
    if _monitoring_task and not _monitoring_task.done():
        logger.info("Monitoring already running")
        return
    
    try:
        success = await start_monitoring()
        if not success:
            logger.error("Failed to start monitoring")
            return
        
        _monitoring_task = asyncio.create_task(telegram_client.run_until_disconnected())
        logger.info("Background monitoring started")
        
        # Start health check task
        asyncio.create_task(_health_check_loop())
        
    except Exception as e:
        logger.error("Failed to start background monitoring", error=str(e))

async def stop_background_monitoring():
    """Stop background monitoring with cleanup"""
    global _monitoring_task
    
    try:
        await stop_monitoring()
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
            try:
                await _monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Background monitoring stopped")
    except Exception as e:
        logger.error("Failed to stop background monitoring", error=str(e))

async def _health_check_loop():
    """Background health check for monitoring"""
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute
            
            if telegram_client and telegram_client.is_connected():
                # Update last activity if we're still connected
                global _last_activity
                
                # Check if we've been inactive for too long
                if (datetime.now() - _last_activity).seconds > 1800:  # 30 minutes
                    logger.warning("No recent activity, connection may be stale")
                
            else:
                logger.warning("Telegram client disconnected, attempting reconnect")
                await start_monitoring()
                
        except Exception as e:
            logger.error("Health check error", error=str(e))
            await asyncio.sleep(60)

# Export main functions and constants
__all__ = [
    'setup_bigquery_tables',
    'start_background_monitoring', 
    'stop_background_monitoring',
    'get_recent_insights',
    'get_message_stats',
    'MONITORED_CHANNELS',
    'telegram_client'
]
