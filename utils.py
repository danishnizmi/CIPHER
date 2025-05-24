import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import asyncio
from google.cloud import bigquery
from google.cloud import secretmanager
import google.generativeai as genai
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
from telethon.tl.types import Channel, Chat

logger = logging.getLogger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")

# MTProto client
telegram_client = None
gemini_model = None

# Monitored channels (can be configured via environment or database)
MONITORED_CHANNELS = [
    "@bbcbreaking",
    "@cnn", 
    "@bitcoin",
    "@ethereum",
    "@techcrunch",
    "@reuters",
    # Add more channels as needed
]

async def get_secret(secret_id: str) -> str:
    """Get secret from Secret Manager"""
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8")
        logger.info(f"Successfully retrieved secret: {secret_id}")
        return secret_value
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        raise

async def initialize_gemini():
    """Initialize Gemini AI with API key from Secret Manager"""
    global gemini_model
    try:
        # Get Gemini API key from Secret Manager
        api_key = await get_secret("gemini-api-key")
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel('gemini-1.5-flash')
        
        logger.info("Gemini AI initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Gemini AI: {e}")
        return False

async def initialize_telegram_client():
    """Initialize Telegram MTProto client"""
    global telegram_client
    
    try:
        # Get MTProto credentials from Secret Manager
        api_id = int(await get_secret("telegram-api-id"))
        api_hash = await get_secret("telegram-api-hash")
        phone_number = await get_secret("telegram-phone-number")
        
        # Create client with session stored in memory
        telegram_client = TelegramClient('session', api_id, api_hash)
        
        # Connect and authenticate
        await telegram_client.connect()
        
        # Check if we're already authorized
        if not await telegram_client.is_user_authorized():
            logger.info("Starting phone authorization...")
            await telegram_client.send_code_request(phone_number)
            logger.warning("Phone code sent. For production, implement proper auth flow.")
            # In production, you'd handle this differently
            # For now, we assume the session is already authenticated
        
        logger.info("Telegram client initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize Telegram client: {e}")
        return False

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables"""
    try:
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            dataset = bq_client.get_dataset(dataset_ref)
            logger.info(f"Dataset {DATASET_ID} already exists")
        except Exception:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "Telegram AI Processor data storage"
            dataset = bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {DATASET_ID}")

        # Create table schema - FIXED: Removed chat_title, using chat_username
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
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info(f"Table {TABLE_ID} already exists")
        except Exception:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "Processed Telegram messages with AI analysis"
            table = bq_client.create_table(table)
            logger.info(f"Created table {TABLE_ID}")

        logger.info("BigQuery setup completed successfully")

    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def join_monitored_channels():
    """Join all monitored channels"""
    if not telegram_client:
        logger.error("Telegram client not initialized")
        return
    
    successful_joins = 0
    failed_joins = 0
    
    for channel_username in MONITORED_CHANNELS:
        try:
            # Try to join the channel
            entity = await telegram_client.get_entity(channel_username)
            
            if isinstance(entity, Channel):
                # For channels, we might need to join
                try:
                    from telethon import functions
                    await telegram_client(functions.channels.JoinChannelRequest(entity))
                    logger.info(f"Joined channel: {channel_username}")
                except Exception as join_error:
                    # Might already be joined
                    logger.info(f"Already in channel or can't join: {channel_username}")
            
            successful_joins += 1
            logger.info(f"Successfully accessed channel: {channel_username}")
            
        except Exception as e:
            logger.error(f"Failed to access channel {channel_username}: {e}")
            failed_joins += 1
    
    logger.info(f"Channel access summary: {successful_joins} successful, {failed_joins} failed")

@events.register(events.NewMessage)
async def handle_new_message(event):
    """Handle new messages from monitored channels"""
    try:
        # Get message details
        message = event.message
        chat = await event.get_chat()
        sender = await event.get_sender()
        
        # Only process messages from monitored channels
        chat_username = getattr(chat, 'username', None)
        if chat_username:
            chat_username = f"@{chat_username}"
            if chat_username not in MONITORED_CHANNELS:
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

        if not text:
            logger.info(f"Message {message_id} has no text content, skipping")
            return

        logger.info(f"Processing message {message_id} from channel {chat_username}")

        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text)
        
        # Prepare data for storage
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "chat_username": chat_username,
            "user_id": user_id,
            "username": username,
            "message_text": text,
            "message_date": message_date,
            "processed_date": datetime.now(),
            **analysis_result
        }
        
        # Store in BigQuery
        await store_processed_message(message_data)
        
        logger.info(f"Successfully processed message {message_id} from {chat_username}")

    except Exception as e:
        logger.error(f"Error handling message: {e}")

async def start_monitoring():
    """Start monitoring Telegram channels"""
    try:
        # Initialize Gemini
        await initialize_gemini()
        
        # Initialize Telegram client
        if not await initialize_telegram_client():
            logger.error("Failed to initialize Telegram client")
            return False
        
        # Join monitored channels
        await join_monitored_channels()
        
        # Add event handler
        telegram_client.add_event_handler(handle_new_message)
        
        logger.info("Started monitoring Telegram channels")
        logger.info(f"Monitoring channels: {', '.join(MONITORED_CHANNELS)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return False

async def stop_monitoring():
    """Stop monitoring and cleanup"""
    try:
        if telegram_client:
            await telegram_client.disconnect()
        logger.info("Stopped monitoring Telegram channels")
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")

async def analyze_with_gemini(text: str) -> Dict[str, Any]:
    """Analyze text with Gemini AI"""
    try:
        # Initialize Gemini if not already done
        if not gemini_model:
            success = await initialize_gemini()
            if not success:
                return {
                    "gemini_analysis": "AI analysis unavailable - initialization failed",
                    "sentiment": "neutral",
                    "key_topics": [],
                    "urgency_score": 0.0,
                    "category": "other"
                }

        # Create a comprehensive prompt for analysis
        prompt = f"""
        Analyze the following message and provide a JSON response with these fields:

        1. sentiment: "positive", "negative", or "neutral"
        2. key_topics: Array of 3-5 main topics/keywords (lowercase, no special characters)
        3. urgency_score: Float between 0.0-1.0 (0=not urgent, 1=very urgent)
        4. category: One of: "news", "breaking", "market", "tech", "politics", "other"
        5. analysis: Brief 1-2 sentence summary of the message

        Consider urgency indicators like:
        - Breaking news indicators: "BREAKING", "URGENT", "ALERT"
        - Market movements: price changes, significant events
        - Time-sensitive information
        - Crisis or emergency situations

        Message to analyze: "{text}"

        Respond ONLY with valid JSON in this exact format:
        {{
            "sentiment": "positive|negative|neutral",
            "key_topics": ["topic1", "topic2", "topic3"],
            "urgency_score": 0.0,
            "category": "category_name",
            "analysis": "Brief summary here"
        }}
        """

        # Generate content using Gemini
        response = await asyncio.to_thread(
            gemini_model.generate_content, 
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                top_p=0.8,
                max_output_tokens=500,
            )
        )
        
        # Clean and parse JSON response
        response_text = response.text.strip()
        
        # Remove any markdown formatting
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Parse JSON
        result = json.loads(response_text)
        
        # Validate and clean the result
        analysis_result = {
            "gemini_analysis": str(result.get("analysis", "Analysis completed"))[:1000],
            "sentiment": str(result.get("sentiment", "neutral")).lower(),
            "key_topics": [str(topic)[:50] for topic in result.get("key_topics", [])[:10]],
            "urgency_score": max(0.0, min(1.0, float(result.get("urgency_score", 0.0)))),
            "category": str(result.get("category", "other")).lower()
        }
        
        # Validate sentiment
        if analysis_result["sentiment"] not in ["positive", "negative", "neutral"]:
            analysis_result["sentiment"] = "neutral"
        
        # Validate category
        valid_categories = ["news", "breaking", "market", "tech", "politics", "other"]
        if analysis_result["category"] not in valid_categories:
            analysis_result["category"] = "other"
        
        logger.info(f"Gemini analysis completed: sentiment={analysis_result['sentiment']}, urgency={analysis_result['urgency_score']}")
        
        return analysis_result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini JSON response: {e}")
        return {
            "gemini_analysis": f"JSON parsing failed: {str(e)[:200]}",
            "sentiment": "neutral",
            "key_topics": [],
            "urgency_score": 0.0,
            "category": "other"
        }
    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return {
            "gemini_analysis": f"Analysis failed: {str(e)[:200]}",
            "sentiment": "neutral",
            "key_topics": [],
            "urgency_score": 0.0,
            "category": "other"
        }

async def store_processed_message(data: Dict[str, Any]):
    """Store processed message in BigQuery"""
    try:
        table_ref = bq_client.dataset(DATASET_ID).table(TABLE_ID)
        table = bq_client.get_table(table_ref)
        
        # Convert datetime objects to strings for BigQuery
        if isinstance(data.get("message_date"), datetime):
            data["message_date"] = data["message_date"].isoformat()
        if isinstance(data.get("processed_date"), datetime):
            data["processed_date"] = data["processed_date"].isoformat()
        
        # Insert row
        errors = bq_client.insert_rows_json(table, [data])
        
        if errors:
            logger.error(f"BigQuery insert errors: {errors}")
            raise Exception(f"BigQuery insert failed: {errors}")
        else:
            logger.info(f"Stored message {data['message_id']} in BigQuery")

    except Exception as e:
        logger.error(f"BigQuery storage failed: {e}")
        raise

async def get_recent_insights(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Get recent processed insights from BigQuery - FIXED query"""
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
            category
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        ORDER BY processed_date DESC
        LIMIT {limit}
        OFFSET {offset}
        """
        
        query_job = bq_client.query(query)
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
                "category": row.category
            })
        
        logger.info(f"Retrieved {len(results)} insights from BigQuery")
        return results

    except Exception as e:
        logger.error(f"Failed to get insights: {e}")
        return []

async def get_message_stats() -> Dict[str, Any]:
    """Get message statistics from BigQuery"""
    try:
        today = datetime.now().date()
        
        query = f"""
        SELECT 
            COUNT(*) as total_messages,
            COUNT(CASE WHEN DATE(processed_date) = '{today}' THEN 1 END) as processed_today,
            AVG(urgency_score) as avg_urgency,
            COUNT(DISTINCT chat_id) as unique_channels,
            COUNT(DISTINCT user_id) as unique_users
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        """
        
        query_job = bq_client.query(query)
        row = next(iter(query_job), None)
        
        if row:
            stats = {
                "total_messages": int(row.total_messages) if row.total_messages else 0,
                "processed_today": int(row.processed_today) if row.processed_today else 0,
                "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
                "unique_channels": int(row.unique_channels) if row.unique_channels else 0,
                "unique_users": int(row.unique_users) if row.unique_users else 0
            }
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "unique_channels": 0,
                "unique_users": 0
            }
        
        logger.info(f"Retrieved stats: {stats['total_messages']} total messages, {stats['processed_today']} today")
        return stats

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {
            "total_messages": 0,
            "processed_today": 0,
            "avg_urgency": 0.0,
            "unique_channels": 0,
            "unique_users": 0
        }

# Background task management
_monitoring_task = None

async def start_background_monitoring():
    """Start monitoring in background task"""
    global _monitoring_task
    
    if _monitoring_task and not _monitoring_task.done():
        logger.info("Monitoring already running")
        return
    
    try:
        await start_monitoring()
        _monitoring_task = asyncio.create_task(telegram_client.run_until_disconnected())
        logger.info("Background monitoring started")
    except Exception as e:
        logger.error(f"Failed to start background monitoring: {e}")

async def stop_background_monitoring():
    """Stop background monitoring"""
    global _monitoring_task
    
    try:
        await stop_monitoring()
        if _monitoring_task and not _monitoring_task.done():
            _monitoring_task.cancel()
        logger.info("Background monitoring stopped")
    except Exception as e:
        logger.error(f"Failed to stop background monitoring: {e}")
