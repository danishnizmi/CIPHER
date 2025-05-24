import os
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
import aiohttp
from google.cloud import bigquery
from google.cloud import secretmanager
import vertexai
from vertexai.generative_models import GenerativeModel

logger = logging.getLogger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")
VERTEX_AI_LOCATION = os.environ.get("VERTEX_AI_LOCATION", "us-central1")
VERTEX_AI_MODEL = os.environ.get("VERTEX_AI_MODEL", "gemini-1.5-flash")

# Initialize Vertex AI
try:
    vertexai.init(project=PROJECT_ID, location=VERTEX_AI_LOCATION)
    gemini_model = GenerativeModel(VERTEX_AI_MODEL)
    logger.info(f"Initialized Vertex AI with model {VERTEX_AI_MODEL} in {VERTEX_AI_LOCATION}")
except Exception as e:
    logger.error(f"Failed to initialize Vertex AI: {e}")
    gemini_model = None

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

        # Create table schema
        schema = [
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED", description="Unique message identifier"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED", description="Chat/channel identifier"),
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

async def setup_telegram_webhook():
    """Configure Telegram webhook"""
    try:
        # Get bot token from Secret Manager
        try:
            bot_token = await get_secret("telegram-bot-token")
        except Exception as e:
            logger.warning(f"Bot token not found in Secret Manager: {e}")
            return

        # Skip webhook setup if token is placeholder
        if not bot_token or bot_token == "REPLACE_WITH_YOUR_TELEGRAM_BOT_TOKEN":
            logger.warning("Bot token is placeholder, skipping webhook setup")
            return

        webhook_url = os.environ.get("WEBHOOK_URL")
        if not webhook_url:
            logger.warning("WEBHOOK_URL not set, skipping webhook setup")
            return

        # Get webhook secret token
        webhook_secret = os.environ.get("TELEGRAM_SECRET_TOKEN", "")

        url = f"https://api.telegram.org/bot{bot_token}/setWebhook"
        data = {
            "url": f"{webhook_url}/webhook/telegram",
            "allowed_updates": ["message", "edited_message"],
            "drop_pending_updates": True,  # Clear any pending updates
        }
        
        # Add secret token if available
        if webhook_secret:
            data["secret_token"] = webhook_secret

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data) as response:
                result = await response.json()
                if result.get("ok"):
                    logger.info(f"Telegram webhook configured successfully: {webhook_url}/webhook/telegram")
                else:
                    logger.error(f"Failed to set webhook: {result}")

    except Exception as e:
        logger.error(f"Webhook setup failed: {e}")

def verify_telegram_webhook(headers: Dict, body: bytes) -> bool:
    """Verify Telegram webhook authenticity"""
    try:
        # Check for secret token in headers (Telegram sends this)
        received_token = headers.get("X-Telegram-Bot-Api-Secret-Token")
        
        # Get expected token from environment (set by Cloud Build)
        expected_token = os.environ.get("TELEGRAM_SECRET_TOKEN")
        
        # If no expected token is configured, skip verification (development mode)
        if not expected_token:
            logger.warning("No webhook secret token configured - skipping verification")
            return True
            
        # If no token received, request is invalid
        if not received_token:
            logger.warning("No secret token received in webhook headers")
            return False
            
        # Compare tokens securely
        is_valid = hmac.compare_digest(expected_token, received_token)
        
        if not is_valid:
            logger.warning("Webhook token verification failed")
        else:
            logger.debug("Webhook token verification successful")
            
        return is_valid
        
    except Exception as e:
        logger.error(f"Webhook verification failed: {e}")
        return False

async def process_telegram_message(data: Dict[str, Any]):
    """Process incoming Telegram message with Gemini AI"""
    try:
        message = data.get("message", {})
        if not message:
            logger.warning("No message data in webhook payload")
            return

        # Extract message data
        message_id = str(message.get("message_id"))
        chat_id = str(message.get("chat", {}).get("id"))
        user_id = str(message.get("from", {}).get("id", ""))
        username = message.get("from", {}).get("username", "")
        text = message.get("text", "")
        
        # Handle timestamp
        timestamp = message.get("date", 0)
        if timestamp:
            date = datetime.fromtimestamp(timestamp)
        else:
            date = datetime.now()

        if not text:
            logger.info(f"Message {message_id} has no text content, skipping")
            return

        logger.info(f"Processing message {message_id} from user {username or user_id}")

        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text)
        
        # Prepare data for storage
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "user_id": user_id,
            "username": username,
            "message_text": text,
            "message_date": date,
            "processed_date": datetime.now(),
            **analysis_result
        }
        
        # Store in BigQuery
        await store_processed_message(message_data)
        
        logger.info(f"Successfully processed message {message_id}")

    except Exception as e:
        logger.error(f"Message processing failed: {e}")

async def analyze_with_gemini(text: str) -> Dict[str, Any]:
    """Analyze text with Gemini AI"""
    try:
        if not gemini_model:
            logger.error("Gemini model not initialized")
            return {
                "gemini_analysis": "AI analysis unavailable - model not initialized",
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
        4. category: One of: "question", "complaint", "suggestion", "information", "request", "other"
        5. analysis: Brief 1-2 sentence summary of the message

        Consider urgency indicators like:
        - Time-sensitive words: "urgent", "asap", "emergency", "help", "problem"
        - Question marks and requests for help
        - Negative sentiment combined with specific issues
        - Complaints about services or problems

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
            generation_config={
                "temperature": 0.1,  # Lower temperature for more consistent JSON
                "top_p": 0.8,
                "max_output_tokens": 500,
            }
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
            "gemini_analysis": str(result.get("analysis", "Analysis completed"))[:1000],  # Limit length
            "sentiment": str(result.get("sentiment", "neutral")).lower(),
            "key_topics": [str(topic)[:50] for topic in result.get("key_topics", [])[:10]],  # Limit topics
            "urgency_score": max(0.0, min(1.0, float(result.get("urgency_score", 0.0)))),  # Clamp 0-1
            "category": str(result.get("category", "other")).lower()
        }
        
        # Validate sentiment
        if analysis_result["sentiment"] not in ["positive", "negative", "neutral"]:
            analysis_result["sentiment"] = "neutral"
        
        # Validate category
        valid_categories = ["question", "complaint", "suggestion", "information", "request", "other"]
        if analysis_result["category"] not in valid_categories:
            analysis_result["category"] = "other"
        
        logger.info(f"Gemini analysis completed: sentiment={analysis_result['sentiment']}, urgency={analysis_result['urgency_score']}")
        
        return analysis_result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini JSON response: {e}")
        logger.error(f"Raw response: {response.text if 'response' in locals() else 'No response'}")
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
    """Get recent processed insights from BigQuery"""
    try:
        query = f"""
        SELECT 
            message_id,
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
            COUNT(DISTINCT chat_id) as unique_chats,
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
                "unique_chats": int(row.unique_chats) if row.unique_chats else 0,
                "unique_users": int(row.unique_users) if row.unique_users else 0
            }
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "unique_chats": 0,
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
            "unique_chats": 0,
            "unique_users": 0
        }

async def reprocess_single_message(message_id: str):
    """Background task to reprocess a single message"""
    try:
        logger.info(f"Reprocessing message {message_id}")
        
        # Query for the original message
        query = f"""
        SELECT message_text, chat_id, user_id, username, message_date
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        WHERE message_id = @message_id
        LIMIT 1
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("message_id", "STRING", message_id)
            ]
        )
        
        query_job = bq_client.query(query, job_config=job_config)
        row = next(iter(query_job), None)
        
        if not row:
            logger.error(f"Message {message_id} not found for reprocessing")
            return
        
        # Reanalyze with Gemini
        analysis_result = await analyze_with_gemini(row.message_text)
        
        # Update the record
        update_query = f"""
        UPDATE `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        SET 
            gemini_analysis = @analysis,
            sentiment = @sentiment,
            key_topics = @topics,
            urgency_score = @urgency,
            category = @category,
            processed_date = @processed_date
        WHERE message_id = @message_id
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("message_id", "STRING", message_id),
                bigquery.ScalarQueryParameter("analysis", "STRING", analysis_result["gemini_analysis"]),
                bigquery.ScalarQueryParameter("sentiment", "STRING", analysis_result["sentiment"]),
                bigquery.ArrayQueryParameter("topics", "STRING", analysis_result["key_topics"]),
                bigquery.ScalarQueryParameter("urgency", "FLOAT", analysis_result["urgency_score"]),
                bigquery.ScalarQueryParameter("category", "STRING", analysis_result["category"]),
                bigquery.ScalarQueryParameter("processed_date", "TIMESTAMP", datetime.now())
            ]
        )
        
        query_job = bq_client.query(update_query, job_config=job_config)
        query_job.result()  # Wait for completion
        
        logger.info(f"Successfully reprocessed message {message_id}")
        
    except Exception as e:
        logger.error(f"Failed to reprocess message {message_id}: {e}")
