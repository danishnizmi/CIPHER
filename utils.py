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
DATASET_ID = "telegram_data"
TABLE_ID = "processed_messages"

# Initialize Vertex AI
vertexai.init(project=PROJECT_ID, location="us-central1")
gemini_model = GenerativeModel("gemini-1.5-flash")

async def get_secret(secret_id: str) -> str:
    """Get secret from Secret Manager"""
    try:
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.error(f"Failed to get secret {secret_id}: {e}")
        raise

async def setup_bigquery_tables():
    """Initialize BigQuery dataset and tables"""
    try:
        # Create dataset if not exists
        dataset_ref = bq_client.dataset(DATASET_ID)
        try:
            bq_client.get_dataset(dataset_ref)
        except:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset {DATASET_ID}")

        # Create table schema
        schema = [
            bigquery.SchemaField("message_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("chat_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("user_id", "STRING"),
            bigquery.SchemaField("username", "STRING"),
            bigquery.SchemaField("message_text", "STRING"),
            bigquery.SchemaField("message_date", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("processed_date", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("gemini_analysis", "STRING"),
            bigquery.SchemaField("sentiment", "STRING"),
            bigquery.SchemaField("key_topics", "STRING", mode="REPEATED"),
            bigquery.SchemaField("urgency_score", "FLOAT"),
            bigquery.SchemaField("category", "STRING"),
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            bq_client.get_table(table_ref)
        except:
            table = bigquery.Table(table_ref, schema=schema)
            bq_client.create_table(table)
            logger.info(f"Created table {TABLE_ID}")

    except Exception as e:
        logger.error(f"BigQuery setup failed: {e}")
        raise

async def setup_telegram_webhook():
    """Configure Telegram webhook"""
    try:
        bot_token = await get_secret("telegram-bot-token")
        webhook_url = os.environ.get("WEBHOOK_URL")
        
        if not webhook_url:
            logger.warning("WEBHOOK_URL not set, skipping webhook setup")
            return

        url = f"https://api.telegram.org/bot{bot_token}/setWebhook"
        data = {
            "url": f"{webhook_url}/webhook/telegram",
            "allowed_updates": ["message", "edited_message"]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data) as response:
                result = await response.json()
                if result.get("ok"):
                    logger.info("Telegram webhook configured successfully")
                else:
                    logger.error(f"Failed to set webhook: {result}")
                    
    except Exception as e:
        logger.error(f"Webhook setup failed: {e}")

def verify_telegram_webhook(headers: Dict, body: bytes) -> bool:
    """Verify Telegram webhook authenticity"""
    try:
        secret_token = os.environ.get("TELEGRAM_SECRET_TOKEN")
        if not secret_token:
            return True  # Skip verification if no secret token set
            
        received_hash = headers.get("X-Telegram-Bot-Api-Secret-Token")
        if not received_hash:
            return False
            
        return hmac.compare_digest(secret_token, received_hash)
    except Exception as e:
        logger.error(f"Webhook verification failed: {e}")
        return False

async def process_telegram_message(data: Dict[str, Any]):
    """Process incoming Telegram message with Gemini AI"""
    try:
        message = data.get("message", {})
        if not message:
            return

        # Extract message data
        message_id = str(message.get("message_id"))
        chat_id = str(message.get("chat", {}).get("id"))
        user_id = str(message.get("from", {}).get("id", ""))
        username = message.get("from", {}).get("username", "")
        text = message.get("text", "")
        date = datetime.fromtimestamp(message.get("date", 0))

        if not text:
            return

        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text)
        
        # Store in BigQuery
        await store_processed_message({
            "message_id": message_id,
            "chat_id": chat_id,
            "user_id": user_id,
            "username": username,
            "message_text": text,
            "message_date": date,
            "processed_date": datetime.now(),
            **analysis_result
        })
        
        logger.info(f"Processed message {message_id}")

    except Exception as e:
        logger.error(f"Message processing failed: {e}")

async def analyze_with_gemini(text: str) -> Dict[str, Any]:
    """Analyze text with Gemini AI"""
    try:
        prompt = f"""
        Analyze the following message and provide:
        1. Sentiment (positive/negative/neutral)
        2. Key topics (list of 3-5 main topics)
        3. Urgency score (0-1, where 1 is most urgent)
        4. Category (question/complaint/suggestion/information/other)
        5. Brief analysis summary

        Message: {text}

        Respond in JSON format:
        {{
            "sentiment": "positive|negative|neutral",
            "key_topics": ["topic1", "topic2", "topic3"],
            "urgency_score": 0.0-1.0,
            "category": "category_name",
            "analysis": "brief summary"
        }}
        """

        response = await asyncio.to_thread(
            gemini_model.generate_content, prompt
        )
        
        # Parse JSON response
        result = json.loads(response.text.strip())
        
        return {
            "gemini_analysis": result.get("analysis", ""),
            "sentiment": result.get("sentiment", "neutral"),
            "key_topics": result.get("key_topics", []),
            "urgency_score": float(result.get("urgency_score", 0.0)),
            "category": result.get("category", "other")
        }

    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return {
            "gemini_analysis": f"Analysis failed: {str(e)}",
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
        
        # Insert row
        errors = bq_client.insert_rows_json(table, [data])
        
        if errors:
            logger.error(f"BigQuery insert errors: {errors}")
        else:
            logger.info(f"Stored message {data['message_id']} in BigQuery")

    except Exception as e:
        logger.error(f"BigQuery storage failed: {e}")

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
                "urgency_score": float(row.urgency_score) if row.urgency_score else 0.0,
                "category": row.category
            })
        
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
        row = next(iter(query_job))
        
        return {
            "total_messages": int(row.total_messages) if row.total_messages else 0,
            "processed_today": int(row.processed_today) if row.processed_today else 0,
            "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
            "unique_chats": int(row.unique_chats) if row.unique_chats else 0,
            "unique_users": int(row.unique_users) if row.unique_users else 0
        }

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {
            "total_messages": 0,
            "processed_today": 0,
            "avg_urgency": 0.0,
            "unique_chats": 0,
            "unique_users": 0
        }
