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
import google.generativeai as genai

logger = logging.getLogger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()

# Project configuration
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
DATASET_ID = os.environ.get("DATASET_ID", "telegram_data")
TABLE_ID = os.environ.get("TABLE_ID", "processed_messages")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

# Initialize Gemini API
gemini_api_key = None
gemini_model = None

async def initialize_gemini():
    """Initialize Gemini API with key from Secret Manager"""
    global gemini_api_key, gemini_model
    try:
        # Get API key from Secret Manager
        gemini_api_key = await get_secret("gemini-api-key")
        
        # Configure Gemini
        genai.configure(api_key=gemini_api_key)
        
        # Initialize model
        gemini_model = genai.GenerativeModel(GEMINI_MODEL)
        
        logger.info(f"Successfully initialized Gemini API with model {GEMINI_MODEL}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize Gemini API: {e}")
        logger.warning("Gemini API not available - AI analysis will be disabled")
        return False

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
            bigquery.SchemaField("confidence_score", "FLOAT", description="AI confidence in analysis"),
            bigquery.SchemaField("processing_time_ms", "INTEGER", description="Time taken to process message"),
        ]

        table_ref = dataset_ref.table(TABLE_ID)
        try:
            table = bq_client.get_table(table_ref)
            logger.info(f"Table {TABLE_ID} already exists")
        except Exception:
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "Processed Telegram messages with Gemini AI analysis"
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
            "max_connections": 40,  # Optimize for production
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
    start_time = datetime.now()
    
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
        first_name = message.get("from", {}).get("first_name", "")
        last_name = message.get("from", {}).get("last_name", "")
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

        # Skip bot commands for analysis
        if text.startswith('/'):
            logger.info(f"Message {message_id} is a bot command, skipping analysis")
            return

        logger.info(f"Processing message {message_id} from user {username or first_name or user_id}")

        # Process with Gemini AI
        analysis_result = await analyze_with_gemini(text)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Prepare data for storage
        message_data = {
            "message_id": message_id,
            "chat_id": chat_id,
            "user_id": user_id,
            "username": username or f"{first_name} {last_name}".strip(),
            "message_text": text[:4000],  # Limit text length for BigQuery
            "message_date": date,
            "processed_date": datetime.now(),
            "processing_time_ms": int(processing_time),
            **analysis_result
        }
        
        # Store in BigQuery
        await store_processed_message(message_data)
        
        logger.info(f"Successfully processed message {message_id} in {processing_time:.0f}ms")

    except Exception as e:
        logger.error(f"Message processing failed: {e}")

async def analyze_with_gemini(text: str) -> Dict[str, Any]:
    """Analyze text with Gemini AI"""
    start_time = datetime.now()
    
    try:
        # Initialize Gemini if not already done
        if gemini_model is None:
            gemini_initialized = await initialize_gemini()
            if not gemini_initialized:
                return get_fallback_analysis(text, "Gemini API not initialized")

        # Create a comprehensive prompt for analysis
        prompt = f"""
Analyze this Telegram message and respond with ONLY a valid JSON object:

Message: "{text}"

Provide analysis in this exact JSON format:
{{
    "sentiment": "positive|negative|neutral",
    "key_topics": ["topic1", "topic2", "topic3"],
    "urgency_score": 0.8,
    "category": "question|complaint|suggestion|information|request|praise|other",
    "confidence_score": 0.9,
    "analysis": "Brief 1-2 sentence summary"
}}

Analysis guidelines:
- sentiment: Based on emotional tone and language
- key_topics: 2-5 main themes/subjects (lowercase, no special chars)
- urgency_score: 0.0-1.0 based on time sensitivity, problems, requests for help
- category: Most appropriate category for the message type
- confidence_score: 0.0-1.0 how confident you are in this analysis
- analysis: Concise summary under 200 characters

Urgency indicators: "urgent", "asap", "emergency", "help", "problem", "broken", "not working"
High urgency: Problems, emergencies, time-sensitive requests
Medium urgency: Questions, requests, complaints
Low urgency: Information, praise, casual conversation

Respond ONLY with the JSON object, no other text.
"""

        # Generate content using Gemini
        response = await asyncio.to_thread(
            gemini_model.generate_content,
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,  # Lower temperature for consistent JSON
                top_p=0.8,
                max_output_tokens=500,
                candidate_count=1,
            )
        )
        
        if not response or not response.text:
            return get_fallback_analysis(text, "Empty response from Gemini")
        
        # Clean and parse JSON response
        response_text = response.text.strip()
        
        # Remove any markdown formatting
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Parse JSON
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                raise ValueError("No valid JSON found in response")
        
        # Validate and clean the result
        analysis_result = {
            "gemini_analysis": str(result.get("analysis", "Analysis completed"))[:500],
            "sentiment": validate_sentiment(result.get("sentiment", "neutral")),
            "key_topics": validate_topics(result.get("key_topics", [])),
            "urgency_score": validate_score(result.get("urgency_score", 0.0)),
            "category": validate_category(result.get("category", "other")),
            "confidence_score": validate_score(result.get("confidence_score", 0.5))
        }
        
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        logger.info(f"Gemini analysis completed in {processing_time:.0f}ms: sentiment={analysis_result['sentiment']}, urgency={analysis_result['urgency_score']}")
        
        return analysis_result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini JSON response: {e}")
        logger.error(f"Raw response: {response.text if 'response' in locals() else 'No response'}")
        return get_fallback_analysis(text, f"JSON parsing failed: {str(e)}")
        
    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return get_fallback_analysis(text, f"Analysis failed: {str(e)}")

def get_fallback_analysis(text: str, error_msg: str) -> Dict[str, Any]:
    """Provide fallback analysis when Gemini is unavailable"""
    # Simple rule-based analysis
    text_lower = text.lower()
    
    # Basic sentiment analysis
    positive_words = ["good", "great", "excellent", "amazing", "love", "perfect", "thanks", "thank you"]
    negative_words = ["bad", "terrible", "awful", "hate", "broken", "problem", "issue", "error", "fail"]
    
    positive_count = sum(1 for word in positive_words if word in text_lower)
    negative_count = sum(1 for word in negative_words if word in text_lower)
    
    if positive_count > negative_count:
        sentiment = "positive"
    elif negative_count > positive_count:
        sentiment = "negative"
    else:
        sentiment = "neutral"
    
    # Basic urgency detection
    urgent_words = ["urgent", "asap", "emergency", "help", "problem", "broken", "not working", "issue"]
    urgency_score = min(1.0, sum(0.3 for word in urgent_words if word in text_lower))
    
    # Basic category detection
    if "?" in text:
        category = "question"
    elif any(word in text_lower for word in ["problem", "issue", "broken", "not working"]):
        category = "complaint"
    elif any(word in text_lower for word in ["suggest", "recommend", "should", "could"]):
        category = "suggestion"
    else:
        category = "information"
    
    return {
        "gemini_analysis": f"Fallback analysis: {error_msg[:200]}",
        "sentiment": sentiment,
        "key_topics": extract_simple_topics(text),
        "urgency_score": urgency_score,
        "category": category,
        "confidence_score": 0.3  # Low confidence for fallback
    }

def extract_simple_topics(text: str) -> List[str]:
    """Extract simple topics from text using basic rules"""
    import re
    
    # Remove common words and extract meaningful terms
    common_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were", "be", "been", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "can", "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them", "my", "your", "his", "her", "its", "our", "their"}
    
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    topics = [word for word in words if word not in common_words]
    
    # Return up to 5 most relevant topics
    return topics[:5]

def validate_sentiment(sentiment: str) -> str:
    """Validate sentiment value"""
    valid_sentiments = ["positive", "negative", "neutral"]
    return sentiment.lower() if sentiment.lower() in valid_sentiments else "neutral"

def validate_category(category: str) -> str:
    """Validate category value"""
    valid_categories = ["question", "complaint", "suggestion", "information", "request", "praise", "other"]
    return category.lower() if category.lower() in valid_categories else "other"

def validate_topics(topics: List) -> List[str]:
    """Validate and clean topics list"""
    if not isinstance(topics, list):
        return []
    
    cleaned_topics = []
    for topic in topics[:10]:  # Limit to 10 topics
        if isinstance(topic, str) and len(topic.strip()) > 0:
            # Clean topic: lowercase, alphanumeric only, max 50 chars
            clean_topic = re.sub(r'[^a-zA-Z0-9\s]', '', str(topic))[:50].strip().lower()
            if clean_topic and len(clean_topic) > 2:
                cleaned_topics.append(clean_topic)
    
    return cleaned_topics

def validate_score(score: Any) -> float:
    """Validate and clamp score to 0.0-1.0 range"""
    try:
        score_float = float(score)
        return max(0.0, min(1.0, score_float))
    except (ValueError, TypeError):
        return 0.0

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
            category,
            confidence_score,
            processing_time_ms
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
                "category": row.category,
                "confidence_score": float(row.confidence_score) if row.confidence_score is not None else 0.0,
                "processing_time_ms": int(row.processing_time_ms) if row.processing_time_ms else 0
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
            AVG(confidence_score) as avg_confidence,
            AVG(processing_time_ms) as avg_processing_time,
            COUNT(DISTINCT chat_id) as unique_chats,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(CASE WHEN sentiment = 'positive' THEN 1 END) as positive_messages,
            COUNT(CASE WHEN sentiment = 'negative' THEN 1 END) as negative_messages,
            COUNT(CASE WHEN urgency_score > 0.7 THEN 1 END) as high_urgency_messages
        FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        """
        
        query_job = bq_client.query(query)
        row = next(iter(query_job), None)
        
        if row:
            stats = {
                "total_messages": int(row.total_messages) if row.total_messages else 0,
                "processed_today": int(row.processed_today) if row.processed_today else 0,
                "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
                "avg_confidence": float(row.avg_confidence) if row.avg_confidence else 0.0,
                "avg_processing_time": float(row.avg_processing_time) if row.avg_processing_time else 0.0,
                "unique_chats": int(row.unique_chats) if row.unique_chats else 0,
                "unique_users": int(row.unique_users) if row.unique_users else 0,
                "positive_messages": int(row.positive_messages) if row.positive_messages else 0,
                "negative_messages": int(row.negative_messages) if row.negative_messages else 0,
                "high_urgency_messages": int(row.high_urgency_messages) if row.high_urgency_messages else 0
            }
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "avg_confidence": 0.0,
                "avg_processing_time": 0.0,
                "unique_chats": 0,
                "unique_users": 0,
                "positive_messages": 0,
                "negative_messages": 0,
                "high_urgency_messages": 0
            }
        
        logger.info(f"Retrieved stats: {stats['total_messages']} total messages, {stats['processed_today']} today")
        return stats

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return {
            "total_messages": 0,
            "processed_today": 0,
            "avg_urgency": 0.0,
            "avg_confidence": 0.0,
            "avg_processing_time": 0.0,
            "unique_chats": 0,
            "unique_users": 0,
            "positive_messages": 0,
            "negative_messages": 0,
            "high_urgency_messages": 0
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
        start_time = datetime.now()
        analysis_result = await analyze_with_gemini(row.message_text)
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Update the record
        update_query = f"""
        UPDATE `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}`
        SET 
            gemini_analysis = @analysis,
            sentiment = @sentiment,
            key_topics = @topics,
            urgency_score = @urgency,
            category = @category,
            confidence_score = @confidence,
            processing_time_ms = @processing_time,
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
                bigquery.ScalarQueryParameter("confidence", "FLOAT", analysis_result["confidence_score"]),
                bigquery.ScalarQueryParameter("processing_time", "INTEGER", int(processing_time)),
                bigquery.ScalarQueryParameter("processed_date", "TIMESTAMP", datetime.now())
            ]
        )
        
        query_job = bq_client.query(update_query, job_config=job_config)
        query_job.result()  # Wait for completion
        
        logger.info(f"Successfully reprocessed message {message_id}")
        
    except Exception as e:
        logger.error(f"Failed to reprocess message {message_id}: {e}")

# Import regex for topic validation
import re
