"""
Threat Intelligence Platform - Analysis Module
Processes threat data, extracts IOCs, and generates insights using Vertex AI.
Streamlined implementation with efficient batching and cost controls.
"""

import os
import re
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from functools import lru_cache, wraps

# Import config module for centralized configuration
import config

# Configure logging with consistent format
logging = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Core configuration from config module
PROJECT_ID = config.project_id
REGION = config.region
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-analysis-events")
MODEL_NAME = os.environ.get("VERTEX_MODEL", "text-bison")

# AI rate limiting to avoid excessive costs
# Reduced limits to control costs
AI_DAILY_QUOTA = int(os.environ.get("AI_DAILY_QUOTA", "50"))  # Max AI requests per day
AI_ANALYSIS_RATE_LIMIT = 5  # Max analyses per minute
AI_MIN_TIME_BETWEEN_CALLS = 12  # Increased seconds between AI calls
_last_ai_call_time = 0
_ai_calls_in_minute = 0
_ai_minute_start = 0
_ai_daily_calls = 0
_ai_day_start = 0

# IOC regex patterns
IOC_PATTERNS = {
    "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%/.]*)*',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
}

# ======== Utility Functions ========

def rate_limited_ai(func):
    """Decorator for rate limiting AI analysis calls with daily quota"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _last_ai_call_time, _ai_calls_in_minute, _ai_minute_start
        global _ai_daily_calls, _ai_day_start
        
        current_time = time.time()
        current_date = datetime.now().date()
        
        # Reset daily counter if day has changed
        current_day_timestamp = datetime.combine(current_date, datetime.min.time()).timestamp()
        if current_day_timestamp != _ai_day_start:
            _ai_day_start = current_day_timestamp
            _ai_daily_calls = 0
        
        # Check daily quota
        if _ai_daily_calls >= AI_DAILY_QUOTA:
            logging.warning(f"AI analysis daily quota reached ({AI_DAILY_QUOTA}/day). Using fallback.")
            content = kwargs.get('content', args[0] if len(args) > 0 else "")
            metadata = kwargs.get('metadata', args[1] if len(args) > 1 else {})
            return _generate_fallback_analysis(content, metadata)
        
        # Reset minute counter if a minute has passed
        if current_time - _ai_minute_start > 60:
            _ai_minute_start = current_time
            _ai_calls_in_minute = 0
        
        # Check rate limit
        if _ai_calls_in_minute >= AI_ANALYSIS_RATE_LIMIT:
            logging.warning(f"AI analysis rate limit reached ({AI_ANALYSIS_RATE_LIMIT}/minute). Using fallback.")
            content = kwargs.get('content', args[0] if len(args) > 0 else "")
            metadata = kwargs.get('metadata', args[1] if len(args) > 1 else {})
            return _generate_fallback_analysis(content, metadata)
        
        # Check time between calls
        time_since_last = current_time - _last_ai_call_time
        if time_since_last < AI_MIN_TIME_BETWEEN_CALLS:
            sleep_time = AI_MIN_TIME_BETWEEN_CALLS - time_since_last
            logging.info(f"Rate limiting AI call: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        # Update tracking variables
        _last_ai_call_time = time.time()
        _ai_calls_in_minute += 1
        _ai_daily_calls += 1
        
        # Log AI usage metrics
        logging.info(f"AI usage - Daily: {_ai_daily_calls}/{AI_DAILY_QUOTA}, Minute: {_ai_calls_in_minute}/{AI_ANALYSIS_RATE_LIMIT}")
        
        # Call the function
        return func(*args, **kwargs)
    
    return wrapper

def exponential_backoff_retry(max_retries=3, base_delay=1.0):
    """Decorator for exponential backoff retry"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for retry in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retry >= max_retries - 1:
                        logging.error(f"Failed after {retry+1} retries: {str(e)}")
                        raise
                    
                    wait_time = base_delay * (2 ** retry)
                    logging.warning(f"Retry {retry+1}/{max_retries} after error: {str(e)}, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
        return wrapper
    return decorator

def get_client(client_type: str) -> Any:
    """Get or initialize a Google Cloud client from config module."""
    return config.get_client(client_type)

def extract_json_from_text(text: str) -> Optional[str]:
    """Extract JSON object from text response"""
    if not text:
        return None
        
    text = text.strip()
    start_idx = text.find('{')
    end_idx = text.rfind('}') + 1
    
    if start_idx >= 0 and end_idx > start_idx:
        return text[start_idx:end_idx]
    return None

@exponential_backoff_retry(max_retries=3, base_delay=2.0)
def publish_event(data: Dict[str, Any]) -> bool:
    """Publish event to Pub/Sub with retry"""
    pubsub_client = get_client('pubsub')
    if isinstance(pubsub_client, config.DummyClient):
        return False
    
    topic_path = pubsub_client.topic_path(PROJECT_ID, PUBSUB_TOPIC)
    json_data = json.dumps(data).encode("utf-8")
    
    future = pubsub_client.publish(topic_path, data=json_data)
    message_id = future.result(timeout=30)
    logging.info(f"Published event {message_id} to {PUBSUB_TOPIC}")
    return True

@exponential_backoff_retry(max_retries=3, base_delay=2.0)
def query_bigquery(query: str, params: Optional[Dict] = None) -> List[Dict]:
    """Execute a BigQuery query with parameters"""
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        return []
        
    try:
        # Import locally to avoid global dependency
        from google.cloud import bigquery
        
        job_config = None
        if params:
            job_config = bigquery.QueryJobConfig()
            # Create query parameters
            query_params = []
            for key, value in params.items():
                if isinstance(value, int):
                    query_params.append(bigquery.ScalarQueryParameter(key, "INT64", value))
                elif isinstance(value, float):
                    query_params.append(bigquery.ScalarQueryParameter(key, "FLOAT64", value))
                elif isinstance(value, bool):
                    query_params.append(bigquery.ScalarQueryParameter(key, "BOOL", value))
                elif isinstance(value, datetime):
                    query_params.append(bigquery.ScalarQueryParameter(key, "TIMESTAMP", value))
                else:
                    query_params.append(bigquery.ScalarQueryParameter(key, "STRING", value))
            
            job_config.query_parameters = query_params
            
        query_job = client.query(query, job_config=job_config)
        return [dict(row) for row in query_job.result()]
    except Exception as e:
        logging.error(f"BigQuery query error: {str(e)}")
        raise

@exponential_backoff_retry(max_retries=3, base_delay=2.0)
def insert_into_bigquery(table_id: str, rows: List[Dict]) -> bool:
    """Insert rows into BigQuery with schema validation"""
    if not rows:
        return True
        
    client = get_client('bigquery')
    if isinstance(client, config.DummyClient):
        return False
    
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    try:
        # Process rows to ensure JSON compatibility
        processed_rows = []
        for row in rows:
            processed_row = {}
            for k, v in row.items():
                # Format datetime fields
                if isinstance(v, datetime):
                    processed_row[k] = v.isoformat()
                # Serialize JSON fields
                elif isinstance(v, (dict, list)):
                    processed_row[k] = json.dumps(v)
                else:
                    processed_row[k] = v
            processed_rows.append(processed_row)
        
        # Insert rows
        errors = client.insert_rows_json(full_table_id, processed_rows)
        
        if not errors:
            return True
        else:
            logging.error(f"Errors inserting rows: {errors}")
            
            # Try to update schema and insert again
            try:
                table = client.get_table(full_table_id)
                current_schema = {field.name: field for field in table.schema}
                
                # Find missing fields
                missing_fields = []
                for row in processed_rows:
                    for field in row:
                        if field not in current_schema:
                            missing_fields.append(bigquery.SchemaField(field, "STRING"))
                
                if missing_fields:
                    # Update schema
                    new_schema = list(table.schema) + missing_fields
                    table.schema = new_schema
                    client.update_table(table, ["schema"])
                    logging.info(f"Updated schema for {full_table_id}")
                    
                    # Try insert again
                    errors = client.insert_rows_json(full_table_id, processed_rows)
                    return not errors
            except Exception as e:
                logging.error(f"Schema update error: {str(e)}")
        
    except Exception as e:
        logging.error(f"Error inserting into BigQuery: {str(e)}")
    
    return False

# ======== IOC Processing Functions ========

def extract_iocs(content: Union[str, Dict], content_type: str = "text") -> List[Dict]:
    """Extract IOCs from different content types"""
    if not content:
        return []
        
    results = []
    timestamp = datetime.utcnow().isoformat()
    
    # Extract from text content
    if content_type == "text":
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, content)
            for value in matches:
                results.append({"value": value, "type": ioc_type, "timestamp": timestamp})
    
    # Extract from CSV content
    elif content_type == "csv":
        import csv
        import io
        
        try:
            csv_reader = csv.reader(io.StringIO(content))
            headers = next(csv_reader, [])
            
            if headers:
                for row_idx, row in enumerate(csv_reader, start=2):
                    if not row or len(row) == 0:
                        continue
                        
                    for col_idx, cell in enumerate(row):
                        if cell:
                            for ioc_type, pattern in IOC_PATTERNS.items():
                                if re.match(pattern, cell):
                                    col_name = headers[col_idx] if col_idx < len(headers) else f"column_{col_idx}"
                                    results.append({
                                        "value": cell, "type": ioc_type, "source_row": row_idx,
                                        "source_column": col_name, "timestamp": timestamp
                                    })
        except Exception as e:
            logging.error(f"Error extracting IOCs from CSV: {str(e)}")
    
    # Extract from JSON content
    elif content_type == "json":
        def process_json_item(item, path=""):
            if isinstance(item, dict):
                for key, value in item.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, (dict, list)):
                        process_json_item(value, current_path)
                    elif isinstance(value, str):
                        for ioc_type, pattern in IOC_PATTERNS.items():
                            if re.match(pattern, value):
                                results.append({
                                    "value": value, "type": ioc_type,
                                    "path": current_path, "timestamp": timestamp
                                })
            elif isinstance(item, list):
                for i, value in enumerate(item):
                    process_json_item(value, f"{path}[{i}]")
                    
        process_json_item(content)
    
    # Remove duplicates while preserving order
    unique_results = []
    seen = set()
    for ioc in results:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_results.append(ioc)
    
    return unique_results

def enrich_ioc(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich an IOC with additional context"""
    if not ioc or "value" not in ioc or "type" not in ioc:
        return ioc
        
    enriched = ioc.copy()
    if "timestamp" not in enriched:
        enriched["timestamp"] = datetime.utcnow().isoformat()
    
    # Perform enrichment based on IOC type
    ioc_type, ioc_value = ioc["type"], ioc["value"]
    
    if ioc_type == "ip":
        # Basic geo classification for IPs
        if (ioc_value.startswith('10.') or 
            ioc_value.startswith('192.168.') or 
            (ioc_value.startswith('172.') and 16 <= int(ioc_value.split('.')[1]) <= 31)):
            enriched["geo"] = {"country": "Private", "city": "Internal"}
        else:
            enriched["geo"] = {"country": "Unknown", "city": "Unknown"}
    
    # Add severity assessment based on a simplified model
    if "context" in enriched and isinstance(enriched["context"], dict):
        context_str = str(enriched["context"]).lower()
        if any(kw in context_str for kw in ["critical", "ransomware", "backdoor", "exploit"]):
            enriched["severity"] = "high"
        elif any(kw in context_str for kw in ["suspicious", "malware", "trojan"]):
            enriched["severity"] = "medium"
        else:
            enriched["severity"] = "low"
    else:
        # Default severity based on IOC type
        if ioc_type in ["md5", "sha1", "sha256"]:
            enriched["severity"] = "medium"  # Hash-based IOCs default to medium
        elif ioc_type == "url" and any(kw in ioc_value.lower() for kw in ["malware", "trojan", "hack", "phish"]):
            enriched["severity"] = "high"   # Suspicious URLs
        else:
            enriched["severity"] = "low"    # Everything else defaults to low
    
    # Add confidence level
    if "confidence" not in enriched:
        enriched["confidence"] = "medium"
    
    return enriched

# ======== AI Analysis Functions ========

@lru_cache(maxsize=5)
def get_vertex_model():
    """Get Vertex AI model with proper caching and error handling"""
    try:
        vertex_initialized = get_client('vertex')
        if not vertex_initialized:
            logging.warning("Vertex AI not available")
            return None
        
        from vertexai.language_models import TextGenerationModel
        model = TextGenerationModel.from_pretrained(MODEL_NAME)
        logging.info(f"Vertex AI model {MODEL_NAME} loaded successfully")
        return model
    except Exception as e:
        logging.error(f"Failed to load Vertex AI model: {str(e)}")
        return None

@rate_limited_ai
def analyze_with_vertex_ai(content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Analyze threat data using Vertex AI LLM with efficient caching and error handling"""
    if not content:
        return {}
    
    # Get cached model or initialize
    model = get_vertex_model()
    if not model:
        logging.warning("Vertex AI model not available, using fallback")
        return _generate_fallback_analysis(content, metadata)
    
    # Truncate content to reduce token usage and costs
    if len(content) > 4000:
        logging.info(f"Truncating content from {len(content)} to 4000 chars to reduce costs")
        content = content[:4000]
    
    # Construct prompt for threat analysis
    prompt = f"""
    You are a threat intelligence analyst. Analyze the following threat intelligence data and extract key information:
    
    {content}
    
    Provide a structured analysis with the following information:
    1. A brief summary of the threat (2-3 sentences)
    2. The threat actor or group responsible (if mentioned)
    3. Targeted sectors or regions (if mentioned)
    4. Attack techniques used (MITRE ATT&CK techniques if possible)
    5. Malware families involved (if mentioned)
    6. Severity assessment (Low, Medium, High, Critical)
    7. Confidence level in this analysis (Low, Medium, High)
    
    Format your response as JSON with these keys: summary, threat_actor, targets, techniques, malware, severity, confidence
    """
    
    try:
        logging.info("Sending content to Vertex AI for analysis")
        
        # Generate response with controlled temperature and token limit
        response = model.predict(prompt, temperature=0.1, max_output_tokens=800)
        
        # Extract JSON from response
        json_str = extract_json_from_text(response.text)
        
        if json_str:
            analysis = json.loads(json_str)
            
            # Add metadata
            source_id = metadata.get("id", "unknown") if metadata else "unknown"
            source_type = metadata.get("type", "unknown") if metadata else "unknown"
                
            analysis.update({
                "source_id": source_id,
                "source_type": source_type,
                "analysis_timestamp": datetime.utcnow().isoformat()
            })
            
            return analysis
        else:
            logging.warning("Could not find JSON in Vertex AI response")
            # Return partial results based on text response
            return {
                "summary": response.text[:500],
                "confidence": "Low",
                "severity": "Medium",
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "source_id": metadata.get("id", "unknown") if metadata else "unknown",
                "source_type": metadata.get("type", "unknown") if metadata else "unknown"
            }
    except Exception as e:
        logging.error(f"Error analyzing with Vertex AI: {str(e)}")
        return _generate_fallback_analysis(content, metadata)

@rate_limited_ai
def batch_summarize_iocs(iocs: List[Dict], max_batch_size: int = 100) -> Dict[str, Any]:
    """Analyze a batch of IOCs to provide a summarized intelligence report"""
    if not iocs or len(iocs) == 0:
        return {"summary": "No IOCs provided for analysis", "confidence": "Low"}

    # Limit the batch size to control costs
    batch_size = min(len(iocs), max_batch_size)
    if len(iocs) > max_batch_size:
        logging.info(f"Truncating IOC batch from {len(iocs)} to {max_batch_size} to control costs")
        iocs = iocs[:max_batch_size]
    
    # Get model
    model = get_vertex_model()
    if not model:
        logging.warning("Vertex AI model not available, using fallback for batch summary")
        return {
            "summary": f"Analysis of {batch_size} indicators of compromise",
            "top_types": ", ".join(set(ioc.get("type", "unknown") for ioc in iocs[:10])),
            "confidence": "Low",
            "severity": "Medium",
            "ioc_count": batch_size,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
    
    # Prepare IOC content for analysis
    ioc_content = "\n".join([
        f"- Type: {ioc.get('type', 'unknown')}, Value: {ioc.get('value', 'unknown')}" 
        for ioc in iocs[:batch_size]
    ])
    
    # Construct a focused prompt
    prompt = f"""
    You are a threat intelligence analyst. Analyze this batch of {batch_size} indicators of compromise (IOCs):
    
    {ioc_content}
    
    Provide a concise intelligence summary that includes:
    1. Overall threat patterns and trends visible in these IOCs (2-3 sentences)
    2. Most common IOC types and their significance
    3. Any notable threat groups or campaigns that might be associated
    4. Any inferred attack vectors or techniques
    5. Overall threat severity assessment (Low, Medium, High, Critical)
    
    Format your response as JSON with these keys: summary, common_types, possible_actors, attack_vectors, severity, confidence
    """
    
    try:
        logging.info(f"Sending batch of {batch_size} IOCs to Vertex AI for summarization")
        
        # Generate response with controlled parameters to reduce costs
        response = model.predict(prompt, temperature=0.1, max_output_tokens=800)
        
        # Extract JSON from response
        json_str = extract_json_from_text(response.text)
        
        if json_str:
            analysis = json.loads(json_str)
            
            # Add metadata
            analysis.update({
                "ioc_count": batch_size,
                "analysis_timestamp": datetime.utcnow().isoformat()
            })
            
            return analysis
        else:
            logging.warning("Could not find JSON in Vertex AI batch summary response")
            # Return partial results
            return {
                "summary": response.text[:500],
                "ioc_count": batch_size,
                "confidence": "Low",
                "severity": "Medium",
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logging.error(f"Error in batch IOC summarization: {str(e)}")
        return {
            "summary": f"Analysis of {batch_size} indicators of compromise",
            "top_types": ", ".join(set(ioc.get("type", "unknown") for ioc in iocs[:10])),
            "confidence": "Low",
            "severity": "Medium",
            "ioc_count": batch_size,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@rate_limited_ai
def summarize_recent_intel(days: int = 7) -> Dict[str, Any]:
    """Summarize recent threat intelligence data"""
    # Query for recent IOCs
    query = f"""
    WITH recent_iocs AS (
        SELECT
            JSON_EXTRACT_SCALAR(ioc_item, '$.type') AS type,
            JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS value,
            source_type,
            analysis_timestamp
        FROM
            `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
            UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
        WHERE 
            analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
    )
    SELECT * FROM recent_iocs
    ORDER BY analysis_timestamp DESC
    LIMIT 100
    """
    
    try:
        rows = query_bigquery(query)
        
        if not rows or len(rows) == 0:
            return {
                "summary": f"No recent threat intelligence data found in the past {days} days.",
                "ioc_count": 0,
                "period_days": days,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
        
        # Convert rows to IOC format
        iocs = []
        for row in rows:
            iocs.append({
                "type": row.get("type"),
                "value": row.get("value"),
                "source": row.get("source_type")
            })
        
        # Use batch summarize function to analyze
        result = batch_summarize_iocs(iocs)
        
        # Add period information
        result["period_days"] = days
        
        # Query for some key statistics
        stats_query = f"""
        SELECT
            COUNT(DISTINCT JSON_EXTRACT_SCALAR(ioc_item, '$.value')) as unique_iocs,
            COUNT(DISTINCT source_id) as sources,
            COUNT(DISTINCT source_type) as feed_types
        FROM
            `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
            UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
        WHERE 
            analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        """
        
        stats_rows = query_bigquery(stats_query)
        if stats_rows and len(stats_rows) > 0:
            result["total_iocs"] = stats_rows[0].get("unique_iocs", 0)
            result["total_sources"] = stats_rows[0].get("sources", 0)
            result["feed_types"] = stats_rows[0].get("feed_types", 0)
        
        return result
        
    except Exception as e:
        logging.error(f"Error summarizing recent intel: {str(e)}")
        return {
            "summary": f"Error summarizing recent threat intelligence from the past {days} days: {str(e)}",
            "ioc_count": 0,
            "period_days": days, 
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

def _generate_fallback_analysis(content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Generate fallback analysis when Vertex AI is unavailable"""
    logging.info("Using fallback analysis method (rule-based)")
    
    # Simple keyword-based severity assessment
    severity = "Medium"  # Default severity
    
    content_lower = content.lower() if content else ""
    if any(word in content_lower for word in ["critical", "ransomware", "backdoor", "zero-day", "0day"]):
        severity = "Critical"
    elif any(word in content_lower for word in ["high", "exploit", "leaked", "vulnerability", "trojan"]):
        severity = "High"
    
    # Extract threat actors using simple pattern matching
    threat_actor = "Unknown"
    actor_patterns = [
        r'(?:threat|threat\s+actor|actor|group|apt):\s*([A-Za-z0-9\s\-_]+)',
        r'attributed\s+to\s+([A-Za-z0-9\s\-_]+)',
        r'(?:APT|group)\s*([0-9]+)'
    ]
    
    for pattern in actor_patterns:
        matches = re.search(pattern, content, re.IGNORECASE) if content else None
        if matches:
            threat_actor = matches.group(1).strip()
            break
    
    # Basic summary extraction - first 1-2 sentences
    summary = ""
    if content:
        sentences = re.split(r'(?<=[.!?])\s+', content)
        summary = " ".join(sentences[:min(2, len(sentences))])
    
    # Create analysis object
    source_id = metadata.get("id", "unknown") if metadata else "unknown"
    source_type = metadata.get("type", "unknown") if metadata else "unknown"
    
    return {
        "summary": summary[:500] if summary else "No content provided for analysis",
        "threat_actor": threat_actor,
        "targets": "Unknown",
        "techniques": "Unknown",
        "malware": "Unknown",
        "severity": severity,
        "confidence": "Low",
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "source_id": source_id,
        "source_type": source_type,
        "fallback": True
    }

# ======== Main Analysis Class ========

class ThreatAnalyzer:
    """Unified threat analysis with optimized GCP integration"""
    
    def __init__(self):
        """Initialize analyzer and ensure resources"""
        self._ensure_tables()
    
    def _ensure_tables(self):
        """Ensure required BigQuery tables exist"""
        client = get_client('bigquery')
        if isinstance(client, config.DummyClient):
            logging.warning("BigQuery not available, cannot ensure tables")
            return
            
        try:
            from google.cloud import bigquery
            from google.cloud.exceptions import NotFound
            
            # Define tables to create if they don't exist
            tables = {
                "threat_analysis": [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("confidence", "STRING")
                ],
                "threat_summaries": [
                    bigquery.SchemaField("summary_id", "STRING"),
                    bigquery.SchemaField("summary_type", "STRING"),
                    bigquery.SchemaField("summary", "STRING"),
                    bigquery.SchemaField("data", "STRING"),
                    bigquery.SchemaField("period_days", "INTEGER"),
                    bigquery.SchemaField("ioc_count", "INTEGER"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("confidence", "STRING"),
                    bigquery.SchemaField("timestamp", "TIMESTAMP")
                ],
                "threat_campaigns": [
                    bigquery.SchemaField("campaign_id", "STRING"),
                    bigquery.SchemaField("campaign_name", "STRING"),
                    bigquery.SchemaField("threat_actor", "STRING"),
                    bigquery.SchemaField("malware", "STRING"),
                    bigquery.SchemaField("techniques", "STRING"),
                    bigquery.SchemaField("targets", "STRING"),
                    bigquery.SchemaField("severity", "STRING"),
                    bigquery.SchemaField("sources", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("source_count", "INTEGER"),
                    bigquery.SchemaField("ioc_count", "INTEGER"),
                    bigquery.SchemaField("first_seen", "STRING"),
                    bigquery.SchemaField("last_seen", "STRING"),
                    bigquery.SchemaField("detection_timestamp", "STRING")
                ]
            }
            
            # Check and create tables as needed
            for table_name, schema in tables.items():
                full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_name}"
                try:
                    client.get_table(full_table_id)
                    logging.info(f"Table {table_name} already exists")
                except NotFound:
                    table = bigquery.Table(full_table_id, schema=schema)
                    client.create_table(table, exists_ok=True)
                    logging.info(f"Created table {table_name}")
        except Exception as e:
            logging.error(f"Error ensuring tables: {str(e)}")
    
    def analyze_feed_data(self, feed_name: str, days_back: int = 7) -> Dict[str, Any]:
        """Analyze threat data from a specific feed"""
        logging.info(f"Analyzing feed {feed_name} for past {days_back} days")
        
        # Query to get recent data from the feed
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
        WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
        LIMIT 100
        """
        
        rows = query_bigquery(query)
        
        if not rows:
            logging.warning(f"No data found for feed {feed_name}")
            return {
                "feed_name": feed_name,
                "processed_count": 0,
                "ioc_count": 0
            }
        
        # Process each row
        processed_count = 0
        ioc_count = 0
        all_iocs = []
        
        for row in rows:
            # Create a unique ID for this analysis
            row_id = row.get("id", str(hash(str(row))))
            
            # Convert row to text for IOC extraction
            content = "\n".join(f"{k}: {v}" for k, v in row.items() 
                              if k != "_ingestion_timestamp" and v)
            
            # Skip if no content
            if not content:
                continue
            
            # Extract IOCs
            is_csv = feed_name.endswith("_csv") or "csv" in feed_name
            iocs = extract_iocs(row.get("csv_content", ""), "csv") if is_csv else extract_iocs(content, "text")
            
            # Enrich IOCs
            enriched_iocs = [enrich_ioc(ioc) for ioc in iocs]
            ioc_count += len(enriched_iocs)
            all_iocs.extend(enriched_iocs)
            
            # Only perform full analysis on a sample of records to control costs
            if processed_count < 3:  # Analyze only first 3 records with Vertex AI
                # Analyze with Vertex AI
                metadata = {"id": row_id, "type": feed_name}
                vertex_analysis = analyze_with_vertex_ai(content, metadata)
                
                # Combine results
                analysis_result = {
                    "source_id": row_id,
                    "source_type": feed_name,
                    "iocs": json.dumps(enriched_iocs),
                    "vertex_analysis": json.dumps(vertex_analysis),
                    "analysis_timestamp": datetime.utcnow(),
                    "severity": vertex_analysis.get("severity", "Medium"),
                    "confidence": vertex_analysis.get("confidence", "Medium")
                }
                
                # Store in BigQuery
                insert_into_bigquery("threat_analysis", [analysis_result])
            
            processed_count += 1
            
            # Log progress periodically
            if processed_count % 10 == 0:
                logging.info(f"Processed {processed_count} items from {feed_name}")
        
        # Create a batch summary if we have enough IOCs
        if len(all_iocs) >= 5:
            summary = batch_summarize_iocs(all_iocs)
            
            # Store the summary
            summary_record = {
                "summary_id": f"{feed_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "summary_type": "feed",
                "summary": summary.get("summary", ""),
                "data": json.dumps(summary),
                "period_days": days_back,
                "ioc_count": len(all_iocs),
                "severity": summary.get("severity", "Medium"),
                "confidence": summary.get("confidence", "Medium"),
                "timestamp": datetime.utcnow()
            }
            
            insert_into_bigquery("threat_summaries", [summary_record])
        
        # Log completion
        logging.info(f"Completed processing {processed_count} items, extracted {ioc_count} IOCs from {feed_name}")
        
        # Publish event
        publish_event({
            "feed_name": feed_name,
            "processed_count": processed_count,
            "ioc_count": ioc_count,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "analysis_complete"
        })
        
        return {
            "feed_name": feed_name,
            "processed_count": processed_count,
            "ioc_count": ioc_count
        }
    
    def get_recent_summary(self, days: int = 7) -> Dict[str, Any]:
        """Get recent summary or generate if none exists"""
        # First check if we have a recent summary in the database
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_summaries`
        WHERE period_days = {days} AND summary_type = 'recent'
          AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
        ORDER BY timestamp DESC
        LIMIT 1
        """
        
        rows = query_bigquery(query)
        
        if rows and len(rows) > 0:
            # Use cached summary to avoid excessive AI costs
            row = rows[0]
            try:
                data = json.loads(row.get("data", "{}"))
                return data
            except json.JSONDecodeError:
                pass
        
        # No recent summary found, generate one
        summary = summarize_recent_intel(days)
        
        # Store the summary
        summary_record = {
            "summary_id": f"recent_{days}days_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "summary_type": "recent",
            "summary": summary.get("summary", ""),
            "data": json.dumps(summary),
            "period_days": days,
            "ioc_count": summary.get("ioc_count", 0),
            "severity": summary.get("severity", "Medium"),
            "confidence": summary.get("confidence", "Medium"),
            "timestamp": datetime.utcnow()
        }
        
        insert_into_bigquery("threat_summaries", [summary_record])
        
        return summary
    
    def analyze_ioc_batch(self, iocs: List[Dict]) -> Dict[str, Any]:
        """Analyze a batch of IOCs to provide a summarized report"""
        if not iocs or len(iocs) == 0:
            return {
                "error": "No IOCs provided for analysis",
                "ioc_count": 0
            }
        
        # Limit batch size
        max_batch = 100
        if len(iocs) > max_batch:
            logging.info(f"Limiting IOC batch from {len(iocs)} to {max_batch}")
            iocs = iocs[:max_batch]
        
        # Get batch summary
        summary = batch_summarize_iocs(iocs)
        
        # Store the summary
        summary_record = {
            "summary_id": f"batch_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "summary_type": "batch",
            "summary": summary.get("summary", ""),
            "data": json.dumps(summary),
            "period_days": 0,
            "ioc_count": len(iocs),
            "severity": summary.get("severity", "Medium"),
            "confidence": summary.get("confidence", "Medium"),
            "timestamp": datetime.utcnow()
        }
        
        insert_into_bigquery("threat_summaries", [summary_record])
        
        return summary
    
    def analyze_csv_file(self, csv_content: str, feed_name: str = "csv_upload") -> Dict[str, Any]:
        """Analyze uploaded CSV for threat intelligence"""
        if not csv_content:
            return {"error": "Empty CSV data"}
        
        try:
            # Extract IOCs
            iocs = extract_iocs(csv_content, "csv")
            
            # Enrich IOCs
            enriched_iocs = [enrich_ioc(ioc) for ioc in iocs]
            
            # Create analysis ID
            analysis_id = f"csv_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Get sample rows for AI analysis
            import csv
            import io
            
            csv_reader = csv.reader(io.StringIO(csv_content))
            headers = next(csv_reader, [])
            sample_rows = list(row for _, row in zip(range(5), csv_reader))
            
            # Create content for analysis
            content = f"CSV File Analysis: {feed_name}\n\nHeaders: {headers}\n\n"
            for i, row in enumerate(sample_rows):
                content += f"Row {i+1}: {row}\n"
            
            # Add IOC summary
            content += f"\nExtracted IOCs:\n"
            ioc_types = {}
            for ioc in enriched_iocs:
                ioc_type = ioc.get("type", "unknown")
                ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            for ioc_type, count in ioc_types.items():
                content += f"- {ioc_type}: {count}\n"
            
            # Analyze with Vertex AI
            metadata = {"id": analysis_id, "type": feed_name}
            vertex_analysis = analyze_with_vertex_ai(content, metadata)
            
            # Store result
            analysis_result = {
                "source_id": analysis_id,
                "source_type": feed_name,
                "iocs": json.dumps(enriched_iocs),
                "vertex_analysis": json.dumps(vertex_analysis),
                "analysis_timestamp": datetime.utcnow(),
                "severity": vertex_analysis.get("severity", "Medium"),
                "confidence": vertex_analysis.get("confidence", "Medium")
            }
            
            insert_into_bigquery("threat_analysis", [analysis_result])
            
            # Get batch summary for all IOCs if there are enough
            batch_summary = {}
            if len(enriched_iocs) >= 5:
                batch_summary = self.analyze_ioc_batch(enriched_iocs)
            
            # Create response
            result = {
                "analysis_id": analysis_id,
                "feed_name": feed_name,
                "iocs": enriched_iocs,
                "ioc_count": len(enriched_iocs),
                "vertex_analysis": vertex_analysis,
                "batch_summary": batch_summary,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            logging.info(f"Analyzed CSV with {len(enriched_iocs)} IOCs extracted")
            return result
        except Exception as e:
            logging.error(f"Error analyzing CSV: {str(e)}")
            return {"error": f"Analysis failed: {str(e)}"}

# ======== Main Function ========

def analyze_threat_data(event, context):
    """Cloud Function for threat data analysis"""
    analyzer = ThreatAnalyzer()
    
    # Parse message
    if hasattr(event, 'get') and event.get('data'):
        import base64
        try:
            data = json.loads(base64.b64decode(event['data']).decode('utf-8'))
            logging.info(f"Received analysis event: {data}")
            
            # Check command type
            command = data.get("command")
            
            # Handle different commands
            if command == "summarize_recent":
                days = data.get("days", 7)
                return analyzer.get_recent_summary(days)
            elif command == "analyze_batch":
                iocs = data.get("iocs", [])
                return analyzer.analyze_ioc_batch(iocs)
            elif command == "analyze_feed":
                feed_name = data.get("feed_name")
                days = data.get("days", 7)
                if feed_name:
                    return analyzer.analyze_feed_data(feed_name, days)
            elif data.get("file_type") == "csv" and "content" in data:
                return analyzer.analyze_csv_file(data["content"], data.get("feed_name", "csv_upload"))
            elif data.get("feed_name"):
                # Analyze feed data
                feed_name = data.get("feed_name")
                days = data.get("days", 7)
                return analyzer.analyze_feed_data(feed_name, days)
        except Exception as e:
            logging.error(f"Error processing event: {str(e)}")
            return {"error": str(e)}
    
    # Handle direct HTTP request (likely from frontend)
    if hasattr(event, 'get') and event.get('path'):
        request_json = event.get('json', {})
        
        # Get command type
        command = request_json.get("command", "recent_summary")
        
        # Process different commands
        if command == "recent_summary":
            days = request_json.get("days", 7)
            return analyzer.get_recent_summary(days)
        elif command == "analyze_batch":
            iocs = request_json.get("iocs", [])
            return analyzer.analyze_ioc_batch(iocs)
        elif command == "analyze_feed":
            feed_name = request_json.get("feed_name")
            days = request_json.get("days", 7)
            if feed_name:
                return analyzer.analyze_feed_data(feed_name, days)
        elif command == "analyze_csv":
            content = request_json.get("content", "")
            feed_name = request_json.get("feed_name", "csv_upload")
            return analyzer.analyze_csv_file(content, feed_name)
    
    # Fallback to analyzing a few default feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware"]
    
    results = []
    for feed in feeds:
        try:
            result = analyzer.analyze_feed_data(feed)
            results.append(result)
        except Exception as e:
            logging.error(f"Error analyzing {feed}: {str(e)}")
            results.append({
                "feed_name": feed,
                "error": str(e)
            })
    
    # Generate a recent summary
    try:
        summary = analyzer.get_recent_summary(7)
        return {"results": results, "summary": summary}
    except Exception as e:
        logging.error(f"Error generating summary: {str(e)}")
        return {"results": results, "error": str(e)}

# For direct execution
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    # Process default feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware"]
    
    for feed in feeds[:1]:  # Only process first feed to save costs when testing
        try:
            result = analyzer.analyze_feed_data(feed)
            print(f"Analyzed {feed}: {result}")
        except Exception as e:
            print(f"Error analyzing {feed}: {str(e)}")
    
    # Generate recent summary
    try:
        summary = analyzer.get_recent_summary(7)
        print(f"Recent summary: {summary.get('summary')}")
    except Exception as e:
        print(f"Error generating summary: {str(e)}")
