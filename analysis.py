"""
Threat Intelligence Platform - Analysis Module
Processes threat data, extracts IOCs, and generates insights using Vertex AI.
Streamlined implementation with optimized GCP integration.
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
AI_ANALYSIS_RATE_LIMIT = 10  # Max analyses per minute
AI_MIN_TIME_BETWEEN_CALLS = 6  # Seconds between AI calls
_last_ai_call_time = 0
_ai_calls_in_minute = 0
_ai_minute_start = 0

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
    """Decorator for rate limiting AI analysis calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _last_ai_call_time, _ai_calls_in_minute, _ai_minute_start
        
        current_time = time.time()
        
        # Reset counter if a minute has passed
        if current_time - _ai_minute_start > 60:
            _ai_minute_start = current_time
            _ai_calls_in_minute = 0
        
        # Check rate limit
        if _ai_calls_in_minute >= AI_ANALYSIS_RATE_LIMIT:
            logging.warning(f"AI analysis rate limit reached ({AI_ANALYSIS_RATE_LIMIT}/minute). Using fallback.")
            content = args[0] if len(args) > 0 else ""
            metadata = args[1] if len(args) > 1 else {}
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
    
    # Process rows to ensure JSON compatibility
    processed_rows = [{k: (v.isoformat() if isinstance(v, datetime) else 
                         json.dumps(v) if isinstance(v, (dict, list)) else v) 
                      for k, v in row.items()} for row in rows]
            
    # Try to insert rows
    errors = client.insert_rows_json(full_table_id, processed_rows)
    
    if not errors:
        return True
        
    # Handle schema mismatches
    logging.warning(f"Insert errors: {errors}")
    
    # Try to update schema
    try:
        from google.cloud import bigquery
        
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
    
    # Add severity assessment
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

@lru_cache(maxsize=100)
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
        logging.warning("Vertex AI model not available")
        return _generate_fallback_analysis(content, metadata)
    
    # Truncate content if it's too long (Vertex AI has context limits)
    if len(content) > 8000:
        logging.info(f"Truncating content from {len(content)} to 8000 chars")
        content = content[:8000]
    
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
        
        # Generate response
        response = model.predict(prompt, temperature=0.1, max_output_tokens=1024)
        
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

def _generate_fallback_analysis(content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Generate fallback analysis when Vertex AI is unavailable"""
    logging.info("Using fallback analysis method (rule-based)")
    
    # Simple keyword-based severity assessment
    severity = "Medium"  # Default severity
    
    content_lower = content.lower()
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
        matches = re.search(pattern, content, re.IGNORECASE)
        if matches:
            threat_actor = matches.group(1).strip()
            break
    
    # Basic summary extraction - first 1-2 sentences
    sentences = re.split(r'(?<=[.!?])\s+', content)
    summary = " ".join(sentences[:min(2, len(sentences))])
    
    # Create analysis object
    source_id = metadata.get("id", "unknown") if metadata else "unknown"
    source_type = metadata.get("type", "unknown") if metadata else "unknown"
    
    return {
        "summary": summary[:500],
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
        
        # Run campaign detection
        self.detect_campaigns(30)
        
        return {
            "feed_name": feed_name,
            "processed_count": processed_count,
            "ioc_count": ioc_count
        }
    
    def detect_campaigns(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Detect threat campaigns by clustering related IOCs and analyses"""
        logging.info(f"Detecting campaigns for past {days_back} days")
        
        # Query to get recent analyses
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
        """
        
        rows = query_bigquery(query)
        
        if not rows:
            logging.warning("No analysis data found for campaign detection")
            return []
        
        # Group analyses by potential campaigns
        analysis_groups = {}
        
        for row in rows:
            # Parse JSON fields
            try:
                vertex_analysis = json.loads(row.get("vertex_analysis", "{}")) if isinstance(row.get("vertex_analysis"), str) else row.get("vertex_analysis", {})
                iocs = json.loads(row.get("iocs", "[]")) if isinstance(row.get("iocs"), str) else row.get("iocs", [])
            except json.JSONDecodeError:
                vertex_analysis = {}
                iocs = []
            
            # Skip if missing key information
            if not vertex_analysis or not iocs:
                continue
            
            # Extract key campaign identifiers
            threat_actor = vertex_analysis.get("threat_actor", "").lower()
            malware = vertex_analysis.get("malware", "").lower()
            
            # Generate campaign identifiers
            campaign_identifiers = []
            
            if threat_actor and threat_actor.lower() != "unknown" and len(threat_actor) > 3:
                campaign_identifiers.append(f"actor:{threat_actor}")
            
            if malware and malware.lower() != "unknown" and len(malware) > 3:
                campaign_identifiers.append(f"malware:{malware}")
            
            # Skip if no strong identifiers
            if not campaign_identifiers:
                continue
            
            # Create a hash key for the campaign
            campaign_key = hashlib.md5(
                "|".join(sorted(campaign_identifiers)).encode()
            ).hexdigest()
            
            # Add to campaign group
            if campaign_key not in analysis_groups:
                analysis_groups[campaign_key] = {
                    "analyses": [],
                    "iocs": [],
                    "identifiers": campaign_identifiers,
                    "threat_actor": threat_actor if threat_actor.lower() != "unknown" else "",
                    "malware": malware if malware.lower() != "unknown" else "",
                    "techniques": vertex_analysis.get("techniques", ""),
                    "targets": vertex_analysis.get("targets", ""),
                    "severity": vertex_analysis.get("severity", "medium"),
                    "timestamps": []
                }
            
            analysis_groups[campaign_key]["analyses"].append(row["source_id"])
            analysis_groups[campaign_key]["iocs"].extend(iocs)
            
            # Track timestamps
            if "analysis_timestamp" in row:
                timestamp = row["analysis_timestamp"]
                if isinstance(timestamp, datetime):
                    analysis_groups[campaign_key]["timestamps"].append(timestamp)
        
        # Convert groups to campaigns
        campaigns = []
        for key, group in analysis_groups.items():
            # Skip small groups (likely false positives)
            if len(group["analyses"]) < 2:
                continue
            
            # Unique IOCs
            unique_iocs = {}
            for ioc in group["iocs"]:
                ioc_key = f"{ioc.get('type')}:{ioc.get('value')}"
                unique_iocs[ioc_key] = ioc
            
            # Calculate first and last seen
            timestamps = group["timestamps"]
            first_seen = min(timestamps) if timestamps else datetime.utcnow()
            last_seen = max(timestamps) if timestamps else datetime.utcnow()
            
            # Generate campaign name
            if group["threat_actor"]:
                prefix = group["threat_actor"].split()[0].title()
            elif group["malware"]:
                prefix = group["malware"].split()[0].title()
            else:
                prefix = "Campaign"
            
            suffix = key[:6]  # Use first 6 chars of hash
            campaign_name = f"{prefix}-{suffix}"
            
            # Create campaign
            campaign = {
                "campaign_id": key,
                "campaign_name": campaign_name,
                "threat_actor": group["threat_actor"],
                "malware": group["malware"],
                "techniques": group["techniques"],
                "targets": group["targets"],
                "severity": group["severity"],
                "sources": json.dumps(group["analyses"]),
                "iocs": json.dumps(list(unique_iocs.values())),
                "source_count": len(group["analyses"]),
                "ioc_count": len(unique_iocs),
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else first_seen,
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                "detection_timestamp": datetime.utcnow().isoformat()
            }
            
            campaigns.append(campaign)
            
            # Store campaign in BigQuery
            insert_into_bigquery("threat_campaigns", [campaign])
        
        logging.info(f"Detected {len(campaigns)} threat campaigns")
        return campaigns
    
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
            
            # Create response
            result = {
                "analysis_id": analysis_id,
                "feed_name": feed_name,
                "iocs": enriched_iocs,
                "ioc_count": len(enriched_iocs),
                "vertex_analysis": vertex_analysis,
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
    if 'data' in event:
        import base64
        try:
            data = json.loads(base64.b64decode(event['data']).decode('utf-8'))
            logging.info(f"Received analysis event: {data}")
            
            feed_name = data.get("feed_name")
            
            # Check if this is a CSV analysis request
            if data.get("file_type") == "csv" and "content" in data:
                return analyzer.analyze_csv_file(data["content"], data.get("feed_name", "csv_upload"))
            elif feed_name:
                # Analyze feed data
                result = analyzer.analyze_feed_data(feed_name)
                
                # Detect campaigns periodically
                if hash(feed_name) % 10 == 0:
                    analyzer.detect_campaigns()
                
                return result
        except Exception as e:
            logging.error(f"Error processing event: {str(e)}")
    
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
    
    # Run campaign detection
    campaigns = analyzer.detect_campaigns()
    
    return {"results": results, "campaign_count": len(campaigns)}

# For direct execution
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    # Process default feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware"]
    
    for feed in feeds:
        try:
            result = analyzer.analyze_feed_data(feed)
            print(f"Analyzed {feed}: {result}")
        except Exception as e:
            print(f"Error analyzing {feed}: {str(e)}")
    
    # Detect campaigns
    campaigns = analyzer.detect_campaigns()
    print(f"Detected {len(campaigns)} campaigns")
