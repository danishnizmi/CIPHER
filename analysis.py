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
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from functools import lru_cache

from google.cloud import bigquery
from google.cloud import pubsub_v1
import vertexai
from vertexai.language_models import TextGenerationModel

# Import config module for centralized configuration
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.environ.get('ENVIRONMENT') != 'production' else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from config module
PROJECT_ID = config.project_id
REGION = config.region
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-analysis-events")
MODEL_NAME = os.environ.get("VERTEX_MODEL", "text-bison")

# Shared GCP clients
_clients = {}

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

# Create a dummy client for graceful degradation
class DummyClient:
    """Dummy client to use when a service is unavailable"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        
    def __getattr__(self, name):
        def dummy_method(*args, **kwargs):
            logger.warning(f"{self.service_name} not available, {name} called but will return None")
            return None
        return dummy_method

# ======== Client Management ========

def get_client(client_type: str):
    """Get or initialize a Google Cloud client (lazy initialization)"""
    global _clients
    
    if client_type in _clients:
        return _clients[client_type]
    
    try:
        if client_type == 'bigquery':
            try:
                _clients[client_type] = bigquery.Client(project=PROJECT_ID)
                logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
            except Exception as e:
                logger.warning(f"BigQuery client initialization failed: {str(e)}")
                _clients[client_type] = DummyClient("BigQuery")
            
        elif client_type == 'pubsub':
            try:
                _clients[client_type] = pubsub_v1.PublisherClient()
                logger.info("Pub/Sub publisher initialized")
            except Exception as e:
                logger.warning(f"Pub/Sub client initialization failed: {str(e)}")
                _clients[client_type] = DummyClient("Pub/Sub")
            
        elif client_type == 'vertex':
            try:
                vertexai.init(project=PROJECT_ID, location=REGION)
                # Store True to indicate successful initialization
                _clients[client_type] = True
                logger.info("Vertex AI initialized successfully")
            except Exception as e:
                logger.warning(f"Vertex AI initialization failed: {str(e)}")
                _clients[client_type] = None
                
        else:
            logger.error(f"Unknown client type: {client_type}")
            return None
            
        return _clients[client_type]
    except Exception as e:
        logger.error(f"Failed to initialize {client_type} client: {str(e)}")
        return None

# ======== Utility Functions ========

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

def publish_event(data: Dict[str, Any]) -> bool:
    """Publish event to Pub/Sub with retry"""
    client = get_client('pubsub')
    if not client:
        return False
    
    try:
        topic_path = client.topic_path(PROJECT_ID, PUBSUB_TOPIC)
        json_data = json.dumps(data).encode("utf-8")
        
        # Publish with retry
        for attempt in range(3):
            try:
                future = client.publish(topic_path, data=json_data)
                message_id = future.result(timeout=30)
                logger.info(f"Published event {message_id} to {PUBSUB_TOPIC}")
                return True
            except Exception as e:
                if attempt == 2:  # Last attempt
                    raise
                logger.warning(f"Publish attempt {attempt+1} failed: {str(e)}, retrying...")
                
        return False
    except Exception as e:
        logger.error(f"Error publishing message: {str(e)}")
        return False

def query_bigquery(query: str, params: Optional[Dict] = None) -> List[Dict]:
    """Execute a BigQuery query with parameters"""
    client = get_client('bigquery')
    if not client or isinstance(client, DummyClient):
        return []
        
    try:
        job_config = bigquery.QueryJobConfig()
        if params:
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
        logger.error(f"BigQuery query error: {str(e)}")
        return []

def insert_into_bigquery(table_id: str, rows: List[Dict]) -> bool:
    """Insert rows into BigQuery with optimized error handling"""
    if not rows:
        return True
        
    client = get_client('bigquery')
    if not client or isinstance(client, DummyClient):
        return False
    
    full_table_id = f"{PROJECT_ID}.{DATASET_ID}.{table_id}"
    
    try:
        # Process rows to ensure JSON compatibility
        processed_rows = []
        for row in rows:
            processed_row = {}
            for key, value in row.items():
                if isinstance(value, datetime):
                    processed_row[key] = value.isoformat()
                elif isinstance(value, (dict, list)):
                    processed_row[key] = json.dumps(value)
                else:
                    processed_row[key] = value
            processed_rows.append(processed_row)
            
        # Try to insert rows
        errors = client.insert_rows_json(full_table_id, processed_rows)
        
        if not errors:
            return True
            
        # Handle schema mismatches
        logger.warning(f"Insert errors: {errors}")
        
        # Try to update schema
        try:
            table = client.get_table(full_table_id)
            current_schema = {field.name: field for field in table.schema}
            
            # Find missing fields
            missing_fields = []
            for row in processed_rows:
                for field in row:
                    if field not in current_schema:
                        field_type = "STRING"  # Default to string for new fields
                        missing_fields.append(bigquery.SchemaField(field, field_type))
            
            if missing_fields:
                # Update schema
                new_schema = list(table.schema) + missing_fields
                table.schema = new_schema
                client.update_table(table, ["schema"])
                logger.info(f"Updated schema for {full_table_id}")
                
                # Try insert again
                errors = client.insert_rows_json(full_table_id, processed_rows)
                return not errors
        except Exception as e:
            logger.error(f"Schema update error: {str(e)}")
            
        return False
    except Exception as e:
        logger.error(f"BigQuery insert error: {str(e)}")
        return False

# ======== AI Analysis Functions ========

def analyze_with_vertex_ai(content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Analyze threat data using Vertex AI LLM"""
    if not get_client('vertex'):
        logger.warning("Vertex AI not initialized")
        return {}
    
    if not content:
        return {}
    
    # Truncate content if it's too long (Vertex AI has context limits)
    if len(content) > 8000:
        logger.info(f"Truncating content from {len(content)} to 8000 chars")
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
        logger.info("Sending content to Vertex AI for analysis")
        
        # Get the model
        model = TextGenerationModel.from_pretrained(MODEL_NAME)
        
        # Generate response with retry logic
        for attempt in range(3):
            try:
                response = model.predict(prompt, temperature=0.1, max_output_tokens=1024)
                
                # Extract JSON from response
                json_str = extract_json_from_text(response.text)
                
                if json_str:
                    analysis = json.loads(json_str)
                    
                    # Add metadata
                    source_id = "unknown"
                    source_type = "unknown"
                    if metadata:
                        source_id = metadata.get("id", "unknown")
                        source_type = metadata.get("type", "unknown")
                        
                    analysis["source_id"] = source_id
                    analysis["source_type"] = source_type
                    analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
                    
                    logger.info(f"Successfully extracted structured analysis from Vertex AI")
                    return analysis
                else:
                    if attempt < 2:
                        logger.warning(f"Could not find JSON in Vertex AI response (attempt {attempt+1}), retrying...")
                    else:
                        logger.warning("Could not find JSON in Vertex AI response after retries")
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
                if attempt < 2:
                    logger.warning(f"Vertex AI error (attempt {attempt+1}): {str(e)}, retrying...")
                else:
                    raise
    except Exception as e:
        logger.error(f"Error analyzing with Vertex AI: {str(e)}")
        return {}

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
                results.append({
                    "value": value,
                    "type": ioc_type,
                    "timestamp": timestamp
                })
    
    # Extract from CSV content
    elif content_type == "csv":
        import csv
        import io
        
        # Parse CSV and extract potential IOCs
        try:
            # Basic CSV parsing
            csv_reader = csv.reader(io.StringIO(content))
            headers = next(csv_reader, [])
            
            if not headers:
                return []
            
            # Map headers to indices
            header_map = {header: i for i, header in enumerate(headers)}
            
            # Process each row
            for row_idx, row in enumerate(csv_reader, start=2):
                if not row or len(row) == 0:
                    continue
                    
                # Check each cell for potential IOCs
                for col_idx, cell in enumerate(row):
                    if not cell:
                        continue
                        
                    # Check each IOC pattern
                    for ioc_type, pattern in IOC_PATTERNS.items():
                        if re.match(pattern, cell):
                            col_name = headers[col_idx] if col_idx < len(headers) else f"column_{col_idx}"
                            
                            results.append({
                                "value": cell,
                                "type": ioc_type,
                                "source_row": row_idx,
                                "source_column": col_name,
                                "timestamp": timestamp
                            })
        except Exception as e:
            logger.error(f"Error extracting IOCs from CSV: {str(e)}")
    
    # Extract from JSON content
    elif content_type == "json":
        def process_json_item(item, path=""):
            if isinstance(item, dict):
                for key, value in item.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, (dict, list)):
                        process_json_item(value, current_path)
                    elif isinstance(value, str):
                        # Check for IOCs in string values
                        for ioc_type, pattern in IOC_PATTERNS.items():
                            if re.match(pattern, value):
                                results.append({
                                    "value": value,
                                    "type": ioc_type,
                                    "path": current_path,
                                    "timestamp": timestamp
                                })
            elif isinstance(item, list):
                for i, value in enumerate(item):
                    current_path = f"{path}[{i}]"
                    process_json_item(value, current_path)
                    
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
    
    # Add timestamp if missing
    if "timestamp" not in enriched:
        enriched["timestamp"] = datetime.utcnow().isoformat()
    
    # Enrichment differs based on IOC type
    ioc_type = ioc["type"]
    ioc_value = ioc["value"]
    
    # Perform enrichment based on IOC type
    if ioc_type == "ip":
        # Use cached geolocation data if available
        geo_data = query_bigquery(
            f"""
            SELECT geo FROM `{PROJECT_ID}.{DATASET_ID}.ioc_enrichment`
            WHERE type = 'ip' AND value = @value
            LIMIT 1
            """,
            {"value": ioc_value}
        )
        
        if geo_data:
            try:
                enriched["geo"] = json.loads(geo_data[0]["geo"])
            except (KeyError, json.JSONDecodeError):
                pass
    
    # Add severity assessment based on context
    if "context" in enriched and isinstance(enriched["context"], dict):
        if any(keyword in str(enriched["context"]).lower() 
               for keyword in ["critical", "ransomware", "backdoor", "exploit"]):
            enriched["severity"] = "high"
        elif any(keyword in str(enriched["context"]).lower() 
                for keyword in ["suspicious", "malware", "trojan"]):
            enriched["severity"] = "medium"
        else:
            enriched["severity"] = "low"
    
    return enriched

# ======== Main Analysis Class ========

class ThreatAnalyzer:
    """Unified threat analysis with optimized GCP integration"""
    
    def __init__(self):
        """Initialize analyzer and ensure resources"""
        self._ensure_tables()
    
    def _ensure_tables(self):
        """Ensure required BigQuery tables exist"""
        client = get_client('bigquery')
        if not client or isinstance(client, DummyClient):
            logger.warning("BigQuery not available, cannot ensure tables")
            return
            
        try:
            # Check/create analysis table
            analysis_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
            try:
                client.get_table(analysis_table_id)
                logger.info("Analysis table already exists")
            except Exception:
                # Create analysis table
                schema = [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP")
                ]
                table = bigquery.Table(analysis_table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                logger.info("Created analysis table")
                
            # Check/create campaigns table
            campaigns_table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
            try:
                client.get_table(campaigns_table_id)
                logger.info("Campaigns table already exists")
            except Exception:
                # Create campaigns table
                schema = [
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
                table = bigquery.Table(campaigns_table_id, schema=schema)
                client.create_table(table, exists_ok=True)
                logger.info("Created campaigns table")
        except Exception as e:
            logger.error(f"Error ensuring tables: {str(e)}")
    
    def analyze_feed_data(self, feed_name: str, days_back: int = 7) -> Dict[str, Any]:
        """Analyze threat data from a specific feed"""
        logger.info(f"Analyzing feed {feed_name} for past {days_back} days")
        
        # Query to get recent data from the feed
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
        WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
        """
        
        rows = query_bigquery(query)
        
        if not rows:
            logger.warning(f"No data found for feed {feed_name}")
            return {
                "feed_name": feed_name,
                "processed_count": 0,
                "ioc_count": 0
            }
        
        # Process each row
        processed_count = 0
        ioc_count = 0
        analysis_results = []
        
        for row in rows:
            # Create a unique ID for this analysis
            row_id = row.get("id", str(hash(str(row))))
            
            # Convert row to text representation for IOC extraction
            content = ""
            for key, value in row.items():
                if key != "_ingestion_timestamp" and value:
                    content += f"{key}: {value}\n"
            
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
                "iocs": enriched_iocs,
                "vertex_analysis": vertex_analysis,
                "analysis_timestamp": datetime.utcnow()
            }
            
            # Store in BigQuery
            insert_into_bigquery("threat_analysis", [analysis_result])
            analysis_results.append(analysis_result)
            
            processed_count += 1
            
            # Log progress periodically
            if processed_count % 10 == 0:
                logger.info(f"Processed {processed_count} items from {feed_name}")
        
        # Log completion
        logger.info(f"Completed processing {processed_count} items, extracted {ioc_count} IOCs from {feed_name}")
        
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
        logger.info(f"Detecting campaigns for past {days_back} days")
        
        # Query to get recent analyses
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
        """
        
        rows = query_bigquery(query)
        
        if not rows:
            logger.warning("No analysis data found for campaign detection")
            return []
        
        # Group analyses by potential campaigns
        campaigns = []
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
            
            if threat_actor and len(threat_actor) > 3:
                campaign_identifiers.append(f"actor:{threat_actor}")
            
            if malware and len(malware) > 3:
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
                    "threat_actor": threat_actor,
                    "malware": malware,
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
                "sources": group["analyses"],
                "iocs": list(unique_iocs.values()),
                "source_count": len(group["analyses"]),
                "ioc_count": len(unique_iocs),
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else first_seen,
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                "detection_timestamp": datetime.utcnow().isoformat()
            }
            
            campaigns.append(campaign)
            
            # Store campaign in BigQuery
            insert_into_bigquery("threat_campaigns", [campaign])
        
        logger.info(f"Detected {len(campaigns)} threat campaigns")
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
            import itertools
            
            csv_reader = csv.reader(io.StringIO(csv_content))
            headers = next(csv_reader, [])
            sample_rows = list(itertools.islice(csv_reader, 5))
            
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
                "iocs": enriched_iocs,
                "vertex_analysis": vertex_analysis,
                "analysis_timestamp": datetime.utcnow()
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
            
            logger.info(f"Analyzed CSV with {len(enriched_iocs)} IOCs extracted")
            return result
        except Exception as e:
            logger.error(f"Error analyzing CSV: {str(e)}")
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
            logger.info(f"Received analysis event: {data}")
            
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
            logger.error(f"Error processing event: {str(e)}")
    
    # Fallback to analyzing a few default feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware"]
    
    results = []
    for feed in feeds:
        try:
            result = analyzer.analyze_feed_data(feed)
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing {feed}: {str(e)}")
            results.append({
                "feed_name": feed,
                "error": str(e)
            })
    
    # Run campaign detection
    campaigns = analyzer.detect_campaigns()
    
    return {"results": results, "campaign_count": len(campaigns)}

# For direct execution
if __name__ == "__main__":
    import itertools  # Needed for CSV analysis
    
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
