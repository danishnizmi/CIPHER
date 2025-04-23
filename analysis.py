"""
Threat Intelligence Platform - Analysis Module
Processes threat data from BigQuery, extracts IOCs, and generates insights using Vertex AI.
"""

import os
import re
import json
import logging
from typing import Dict, List, Any, Set
from datetime import datetime, timedelta

from google.cloud import bigquery
from google.cloud import pubsub_v1
import vertexai
from vertexai.language_models import TextGenerationModel
import requests

# Import config module
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = config.project_id
REGION = config.region
DATASET_ID = config.bigquery_dataset
PUBSUB_TOPIC = config.get("PUBSUB_TOPIC", "threat-analysis-events")

# Global clients
bq_client = None
publisher = None
llm = None

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

def initialize_clients():
    """Initialize GCP clients"""
    global bq_client, publisher, llm
    
    try:
        # Initialize BigQuery
        if not bq_client:
            bq_client = bigquery.Client(project=PROJECT_ID)
            logger.info(f"BigQuery client initialized for project {PROJECT_ID}")
        
        # Initialize Pub/Sub
        if not publisher:
            publisher = pubsub_v1.PublisherClient()
            logger.info("Pub/Sub publisher initialized")
        
        # Initialize Vertex AI
        try:
            vertexai.init(project=PROJECT_ID, location=REGION)
            llm = TextGenerationModel.from_pretrained("text-bison")
            logger.info("Vertex AI initialized successfully")
        except Exception as e:
            logger.warning(f"Vertex AI initialization failed: {str(e)}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize clients: {str(e)}")
        return False

class ThreatAnalyzer:
    """Main class for threat data analysis"""
    
    def __init__(self):
        """Initialize the analyzer"""
        self.ready = initialize_clients()
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns"""
        if not text:
            return {}
            
        results = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))
                results[ioc_type] = unique_matches
                logger.info(f"Extracted {len(unique_matches)} {ioc_type} indicators")
        
        return results
    
    def analyze_with_vertex_ai(self, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data using Vertex AI LLM"""
        if not content or not llm:
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
            response = llm.predict(prompt, temperature=0.1, max_output_tokens=1024)
            
            # Try to parse JSON from response
            try:
                start_index = response.text.find('{')
                end_index = response.text.rfind('}') + 1
                
                if start_index >= 0 and end_index > start_index:
                    json_str = response.text[start_index:end_index]
                    analysis = json.loads(json_str)
                    
                    # Add metadata
                    analysis["source_id"] = metadata.get("id", "unknown")
                    analysis["source_type"] = metadata.get("type", "unknown")
                    analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
                    
                    logger.info(f"Successfully extracted structured analysis from Vertex AI")
                    return analysis
                else:
                    logger.warning("Could not find JSON in Vertex AI response")
                    return {}
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON from Vertex AI response: {str(e)}")
                return {}
        except Exception as e:
            logger.error(f"Error analyzing with Vertex AI: {str(e)}")
            return {}
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Enrich an IOC with additional context"""
        enrichment = {
            "value": ioc_value,
            "type": ioc_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Enrich IP addresses
        if ioc_type == "ip":
            try:
                response = requests.get(f"https://ipinfo.io/{ioc_value}/json", timeout=5)
                if response.status_code == 200:
                    ip_data = response.json()
                    enrichment.update({
                        "geo": {
                            "country": ip_data.get("country"),
                            "region": ip_data.get("region"),
                            "city": ip_data.get("city"),
                            "loc": ip_data.get("loc")
                        },
                        "asn": ip_data.get("org"),
                        "hostname": ip_data.get("hostname")
                    })
                    logger.info(f"Successfully enriched IP {ioc_value}")
            except Exception as e:
                logger.warning(f"Error enriching IP {ioc_value}: {str(e)}")
        
        # More enrichment could be added for other IOC types
        
        return enrichment
    
    def analyze_feed_data(self, feed_name: str, days_back: int = 7) -> Dict[str, Any]:
        """Analyze threat data from a specific feed"""
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return {"error": "BigQuery client not initialized"}
        
        try:
            # Query recent data from BigQuery
            query = f"""
            SELECT *
            FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
            WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
            """
            
            query_job = bq_client.query(query)
            results = query_job.result()
            
            processed_count = 0
            ioc_count = 0
            analysis_results = []
            
            for row in results:
                row_dict = dict(row.items())
                
                # Create a text representation of the row for IOC extraction
                content = ""
                for key, value in row_dict.items():
                    if key != "_ingestion_timestamp" and value:
                        content += f"{key}: {value}\n"
                
                # Skip if no content
                if not content:
                    continue
                
                # Extract IOCs
                iocs = self.extract_iocs(content)
                all_iocs = []
                
                # Enrich IOCs
                for ioc_type, values in iocs.items():
                    for value in values:
                        enriched_ioc = self.enrich_ioc(value, ioc_type)
                        all_iocs.append(enriched_ioc)
                        ioc_count += 1
                
                # Analyze with Vertex AI
                metadata = {"id": row_dict.get("id", str(hash(str(row_dict)))), "type": feed_name}
                vertex_analysis = {}
                if llm:
                    vertex_analysis = self.analyze_with_vertex_ai(content, metadata)
                
                # Combine results
                analysis_result = {
                    "source_id": metadata["id"],
                    "source_type": metadata["type"],
                    "iocs": all_iocs,
                    "vertex_analysis": vertex_analysis,
                    "analysis_timestamp": datetime.utcnow().isoformat()
                }
                
                # Store analysis result in BigQuery
                self._store_analysis_result(analysis_result)
                analysis_results.append(analysis_result)
                
                processed_count += 1
                
                # Log progress periodically
                if processed_count % 10 == 0:
                    logger.info(f"Processed {processed_count} items from {feed_name}")
            
            logger.info(f"Completed processing {processed_count} items, extracted {ioc_count} IOCs from {feed_name}")
            
            # Publish event
            self._publish_analysis_event(feed_name, processed_count, ioc_count)
            
            return {
                "feed_name": feed_name,
                "processed_count": processed_count,
                "ioc_count": ioc_count
            }
        except Exception as e:
            logger.error(f"Error analyzing feed {feed_name}: {str(e)}")
            return {
                "feed_name": feed_name,
                "error": str(e),
                "processed_count": 0,
                "ioc_count": 0
            }
    
    def _store_analysis_result(self, analysis_result: Dict[str, Any]) -> None:
        """Store analysis result in BigQuery"""
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return
            
        table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
        
        # Convert complex types to JSON strings
        result_copy = analysis_result.copy()
        
        for key in ["iocs", "vertex_analysis"]:
            if key in result_copy and result_copy[key]:
                result_copy[key] = json.dumps(result_copy[key])
        
        try:
            # Try to insert the row
            errors = bq_client.insert_rows_json(table_id, [result_copy])
            
            if errors:
                logger.error(f"Errors inserting analysis result: {errors}")
                
                # Table might not exist, try to create it
                schema = [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP")
                ]
                
                table = bigquery.Table(table_id, schema=schema)
                bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
                
                # Try again
                errors = bq_client.insert_rows_json(table_id, [result_copy])
                if errors:
                    logger.error(f"Still getting errors after table creation: {errors}")
        except Exception as e:
            logger.error(f"Error storing analysis result: {str(e)}")
    
    def _publish_analysis_event(self, feed_name: str, processed_count: int, ioc_count: int) -> None:
        """Publish event to Pub/Sub about analysis completion"""
        if not publisher:
            logger.error("Pub/Sub publisher not initialized")
            return
            
        try:
            topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
            
            message = {
                "feed_name": feed_name,
                "processed_count": processed_count,
                "ioc_count": ioc_count,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "analysis_complete"
            }
            
            data = json.dumps(message).encode("utf-8")
            future = publisher.publish(topic_path, data=data)
            message_id = future.result()
            
            logger.info(f"Published analysis event with ID {message_id}")
        except Exception as e:
            logger.error(f"Error publishing analysis event: {str(e)}")
    
    def detect_campaigns(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Detect threat campaigns by clustering related IOCs and analyses"""
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return []
            
        try:
            # Get recent analyses
            query = f"""
            SELECT *
            FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
            WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
            """
            
            query_job = bq_client.query(query)
            results = query_job.result()
            
            # Group analyses
            campaigns = []
            analysis_groups = {}
            
            for row in results:
                row_dict = dict(row.items())
                
                # Parse JSON fields
                try:
                    vertex_analysis = json.loads(row_dict.get("vertex_analysis", "{}"))
                    iocs = json.loads(row_dict.get("iocs", "[]"))
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
                import hashlib
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
                
                analysis_groups[campaign_key]["analyses"].append(row_dict["source_id"])
                analysis_groups[campaign_key]["iocs"].extend(iocs)
                
                # Track timestamps
                if "analysis_timestamp" in row_dict:
                    timestamp = row_dict["analysis_timestamp"]
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
                }
                
                campaigns.append(campaign)
                
                # Store campaign in BigQuery
                self._store_campaign(campaign)
            
            logger.info(f"Detected {len(campaigns)} threat campaigns")
            return campaigns
        except Exception as e:
            logger.error(f"Error detecting campaigns: {str(e)}")
            return []
    
    def _store_campaign(self, campaign: Dict[str, Any]) -> None:
        """Store campaign data in BigQuery"""
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return
            
        table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
        
        # Convert complex types to strings
        campaign_copy = campaign.copy()
        campaign_copy["iocs"] = json.dumps(campaign["iocs"])
        campaign_copy["sources"] = json.dumps(campaign["sources"])
        campaign_copy["detection_timestamp"] = datetime.utcnow().isoformat()
        
        try:
            # Try to insert the row
            errors = bq_client.insert_rows_json(table_id, [campaign_copy])
            
            if errors:
                logger.error(f"Errors inserting campaign: {errors}")
                
                # Table might not exist, try to create it
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
                
                table = bigquery.Table(table_id, schema=schema)
                bq_client.create_table(table, exists_ok=True)
                logger.info(f"Created table {table_id}")
                
                # Try again
                errors = bq_client.insert_rows_json(table_id, [campaign_copy])
                if errors:
                    logger.error(f"Still getting errors after table creation: {errors}")
        except Exception as e:
            logger.error(f"Error storing campaign: {str(e)}")
    
    def get_ioc_geo_stats(self, days_back: int = 30) -> Dict[str, Any]:
        """Get geographic distribution of IP-based IOCs"""
        if not bq_client:
            logger.error("BigQuery client not initialized")
            return {}
            
        try:
            query = f"""
            WITH ip_iocs AS (
              SELECT
                JSON_EXTRACT_SCALAR(ioc_item, '$.value') AS ip,
                JSON_EXTRACT_SCALAR(ioc_item, '$.geo.country') AS country,
                JSON_EXTRACT_SCALAR(ioc_item, '$.geo.city') AS city,
                JSON_EXTRACT_SCALAR(ioc_item, '$.geo.loc') AS location
              FROM
                `{PROJECT_ID}.{DATASET_ID}.threat_analysis`,
                UNNEST(JSON_EXTRACT_ARRAY(iocs)) AS ioc_item
              WHERE
                JSON_EXTRACT_SCALAR(ioc_item, '$.type') = 'ip'
                AND analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
            )
            SELECT
              country,
              COUNT(*) as count,
              ARRAY_AGG(STRUCT(city, ip)) as cities
            FROM
              ip_iocs
            WHERE
              country IS NOT NULL
            GROUP BY
              country
            ORDER BY
              count DESC
            LIMIT 50
            """
            
            query_job = bq_client.query(query)
            results = query_job.result()
            
            countries = []
            for row in results:
                country_data = {
                    "country": row.country.strip('"'),
                    "count": row.count,
                    "cities": [{
                        "name": city.city.strip('"') if city.city else "Unknown",
                        "ip": city.ip.strip('"')
                    } for city in row.cities[:10]]  # Limit to 10 cities per country
                }
                countries.append(country_data)
            
            return {
                "countries": countries,
                "total_countries": len(countries),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting IOC geo stats: {str(e)}")
            return {"error": str(e)}

# Cloud Function entry point
def analyze_threat_data(event, context):
    """Pub/Sub triggered function for threat data analysis"""
    analyzer = ThreatAnalyzer()
    
    # Parse message
    if 'data' in event:
        import base64
        try:
            data = json.loads(base64.b64decode(event['data']).decode('utf-8'))
            logger.info(f"Received analysis event: {str(data)}")
            
            feed_name = data.get("feed_name")
            
            if feed_name:
                # Analyze feed data
                result = analyzer.analyze_feed_data(feed_name)
                
                # Detect campaigns periodically (every 10th message)
                if hash(feed_name) % 10 == 0:
                    campaigns = analyzer.detect_campaigns()
                
                return result
        except Exception as e:
            logger.error(f"Error processing event data: {str(e)}")
    
    # Fallback to analyzing all feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware", 
             "feodotracker_c2", "cisa_vulnerabilities", "tor_exit_nodes"]
    
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
    
    # Always run campaign detection
    campaigns = analyzer.detect_campaigns()
    
    return {"results": results, "campaign_count": len(campaigns)}

# CLI entry point
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    # Analyze feeds
    feeds = ["threatfox_iocs", "phishtank_urls", "urlhaus_malware", 
             "feodotracker_c2", "cisa_vulnerabilities", "tor_exit_nodes"]
    
    for feed in feeds:
        try:
            result = analyzer.analyze_feed_data(feed)
            print(f"Analyzed {feed}: {result}")
        except Exception as e:
            print(f"Error analyzing {feed}: {str(e)}")
    
    # Detect campaigns
    campaigns = analyzer.detect_campaigns()
    print(f"Detected {len(campaigns)} campaigns")
    
    # Get geographic stats
    geo_stats = analyzer.get_ioc_geo_stats()
    print(f"Found IOCs from {geo_stats.get('total_countries', 0)} countries")
