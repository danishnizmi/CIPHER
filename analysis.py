"""
Threat Intelligence Platform - Analysis Module
Processes and analyzes threat data using Vertex AI and extracts IOCs.
"""

import os
import re
import json
import logging
import hashlib
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timedelta

from google.cloud import bigquery
from google.cloud import storage
from google.cloud import pubsub_v1
from google.cloud import language_v1
import vertexai
from vertexai.language_models import TextGenerationModel
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GCP Configuration
PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
REGION = os.environ.get("GCP_REGION", "us-central1")
DATASET_ID = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
PUBSUB_TOPIC = os.environ.get("PUBSUB_TOPIC", "threat-analysis-events")

# Initialize GCP clients
bq_client = bigquery.Client()
publisher = pubsub_v1.PublisherClient()
language_client = language_v1.LanguageServiceClient()
vertexai.init(project=PROJECT_ID, location=REGION)

# Indicators of Compromise (IOC) Regex Patterns
IOC_PATTERNS = {
    "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
    "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%/.]*)*',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "bitcoin_address": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "file_path": r'\b(?:[a-zA-Z]:)?\\(?:[^\\/:*?"<>|\r\n]+\\)+[^\\/:*?"<>|\r\n]*\b'
}


class ThreatAnalyzer:
    """Main class for handling threat data analysis"""
    
    def __init__(self):
        """Initialize analysis resources"""
        self.llm = TextGenerationModel.from_pretrained("text-bison")
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns"""
        results = {}
        
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))
                results[ioc_type] = unique_matches
        
        return results
    
    def analyze_text_with_nlp(self, text: str) -> Dict[str, Any]:
        """Analyze text using Cloud Natural Language API"""
        if not text:
            return {}
        
        document = language_v1.Document(
            content=text,
            type_=language_v1.Document.Type.PLAIN_TEXT
        )
        
        # Entity analysis
        entity_response = language_client.analyze_entities(
            request={"document": document}
        )
        
        # Sentiment analysis
        sentiment_response = language_client.analyze_sentiment(
            request={"document": document}
        )
        
        # Extract entities by type
        entities = {}
        for entity in entity_response.entities:
            entity_type = language_v1.Entity.Type(entity.type_).name
            if entity_type not in entities:
                entities[entity_type] = []
            
            entities[entity_type].append({
                "name": entity.name,
                "salience": entity.salience,
                "mentions": len(entity.mentions)
            })
        
        return {
            "entities": entities,
            "sentiment": {
                "score": sentiment_response.document_sentiment.score,
                "magnitude": sentiment_response.document_sentiment.magnitude
            }
        }
    
    def analyze_with_vertex_ai(self, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data using Vertex AI LLM"""
        if not content:
            return {}
        
        # Construct prompt for threat analysis
        prompt = f"""
        Analyze the following threat intelligence data and extract key information:
        
        {content}
        
        Please provide the following:
        1. A summary of the threat (2-3 sentences)
        2. Identify the threat actor or group if possible
        3. Identify targeted sectors or regions
        4. Identify the attack techniques (MITRE ATT&CK if possible)
        5. Identify malware families mentioned
        6. Assess severity (Low, Medium, High, Critical)
        7. Confidence level (Low, Medium, High)
        
        Format your response as JSON with these keys: summary, threat_actor, targets, techniques, malware, severity, confidence
        """
        
        try:
            response = self.llm.predict(prompt, temperature=0.1, max_output_tokens=1024)
            
            # Try to parse JSON from response
            try:
                start_index = response.text.find('{')
                end_index = response.text.rfind('}') + 1
                if start_index >= 0 and end_index > start_index:
                    json_str = response.text[start_index:end_index]
                    analysis = json.loads(json_str)
                    
                    # Add metadata and timestamp
                    analysis["source_id"] = metadata.get("id", "unknown")
                    analysis["source_type"] = metadata.get("type", "unknown")
                    analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
                    
                    return analysis
            except json.JSONDecodeError:
                # Fallback to structured extraction if JSON parsing fails
                analysis = {
                    "summary": self._extract_section(response.text, "summary"),
                    "threat_actor": self._extract_section(response.text, "threat_actor"),
                    "targets": self._extract_section(response.text, "targets"),
                    "techniques": self._extract_section(response.text, "techniques"),
                    "malware": self._extract_section(response.text, "malware"),
                    "severity": self._extract_section(response.text, "severity"),
                    "confidence": self._extract_section(response.text, "confidence"),
                    "source_id": metadata.get("id", "unknown"),
                    "source_type": metadata.get("type", "unknown"),
                    "analysis_timestamp": datetime.utcnow().isoformat()
                }
                return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing with Vertex AI: {str(e)}")
            return {
                "error": str(e),
                "source_id": metadata.get("id", "unknown"),
                "source_type": metadata.get("type", "unknown"),
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
    
    def _extract_section(self, text: str, section_name: str) -> str:
        """Helper to extract a section from LLM response"""
        patterns = [
            f"{section_name}[:\s]+(.*?)(?:\n\n|\n[A-Za-z])",
            f"{section_name.title()}[:\s]+(.*?)(?:\n\n|\n[A-Za-z])",
            f"{section_name.upper()}[:\s]+(.*?)(?:\n\n|\n[A-Za-z])"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return ""
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Enrich an IOC with additional context from external sources"""
        enrichment = {
            "value": ioc_value,
            "type": ioc_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Enrich IP addresses
        if ioc_type == "ip":
            try:
                response = requests.get(f"https://ipinfo.io/{ioc_value}/json")
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
            except Exception as e:
                logger.warning(f"Error enriching IP {ioc_value}: {str(e)}")
        
        # Enrich domains
        elif ioc_type == "domain":
            try:
                # Simple WHOIS data extraction
                response = requests.get(f"https://whoisjson.com/api/v1/whois?domain={ioc_value}")
                if response.status_code == 200:
                    whois_data = response.json()
                    enrichment.update({
                        "registrar": whois_data.get("registrar"),
                        "creation_date": whois_data.get("creation_date"),
                        "expiration_date": whois_data.get("expiration_date")
                    })
            except Exception as e:
                logger.warning(f"Error enriching domain {ioc_value}: {str(e)}")
        
        # Enrich file hashes
        elif ioc_type in ["md5", "sha1", "sha256"]:
            try:
                # Check VirusTotal API (requires API key)
                vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
                if vt_api_key:
                    headers = {"x-apikey": vt_api_key}
                    response = requests.get(
                        f"https://www.virustotal.com/api/v3/files/{ioc_value}",
                        headers=headers
                    )
                    if response.status_code == 200:
                        vt_data = response.json()
                        attributes = vt_data.get("data", {}).get("attributes", {})
                        
                        enrichment.update({
                            "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{sum(attributes.get('last_analysis_stats', {}).values())}",
                            "first_seen": attributes.get("first_submission_date"),
                            "file_type": attributes.get("type_description"),
                            "names": attributes.get("names", [])[:5]  # Limit to top 5 names
                        })
            except Exception as e:
                logger.warning(f"Error enriching hash {ioc_value}: {str(e)}")
        
        return enrichment
    
    def analyze_and_store_feed_data(self, feed_name: str, days_back: int = 1) -> Dict[str, Any]:
        """Analyze and enrich threat data from a specific feed"""
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
            
            # Different feeds have different structures
            content = ""
            metadata = {"id": row_dict.get("id", "unknown"), "type": feed_name}
            
            if feed_name == "alienvault_pulses":
                content = row_dict.get("description", "") or ""
                if "indicators" in row_dict:
                    for indicator in row_dict["indicators"]:
                        content += f"\n{indicator.get('title', '')}: {indicator.get('indicator', '')}"
            
            elif feed_name == "misp_events":
                content = row_dict.get("info", "") or ""
                if "Attribute" in row_dict:
                    for attr in row_dict["Attribute"]:
                        content += f"\n{attr.get('type', '')}: {attr.get('value', '')}"
            
            elif feed_name == "threatfox_iocs":
                content = row_dict.get("threat_type_desc", "") or ""
                content += f"\n{row_dict.get('ioc_type', '')}: {row_dict.get('ioc', '')}"
            
            # Skip if no content to analyze
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
            
            # Analyze with Cloud NLP
            nlp_analysis = self.analyze_text_with_nlp(content)
            
            # Analyze with Vertex AI
            vertex_analysis = self.analyze_with_vertex_ai(content, metadata)
            
            # Combine results
            analysis_result = {
                "source_id": metadata["id"],
                "source_type": metadata["type"],
                "iocs": all_iocs,
                "nlp_analysis": nlp_analysis,
                "vertex_analysis": vertex_analysis,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }
            
            # Store analysis result in BigQuery
            self._store_analysis_result(analysis_result)
            analysis_results.append(analysis_result)
            
            processed_count += 1
        
        logger.info(f"Processed {processed_count} items, extracted {ioc_count} IOCs from {feed_name}")
        
        return {
            "feed_name": feed_name,
            "processed_count": processed_count,
            "ioc_count": ioc_count
        }
    
    def _store_analysis_result(self, analysis_result: Dict[str, Any]) -> None:
        """Store analysis result in BigQuery"""
        table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_analysis"
        
        # Make sure nested structures are properly serialized
        for key in ["nlp_analysis", "vertex_analysis"]:
            if isinstance(analysis_result.get(key), dict):
                analysis_result[key] = json.dumps(analysis_result[key])
        
        # Convert list of IOCs to JSON string
        if "iocs" in analysis_result:
            analysis_result["iocs"] = json.dumps(analysis_result["iocs"])
        
        rows_to_insert = [analysis_result]
        
        try:
            errors = bq_client.insert_rows_json(table_id, rows_to_insert)
            if errors:
                logger.error(f"Errors inserting rows: {errors}")
        except Exception as e:
            logger.error(f"Error storing analysis result: {str(e)}")
            
            # Create table if it doesn't exist
            if "not found" in str(e).lower():
                schema = [
                    bigquery.SchemaField("source_id", "STRING"),
                    bigquery.SchemaField("source_type", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("nlp_analysis", "STRING"),
                    bigquery.SchemaField("vertex_analysis", "STRING"),
                    bigquery.SchemaField("analysis_timestamp", "TIMESTAMP")
                ]
                
                table = bigquery.Table(table_id, schema=schema)
                table = bq_client.create_table(table)
                logger.info(f"Created table {table_id}")
                
                # Try again
                errors = bq_client.insert_rows_json(table_id, rows_to_insert)
                if errors:
                    logger.error(f"Errors inserting rows after table creation: {errors}")
    
    def detect_campaign(self, timespan_days: int = 7) -> List[Dict[str, Any]]:
        """Detect threat campaigns by clustering related IOCs and analyses"""
        # Query recent analyses
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {timespan_days} DAY)
        """
        
        query_job = bq_client.query(query)
        results = query_job.result()
        
        # Group analyses by common attributes
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
            techniques = vertex_analysis.get("techniques", "").lower()
            targets = vertex_analysis.get("targets", "").lower()
            
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
                    "techniques": techniques,
                    "targets": targets
                }
            
            analysis_groups[campaign_key]["analyses"].append(row_dict["source_id"])
            analysis_groups[campaign_key]["iocs"].extend(iocs)
        
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
            
            # Create campaign
            campaign = {
                "campaign_id": key,
                "threat_actor": group["threat_actor"],
                "malware": group["malware"],
                "techniques": group["techniques"],
                "targets": group["targets"],
                "sources": group["analyses"],
                "iocs": list(unique_iocs.values()),
                "source_count": len(group["analyses"]),
                "ioc_count": len(unique_iocs),
                "first_seen": min([a["analysis_timestamp"] for a in group["analyses"] if "analysis_timestamp" in a]),
                "last_seen": max([a["analysis_timestamp"] for a in group["analyses"] if "analysis_timestamp" in a]),
                "campaign_name": self._generate_campaign_name(group)
            }
            
            campaigns.append(campaign)
            
            # Store campaign in BigQuery
            self._store_campaign(campaign)
        
        logger.info(f"Detected {len(campaigns)} threat campaigns")
        return campaigns
    
    def _generate_campaign_name(self, group: Dict[str, Any]) -> str:
        """Generate a campaign name based on group attributes"""
        if group["threat_actor"]:
            prefix = group["threat_actor"].split()[0].title()
        elif group["malware"]:
            prefix = group["malware"].split()[0].title()
        else:
            prefix = "Campaign"
        
        # Add random suffix
        suffix = hashlib.md5(
            str(group["identifiers"]).encode()
        ).hexdigest()[:6]
        
        return f"{prefix}-{suffix}"
    
    def _store_campaign(self, campaign: Dict[str, Any]) -> None:
        """Store campaign data in BigQuery"""
        table_id = f"{PROJECT_ID}.{DATASET_ID}.threat_campaigns"
        
        # Convert complex types to strings
        campaign_copy = campaign.copy()
        campaign_copy["iocs"] = json.dumps(campaign["iocs"])
        campaign_copy["sources"] = json.dumps(campaign["sources"])
        campaign_copy["detection_timestamp"] = datetime.utcnow().isoformat()
        
        rows_to_insert = [campaign_copy]
        
        try:
            errors = bq_client.insert_rows_json(table_id, rows_to_insert)
            if errors:
                logger.error(f"Errors inserting campaign: {errors}")
        except Exception as e:
            logger.error(f"Error storing campaign: {str(e)}")
            
            # Create table if it doesn't exist
            if "not found" in str(e).lower():
                schema = [
                    bigquery.SchemaField("campaign_id", "STRING"),
                    bigquery.SchemaField("campaign_name", "STRING"),
                    bigquery.SchemaField("threat_actor", "STRING"),
                    bigquery.SchemaField("malware", "STRING"),
                    bigquery.SchemaField("techniques", "STRING"),
                    bigquery.SchemaField("targets", "STRING"),
                    bigquery.SchemaField("sources", "STRING"),
                    bigquery.SchemaField("iocs", "STRING"),
                    bigquery.SchemaField("source_count", "INTEGER"),
                    bigquery.SchemaField("ioc_count", "INTEGER"),
                    bigquery.SchemaField("first_seen", "TIMESTAMP"),
                    bigquery.SchemaField("last_seen", "TIMESTAMP"),
                    bigquery.SchemaField("detection_timestamp", "TIMESTAMP")
                ]
                
                table = bigquery.Table(table_id, schema=schema)
                table = bq_client.create_table(table)
                logger.info(f"Created table {table_id}")
                
                # Try again
                errors = bq_client.insert_rows_json(table_id, rows_to_insert)
                if errors:
                    logger.error(f"Errors inserting campaign after table creation: {errors}")


# Cloud Function entry point
def analyze_threat_data(event, context):
    """Pub/Sub triggered Cloud Function for threat data analysis"""
    analyzer = ThreatAnalyzer()
    
    # Parse message
    if 'data' in event:
        import base64
        data = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        
        feed_name = data.get("feed_name")
        
        if feed_name:
            # Analyze feed data
            result = analyzer.analyze_and_store_feed_data(feed_name)
            
            # Detect campaigns periodically (every 10th message)
            if hash(feed_name) % 10 == 0:
                campaigns = analyzer.detect_campaign()
            
            return result
    
    # Fallback to analyzing all feeds
    feeds = ["alienvault_pulses", "misp_events", "threatfox_iocs"]
    results = []
    
    for feed in feeds:
        try:
            result = analyzer.analyze_and_store_feed_data(feed)
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing {feed}: {str(e)}")
            results.append({
                "feed_name": feed,
                "error": str(e)
            })
    
    # Always run campaign detection
    campaigns = analyzer.detect_campaign()
    
    return {"results": results, "campaign_count": len(campaigns)}


# CLI entry point
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    # Analyze and detect campaigns
    feeds = ["alienvault_pulses", "misp_events", "threatfox_iocs"]
    for feed in feeds:
        result = analyzer.analyze_and_store_feed_data(feed)
        print(f"Analyzed {feed}: {result}")
    
    campaigns = analyzer.detect_campaign()
    print(f"Detected {len(campaigns)} campaigns")
