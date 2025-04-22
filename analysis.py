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
PROJECT_ID = os.environ.get("GCP_PROJECT", "primal-chariot-382610")
REGION = os.environ.get("GCP_REGION", "us-central1")
DATASET_ID = os.environ.get("BIGQUERY_DATASET", "threat_intelligence")
PUBSUB_TOPIC = os.environ.get("PUBSUB_TOPIC", "threat-analysis-events")

# Initialize GCP clients
bq_client = bigquery.Client()
publisher = pubsub_v1.PublisherClient()
language_client = language_v1.LanguageServiceClient()

# Initialize Vertex AI with proper error handling
try:
    vertexai.init(project=PROJECT_ID, location=REGION)
    VERTEX_AI_AVAILABLE = True
    logger.info(f"Vertex AI initialized successfully in {REGION}")
except Exception as e:
    VERTEX_AI_AVAILABLE = False
    logger.warning(f"Vertex AI initialization failed: {str(e)}")

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
    "file_path": r'\b(?:[a-zA-Z]:)?\\(?:[^\\/:*?"<>|\r\n]+\\)+[^\\/:*?"<>|\r\n]*\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
    "registry_key": r'HKEY_[A-Z_]+(?:\\[A-Za-z0-9_]+)+',
    "mac_address": r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
}


class ThreatAnalyzer:
    """Main class for handling threat data analysis"""
    
    def __init__(self):
        """Initialize analysis resources"""
        self.llm = None
        if VERTEX_AI_AVAILABLE:
            try:
                self.llm = TextGenerationModel.from_pretrained("text-bison")
                logger.info("Vertex AI LLM initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Vertex AI LLM: {str(e)}")
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns"""
        results = {}
        
        if not text:
            return results
            
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))
                results[ioc_type] = unique_matches
                
                # Log count of extracted IOCs
                logger.info(f"Extracted {len(unique_matches)} {ioc_type} indicators")
        
        return results
    
    def analyze_text_with_nlp(self, text: str) -> Dict[str, Any]:
        """Analyze text using Cloud Natural Language API"""
        if not text:
            return {}
        
        try:
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
        except Exception as e:
            logger.error(f"Error analyzing with NLP: {str(e)}")
            return {
                "error": str(e),
                "entities": {},
                "sentiment": {"score": 0, "magnitude": 0}
            }
    
    def analyze_with_vertex_ai(self, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data using Vertex AI LLM"""
        if not content or not self.llm:
            if not content:
                logger.warning("Empty content for Vertex AI analysis")
            if not self.llm:
                logger.warning("Vertex AI LLM not available")
            return {}
        
        # Truncate content if it's too long (Vertex AI has context limits)
        if len(content) > 8000:
            logger.info(f"Truncating content from {len(content)} to 8000 chars")
            content = content[:8000]
        
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
            logger.info("Sending content to Vertex AI for analysis")
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
                    
                    logger.info(f"Successfully extracted structured analysis from Vertex AI response")
                    return analysis
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON from Vertex AI response: {str(e)}")
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
                logger.info(f"Used fallback section extraction for Vertex AI response")
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
        
        # Enrich domains
        elif ioc_type == "domain":
            try:
                # Simple WHOIS data extraction or fallback to domain age check
                try:
                    response = requests.get(f"https://whoisjson.com/api/v1/whois?domain={ioc_value}", timeout=5)
                    if response.status_code == 200:
                        whois_data = response.json()
                        enrichment.update({
                            "registrar": whois_data.get("registrar"),
                            "creation_date": whois_data.get("creation_date"),
                            "expiration_date": whois_data.get("expiration_date")
                        })
                        logger.info(f"Successfully enriched domain {ioc_value} with WHOIS data")
                except Exception:
                    # If WHOIS fails, try to resolve the domain at least
                    import socket
                    try:
                        ip = socket.gethostbyname(ioc_value)
                        enrichment["resolved_ip"] = ip
                        logger.info(f"Domain {ioc_value} resolves to {ip}")
                    except socket.error:
                        enrichment["resolved"] = False
                        logger.info(f"Domain {ioc_value} does not resolve")
            except Exception as e:
                logger.warning(f"Error enriching domain {ioc_value}: {str(e)}")
        
        # Enrich file hashes
        elif ioc_type in ["md5", "sha1", "sha256"]:
            try:
                # Check VirusTotal API if key available
                vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
                if vt_api_key:
                    headers = {"x-apikey": vt_api_key}
                    response = requests.get(
                        f"https://www.virustotal.com/api/v3/files/{ioc_value}",
                        headers=headers,
                        timeout=10
                    )
                    if response.status_code == 200:
                        vt_data = response.json()
                        attributes = vt_data.get("data", {}).get("attributes", {})
                        
                        analysis_stats = attributes.get("last_analysis_stats", {})
                        malicious_count = analysis_stats.get("malicious", 0)
                        total_count = sum(analysis_stats.values()) if analysis_stats else 0
                        
                        enrichment.update({
                            "detection_ratio": f"{malicious_count}/{total_count}",
                            "first_seen": attributes.get("first_submission_date"),
                            "file_type": attributes.get("type_description"),
                            "names": attributes.get("names", [])[:5]  # Limit to top 5 names
                        })
                        logger.info(f"Successfully enriched hash {ioc_value} with VirusTotal data")
                else:
                    logger.info("No VirusTotal API key available for hash enrichment")
            except Exception as e:
                logger.warning(f"Error enriching hash {ioc_value}: {str(e)}")
        
        # Enrich URLs
        elif ioc_type == "url":
            try:
                # Extract domain from URL for further enrichment
                domain_match = re.search(r'https?://([^/]+)', ioc_value)
                if domain_match:
                    domain = domain_match.group(1)
                    enrichment["domain"] = domain
                    
                    # Try to get domain reputation
                    import socket
                    try:
                        ip = socket.gethostbyname(domain)
                        enrichment["resolved_ip"] = ip
                    except socket.error:
                        enrichment["resolved"] = False
            except Exception as e:
                logger.warning(f"Error enriching URL {ioc_value}: {str(e)}")
        
        return enrichment
    
    def analyze_and_store_feed_data(self, feed_name: str, days_back: int = 1) -> Dict[str, Any]:
        """Analyze and enrich threat data from a specific feed"""
        # Query recent data from BigQuery
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.{feed_name}`
        WHERE _ingestion_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
        """
        
        try:
            query_job = bq_client.query(query)
            results = query_job.result()
            
            processed_count = 0
            ioc_count = 0
            analysis_results = []
            
            for row in results:
                row_dict = dict(row.items())
                
                # Different feeds have different structures
                content = ""
                metadata = {"id": row_dict.get("id", str(hash(str(row_dict)))), "type": feed_name}
                
                # Process based on feed type
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
                
                elif feed_name == "phishtank_urls":
                    content = f"Phishing URL: {row_dict.get('url', '')}\n"
                    content += f"Target: {row_dict.get('target', '')}\n"
                    content += f"Verification: {row_dict.get('verified', 'Unknown')}"
                
                elif feed_name == "urlhaus_malware":
                    content = f"Malicious URL: {row_dict.get('url', '')}\n"
                    content += f"Status: {row_dict.get('status', '')}\n"
                    content += f"Threat: {row_dict.get('threat', '')}\n"
                    if row_dict.get('tags'):
                        content += f"Tags: {', '.join(row_dict.get('tags', []))}\n"
                
                elif feed_name == "feodotracker_c2":
                    content = f"C2 Server: {row_dict.get('ip_address', '')}:{row_dict.get('port', '')}\n"
                    content += f"Malware: {row_dict.get('malware', '')}\n"
                    content += f"Status: {row_dict.get('status', '')}\n"
                    content += f"First Seen: {row_dict.get('first_seen', '')}"
                
                elif feed_name == "sslbl_certificates":
                    content = f"Malicious SSL Certificate: {row_dict.get('ssl_fingerprint', '')}\n"
                    content += f"Malware: {row_dict.get('malware', '')}\n"
                    content += f"First Seen: {row_dict.get('first_seen', '')}\n"
                    content += f"Last Seen: {row_dict.get('last_seen', '')}"
                
                # Generic fallback - convert row to text
                else:
                    for key, value in row_dict.items():
                        if key != "_ingestion_timestamp" and value:
                            content += f"{key}: {value}\n"
                
                # Skip if no content to analyze
                if not content:
                    logger.warning(f"No content to analyze for {feed_name} record {metadata['id']}")
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
                
                # Analyze with Vertex AI if available
                vertex_analysis = {}
                if self.llm:
                    vertex_analysis = self.analyze_with_vertex_ai(content, metadata)
                else:
                    logger.warning(f"Skipping Vertex AI analysis for {feed_name} as LLM is not available")
                
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
                
                # Log progress every 10 records
                if processed_count % 10 == 0:
                    logger.info(f"Processed {processed_count} items from {feed_name}")
            
            logger.info(f"Completed processing {processed_count} items, extracted {ioc_count} IOCs from {feed_name}")
            
            # Publish event to notify of analysis completion
            try:
                self._publish_analysis_event(feed_name, processed_count, ioc_count)
            except Exception as e:
                logger.error(f"Failed to publish analysis event: {str(e)}")
            
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
    
    def _publish_analysis_event(self, feed_name: str, processed_count: int, ioc_count: int) -> None:
        """Publish an event to Pub/Sub about completed analysis"""
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
    
    def detect_campaign(self, timespan_days: int = 7) -> List[Dict[str, Any]]:
        """Detect threat campaigns by clustering related IOCs and analyses"""
        # Query recent analyses
        query = f"""
        SELECT *
        FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis`
        WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {timespan_days} DAY)
        """
        
        try:
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
                
                # Try to match on techniques as well
                if techniques and len(techniques) > 3:
                    # Look for ATT&CK techniques (e.g., T1566)
                    technique_matches = re.findall(r'T\d{4}(?:\.\d{3})?', techniques)
                    for technique in technique_matches:
                        campaign_identifiers.append(f"technique:{technique}")
                
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
                        "targets": targets,
                        "timestamps": []
                    }
                
                analysis_groups[campaign_key]["analyses"].append(row_dict["source_id"])
                analysis_groups[campaign_key]["iocs"].extend(iocs)
                
                # Track timestamps for first/last seen
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
                    "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else first_seen,
                    "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                    "campaign_name": self._generate_campaign_name(group)
                }
                
                campaigns.append(campaign)
                
                # Store campaign in BigQuery
                self._store_campaign(campaign)
            
            logger.info(f"Detected {len(campaigns)} threat campaigns")
            return campaigns
            
        except Exception as e:
            logger.error(f"Error detecting campaigns: {str(e)}")
            return []
    
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

    def generate_threat_report(self, campaign_id: str = None, days: int = 7) -> Dict[str, Any]:
        """Generate a comprehensive threat report based on analyzed data"""
        if not self.llm:
            logger.warning("Vertex AI LLM not available for report generation")
            return {"error": "LLM not available for report generation"}
        
        if campaign_id:
            # Generate report for specific campaign
            query = f"""
            SELECT * 
            FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE campaign_id = '{campaign_id}'
            """
            
            query_job = bq_client.query(query)
            results = query_job.result()
            
            campaigns = [dict(row) for row in results]
            if not campaigns:
                return {"error": f"Campaign {campaign_id} not found"}
            
            campaign = campaigns[0]
            
            # Get related IOCs
            iocs = json.loads(campaign.get("iocs", "[]"))
            
            # Generate report using Vertex AI
            prompt = f"""
            Generate a comprehensive threat intelligence report for the following campaign:
            
            Campaign Name: {campaign.get('campaign_name')}
            Threat Actor: {campaign.get('threat_actor')}
            Malware: {campaign.get('malware')}
            Techniques: {campaign.get('techniques')}
            Targets: {campaign.get('targets')}
            First Seen: {campaign.get('first_seen')}
            Last Seen: {campaign.get('last_seen')}
            
            Include the following sections:
            1. Executive Summary
            2. Threat Actor Profile
            3. Technical Analysis
            4. Indicators of Compromise
            5. Mitigation Recommendations
            
            Format the report in Markdown.
            """
            
            try:
                response = self.llm.predict(prompt, temperature=0.2, max_output_tokens=2048)
                return {
                    "campaign_id": campaign_id,
                    "campaign_name": campaign.get('campaign_name'),
                    "report_content": response.text,
                    "generated_at": datetime.utcnow().isoformat(),
                    "ioc_count": len(iocs)
                }
            except Exception as e:
                logger.error(f"Error generating campaign report: {str(e)}")
                return {"error": str(e)}
        else:
            # Generate summary report of recent activity
            query = f"""
            SELECT COUNT(*) as campaign_count,
                   (SELECT COUNT(*) FROM `{PROJECT_ID}.{DATASET_ID}.threat_analysis` 
                    WHERE analysis_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)) as analysis_count
            FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            """
            
            query_job = bq_client.query(query)
            results = query_job.result()
            stats = next(results)
            
            # Get top threats
            top_threats_query = f"""
            SELECT threat_actor, malware, COUNT(*) as count
            FROM `{PROJECT_ID}.{DATASET_ID}.threat_campaigns`
            WHERE detection_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            GROUP BY threat_actor, malware
            ORDER BY count DESC
            LIMIT 5
            """
            
            threats_job = bq_client.query(top_threats_query)
            threats_results = threats_job.result()
            top_threats = [dict(row) for row in threats_results]
            
            # Generate summary prompt
            prompt = f"""
            Generate a threat intelligence summary report for the past {days} days with the following statistics:
            
            - Total campaigns detected: {stats.campaign_count}
            - Total threat analyses performed: {stats.analysis_count}
            
            Top threats observed:
            {json.dumps(top_threats, indent=2)}
            
            Include the following sections:
            1. Executive Summary
            2. Key Findings
            3. Emerging Threats
            4. Recommendations
            
            Format the report in Markdown.
            """
            
            try:
                response = self.llm.predict(prompt, temperature=0.2, max_output_tokens=2048)
                return {
                    "report_type": "summary",
                    "report_content": response.text,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_days": days,
                    "campaign_count": stats.campaign_count,
                    "analysis_count": stats.analysis_count
                }
            except Exception as e:
                logger.error(f"Error generating summary report: {str(e)}")
                return {"error": str(e)}


# Cloud Function entry point
def analyze_threat_data(event, context):
    """Pub/Sub triggered Cloud Function for threat data analysis"""
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
                result = analyzer.analyze_and_store_feed_data(feed_name)
                
                # Detect campaigns periodically (every 10th message)
                if hash(feed_name) % 10 == 0:
                    campaigns = analyzer.detect_campaign()
                
                return result
        except Exception as e:
            logger.error(f"Error processing event data: {str(e)}")
    
    # Fallback to analyzing all feeds
    feeds = ["alienvault_pulses", "misp_events", "threatfox_iocs", 
             "phishtank_urls", "urlhaus_malware", "feodotracker_c2", "sslbl_certificates"]
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
    feeds = ["alienvault_pulses", "misp_events", "threatfox_iocs", 
             "phishtank_urls", "urlhaus_malware", "feodotracker_c2", "sslbl_certificates"]
    
    for feed in feeds:
        try:
            result = analyzer.analyze_and_store_feed_data(feed)
            print(f"Analyzed {feed}: {result}")
        except Exception as e:
            print(f"Error analyzing {feed}: {str(e)}")
    
    campaigns = analyzer.detect_campaign()
    print(f"Detected {len(campaigns)} campaigns")
