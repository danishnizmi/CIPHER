"""
Optimized analysis module for threat intelligence data.
Handles processing, enrichment, and AI-powered analysis of threat indicators.
"""

import os
import json
import logging
import hashlib
import re
import ipaddress
import socket
import time
import threading
from typing import Dict, List, Any, Union, Optional, Tuple
from datetime import datetime, timedelta
import traceback

import requests
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound
from google.api_core.exceptions import GoogleAPIError
import vertexai
from vertexai.language_models import TextGenerationModel
from vertexai.preview.generative_models import GenerativeModel

# Import configuration
from config import Config, ServiceManager, ServiceStatus, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Global analysis state
analysis_status = {
    "last_run": None,
    "running": False,
    "indicators_processed": 0,
    "indicators_failed": 0,
    "errors": []
}

# Lock for thread-safe operations
_analysis_lock = threading.Lock()

# AI models for NLP analysis
text_model = None
generative_model = None

# -------------------- Helper Functions --------------------

def get_clients():
    """Get initialized clients from service manager."""
    service_manager = Config.get_service_manager()
    
    return (
        service_manager.get_client('bigquery'),
        service_manager.get_client('storage'),
        service_manager.get_client('publisher'),
        service_manager.get_client('subscriber')
    )

def publish_event(event_type: str, data: dict = None):
    """Publish event through event bus if available."""
    try:
        from flask import g
        if hasattr(g, 'event_bus'):
            g.event_bus.publish(event_type, data)
            logger.debug(f"Published event: {event_type}")
    except Exception as e:
        logger.debug(f"Not in Flask context, skipping event publish: {e}")

def update_service_status(status: ServiceStatus, error: str = None):
    """Update analysis service status."""
    service_manager = Config.get_service_manager()
    service_manager.update_status('analysis', status, error)

def check_ingestion_status():
    """Check if ingestion is running before starting analysis."""
    service_manager = Config.get_service_manager()
    status = service_manager.get_status()
    
    ingestion_status = status['services'].get('ingestion', ServiceStatus.INITIALIZING.value)
    
    if ingestion_status == ServiceStatus.READY.value:
        return True
    else:
        logger.warning(f"Ingestion not ready ({ingestion_status}), deferring analysis")
        return False

# -------------------- AI Model Initialization --------------------

def initialize_ai_models():
    """Initialize AI models with error handling and fallbacks."""
    global text_model, generative_model
    
    if not Config.NLP_ENABLED:
        logger.info("NLP analysis is disabled in configuration")
        return False
        
    service_manager = Config.get_service_manager()
    
    try:
        service_manager.update_status('ai_models', ServiceStatus.INITIALIZING)
        
        vertexai.init(project=Config.GCP_PROJECT, location=Config.VERTEXAI_LOCATION)
        
        # Try loading preferred model with fallback
        try:
            text_model = TextGenerationModel.from_pretrained(Config.VERTEXAI_MODEL)
            logger.info(f"Initialized text model: {Config.VERTEXAI_MODEL}")
        except Exception as e:
            logger.warning(f"Could not load specified model: {str(e)}")
            try:
                text_model = TextGenerationModel.from_pretrained("text-bison@latest")
                logger.info("Initialized fallback text-bison model")
            except Exception:
                logger.error("Could not load fallback text model")
                text_model = None
        
        # Try to load generative model
        try:
            generative_model = GenerativeModel("gemini-1.0-pro")
            logger.info("Initialized Gemini model for advanced analysis")
        except Exception as e:
            logger.warning(f"Could not load Gemini model: {str(e)}")
            generative_model = None
        
        if text_model or generative_model:
            service_manager.update_status('ai_models', ServiceStatus.READY)
            return True
        else:
            service_manager.update_status('ai_models', ServiceStatus.ERROR, "No AI models available")
            return False
        
    except Exception as e:
        logger.error(f"Error initializing Vertex AI: {str(e)}")
        logger.error(traceback.format_exc())
        service_manager.update_status('ai_models', ServiceStatus.ERROR, str(e))
        return False

# Initialize AI models if enabled
if Config.NLP_ENABLED:
    initialize_ai_models()

# -------------------- Data Validation --------------------

class DataValidator:
    """Validates data formats and structures."""
    
    @staticmethod
    def is_valid_ip(value: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def is_valid_domain(value: str) -> bool:
        """Check if a string is a valid domain name."""
        if not isinstance(value, str): return False
        domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        return bool(re.match(domain_pattern, value.lower()))
    
    @staticmethod
    def is_valid_url(value: str) -> bool:
        """Check if a string is a valid URL."""
        if not isinstance(value, str): return False
        url_pattern = r'^(http|https|ftp)://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, value.lower()))
    
    @staticmethod
    def is_valid_hash(value: str, hash_type: str) -> bool:
        """Check if a string is a valid hash of the specified type."""
        if not isinstance(value, str): return False
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$'
        }
        return hash_type in hash_patterns and bool(re.match(hash_patterns[hash_type], value.lower()))
    
    @staticmethod
    def validate_indicator(indicator: Dict) -> Tuple[bool, Optional[str]]:
        """Validate an indicator object."""
        if not isinstance(indicator, dict):
            return False, "Indicator must be a dictionary"
            
        if 'type' not in indicator:
            return False, "Indicator missing 'type' field"
        if 'value' not in indicator:
            return False, "Indicator missing 'value' field"
            
        ioc_type = indicator['type'].lower()
        value = indicator['value']
        
        validate_funcs = {
            'ip': DataValidator.is_valid_ip,
            'domain': DataValidator.is_valid_domain,
            'url': DataValidator.is_valid_url
        }
        
        if ioc_type in ['md5', 'sha1', 'sha256']:
            if not DataValidator.is_valid_hash(value, ioc_type):
                return False, f"Invalid {ioc_type} hash: {value}"
        elif ioc_type in validate_funcs and not validate_funcs[ioc_type](value):
            return False, f"Invalid {ioc_type}: {value}"
                
        return True, None

# -------------------- Enrichment Functions --------------------

def enrich_with_geo_data(ip_address: str) -> Dict[str, Any]:
    """Enrich IP indicators with geolocation data."""
    geo_data = {
        "country": None, "city": None, "asn": None, 
        "asn_org": None, "latitude": None, "longitude": None
    }
    
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            geo_data["country"] = "Private"
            return geo_data
        
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            geo_data["country"] = data.get("country")
            geo_data["city"] = data.get("city")
            
            if data.get("org"):
                org_parts = data.get("org", "").split(maxsplit=1)
                geo_data["asn"] = org_parts[0] if org_parts else None
                geo_data["asn_org"] = org_parts[1] if len(org_parts) > 1 else None
            
            if data.get("loc"):
                try:
                    lat, lng = data.get("loc").split(",")
                    geo_data["latitude"] = float(lat)
                    geo_data["longitude"] = float(lng)
                except (ValueError, TypeError):
                    pass
    
    except Exception as e:
        logger.warning(f"Error enriching IP with geo data: {str(e)}")
    
    return geo_data

def enrich_with_dns_data(domain: str) -> Dict[str, Any]:
    """Enrich domain indicators with DNS resolution data."""
    dns_data = {
        "resolved_ips": [],
        "has_mx": False,
        "nameservers": []
    }
    
    try:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            dns_data["resolved_ips"] = ips
        except socket.gaierror:
            pass
        
        try:
            import dns.resolver
            
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_data["has_mx"] = len(mx_records) > 0
                dns_data["mx_records"] = [str(mx.exchange) for mx in mx_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_data["nameservers"] = [ns.target.to_text() for ns in ns_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_data["txt_records"] = [txt.strings[0].decode('utf-8') for txt in txt_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
        except ImportError:
            dns_data["has_mx"] = len(dns_data["resolved_ips"]) > 0
    
    except Exception as e:
        logger.warning(f"Error enriching domain with DNS data: {str(e)}")
    
    return dns_data

# -------------------- AI Analysis Functions --------------------

def analyze_text_with_ai(text: str, prompt_type: str) -> Dict[str, Any]:
    """Analyze text using AI to extract threat intelligence insights."""
    if not text_model and not generative_model:
        return {"error": "AI analysis not available"}
    
    result = {
        "processed": False,
        "entities": [],
        "sentiment": None,
        "categories": [],
        "summary": None
    }
    
    try:
        prompts = {
            "extract_iocs": f"""
                Extract all indicators of compromise (IOCs) from the following text. 
                Return a JSON array of objects with 'type' and 'value' for each IOC.
                Only include valid IOCs like IP addresses, domains, URLs, file hashes, and email addresses.
                
                Text to analyze: {text}
                
                JSON Response:
                """,
            "threat_assessment": f"""
                Analyze the following potential threat information and provide an assessment.
                Return a JSON object with:
                - threat_level (low, medium, high, critical)
                - confidence (0-100)
                - tactics (MITRE ATT&CK tactics if applicable)
                - techniques (MITRE ATT&CK techniques if applicable)
                - summary (brief assessment)
                
                Text to analyze: {text}
                
                JSON Response:
                """,
            "summarize": f"""
                Summarize the following threat intelligence information in 2-3 sentences.
                Focus on the key threat actors, targets, methods, and indicators.
                
                Text to analyze: {text}
                
                Summary:
                """
        }
        
        prompt = prompts.get(prompt_type)
        if not prompt:
            return {"error": "Unknown prompt type"}
        
        # Try Gemini model first if available
        if generative_model:
            try:
                response = generative_model.generate_content(prompt)
                response_text = response.text
                
                if prompt_type in ["extract_iocs", "threat_assessment"]:
                    try:
                        json_pattern = r'({[\s\S]*}|\[[\s\S]*\])'
                        json_match = re.search(json_pattern, response_text)
                        
                        if json_match:
                            result = json.loads(json_match.group(0))
                            result["processed"] = True
                            result["model"] = "gemini"
                        else:
                            raise ValueError("Failed to parse JSON from Gemini response")
                    except (json.JSONDecodeError, ValueError):
                        if text_model:
                            return analyze_with_text_model(text, prompt_type, prompt)
                        else:
                            result["error"] = "Failed to parse JSON from response"
                elif prompt_type == "summarize":
                    result["summary"] = response_text.strip()
                    result["processed"] = True
                    result["model"] = "gemini"
                
                return result
                
            except Exception as e:
                logger.warning(f"Gemini model error: {str(e)}, falling back to text model")
                if text_model:
                    return analyze_with_text_model(text, prompt_type, prompt)
                else:
                    result["error"] = str(e)
                    return result
        
        elif text_model:
            return analyze_with_text_model(text, prompt_type, prompt)
    
    except Exception as e:
        logger.error(f"Error analyzing text with AI: {str(e)}")
        result["error"] = str(e)
    
    return result

def analyze_with_text_model(text: str, prompt_type: str, prompt: str) -> Dict[str, Any]:
    """Helper function to analyze text with the text generation model."""
    result = {
        "processed": False,
        "entities": [],
        "sentiment": None,
        "categories": [],
        "summary": None,
        "model": "text-bison"
    }
    
    try:
        response = text_model.predict(
            prompt=prompt,
            temperature=0.2,
            max_output_tokens=1024,
            top_p=0.8,
            top_k=40
        )
        
        if prompt_type in ["extract_iocs", "threat_assessment"]:
            try:
                json_pattern = r'({[\s\S]*}|\[[\s\S]*\])'
                json_match = re.search(json_pattern, response.text)
                
                if json_match:
                    parsed_result = json.loads(json_match.group(0))
                    result.update(parsed_result)
                    result["processed"] = True
                else:
                    result["error"] = "Failed to parse JSON from response"
            except json.JSONDecodeError:
                result["error"] = "Failed to parse JSON from response"
        elif prompt_type == "summarize":
            result["summary"] = response.text.strip()
            result["processed"] = True
    
    except Exception as e:
        logger.error(f"Error with text model: {str(e)}")
        result["error"] = str(e)
        
    return result

# -------------------- Risk Scoring --------------------

def compute_confidence_score(indicator: Dict[str, Any]) -> int:
    """Compute a confidence score for an indicator."""
    base_score = indicator.get('confidence', 50)
    boost_factors = 0
    
    sources = indicator.get('sources', [])
    if isinstance(sources, list) and len(sources) > 1:
        boost_factors += min(len(sources) * 5, 20)
    
    created_at = indicator.get('created_at')
    if isinstance(created_at, datetime):
        age_days = (datetime.utcnow() - created_at).days
        if age_days < 7:
            boost_factors += 10
        elif age_days > 90:
            boost_factors -= 10
    
    if indicator.get('related_threat_actors'): boost_factors += 10
    if indicator.get('related_campaigns'): boost_factors += 10
    
    return max(0, min(base_score + boost_factors, 100))

def calculate_risk_score(indicator: Dict[str, Any]) -> int:
    """Calculate a risk score for an indicator."""
    base_score = indicator.get('confidence', 50)
    risk_modifiers = 0
    
    if indicator.get('related_campaigns'): risk_modifiers += 15
    if indicator.get('related_threat_actors'): risk_modifiers += 10
    
    created_at = indicator.get('created_at')
    if isinstance(created_at, datetime):
        age_days = (datetime.utcnow() - created_at).days
        if age_days < 7: risk_modifiers += 20
        elif age_days < 30: risk_modifiers += 10
        elif age_days > 180: risk_modifiers -= 20
    elif isinstance(created_at, str):
        try:
            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            age_days = (datetime.utcnow() - dt).days
            if age_days < 7: risk_modifiers += 20
            elif age_days < 30: risk_modifiers += 10
            elif age_days > 180: risk_modifiers -= 20
        except (ValueError, TypeError):
            pass
    
    indicator_type = indicator.get('type', '').lower()
    if indicator_type in ['md5', 'sha1', 'sha256']:
        risk_modifiers += 5
    elif indicator_type == 'ip':
        if indicator.get('tags') and any(tag in indicator.get('tags', []) for tag in ['c2', 'botnet', 'ransomware']):
            risk_modifiers += 25
    
    if indicator.get('tags') and 'false_positive' in indicator.get('tags', []):
        risk_modifiers -= 50
    
    return max(0, min(base_score + risk_modifiers, 100))

# -------------------- Data Storage --------------------

def store_analysis_result(indicator_id: str, analysis_data: Dict[str, Any]) -> bool:
    """Store analysis results in BigQuery."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        table_id = Config.get_table_name('indicators')
        table = bq_client.get_table(table_id)
        
        from ingestion import DataProcessor
        sanitized_data = DataProcessor.sanitize_record(analysis_data)
        
        update_fields = {
            'last_analyzed': datetime.utcnow(),
            'confidence': sanitized_data.get('confidence'),
            'risk_score': sanitized_data.get('risk_score'),
            'analysis_summary': sanitized_data.get('summary')
        }
        
        query_parts = [
            f"UPDATE `{table_id}` SET",
            "last_analyzed = @last_analyzed",
            "confidence = @confidence",
            "risk_score = @risk_score",
            "analysis_summary = @analysis_summary"
        ]
        
        if 'enrichment' in sanitized_data:
            for key, value in sanitized_data['enrichment'].items():
                field_name = f'enrichment_{key}'
                update_fields[field_name] = value
                query_parts.append(f", {field_name} = @{field_name}")
        
        if 'tags' in sanitized_data and sanitized_data['tags']:
            query_parts.append(", tags = ARRAY_CONCAT(IFNULL(tags, []), "
                             "ARRAY(SELECT DISTINCT x FROM UNNEST(@new_tags) x "
                             "WHERE x NOT IN (SELECT y FROM UNNEST(IFNULL(tags, [])) y)))")
            update_fields['new_tags'] = sanitized_data.get('tags', [])
        
        query_parts.append("WHERE id = @indicator_id")
        update_fields['indicator_id'] = indicator_id
        
        query_params = []
        for key, value in update_fields.items():
            if value is None: continue
            
            if isinstance(value, datetime):
                query_params.append(bigquery.ScalarQueryParameter(key, "TIMESTAMP", value))
            elif isinstance(value, int):
                query_params.append(bigquery.ScalarQueryParameter(key, "INT64", value))
            elif isinstance(value, float):
                query_params.append(bigquery.ScalarQueryParameter(key, "FLOAT64", value))
            elif isinstance(value, list):
                query_params.append(bigquery.ArrayQueryParameter(key, "STRING", value))
            else:
                query_params.append(bigquery.ScalarQueryParameter(key, "STRING", str(value)))
        
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        query_job = bq_client.query(" ".join(query_parts), job_config=job_config)
        query_job.result()
        
        logger.info(f"Successfully stored analysis results for indicator {indicator_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error storing analysis results: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return False

def get_indicator_data(indicator_id: str) -> Dict[str, Any]:
    """Retrieve indicator data from BigQuery."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return {}
    
    try:
        query = f"""
        SELECT * FROM `{Config.get_table_name('indicators')}`
        WHERE id = @indicator_id
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator_id", "STRING", indicator_id)
            ]
        )
        results = list(bq_client.query(query, job_config=job_config))
        
        if not results:
            logger.warning(f"Indicator {indicator_id} not found")
            return {}
        
        indicator = dict(results[0])
        for key, value in indicator.items():
            if isinstance(value, datetime):
                indicator[key] = value.isoformat()
        
        return indicator
    
    except Exception as e:
        logger.error(f"Error retrieving indicator data: {str(e)}")
        report_error(e)
        return {}

def get_related_indicators(indicator_value: str, indicator_type: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Find indicators related to the given indicator."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return []
    
    related_indicators = []
    table_id = Config.get_table_name('indicators')
    
    try:
        query_templates = {
            'network': f"""
                WITH original AS (
                    SELECT * FROM `{table_id}`
                    WHERE (type = @indicator_type AND value = @indicator_value)
                )
                SELECT i.* FROM `{table_id}` i
                JOIN original o ON (
                    i.source = o.source OR
                    i.campaign_id = o.campaign_id OR
                    i.report_id = o.report_id
                )
                WHERE i.value != @indicator_value
                ORDER BY i.confidence DESC
                LIMIT @limit
            """,
            'hash': f"""
                WITH original AS (
                    SELECT * FROM `{table_id}`
                    WHERE (type = @indicator_type AND value = @indicator_value)
                )
                SELECT i.* FROM `{table_id}` i
                JOIN original o ON (
                    i.related_malware_ids = o.related_malware_ids OR
                    i.campaign_id = o.campaign_id OR
                    i.report_id = o.report_id
                )
                WHERE i.value != @indicator_value
                ORDER BY i.confidence DESC
                LIMIT @limit
            """,
            'generic': f"""
                WITH original AS (
                    SELECT * FROM `{table_id}`
                    WHERE (type = @indicator_type AND value = @indicator_value)
                )
                SELECT i.* FROM `{table_id}` i
                JOIN original o ON (
                    i.source = o.source OR
                    i.campaign_id = o.campaign_id OR
                    i.report_id = o.report_id
                )
                WHERE i.value != @indicator_value
                ORDER BY i.created_at DESC
                LIMIT @limit
            """
        }
        
        if indicator_type in ['ip', 'domain', 'url']:
            query = query_templates['network']
        elif indicator_type in ['md5', 'sha1', 'sha256']:
            query = query_templates['hash']
        else:
            query = query_templates['generic']
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator_type", "STRING", indicator_type),
                bigquery.ScalarQueryParameter("indicator_value", "STRING", indicator_value),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        for row in query_job:
            indicator = dict(row)
            for key, value in indicator.items():
                if isinstance(value, datetime):
                    indicator[key] = value.isoformat()
            related_indicators.append(indicator)
        
        logger.info(f"Found {len(related_indicators)} indicators related to {indicator_type}:{indicator_value}")
    
    except Exception as e:
        logger.error(f"Error finding related indicators: {str(e)}")
        report_error(e)
    
    return related_indicators

def upload_analysis_to_gcs(analysis_data: Dict[str, Any], indicator_id: str) -> Optional[str]:
    """Upload analysis results to Google Cloud Storage."""
    _, storage_client, _, _ = get_clients()
    
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"analysis/{indicator_id}/{timestamp}.json"
        
        bucket = storage_client.bucket(Config.GCS_BUCKET)
        blob = bucket.blob(filename)
        
        def json_serializer(obj):
            if isinstance(obj, (datetime, datetime.date)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        blob.upload_from_string(
            json.dumps(analysis_data, default=json_serializer),
            content_type="application/json"
        )
        
        gcs_uri = f"gs://{Config.GCS_BUCKET}/{filename}"
        logger.info(f"Stored analysis for indicator {indicator_id} at {gcs_uri}")
        
        return gcs_uri
    
    except Exception as e:
        logger.error(f"Error uploading analysis to GCS: {str(e)}")
        report_error(e)
        return None

# -------------------- Main Analysis Functions --------------------

def analyze_indicator(indicator_id: str, force_reanalysis: bool = False) -> Dict[str, Any]:
    """Analyze a single indicator and enrich it with additional information."""
    global analysis_status
    
    logger.info(f"Analyzing indicator {indicator_id}")
    
    indicator = get_indicator_data(indicator_id)
    
    if not indicator:
        logger.warning(f"Indicator {indicator_id} not found")
        with _analysis_lock:
            analysis_status["indicators_failed"] += 1
            analysis_status["errors"].append(f"Indicator {indicator_id} not found")
        return {"error": "Indicator not found"}
    
    valid, error_msg = DataValidator.validate_indicator(indicator)
    if not valid:
        logger.warning(f"Invalid indicator {indicator_id}: {error_msg}")
        with _analysis_lock:
            analysis_status["indicators_failed"] += 1
            analysis_status["errors"].append(f"Invalid indicator {indicator_id}: {error_msg}")
        return {"error": f"Invalid indicator: {error_msg}"}
    
    if not force_reanalysis and indicator.get('last_analyzed'):
        if isinstance(indicator['last_analyzed'], str):
            try:
                last_analyzed = datetime.fromisoformat(indicator['last_analyzed'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                last_analyzed = None
        else:
            last_analyzed = indicator.get('last_analyzed')
        
        if last_analyzed and (datetime.utcnow() - last_analyzed) < timedelta(hours=24):
            logger.info(f"Indicator {indicator_id} was recently analyzed, skipping")
            return {"status": "skipped", "reason": "recently_analyzed"}
    
    analysis_result = {
        "indicator_id": indicator_id,
        "indicator_type": indicator.get('type'),
        "indicator_value": indicator.get('value'),
        "timestamp": datetime.utcnow().isoformat(),
        "enrichment": {},
        "tags": []
    }
    
    if not indicator.get('type') and indicator.get('value'):
        from ingestion import DataProcessor
        indicator_type = DataProcessor.determine_ioc_type(indicator['value'])
        analysis_result["detected_type"] = indicator_type
    else:
        indicator_type = indicator.get('type', 'unknown')
    
    # Enrich based on indicator type
    if indicator_type == 'ip':
        geo_data = enrich_with_geo_data(indicator['value'])
        analysis_result["enrichment"]["geo"] = geo_data
        
        if geo_data.get('country'):
            analysis_result["tags"].append(f"country:{geo_data['country']}")
        if geo_data.get('asn'):
            analysis_result["tags"].append(f"asn:{geo_data['asn']}")
    
    elif indicator_type == 'domain':
        dns_data = enrich_with_dns_data(indicator['value'])
        analysis_result["enrichment"]["dns"] = dns_data
        
        if dns_data.get('resolved_ips'):
            analysis_result["tags"].append(f"active")
        if dns_data.get('has_mx'):
            analysis_result["tags"].append(f"has_mx")
    
    elif indicator_type == 'url':
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(indicator['value'])
            domain = parsed_url.netloc
            
            if domain:
                dns_data = enrich_with_dns_data(domain)
                analysis_result["enrichment"]["dns"] = dns_data
                
                if dns_data.get('resolved_ips'):
                    analysis_result["tags"].append(f"active")
        except Exception as e:
            logger.warning(f"Error parsing URL {indicator['value']}: {str(e)}")
    
    # Get related indicators
    if indicator.get('value') and indicator.get('type'):
        related = get_related_indicators(
            indicator_value=indicator['value'],
            indicator_type=indicator['type']
        )
        
        if related:
            analysis_result["related_indicators_count"] = len(related)
            analysis_result["related_indicators_sample"] = related[:3]
    
    # Calculate scores
    analysis_result["confidence"] = compute_confidence_score(indicator)
    analysis_result["risk_score"] = calculate_risk_score(indicator)
    
    # Add severity tag
    if analysis_result["risk_score"] >= 80:
        analysis_result["tags"].append("severity:critical")
    elif analysis_result["risk_score"] >= 60:
        analysis_result["tags"].append("severity:high")
    elif analysis_result["risk_score"] >= 40:
        analysis_result["tags"].append("severity:medium")
    else:
        analysis_result["tags"].append("severity:low")
    
    # AI Analysis
    if indicator.get('description') and Config.NLP_ENABLED and (text_model or generative_model):
        try:
            ai_analysis = analyze_text_with_ai(
                text=indicator['description'],
                prompt_type="threat_assessment"
            )
            
            if ai_analysis.get('processed'):
                analysis_result["ai_insights"] = ai_analysis
                
                summary_analysis = analyze_text_with_ai(
                    text=indicator['description'],
                    prompt_type="summarize"
                )
                
                if summary_analysis.get('summary'):
                    analysis_result["summary"] = summary_analysis['summary']
                
                if ai_analysis.get('tactics'):
                    for tactic in ai_analysis.get('tactics', []):
                        analysis_result["tags"].append(f"mitre:tactic:{tactic}")
                
                if ai_analysis.get('techniques'):
                    for technique in ai_analysis.get('techniques', []):
                        analysis_result["tags"].append(f"mitre:technique:{technique}")
        
        except Exception as e:
            logger.error(f"Error performing AI analysis: {str(e)}")
    
    # Upload to GCS
    gcs_uri = upload_analysis_to_gcs(analysis_result, indicator_id)
    if gcs_uri:
        analysis_result["gcs_uri"] = gcs_uri
    
    # Store results
    success = store_analysis_result(indicator_id, analysis_result)
    analysis_result["stored"] = success
    
    if success:
        with _analysis_lock:
            analysis_status["indicators_processed"] += 1
        
        # Publish event
        publish_event('analysis_completed', {
            'indicator_id': indicator_id,
            'risk_score': analysis_result.get('risk_score')
        })
    else:
        with _analysis_lock:
            analysis_status["indicators_failed"] += 1
            analysis_status["errors"].append(f"Failed to store analysis for indicator {indicator_id}")
    
    logger.info(f"Completed analysis for indicator {indicator_id}")
    return analysis_result

def batch_analyze_indicators(indicator_ids: List[str], force_reanalysis: bool = False) -> Dict[str, Any]:
    """Analyze multiple indicators in batch."""
    logger.info(f"Starting batch analysis of {len(indicator_ids)} indicators")
    
    results = {
        "total": len(indicator_ids),
        "successful": 0,
        "failed": 0,
        "skipped": 0,
        "details": []
    }
    
    for idx, indicator_id in enumerate(indicator_ids):
        try:
            logger.info(f"Processing indicator {idx+1}/{len(indicator_ids)}: {indicator_id}")
            
            analysis_result = analyze_indicator(indicator_id, force_reanalysis)
            
            if analysis_result.get('error'):
                results["failed"] += 1
            elif analysis_result.get('status') == 'skipped':
                results["skipped"] += 1
            else:
                results["successful"] += 1
            
            results["details"].append({
                "indicator_id": indicator_id,
                "success": not analysis_result.get('error'),
                "skipped": analysis_result.get('status') == 'skipped',
                "confidence": analysis_result.get('confidence'),
                "risk_score": analysis_result.get('risk_score')
            })
        
        except Exception as e:
            logger.error(f"Error analyzing indicator {indicator_id}: {str(e)}")
            report_error(e)
            results["failed"] += 1
            results["details"].append({
                "indicator_id": indicator_id,
                "success": False,
                "error": str(e)
            })
    
    logger.info(f"Batch analysis completed: {results['successful']} successful, {results['failed']} failed, {results['skipped']} skipped")
    return results

def find_indicators_for_analysis(limit: int = 100) -> List[str]:
    """Find indicators that need analysis or reanalysis."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return []
    
    indicator_ids = []
    table_id = Config.get_table_name('indicators')
    
    try:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        query = f"""
        SELECT id FROM `{table_id}`
        WHERE 
            last_analyzed IS NULL
            OR last_analyzed < @seven_days_ago
        ORDER BY confidence DESC, created_at DESC
        LIMIT @limit
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("seven_days_ago", "TIMESTAMP", seven_days_ago),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        for row in query_job:
            indicator_ids.append(row.id)
        
        logger.info(f"Found {len(indicator_ids)} indicators needing analysis")
    
    except Exception as e:
        logger.error(f"Error finding indicators for analysis: {str(e)}")
        report_error(e)
    
    return indicator_ids

def analyze_threat_data(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for threat data analysis."""
    global analysis_status
    
    with _analysis_lock:
        analysis_status = {
            "last_run": datetime.utcnow().isoformat(),
            "running": True,
            "indicators_processed": 0,
            "indicators_failed": 0,
            "errors": []
        }
        update_service_status(ServiceStatus.READY)
    
    logger.info(f"Received analysis request: {event_data}")
    
    try:
        analyze_all = event_data.get('analyze_all', False)
        force_reanalysis = event_data.get('force_reanalysis', False)
        indicator_ids = event_data.get('indicator_ids', [])
        
        if analyze_all:
            limit = int(event_data.get('limit', 100))
            indicator_ids = find_indicators_for_analysis(limit=limit)
        
        if not indicator_ids:
            logger.warning("No indicators specified for analysis")
            with _analysis_lock:
                analysis_status["running"] = False
            return {
                "status": "error",
                "message": "No indicators specified for analysis"
            }
        
        results = batch_analyze_indicators(indicator_ids, force_reanalysis)
        
        with _analysis_lock:
            analysis_status["running"] = False
        
        # Publish completion event
        publish_event('analysis_batch_completed', {
            'total': results['total'],
            'successful': results['successful'],
            'failed': results['failed'],
            'skipped': results['skipped']
        })
        
        return {"status": "success", "results": results}
    
    except Exception as e:
        logger.error(f"Error processing analysis request: {str(e)}")
        report_error(e)
        
        with _analysis_lock:
            analysis_status["running"] = False
            analysis_status["errors"].append(str(e))
            update_service_status(ServiceStatus.ERROR, str(e))
        
        return {"status": "error", "message": str(e)}

# -------------------- Background Analysis --------------------

def start_background_analysis(limit: int = 100):
    """Start background analysis thread with ingestion coordination."""
    def analysis_thread():
        service_manager = Config.get_service_manager()
        
        while True:
            try:
                # Check if ingestion is ready
                if not check_ingestion_status():
                    time.sleep(300)  # Wait 5 minutes
                    continue
                
                update_service_status(ServiceStatus.READY)
                
                # Find indicators that need analysis
                indicators = find_indicators_for_analysis(limit=limit)
                
                if not indicators:
                    logger.info("No indicators need analysis at this time")
                    time.sleep(1800)  # Sleep for 30 minutes
                    continue
                
                # Process indicators
                logger.info(f"Processing {len(indicators)} indicators in background")
                analyze_threat_data({
                    "indicator_ids": indicators,
                    "force_reanalysis": False
                })
                
                time.sleep(900)  # Sleep for 15 minutes before next batch
                
            except Exception as e:
                logger.error(f"Error in background analysis thread: {str(e)}")
                update_service_status(ServiceStatus.ERROR, str(e))
                time.sleep(300)  # Sleep for 5 minutes before retrying
    
    thread = threading.Thread(target=analysis_thread)
    thread.daemon = True
    thread.start()
    logger.info("Background analysis thread started")
    return thread

def get_analysis_status() -> Dict:
    """Get the current status of the analysis process."""
    global analysis_status
    
    with _analysis_lock:
        status_copy = dict(analysis_status)
    
    status_copy["current_time"] = datetime.utcnow().isoformat()
    return status_copy

# -------------------- Correlation Analysis --------------------

def find_correlations(time_window_days: int = 30, min_confidence: int = 70, limit: int = 1000) -> Dict[str, Any]:
    """Find correlations between indicators."""
    bq_client, _, _, _ = get_clients()
    
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return {"error": "BigQuery client not initialized"}
    
    try:
        logger.info(f"Finding correlations with time window of {time_window_days} days")
        
        start_date = datetime.utcnow() - timedelta(days=time_window_days)
        table_id = Config.get_table_name('indicators')
        
        query = f"""
        WITH recent_indicators AS (
            SELECT * FROM `{table_id}`
            WHERE 
                created_at > @start_date
                AND confidence >= @min_confidence
            ORDER BY confidence DESC
            LIMIT @limit
        )
        SELECT 
            a.id as indicator_a_id,
            a.type as indicator_a_type,
            a.value as indicator_a_value,
            b.id as indicator_b_id,
            b.type as indicator_b_type,
            b.value as indicator_b_value,
            a.source as source_a,
            b.source as source_b,
            a.confidence as confidence_a,
            b.confidence as confidence_b,
            a.created_at as created_at_a,
            b.created_at as created_at_b
        FROM recent_indicators a
        JOIN recent_indicators b
        ON 
            a.id != b.id
            AND (
                a.source = b.source
                OR a.campaign_id = b.campaign_id
                OR a.report_id = b.report_id
                OR (a.related_threat_actors IS NOT NULL AND b.related_threat_actors IS NOT NULL AND 
                    EXISTS(SELECT 1 FROM UNNEST(a.related_threat_actors) x JOIN UNNEST(b.related_threat_actors) y ON x = y))
            )
        ORDER BY a.confidence + b.confidence DESC
        LIMIT 1000
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("start_date", "TIMESTAMP", start_date),
                bigquery.ScalarQueryParameter("min_confidence", "INT64", min_confidence),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        correlations = []
        correlation_groups = {}
        
        for row in query_job:
            correlation = {
                "indicator_a": {
                    "id": row.indicator_a_id,
                    "type": row.indicator_a_type,
                    "value": row.indicator_a_value,
                    "source": row.source_a,
                    "confidence": row.confidence_a,
                    "created_at": row.created_at_a.isoformat() if row.created_at_a else None
                },
                "indicator_b": {
                    "id": row.indicator_b_id,
                    "type": row.indicator_b_type,
                    "value": row.indicator_b_value,
                    "source": row.source_b,
                    "confidence": row.confidence_b,
                    "created_at": row.created_at_b.isoformat() if row.created_at_b else None
                },
                "strength": (row.confidence_a + row.confidence_b) / 2,
                "correlation_type": "co-occurrence"
            }
            correlations.append(correlation)
            
            type_pair = f"{row.indicator_a_type}-{row.indicator_b_type}"
            if type_pair not in correlation_groups:
                correlation_groups[type_pair] = []
            correlation_groups[type_pair].append(correlation)
        
        stats = {
            "total_correlations": len(correlations),
            "by_type": {k: len(v) for k, v in correlation_groups.items()},
            "time_window_days": time_window_days,
            "min_confidence": min_confidence
        }
        
        logger.info(f"Found {len(correlations)} correlations")
        
        return {
            "statistics": stats,
            "correlations": correlations[:100],
            "correlation_groups": {k: len(v) for k, v in correlation_groups.items()}
        }
    
    except Exception as e:
        logger.error(f"Error finding correlations: {str(e)}")
        report_error(e)
        return {"error": f"Error finding correlations: {str(e)}"}

# -------------------- Pub/Sub Handler --------------------

def analyze_from_pubsub(event, context):
    """Cloud Function entry point for PubSub triggered analysis."""
    try:
        logger.info(f"Received PubSub message: {event}")
        
        if 'data' in event:
            import base64
            message_data_bytes = base64.b64decode(event['data'])
            message_data = json.loads(message_data_bytes)
        else:
            message_data = {}
        
        result = analyze_threat_data(message_data)
        
        logger.info(f"Analysis complete: {result.get('status')}")
        
        # Publish result
        if result.get('status') == 'success':
            _, _, publisher, _ = get_clients()
            if publisher:
                try:
                    result_topic = f"projects/{Config.GCP_PROJECT}/topics/threat-analysis-results"
                    
                    def json_serializer(obj):
                        if isinstance(obj, (datetime, datetime.date)):
                            return obj.isoformat()
                        raise TypeError(f"Type {type(obj)} not serializable")
                    
                    future = publisher.publish(
                        result_topic,
                        json.dumps(result, default=json_serializer).encode('utf-8'),
                        operation="analysis_complete"
                    )
                    future.result()
                    logger.info(f"Published analysis results to {result_topic}")
                except Exception as e:
                    logger.error(f"Error publishing analysis results: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}")
        report_error(e)

# Auto-start background analysis
if Config.ENVIRONMENT == 'production' and Config.ANALYSIS_ENABLED:
    def delayed_analysis_start():
        time.sleep(30)  # Wait 30 seconds for app startup
        start_background_analysis(limit=50)
        
    startup_thread = threading.Thread(target=delayed_analysis_start)
    startup_thread.daemon = True
    startup_thread.start()
    logger.info("Auto-analysis enabled - will start analysis after app startup")

# Module initialization
if __name__ != "__main__":
    logger.info("Initializing analysis module")
    if Config.NLP_ENABLED and not text_model and not generative_model:
        initialize_ai_models()

# CLI mode
if __name__ == "__main__":
    logger.info("Running analysis.py as standalone script")
    
    # Initialize config
    Config.init_app()
    
    # Initialize AI models if needed
    if Config.NLP_ENABLED and not text_model and not generative_model:
        initialize_ai_models()
    
    # Find indicators that need analysis
    indicators = find_indicators_for_analysis(limit=100)
    
    if indicators:
        logger.info(f"Found {len(indicators)} indicators that need analysis")
        result = analyze_threat_data({
            "indicator_ids": indicators,
            "force_reanalysis": False
        })
        
        print(f"Analysis complete: {result.get('status')}")
        successful = result.get('results', {}).get('successful', 0)
        failed = result.get('results', {}).get('failed', 0) 
        skipped = result.get('results', {}).get('skipped', 0)
        print(f"Processed {successful + failed + skipped} indicators: {successful} successful, {failed} failed, {skipped} skipped")
    else:
        print("No indicators need analysis at this time")
    
    # Run correlation analysis
    print("\nFinding correlations...")
    correlations = find_correlations(time_window_days=30, min_confidence=60)
    if "error" not in correlations:
        print(f"Found {correlations['statistics']['total_correlations']} correlations")
    else:
        print(f"Error finding correlations: {correlations.get('error')}")
