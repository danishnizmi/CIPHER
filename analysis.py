"""
Analysis module for threat intelligence data.
Handles processing, enrichment, and AI-powered analysis of threat indicators.
"""

import os
import json
import uuid
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
from config import Config, initialize_bigquery, initialize_storage, initialize_pubsub, report_error

# Initialize logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global analysis state for status tracking
analysis_status = {
    "last_run": None,
    "running": False,
    "indicators_processed": 0,
    "indicators_failed": 0,
    "errors": []
}

# Initialize GCP clients - with error handling
try:
    bq_client = initialize_bigquery()
    storage_client = initialize_storage()
    publisher, subscriber = initialize_pubsub()
    logger.info("Successfully initialized GCP clients")
except Exception as e:
    logger.error(f"Error initializing GCP clients: {str(e)}")
    logger.error(traceback.format_exc())
    bq_client = None
    storage_client = None
    publisher = None
    subscriber = None

# Initialize Vertex AI for NLP analysis if enabled
text_model = None
generative_model = None

def initialize_ai_models():
    """Initialize AI models with error handling and fallbacks."""
    global text_model, generative_model
    
    if not Config.NLP_ENABLED:
        logger.info("NLP analysis is disabled in configuration")
        return False
        
    try:
        # Initialize Vertex AI
        vertexai.init(project=Config.GCP_PROJECT, location=Config.VERTEXAI_LOCATION)
        
        # Try to load the specified model first
        try:
            text_model = TextGenerationModel.from_pretrained(Config.VERTEXAI_MODEL)
            logger.info(f"Initialized Vertex AI Text Generation Model: {Config.VERTEXAI_MODEL}")
        except Exception as e:
            logger.warning(f"Could not load specified model {Config.VERTEXAI_MODEL}: {str(e)}")
            # Try a fallback model
            try:
                text_model = TextGenerationModel.from_pretrained("text-bison@latest")
                logger.info("Initialized fallback text-bison model")
            except Exception as e2:
                logger.error(f"Could not load fallback model either: {str(e2)}")
                text_model = None
        
        # Try to load generative model for more advanced analysis
        try:
            generative_model = GenerativeModel("gemini-1.0-pro")
            logger.info("Initialized Gemini model for advanced analysis")
        except Exception as e:
            logger.warning(f"Could not load Gemini model: {str(e)}")
            generative_model = None
            
        return text_model is not None or generative_model is not None
        
    except Exception as e:
        logger.error(f"Error initializing Vertex AI: {str(e)}")
        logger.error(traceback.format_exc())
        return False

# Initialize AI models
if Config.NLP_ENABLED:
    initialize_ai_models()

# -------------------- Data Validation and Sanitization Classes --------------------

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
        if not isinstance(value, str):
            return False
        domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        return bool(re.match(domain_pattern, value.lower()))
    
    @staticmethod
    def is_valid_url(value: str) -> bool:
        """Check if a string is a valid URL."""
        if not isinstance(value, str):
            return False
        url_pattern = r'^(http|https|ftp)://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, value.lower()))
    
    @staticmethod
    def is_valid_hash(value: str, hash_type: str) -> bool:
        """Check if a string is a valid hash of the specified type."""
        if not isinstance(value, str):
            return False
            
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$'
        }
        
        if hash_type not in hash_patterns:
            return False
            
        return bool(re.match(hash_patterns[hash_type], value.lower()))
    
    @staticmethod
    def is_valid_email(value: str) -> bool:
        """Check if a string is a valid email address."""
        if not isinstance(value, str):
            return False
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, value))
    
    @staticmethod
    def validate_indicator(indicator: Dict) -> Tuple[bool, Optional[str]]:
        """Validate an indicator object."""
        if not isinstance(indicator, dict):
            return False, "Indicator must be a dictionary"
            
        # Check required fields
        if 'type' not in indicator:
            return False, "Indicator missing 'type' field"
        if 'value' not in indicator:
            return False, "Indicator missing 'value' field"
            
        # Validate based on type
        ioc_type = indicator['type'].lower()
        value = indicator['value']
        
        if ioc_type == 'ip':
            if not DataValidator.is_valid_ip(value):
                return False, f"Invalid IP address: {value}"
        elif ioc_type == 'domain':
            if not DataValidator.is_valid_domain(value):
                return False, f"Invalid domain name: {value}"
        elif ioc_type == 'url':
            if not DataValidator.is_valid_url(value):
                return False, f"Invalid URL: {value}"
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            if not DataValidator.is_valid_hash(value, ioc_type):
                return False, f"Invalid {ioc_type} hash: {value}"
        elif ioc_type == 'email':
            if not DataValidator.is_valid_email(value):
                return False, f"Invalid email address: {value}"
                
        return True, None

class DataSanitizer:
    """Sanitizes data to prevent injection issues and ensure consistent format."""
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string values to prevent XSS and injection attacks."""
        if not value or not isinstance(value, str):
            return ""
            
        # Remove control characters
        value = re.sub(r'[\x00-\x1F\x7F]', '', value)
        
        # Limit string length to prevent abuse
        max_length = 32768  # 32KB
        if len(value) > max_length:
            return value[:max_length]
            
        return value
    
    @staticmethod
    def sanitize_indicator(indicator: Dict) -> Dict:
        """Sanitize an indicator object."""
        if not isinstance(indicator, dict):
            return {}
            
        sanitized = {}
        
        for key, value in indicator.items():
            # Handle nested dictionaries
            if isinstance(value, dict):
                sanitized[key] = DataSanitizer.sanitize_indicator(value)
                
            # Handle lists
            elif isinstance(value, list):
                if value and all(isinstance(item, dict) for item in value):
                    # List of dictionaries
                    sanitized[key] = [DataSanitizer.sanitize_indicator(item) for item in value]
                elif value and all(isinstance(item, str) for item in value):
                    # List of strings
                    sanitized[key] = [DataSanitizer.sanitize_string(item) for item in value]
                else:
                    # Other lists, keep as is
                    sanitized[key] = value
                    
            # Handle strings
            elif isinstance(value, str):
                sanitized[key] = DataSanitizer.sanitize_string(value)
                
            # Pass through other types
            else:
                sanitized[key] = value
                
        return sanitized

# -------------------- Helper Functions --------------------

def extract_ioc_type(value: str) -> str:
    """
    Identify the type of indicator based on its format.
    
    Args:
        value: The indicator value to analyze
    
    Returns:
        String representing the IOC type (ip, domain, url, hash, etc.)
    """
    if not value or not isinstance(value, str):
        return "unknown"
        
    value = value.strip().lower()
    
    # Check for IP address
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    
    # Check for domain
    domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if re.match(domain_pattern, value):
        return "domain"
    
    # Check for URL
    url_pattern = r'^(http|https|ftp)://[^\s/$.?#].[^\s]*$'
    if re.match(url_pattern, value):
        return "url"
    
    # Check for file hash
    md5_pattern = r'^[a-f0-9]{32}$'
    sha1_pattern = r'^[a-f0-9]{40}$'
    sha256_pattern = r'^[a-f0-9]{64}$'
    
    if re.match(md5_pattern, value):
        return "md5"
    elif re.match(sha1_pattern, value):
        return "sha1"
    elif re.match(sha256_pattern, value):
        return "sha256"
    
    # Check for email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, value):
        return "email"
    
    # Default type
    return "unknown"

def compute_confidence_score(indicator: Dict[str, Any]) -> int:
    """
    Compute a confidence score for an indicator based on multiple factors.
    
    Args:
        indicator: The indicator data
    
    Returns:
        Confidence score (0-100)
    """
    base_score = indicator.get('confidence', 50)
    
    # Factors that can increase confidence
    boost_factors = 0
    
    # Multiple sources reporting the same IOC
    sources = indicator.get('sources', [])
    if isinstance(sources, list) and len(sources) > 1:
        boost_factors += min(len(sources) * 5, 20)  # Up to 20 points for multiple sources
    
    # Recent activity
    created_at = indicator.get('created_at')
    if isinstance(created_at, datetime):
        age_days = (datetime.utcnow() - created_at).days
        if age_days < 7:
            boost_factors += 10  # Very recent indicators get a boost
        elif age_days > 90:
            boost_factors -= 10  # Older indicators get reduced confidence
    
    # Associated with known threat actors
    if indicator.get('related_threat_actors'):
        boost_factors += 10
    
    # Associated with active campaigns
    if indicator.get('related_campaigns'):
        boost_factors += 10
    
    # Final score calculation
    final_score = base_score + boost_factors
    
    # Ensure within bounds
    return max(0, min(final_score, 100))

def enrich_with_geo_data(ip_address: str) -> Dict[str, Any]:
    """
    Enrich IP indicators with geolocation data.
    
    Args:
        ip_address: The IP address to enrich
    
    Returns:
        Dictionary containing geolocation data
    """
    geo_data = {
        "country": None,
        "city": None,
        "asn": None,
        "asn_org": None,
        "latitude": None,
        "longitude": None
    }
    
    try:
        # Check if IP is private
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            geo_data["country"] = "Private"
            return geo_data
        
        # Make API request to free geolocation service
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            geo_data["country"] = data.get("country")
            geo_data["city"] = data.get("city")
            geo_data["asn"] = data.get("org", "").split()[0] if data.get("org") else None
            geo_data["asn_org"] = " ".join(data.get("org", "").split()[1:]) if data.get("org") else None
            
            # Parse location coordinates
            if data.get("loc"):
                try:
                    lat, lng = data.get("loc").split(",")
                    geo_data["latitude"] = float(lat)
                    geo_data["longitude"] = float(lng)
                except (ValueError, TypeError):
                    pass
    
    except requests.RequestException as e:
        logger.warning(f"Network error enriching IP with geo data: {str(e)}")
    except Exception as e:
        logger.warning(f"Error enriching IP with geo data: {str(e)}")
    
    return geo_data

def enrich_with_dns_data(domain: str) -> Dict[str, Any]:
    """
    Enrich domain indicators with DNS resolution data.
    
    Args:
        domain: The domain to enrich
    
    Returns:
        Dictionary containing DNS data
    """
    dns_data = {
        "resolved_ips": [],
        "has_mx": False,
        "nameservers": []
    }
    
    try:
        # Get A records
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            dns_data["resolved_ips"] = ips
        except socket.gaierror:
            pass
        
        # Try to use dnspython if available for more detailed lookups
        try:
            import dns.resolver
            
            # Check for MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_data["has_mx"] = len(mx_records) > 0
                dns_data["mx_records"] = [str(mx.exchange) for mx in mx_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get nameservers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_data["nameservers"] = [ns.target.to_text() for ns in ns_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            # Try to get TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_data["txt_records"] = [txt.strings[0].decode('utf-8') for txt in txt_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
        except ImportError:
            # Fallback to simpler checks
            dns_data["has_mx"] = len(dns_data["resolved_ips"]) > 0
    
    except Exception as e:
        logger.warning(f"Error enriching domain with DNS data: {str(e)}")
    
    return dns_data

def analyze_text_with_ai(text: str, prompt_type: str) -> Dict[str, Any]:
    """
    Analyze text using Vertex AI to extract threat intelligence insights.
    
    Args:
        text: The text to analyze
        prompt_type: Type of analysis to perform
    
    Returns:
        Dictionary containing analysis results
    """
    if not text_model and not generative_model:
        logger.warning("AI models not initialized, skipping text analysis")
        return {"error": "AI analysis not available"}
    
    result = {
        "processed": False,
        "entities": [],
        "sentiment": None,
        "categories": [],
        "summary": None
    }
    
    try:
        # Build prompts based on analysis type
        if prompt_type == "extract_iocs":
            prompt = f"""
            Extract all indicators of compromise (IOCs) from the following text. 
            Return a JSON array of objects with 'type' and 'value' for each IOC.
            Only include valid IOCs like IP addresses, domains, URLs, file hashes, and email addresses.
            
            Text to analyze: {text}
            
            JSON Response:
            """
        elif prompt_type == "threat_assessment":
            prompt = f"""
            Analyze the following potential threat information and provide an assessment.
            Return a JSON object with:
            - threat_level (low, medium, high, critical)
            - confidence (0-100)
            - tactics (MITRE ATT&CK tactics if applicable)
            - techniques (MITRE ATT&CK techniques if applicable)
            - summary (brief assessment)
            
            Text to analyze: {text}
            
            JSON Response:
            """
        elif prompt_type == "summarize":
            prompt = f"""
            Summarize the following threat intelligence information in 2-3 sentences.
            Focus on the key threat actors, targets, methods, and indicators.
            
            Text to analyze: {text}
            
            Summary:
            """
        else:
            return {"error": "Unknown prompt type"}
        
        # Try Gemini model first if available (more powerful)
        if generative_model:
            try:
                response = generative_model.generate_content(prompt)
                response_text = response.text
                
                # Process response based on prompt type
                if prompt_type in ["extract_iocs", "threat_assessment"]:
                    try:
                        # Find JSON in response
                        json_pattern = r'({[\s\S]*}|\[[\s\S]*\])'
                        json_match = re.search(json_pattern, response_text)
                        
                        if json_match:
                            json_str = json_match.group(0)
                            result = json.loads(json_str)
                            result["processed"] = True
                            result["model"] = "gemini"
                        else:
                            # Fallback to text model
                            raise ValueError("Failed to parse JSON from Gemini response")
                    except (json.JSONDecodeError, ValueError):
                        # Fallback to text model
                        logger.info("Falling back to text model for JSON parsing")
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
        
        # Use text model if Gemini not available
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
        # Get response from Vertex AI
        response = text_model.predict(
            prompt=prompt,
            temperature=0.2,  # Low temperature for consistent outputs
            max_output_tokens=1024,
            top_p=0.8,
            top_k=40
        )
        
        # Process response based on prompt type
        if prompt_type in ["extract_iocs", "threat_assessment"]:
            try:
                # Find JSON in response
                json_pattern = r'({[\s\S]*}|\[[\s\S]*\])'
                json_match = re.search(json_pattern, response.text)
                
                if json_match:
                    json_str = json_match.group(0)
                    parsed_result = json.loads(json_str)
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

def calculate_risk_score(indicator: Dict[str, Any]) -> int:
    """
    Calculate a risk score for an indicator based on multiple factors.
    
    Args:
        indicator: The indicator data
    
    Returns:
        Risk score (0-100)
    """
    # Base score determined by indicator confidence
    base_score = indicator.get('confidence', 50)
    
    # Risk modifiers
    risk_modifiers = 0
    
    # Higher risk for indicators associated with active campaigns
    if indicator.get('related_campaigns'):
        risk_modifiers += 15
    
    # Higher risk for indicators associated with high-profile threat actors
    if indicator.get('related_threat_actors'):
        risk_modifiers += 10
    
    # Higher risk for recently observed indicators
    created_at = indicator.get('created_at')
    if isinstance(created_at, datetime):
        age_days = (datetime.utcnow() - created_at).days
        if age_days < 7:
            risk_modifiers += 20  # Very recent indicators are higher risk
        elif age_days < 30:
            risk_modifiers += 10  # Recent indicators are higher risk
        elif age_days > 180:
            risk_modifiers -= 20  # Older indicators are lower risk
    elif isinstance(created_at, str):
        try:
            # Try to parse string date
            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            age_days = (datetime.utcnow() - dt).days
            if age_days < 7:
                risk_modifiers += 20
            elif age_days < 30:
                risk_modifiers += 10
            elif age_days > 180:
                risk_modifiers -= 20
        except (ValueError, TypeError):
            pass
    
    # Adjust risk based on indicator type
    indicator_type = indicator.get('type', '').lower()
    if indicator_type in ['md5', 'sha1', 'sha256']:
        risk_modifiers += 5  # File hashes are slightly higher risk
    elif indicator_type == 'ip':
        # Look for IP reputation data
        if indicator.get('tags') and any(tag in indicator.get('tags', []) for tag in ['c2', 'botnet', 'ransomware']):
            risk_modifiers += 25  # IPs associated with serious threats
    
    # Adjust for reported false positives
    if indicator.get('tags') and 'false_positive' in indicator.get('tags', []):
        risk_modifiers -= 50
    
    # Calculate final score
    final_score = base_score + risk_modifiers
    
    # Ensure within bounds
    return max(0, min(final_score, 100))

def store_analysis_result(indicator_id: str, analysis_data: Dict[str, Any]) -> bool:
    """
    Store analysis results in BigQuery.
    
    Args:
        indicator_id: The ID of the indicator
        analysis_data: The analysis data to store
    
    Returns:
        Boolean indicating success
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return False
    
    try:
        # Get the indicators table
        table_id = Config.get_table_name('indicators')
        table = bq_client.get_table(table_id)
        
        # Sanitize analysis data
        sanitized_data = DataSanitizer.sanitize_indicator(analysis_data)
        
        # Prepare update data
        update_fields = {
            'last_analyzed': datetime.utcnow(),
            'confidence': sanitized_data.get('confidence'),
            'risk_score': sanitized_data.get('risk_score'),
            'analysis_summary': sanitized_data.get('summary')
        }
        
        # Add enrichment data if present
        if 'enrichment' in sanitized_data:
            for key, value in sanitized_data['enrichment'].items():
                update_fields[f'enrichment_{key}'] = value
        
        # Prepare the query
        query = f"""
        UPDATE `{table_id}`
        SET
            last_analyzed = @last_analyzed,
            confidence = @confidence,
            risk_score = @risk_score,
            analysis_summary = @analysis_summary
        """
        
        # Add enrichment fields to query if present
        if 'enrichment' in sanitized_data:
            for key in sanitized_data['enrichment'].keys():
                update_fields[f'enrichment_{key}'] = sanitized_data['enrichment'].get(key)
                query += f",\n    enrichment_{key} = @enrichment_{key}"
        
        # Add tags if present (append to existing tags)
        if 'tags' in sanitized_data and sanitized_data['tags']:
            query += f"""
            , tags = ARRAY_CONCAT(
                IFNULL(tags, []),
                ARRAY(SELECT DISTINCT x FROM UNNEST(@new_tags) x WHERE x NOT IN (SELECT y FROM UNNEST(IFNULL(tags, [])) y))
            )
            """
            update_fields['new_tags'] = sanitized_data.get('tags', [])
        
        # Add where clause
        query += f"\nWHERE id = @indicator_id"
        update_fields['indicator_id'] = indicator_id
        
        # Create query parameters
        query_params = []
        for key, value in update_fields.items():
            # Skip None values
            if value is None:
                continue
                
            # Determine parameter type
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
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        query_job = bq_client.query(query, job_config=job_config)
        query_job.result()  # Wait for the query to complete
        
        logger.info(f"Successfully stored analysis results for indicator {indicator_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error storing analysis results: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return False

def get_indicator_data(indicator_id: str) -> Dict[str, Any]:
    """
    Retrieve indicator data from BigQuery.
    
    Args:
        indicator_id: The ID of the indicator
    
    Returns:
        Dictionary containing indicator data
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return {}
    
    try:
        # Prepare query
        query = f"""
        SELECT * FROM `{Config.get_table_name('indicators')}`
        WHERE id = @indicator_id
        """
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator_id", "STRING", indicator_id)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        results = list(query_job)
        
        if not results:
            logger.warning(f"Indicator {indicator_id} not found")
            return {}
        
        # Convert to dictionary and handle datetime fields
        indicator = dict(results[0])
        for key, value in indicator.items():
            if isinstance(value, datetime):
                indicator[key] = value.isoformat()
        
        return indicator
    
    except Exception as e:
        logger.error(f"Error retrieving indicator data: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {}

def get_related_indicators(indicator_value: str, indicator_type: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Find indicators related to the given indicator.
    
    Args:
        indicator_value: The value of the indicator
        indicator_type: The type of the indicator
        limit: Maximum number of related indicators to return
    
    Returns:
        List of related indicators
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return []
    
    related_indicators = []
    
    try:
        # Build query based on indicator type
        if indicator_type in ['ip', 'domain', 'url']:
            # For network indicators, look for other indicators observed with the same IP/domain
            query = f"""
            WITH original AS (
                SELECT * FROM `{Config.get_table_name('indicators')}`
                WHERE (type = @indicator_type AND value = @indicator_value)
            )
            SELECT i.* FROM `{Config.get_table_name('indicators')}` i
            JOIN original o ON (
                i.source = o.source OR
                i.campaign_id = o.campaign_id OR
                i.report_id = o.report_id
            )
            WHERE i.value != @indicator_value
            ORDER BY i.confidence DESC
            LIMIT @limit
            """
        elif indicator_type in ['md5', 'sha1', 'sha256']:
            # For file hash indicators, look for other hashes of the same file or related malware
            query = f"""
            WITH original AS (
                SELECT * FROM `{Config.get_table_name('indicators')}`
                WHERE (type = @indicator_type AND value = @indicator_value)
            )
            SELECT i.* FROM `{Config.get_table_name('indicators')}` i
            JOIN original o ON (
                i.related_malware_ids = o.related_malware_ids OR
                i.campaign_id = o.campaign_id OR
                i.report_id = o.report_id
            )
            WHERE i.value != @indicator_value
            ORDER BY i.confidence DESC
            LIMIT @limit
            """
        else:
            # For other indicators, use a more generic approach
            query = f"""
            WITH original AS (
                SELECT * FROM `{Config.get_table_name('indicators')}`
                WHERE (type = @indicator_type AND value = @indicator_value)
            )
            SELECT i.* FROM `{Config.get_table_name('indicators')}` i
            JOIN original o ON (
                i.source = o.source OR
                i.campaign_id = o.campaign_id OR
                i.report_id = o.report_id
            )
            WHERE i.value != @indicator_value
            ORDER BY i.created_at DESC
            LIMIT @limit
            """
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator_type", "STRING", indicator_type),
                bigquery.ScalarQueryParameter("indicator_value", "STRING", indicator_value),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        # Process results
        for row in query_job:
            indicator = dict(row)
            for key, value in indicator.items():
                if isinstance(value, datetime):
                    indicator[key] = value.isoformat()
            related_indicators.append(indicator)
        
        logger.info(f"Found {len(related_indicators)} indicators related to {indicator_type}:{indicator_value}")
    
    except Exception as e:
        logger.error(f"Error finding related indicators: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
    
    return related_indicators

def upload_analysis_to_gcs(analysis_data: Dict[str, Any], indicator_id: str) -> Optional[str]:
    """
    Upload analysis results to Google Cloud Storage.
    
    Args:
        analysis_data: The analysis data to upload
        indicator_id: The ID of the indicator
    
    Returns:
        GCS URI of the uploaded file or None if failed
    """
    if not storage_client:
        logger.error("Storage client not initialized")
        return None
    
    try:
        # Generate a unique filename
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        filename = f"analysis/{indicator_id}/{timestamp}.json"
        
        # Get bucket
        bucket = storage_client.bucket(Config.GCS_BUCKET)
        blob = bucket.blob(filename)
        
        # Serialize dates for JSON
        def json_serializer(obj):
            if isinstance(obj, (datetime, datetime.date)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        # Upload the file
        blob.upload_from_string(
            json.dumps(analysis_data, default=json_serializer),
            content_type="application/json"
        )
        
        gcs_uri = f"gs://{Config.GCS_BUCKET}/{filename}"
        logger.info(f"Stored analysis for indicator {indicator_id} at {gcs_uri}")
        
        return gcs_uri
    
    except Exception as e:
        logger.error(f"Error uploading analysis to GCS: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return None

# -------------------- Main Analysis Functions --------------------

def analyze_indicator(indicator_id: str, force_reanalysis: bool = False) -> Dict[str, Any]:
    """
    Analyze a single indicator and enrich it with additional information.
    
    Args:
        indicator_id: The ID of the indicator to analyze
        force_reanalysis: Whether to force reanalysis even if recently analyzed
    
    Returns:
        Dictionary containing analysis results
    """
    global analysis_status
    
    logger.info(f"Analyzing indicator {indicator_id}")
    
    # Get indicator data
    indicator = get_indicator_data(indicator_id)
    
    if not indicator:
        logger.warning(f"Indicator {indicator_id} not found")
        analysis_status["indicators_failed"] += 1
        analysis_status["errors"].append(f"Indicator {indicator_id} not found")
        return {"error": "Indicator not found"}
    
    # Validate incoming indicator data
    valid, error_msg = DataValidator.validate_indicator(indicator)
    if not valid:
        logger.warning(f"Invalid indicator {indicator_id}: {error_msg}")
        analysis_status["indicators_failed"] += 1
        analysis_status["errors"].append(f"Invalid indicator {indicator_id}: {error_msg}")
        return {"error": f"Invalid indicator: {error_msg}"}
    
    # Check if analysis is needed
    if not force_reanalysis and indicator.get('last_analyzed'):
        # Convert string date to datetime if needed
        if isinstance(indicator['last_analyzed'], str):
            try:
                last_analyzed = datetime.fromisoformat(indicator['last_analyzed'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                last_analyzed = None
        else:
            last_analyzed = indicator.get('last_analyzed')
        
        # Skip if recently analyzed (within 24 hours)
        if last_analyzed and (datetime.utcnow() - last_analyzed) < timedelta(hours=24):
            logger.info(f"Indicator {indicator_id} was recently analyzed, skipping")
            return {"status": "skipped", "reason": "recently_analyzed"}
    
    # Initialize analysis result
    analysis_result = {
        "indicator_id": indicator_id,
        "indicator_type": indicator.get('type'),
        "indicator_value": indicator.get('value'),
        "timestamp": datetime.utcnow().isoformat(),
        "enrichment": {},
        "tags": []
    }
    
    # Determine indicator type if not set
    if not indicator.get('type') and indicator.get('value'):
        indicator_type = extract_ioc_type(indicator['value'])
        analysis_result["detected_type"] = indicator_type
    else:
        indicator_type = indicator.get('type', 'unknown')
    
    # Enrich based on indicator type
    if indicator_type == 'ip':
        # Enrich IP with geolocation data
        geo_data = enrich_with_geo_data(indicator['value'])
        analysis_result["enrichment"]["geo"] = geo_data
        
        # Add country tag if available
        if geo_data.get('country'):
            analysis_result["tags"].append(f"country:{geo_data['country']}")
        
        # Add ASN tag if available
        if geo_data.get('asn'):
            analysis_result["tags"].append(f"asn:{geo_data['asn']}")
    
    elif indicator_type == 'domain':
        # Enrich domain with DNS data
        dns_data = enrich_with_dns_data(indicator['value'])
        analysis_result["enrichment"]["dns"] = dns_data
        
        # Add tags based on DNS data
        if dns_data.get('resolved_ips'):
            analysis_result["tags"].append(f"active")
        
        if dns_data.get('has_mx'):
            analysis_result["tags"].append(f"has_mx")
    
    elif indicator_type == 'url':
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(indicator['value'])
            domain = parsed_url.netloc
            
            # Enrich with DNS data for the domain
            if domain:
                dns_data = enrich_with_dns_data(domain)
                analysis_result["enrichment"]["dns"] = dns_data
                
                # Add tags based on DNS data
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
            
            # Add first 3 related indicators
            analysis_result["related_indicators_sample"] = related[:3]
    
    # Calculate confidence score
    confidence = compute_confidence_score(indicator)
    analysis_result["confidence"] = confidence
    
    # Calculate risk score
    risk_score = calculate_risk_score(indicator)
    analysis_result["risk_score"] = risk_score
    
    # Add severity tag based on risk score
    if risk_score >= 80:
        analysis_result["tags"].append("severity:critical")
    elif risk_score >= 60:
        analysis_result["tags"].append("severity:high")
    elif risk_score >= 40:
        analysis_result["tags"].append("severity:medium")
    else:
        analysis_result["tags"].append("severity:low")
    
    # Add any descriptions to the analysis
    if indicator.get('description'):
        # Use AI to extract insights from description if available
        if Config.NLP_ENABLED and (text_model or generative_model):
            try:
                ai_analysis = analyze_text_with_ai(
                    text=indicator['description'],
                    prompt_type="threat_assessment"
                )
                
                if ai_analysis.get('processed'):
                    # Add AI insights
                    analysis_result["ai_insights"] = ai_analysis
                    
                    # Generate summary
                    summary_analysis = analyze_text_with_ai(
                        text=indicator['description'],
                        prompt_type="summarize"
                    )
                    
                    if summary_analysis.get('summary'):
                        analysis_result["summary"] = summary_analysis['summary']
                    
                    # Add MITRE ATT&CK tactics/techniques if identified
                    if ai_analysis.get('tactics'):
                        for tactic in ai_analysis.get('tactics', []):
                            analysis_result["tags"].append(f"mitre:tactic:{tactic}")
                    
                    if ai_analysis.get('techniques'):
                        for technique in ai_analysis.get('techniques', []):
                            analysis_result["tags"].append(f"mitre:technique:{technique}")
            
            except Exception as e:
                logger.error(f"Error performing AI analysis: {str(e)}")
    
    # Upload full analysis to GCS for reference
    gcs_uri = upload_analysis_to_gcs(analysis_result, indicator_id)
    if gcs_uri:
        analysis_result["gcs_uri"] = gcs_uri
    
    # Store analysis results in BigQuery
    success = store_analysis_result(indicator_id, analysis_result)
    analysis_result["stored"] = success
    
    if success:
        analysis_status["indicators_processed"] += 1
    else:
        analysis_status["indicators_failed"] += 1
        analysis_status["errors"].append(f"Failed to store analysis for indicator {indicator_id}")
    
    logger.info(f"Completed analysis for indicator {indicator_id}")
    return analysis_result

def batch_analyze_indicators(indicator_ids: List[str], force_reanalysis: bool = False) -> Dict[str, Any]:
    """
    Analyze multiple indicators in batch.
    
    Args:
        indicator_ids: List of indicator IDs to analyze
        force_reanalysis: Whether to force reanalysis
    
    Returns:
        Dictionary containing batch analysis results
    """
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
            
            # Analyze the indicator
            analysis_result = analyze_indicator(indicator_id, force_reanalysis)
            
            # Update statistics
            if analysis_result.get('error'):
                results["failed"] += 1
            elif analysis_result.get('status') == 'skipped':
                results["skipped"] += 1
            else:
                results["successful"] += 1
            
            # Add summarized result
            results["details"].append({
                "indicator_id": indicator_id,
                "success": not analysis_result.get('error'),
                "skipped": analysis_result.get('status') == 'skipped',
                "confidence": analysis_result.get('confidence'),
                "risk_score": analysis_result.get('risk_score')
            })
        
        except Exception as e:
            logger.error(f"Error analyzing indicator {indicator_id}: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
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
    """
    Find indicators that need analysis or reanalysis.
    
    Args:
        limit: Maximum number of indicators to return
    
    Returns:
        List of indicator IDs
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return []
    
    indicator_ids = []
    
    try:
        # Find indicators that have never been analyzed or were analyzed more than 7 days ago
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        query = f"""
        SELECT id FROM `{Config.get_table_name('indicators')}`
        WHERE 
            last_analyzed IS NULL
            OR last_analyzed < @seven_days_ago
        ORDER BY confidence DESC, created_at DESC
        LIMIT @limit
        """
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("seven_days_ago", "TIMESTAMP", seven_days_ago),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        # Extract indicator IDs
        for row in query_job:
            indicator_ids.append(row.id)
        
        logger.info(f"Found {len(indicator_ids)} indicators needing analysis")
    
    except Exception as e:
        logger.error(f"Error finding indicators for analysis: {str(e)}")
        report_error(e)
    
    return indicator_ids

def analyze_threat_data(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for threat data analysis.
    
    Args:
        event_data: Event data from PubSub trigger
    
    Returns:
        Dictionary containing analysis results
    """
    global analysis_status
    
    # Reset status
    analysis_status = {
        "last_run": datetime.utcnow().isoformat(),
        "running": True,
        "indicators_processed": 0,
        "indicators_failed": 0,
        "errors": []
    }
    
    logger.info(f"Received analysis request: {event_data}")
    
    try:
        # Extract parameters from event
        analyze_all = event_data.get('analyze_all', False)
        force_reanalysis = event_data.get('force_reanalysis', False)
        indicator_ids = event_data.get('indicator_ids', [])
        
        # If analyze_all, find indicators that need analysis
        if analyze_all:
            limit = int(event_data.get('limit', 100))
            indicator_ids = find_indicators_for_analysis(limit=limit)
        
        # Validate indicator_ids
        if not indicator_ids:
            logger.warning("No indicators specified for analysis")
            analysis_status["running"] = False
            return {
                "status": "error",
                "message": "No indicators specified for analysis"
            }
        
        # Analyze indicators
        results = batch_analyze_indicators(indicator_ids, force_reanalysis)
        
        # Update status
        analysis_status["running"] = False
        
        # Return results
        return {
            "status": "success",
            "results": results
        }
    
    except Exception as e:
        logger.error(f"Error processing analysis request: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        
        # Update status
        analysis_status["running"] = False
        analysis_status["errors"].append(str(e))
        
        return {
            "status": "error",
            "message": str(e)
        }

# -------------------- Correlation Analysis Functions --------------------

def find_correlations(time_window_days: int = 30, min_confidence: int = 70, limit: int = 1000) -> Dict[str, Any]:
    """
    Find correlations between indicators observed in the same time window.
    
    Args:
        time_window_days: Time window in days to look for correlations
        min_confidence: Minimum confidence score for indicators
        limit: Maximum number of indicators to analyze
    
    Returns:
        Dictionary containing correlation results
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return {"error": "BigQuery client not initialized"}
    
    try:
        logger.info(f"Finding correlations with time window of {time_window_days} days")
        
        # Calculate time window
        start_date = datetime.utcnow() - timedelta(days=time_window_days)
        
        # Query to find indicators in the time window
        query = f"""
        WITH recent_indicators AS (
            SELECT * FROM `{Config.get_table_name('indicators')}`
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
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("start_date", "TIMESTAMP", start_date),
                bigquery.ScalarQueryParameter("min_confidence", "INT64", min_confidence),
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        # Process correlations
        correlations = []
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
        
        # Group correlations by type
        correlation_groups = {}
        for correlation in correlations:
            type_pair = f"{correlation['indicator_a']['type']}-{correlation['indicator_b']['type']}"
            if type_pair not in correlation_groups:
                correlation_groups[type_pair] = []
            correlation_groups[type_pair].append(correlation)
        
        # Calculate statistics
        stats = {
            "total_correlations": len(correlations),
            "by_type": {k: len(v) for k, v in correlation_groups.items()},
            "time_window_days": time_window_days,
            "min_confidence": min_confidence
        }
        
        logger.info(f"Found {len(correlations)} correlations")
        
        return {
            "statistics": stats,
            "correlations": correlations[:100],  # Return only first 100 to avoid overwhelming response
            "correlation_groups": {k: len(v) for k, v in correlation_groups.items()}
        }
    
    except Exception as e:
        logger.error(f"Error finding correlations: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {"error": f"Error finding correlations: {str(e)}"}

def detect_campaigns(min_indicators: int = 5, min_confidence: int = 70) -> Dict[str, Any]:
    """
    Detect potential campaigns based on related indicators.
    
    Args:
        min_indicators: Minimum number of indicators to form a campaign
        min_confidence: Minimum confidence score for indicators
    
    Returns:
        Dictionary containing detected campaigns
    """
    if not bq_client:
        logger.error("BigQuery client not initialized")
        return {"error": "BigQuery client not initialized"}
    
    try:
        logger.info(f"Detecting campaigns with min_indicators={min_indicators}, min_confidence={min_confidence}")
        
        # Query to find potential campaigns
        query = f"""
        WITH indicator_sources AS (
            SELECT 
                source,
                COUNT(*) as indicator_count,
                ARRAY_AGG(DISTINCT type) as indicator_types,
                ARRAY_AGG(STRUCT(id, type, value, confidence, created_at)) as indicators
            FROM `{Config.get_table_name('indicators')}`
            WHERE confidence >= @min_confidence
            GROUP BY source
            HAVING COUNT(*) >= @min_indicators
        )
        SELECT * FROM indicator_sources
        ORDER BY indicator_count DESC
        LIMIT 100
        """
        
        # Execute the query
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("min_indicators", "INT64", min_indicators),
                bigquery.ScalarQueryParameter("min_confidence", "INT64", min_confidence)
            ]
        )
        query_job = bq_client.query(query, job_config=job_config)
        
        # Process potential campaigns
        campaigns = []
        for row in query_job:
            # Format indicators
            indicators = []
            for indicator in row.indicators:
                indicators.append({
                    "id": indicator.id,
                    "type": indicator.type,
                    "value": indicator.value,
                    "confidence": indicator.confidence,
                    "created_at": indicator.created_at.isoformat() if indicator.created_at else None
                })
            
            # Create campaign object
            campaign = {
                "source": row.source,
                "indicator_count": row.indicator_count,
                "indicator_types": row.indicator_types,
                "indicators": indicators,
                "first_seen": min([ind.get("created_at", "9999") for ind in indicators if ind.get("created_at")], default=None),
                "last_seen": max([ind.get("created_at", "0") for ind in indicators if ind.get("created_at")], default=None),
                "campaign_id": f"auto-{hashlib.md5(row.source.encode()).hexdigest()[:8]}"
            }
            campaigns.append(campaign)
        
        logger.info(f"Detected {len(campaigns)} potential campaigns")
        
        return {
            "total_campaigns": len(campaigns),
            "campaigns": campaigns
        }
    
    except Exception as e:
        logger.error(f"Error detecting campaigns: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {"error": f"Error detecting campaigns: {str(e)}"}

# -------------------- Background Analysis Thread --------------------

def start_background_analysis(limit: int = 100):
    """Start background analysis thread for continuous processing."""
    def analysis_thread():
        logger.info("Starting background analysis thread")
        
        while True:
            try:
                # Find indicators that need analysis
                indicators = find_indicators_for_analysis(limit=limit)
                
                if not indicators:
                    logger.info("No indicators need analysis at this time")
                    # Sleep for 30 minutes before checking again
                    time.sleep(1800)
                    continue
                
                # Process indicators
                logger.info(f"Processing {len(indicators)} indicators in background")
                analyze_threat_data({
                    "indicator_ids": indicators,
                    "force_reanalysis": False
                })
                
                # Sleep for 15 minutes before next batch
                time.sleep(900)
                
            except Exception as e:
                logger.error(f"Error in background analysis thread: {str(e)}")
                if Config.ENVIRONMENT != 'production':
                    logger.error(traceback.format_exc())
                # Sleep for 5 minutes before retrying after error
                time.sleep(300)
    
    thread = threading.Thread(target=analysis_thread)
    thread.daemon = True
    thread.start()
    logger.info("Background analysis thread started")
    return thread

def get_analysis_status() -> Dict:
    """Get the current status of the analysis process."""
    global analysis_status
    
    # Create a copy of the status to avoid modification issues
    status_copy = analysis_status.copy()
    
    # Add current timestamp
    status_copy["current_time"] = datetime.utcnow().isoformat()
    
    return status_copy

# -------------------- Main Function --------------------

def analyze_from_pubsub(event, context):
    """
    Cloud Function entry point for PubSub triggered analysis.
    
    Args:
        event: The PubSub event
        context: The event context
    
    Returns:
        None
    """
    try:
        logger.info(f"Received PubSub message: {event}")
        
        # Extract message data
        if 'data' in event:
            import base64
            message_data_bytes = base64.b64decode(event['data'])
            message_data = json.loads(message_data_bytes)
        else:
            message_data = {}
        
        # Process the analysis request
        result = analyze_threat_data(message_data)
        
        # Log the result summary
        logger.info(f"Analysis complete: {result.get('status')}")
        
        # Optionally publish result to another topic
        if publisher and result.get('status') == 'success':
            try:
                result_topic = f"projects/{Config.GCP_PROJECT}/topics/threat-analysis-results"
                
                # Convert datetime objects to strings for JSON serialization
                def json_serializer(obj):
                    if isinstance(obj, (datetime, datetime.date)):
                        return obj.isoformat()
                    raise TypeError(f"Type {type(obj)} not serializable")
                
                future = publisher.publish(
                    result_topic,
                    json.dumps(result, default=json_serializer).encode('utf-8'),
                    operation="analysis_complete"
                )
                future.result()  # Wait for the publish operation to complete
                logger.info(f"Published analysis results to {result_topic}")
            except Exception as e:
                logger.error(f"Error publishing analysis results: {str(e)}")
                if Config.ENVIRONMENT != 'production':
                    logger.error(traceback.format_exc())
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)

# Auto-start background analysis in production if enabled
if Config.ENVIRONMENT == 'production' and Config.ANALYSIS_ENABLED:
    # Wait a bit to ensure the app has started
    logger.info("Auto-analysis enabled - will start analysis after app startup")
    
    def delayed_analysis_start():
        time.sleep(30)  # Wait 30 seconds for app startup
        start_background_analysis(limit=50)
        
    startup_thread = threading.Thread(target=delayed_analysis_start)
    startup_thread.daemon = True
    startup_thread.start()

# Module initialization - execute when imported
if __name__ != "__main__":
    logger.info("Initializing analysis module")
    if Config.NLP_ENABLED and not text_model and not generative_model:
        initialize_ai_models()

# Run when executed directly
if __name__ == "__main__":
    # When run as a script, analyze all pending indicators
    logger.info("Running analysis.py as standalone script")
    
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
        
    # Also run campaign detection
    print("\nDetecting potential campaigns...")
    campaigns = detect_campaigns(min_indicators=3, min_confidence=60)
    if "error" not in campaigns:
        print(f"Detected {campaigns.get('total_campaigns', 0)} potential campaigns")
    else:
        print(f"Error detecting campaigns: {campaigns.get('error')}")
