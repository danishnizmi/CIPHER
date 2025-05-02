import os
import json
import uuid
import logging
import hashlib
import re
import ipaddress
import socket
from typing import Dict, List, Any, Union, Optional, Tuple
from datetime import datetime, timedelta
import traceback

import requests
from google.cloud import bigquery, storage, pubsub_v1
from google.cloud.exceptions import NotFound
from google.api_core.exceptions import GoogleAPIError
import vertexai
from vertexai.language_models import TextGenerationModel

# Import configuration
from config import Config, initialize_bigquery, initialize_storage, initialize_pubsub, report_error

# Initialize logging
logger = logging.getLogger(__name__)

# Initialize GCP clients
bq_client = initialize_bigquery()
storage_client = initialize_storage()
publisher, subscriber = initialize_pubsub()

# Initialize Vertex AI for NLP analysis if enabled
if Config.NLP_ENABLED:
    try:
        vertexai.init(project=Config.GCP_PROJECT, location=Config.VERTEXAI_LOCATION)
        text_model = TextGenerationModel.from_pretrained(Config.VERTEXAI_MODEL)
        logger.info(f"Initialized Vertex AI Text Generation Model: {Config.VERTEXAI_MODEL}")
    except Exception as e:
        logger.error(f"Error initializing Vertex AI: {str(e)}")
        text_model = None
else:
    text_model = None

# -------------------- Helper Functions --------------------

def extract_ioc_type(value: str) -> str:
    """
    Identify the type of indicator based on its format.
    
    Args:
        value: The indicator value to analyze
    
    Returns:
        String representing the IOC type (ip, domain, url, hash, etc.)
    """
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
        
        # Check for MX records
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_data["has_mx"] = len(mx_records) > 0
        except:
            # Fall back to simple check
            dns_data["has_mx"] = len(dns_data["resolved_ips"]) > 0
        
        # Get nameservers
        try:
            import dns.resolver
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_data["nameservers"] = [ns.target.to_text() for ns in ns_records]
        except:
            pass
    
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
    if not text_model:
        logger.warning("Vertex AI text model not initialized, skipping text analysis")
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
                    result = json.loads(json_str)
                    result["processed"] = True
                else:
                    result["error"] = "Failed to parse JSON from response"
            except json.JSONDecodeError:
                result["error"] = "Failed to parse JSON from response"
        elif prompt_type == "summarize":
            result["summary"] = response.text.strip()
            result["processed"] = True
    
    except Exception as e:
        logger.error(f"Error analyzing text with AI: {str(e)}")
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
    
    # Adjust risk based on indicator type
    indicator_type = indicator.get('type', '').lower()
    if indicator_type in ['md5', 'sha1', 'sha256']:
        risk_modifiers += 5  # File hashes are slightly higher risk
    elif indicator_type == 'ip':
        # Look for IP reputation data
        if indicator.get('tags') and any(tag in indicator.get('tags', []) for tag in ['c2', 'botnet', 'ransomware']):
            risk_modifiers += 25  # IPs associated with serious threats
    
    # Adjust for reported false positives
    if 'false_positive' in indicator.get('tags', []):
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
        
        # Prepare update data
        update_fields = {
            'last_analyzed': datetime.utcnow(),
            'confidence': analysis_data.get('confidence'),
            'risk_score': analysis_data.get('risk_score'),
            'analysis_summary': analysis_data.get('summary')
        }
        
        # Add enrichment data if present
        if 'enrichment' in analysis_data:
            for key, value in analysis_data['enrichment'].items():
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
        if 'enrichment' in analysis_data:
            for key in analysis_data['enrichment'].keys():
                update_fields[f'enrichment_{key}'] = analysis_data['enrichment'].get(key)
                query += f",\n    enrichment_{key} = @enrichment_{key}"
        
        # Add tags if present (append to existing tags)
        if 'tags' in analysis_data and analysis_data['tags']:
            query += f"""
            , tags = ARRAY_CONCAT(
                IFNULL(tags, []),
                ARRAY(SELECT DISTINCT x FROM UNNEST(@new_tags) x WHERE x NOT IN (SELECT y FROM UNNEST(IFNULL(tags, [])) y))
            )
            """
            update_fields['new_tags'] = analysis_data.get('tags', [])
        
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
        
        # Upload the file
        blob.upload_from_string(
            json.dumps(analysis_data, default=str),
            content_type="application/json"
        )
        
        # Return the GCS URI
        return f"gs://{Config.GCS_BUCKET}/{filename}"
    
    except Exception as e:
        logger.error(f"Error uploading analysis to GCS: {str(e)}")
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
    logger.info(f"Analyzing indicator {indicator_id}")
    
    # Get indicator data
    indicator = get_indicator_data(indicator_id)
    
    if not indicator:
        logger.warning(f"Indicator {indicator_id} not found")
        return {"error": "Indicator not found"}
    
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
        if Config.NLP_ENABLED and text_model:
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
            return {
                "status": "error",
                "message": "No indicators specified for analysis"
            }
        
        # Analyze indicators
        results = batch_analyze_indicators(indicator_ids, force_reanalysis)
        
        # Return results
        return {
            "status": "success",
            "results": results
        }
    
    except Exception as e:
        logger.error(f"Error processing analysis request: {str(e)}\n{traceback.format_exc()}")
        report_error(e)
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
        report_error(e)
        return {"error": f"Error detecting campaigns: {str(e)}"}

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
                future = publisher.publish(
                    result_topic,
                    json.dumps(result).encode('utf-8'),
                    operation="analysis_complete"
                )
                future.result()  # Wait for the publish operation to complete
                logger.info(f"Published analysis results to {result_topic}")
            except Exception as e:
                logger.error(f"Error publishing analysis results: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error processing PubSub message: {str(e)}\n{traceback.format_exc()}")
        report_error(e)
