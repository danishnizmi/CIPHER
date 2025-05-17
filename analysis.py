"""
Enhanced analysis module for threat intelligence platform.
Focuses on targeted analysis rather than batch processing all IOCs.
Implements domain analysis, infrastructure clustering, and strategic AI usage.
"""

import os
import json
import logging
import re
import time
import threading
import uuid
import statistics
from typing import Dict, List, Any, Union, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import traceback
import random
import difflib
import requests
from urllib.parse import urlparse
import dns.resolver
import tldextract

# Import centralized configuration and utilities
from config import (
    Config, ServiceManager, ServiceStatus, report_error,
    Utils, CircuitBreaker, CacheManager, shared_cache
)

# Initialize logging
logger = logging.getLogger(__name__)

# Global analysis state
analysis_status = {
    "last_run": None,
    "running": False,
    "domains_analyzed": 0,
    "ips_analyzed": 0,
    "urls_analyzed": 0,
    "total_iocs": 0,
    "pattern_discoveries": 0,
    "errors": [],
    "high_value_detections": [],
    "ai_model_status": "initializing"
}

# Lock for thread-safe operations
_analysis_lock = threading.Lock()

# AI models - initialized lazily
text_model = None
generative_model = None
_ai_models_initialized = False
_ai_models_lock = threading.Lock()

# Create circuit breakers for external API calls
reputation_circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

# ==================== Constants and Configuration ====================

# Typosquatting techniques
TYPO_TECHNIQUES = [
    'character_replacement',   # Replace similar looking characters: o → 0, i → 1
    'character_omission',      # Omit a character: google → gogle
    'character_addition',      # Add a character: google → gooogle
    'character_swap',          # Swap adjacent characters: google → gogole
    'subdomain',               # Use domain as subdomain: google → google.malicious.com
    'hyphenation',             # Add hyphens: google → goo-gle
    'homoglyphs',              # Replace with similar Unicode chars: google → gооgle
    'tld_variation'            # Change TLD: google.com → google.net
]

# Common TLDs for phishing
COMMON_PHISHING_TLDS = [
    "com", "org", "net", "info", "xyz", "online", "site", "top", 
    "club", "app", "live", "shop", "tech", "store"
]

# Homoglyphs for lookalike detection
HOMOGLYPHS = {
    'a': ['а', 'ạ', 'ɑ', 'ạ'],
    'b': ['ḅ', 'ḃ', 'Ь', 'ƅ'],
    'c': ['с', 'ċ', 'ҫ'],
    'e': ['е', 'ḙ', 'ḛ', 'ẹ'],
    'g': ['ġ', 'ḡ', 'ģ'],
    'i': ['ι', 'і', 'ӏ', 'ḭ', 'í'],
    'k': ['ḳ', 'ḵ', 'ḱ'],
    'o': ['о', 'ọ', 'ο', '0'],
    's': ['ѕ', 'ṣ', 'ș'],
    'p': ['р', 'ṗ', 'ṕ', 'ρ'],
    'r': ['ṛ', 'ṙ', 'ṟ'],
    't': ['ṭ', 'ṯ', 'т'],
    'u': ['υ', 'ṳ', 'ṵ'],
    'v': ['ν', 'ѵ'],
    'w': ['ẇ', 'ẉ', 'ẃ'],
    'y': ['у', 'ỵ', 'ỳ']
}

# Top domains to watch for lookalikes (globally popular domains that are often spoofed)
TOP_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "paypal.com", "dropbox.com", "github.com", "yahoo.com", "wikipedia.org",
    "wordpress.com", "adobe.com", "twitch.tv", "reddit.com", "pinterest.com",
    "whatsapp.com", "zoom.us", "office.com", "gmail.com", "outlook.com",
    "spotify.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "americanexpress.com", "discover.com", "icloud.com", "salesforce.com", "slack.com"
]

# Reputation services configuration - retained as is due to specific structure
REPUTATION_SERVICES = {
    'domain': [
        {
            'name': 'VirusTotal',
            'url': 'https://www.virustotal.com/vtapi/v2/domain/report',
            'params': lambda domain: {'apikey': os.getenv('VIRUSTOTAL_API_KEY', ''), 'domain': domain},
            'free_limit': 4,  # Requests per minute for free API
            'extract_score': lambda resp: min(100, resp.get('positives', 0) * 10)
        },
        {
            'name': 'URLhaus',
            'url': 'https://urlhaus-api.abuse.ch/v1/host/',
            'data': lambda domain: {'host': domain},
            'extract_score': lambda resp: 85 if resp.get('query_status') == 'ok' else 0,
            'free_limit': 100  # Generous limit
        }
    ],
    'ip': [
        {
            'name': 'AbuseIPDB',
            'url': 'https://api.abuseipdb.com/api/v2/check',
            'params': lambda ip: {'ipAddress': ip, 'maxAgeInDays': 90},
            'headers': lambda: {'Key': os.getenv('ABUSEIPDB_API_KEY', ''), 'Accept': 'application/json'},
            'extract_score': lambda resp: resp.get('data', {}).get('abuseConfidenceScore', 0),
            'free_limit': 1000  # Daily limit for free tier
        },
        {
            'name': 'IPQualityScore',
            'url': 'https://ipqualityscore.com/api/json/ip/{api_key}/{ip}',
            'url_format': lambda ip: f"https://ipqualityscore.com/api/json/ip/{os.getenv('IPQUALITYSCORE_API_KEY', '')}/{ip}",
            'extract_score': lambda resp: min(100, (resp.get('fraud_score', 0) + 
                                       (50 if resp.get('proxy', False) else 0) + 
                                       (50 if resp.get('vpn', False) else 0)) / 2),
            'free_limit': 5000  # Monthly limit
        }
    ],
    'url': [
        {
            'name': 'Google Safe Browsing',
            'url': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            'json': lambda url: {
                'client': {'clientId': 'threatintelplatform', 'clientVersion': Config.VERSION},
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            },
            'params': lambda _: {'key': os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')},
            'extract_score': lambda resp: 90 if resp.get('matches') else 0,
            'free_limit': 10000  # Very generous free tier
        },
        {
            'name': 'URLhaus',
            'url': 'https://urlhaus-api.abuse.ch/v1/url/',
            'data': lambda url: {'url': url},
            'extract_score': lambda resp: 85 if resp.get('query_status') == 'ok' else 0,
            'free_limit': 100  
        }
    ]
}

# ==================== Helper Functions ====================

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

def validate_feed_id(feed_id: str) -> bool:
    """Validate feed ID format."""
    if not feed_id or not isinstance(feed_id, str):
        return False
    # Allow alphanumeric, hyphens, and underscores
    return re.match(r'^[a-zA-Z0-9_-]+$', feed_id) is not None

def calculate_domain_similarity(domain1: str, domain2: str) -> float:
    """Calculate similarity between two domains using sequence matcher."""
    # Extract root domains without TLD for better comparison
    extract1 = tldextract.extract(domain1)
    extract2 = tldextract.extract(domain2)
    
    # Compare the domain parts (without subdomains and TLD)
    domain1_root = extract1.domain
    domain2_root = extract2.domain
    
    # Calculate similarity using sequence matcher
    similarity = difflib.SequenceMatcher(None, domain1_root, domain2_root).ratio()
    
    # Adjust score if TLDs match
    if extract1.suffix == extract2.suffix:
        similarity += 0.1
        
    # Cap at 1.0
    return min(1.0, similarity)

def is_potential_typosquat(domain: str, reference_domain: str) -> Tuple[bool, str, float]:
    """
    Determine if a domain is a potential typosquat of a reference domain.
    
    Args:
        domain: Domain to check
        reference_domain: Reference domain to compare against
        
    Returns:
        Tuple of (is_typosquat, technique, similarity_score)
    """
    # Extract components
    domain_parts = tldextract.extract(domain)
    ref_parts = tldextract.extract(reference_domain)
    
    # Only compare the domain part (without subdomain and TLD)
    domain_name = domain_parts.domain
    ref_name = ref_parts.domain
    
    # Calculate base similarity
    similarity = calculate_domain_similarity(domain, reference_domain)
    
    # Too different, not a typosquat
    if similarity < 0.7:
        return False, "", 0.0
    
    # Check for different typosquatting techniques
    techniques = []
    
    # Character replacement (levenshtein distance of 1)
    if len(domain_name) == len(ref_name) and sum(c1 != c2 for c1, c2 in zip(domain_name, ref_name)) <= 2:
        techniques.append(('character_replacement', similarity + 0.15))
    
    # Character omission (ref domain has one more character)
    if len(ref_name) == len(domain_name) + 1:
        for i in range(len(ref_name)):
            if i < len(domain_name) and domain_name[:i] + domain_name[i:] == ref_name[:i] + ref_name[i+1:]:
                techniques.append(('character_omission', similarity + 0.2))
                break
    
    # Character addition (domain has one more character)
    if len(domain_name) == len(ref_name) + 1:
        for i in range(len(domain_name)):
            if domain_name[:i] + domain_name[i+1:] == ref_name:
                techniques.append(('character_addition', similarity + 0.15))
                break
    
    # Character swap (adjacent characters swapped)
    if len(domain_name) == len(ref_name):
        for i in range(len(domain_name) - 1):
            swapped = list(domain_name)
            swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
            if ''.join(swapped) == ref_name:
                techniques.append(('character_swap', similarity + 0.25))
                break
    
    # Subdomain attack (using target domain as subdomain)
    if domain_parts.subdomain == ref_name or domain_parts.subdomain.endswith(f".{ref_name}"):
        techniques.append(('subdomain', 0.9))
    
    # Hyphenation
    if domain_name.replace('-', '') == ref_name:
        techniques.append(('hyphenation', similarity + 0.2))
    
    # TLD variation
    if domain_name == ref_name and domain_parts.suffix != ref_parts.suffix:
        techniques.append(('tld_variation', 0.85))
    
    # Homoglyph attack (similar looking characters)
    has_homoglyphs = False
    for i, char in enumerate(domain_name):
        if i < len(ref_name) and char != ref_name[i]:
            if char.lower() in HOMOGLYPHS.get(ref_name[i].lower(), []):
                has_homoglyphs = True
                break
    if has_homoglyphs:
        techniques.append(('homoglyphs', 0.95))  # This is a very strong signal
    
    if not techniques:
        return False, "", 0.0
    
    # Return the most confident technique
    best_technique = max(techniques, key=lambda x: x[1])
    return True, best_technique[0], best_technique[1]

def rate_limit_reputation_request(service_name: str, limit_per_minute: int) -> bool:
    """
    Implement rate limiting for reputation service requests.
    Returns True if request is allowed, False if it should be skipped.
    """
    cache_key = f"rate_limit_{service_name}"
    timestamps = shared_cache.get(cache_key, [])
    
    # Remove timestamps older than 1 minute
    now = time.time()
    timestamps = [ts for ts in timestamps if now - ts < 60]
    
    # Check if we've hit the limit
    if len(timestamps) >= limit_per_minute:
        return False
    
    # Add current timestamp and update cache
    timestamps.append(now)
    shared_cache.set(cache_key, timestamps, ttl=60)
    return True

def get_reputation_score(ioc_type: str, ioc_value: str) -> Tuple[int, str, Dict]:
    """
    Get reputation score from configured services.
    Returns tuple of (score, source, details).
    Uses caching to avoid repeated queries.
    """
    # Check cache first
    cache_key = f"reputation:{ioc_type}:{ioc_value}"
    cached_result = shared_cache.get(cache_key)
    if cached_result:
        return cached_result
    
    # Default response
    result = (0, "none", {})
    
    # Get appropriate services for this IOC type
    services = REPUTATION_SERVICES.get(ioc_type, [])
    
    for service in services:
        # Check rate limiting
        if not rate_limit_reputation_request(service['name'], service.get('free_limit', 10)):
            logger.debug(f"Rate limit exceeded for {service['name']}, skipping")
            continue
        
        try:
            # Execute request with circuit breaker protection
            result = reputation_circuit_breaker.call(
                _execute_reputation_request,
                service,
                ioc_value
            )
            
            # If we got a positive score, return it
            if result[0] > 0:
                shared_cache.set(cache_key, result, ttl=86400)  # Cache for 24 hours
                return result
                
        except Exception as e:
            logger.warning(f"Error querying reputation service {service['name']}: {str(e)}")
            continue
    
    # Cache the result (even if no positive scores found)
    shared_cache.set(cache_key, result, ttl=3600)  # Cache for 1 hour
    
    return result

def _execute_reputation_request(service: Dict, ioc_value: str) -> Tuple[int, str, Dict]:
    """Execute request to reputation service (used with circuit breaker)."""
    # Prepare request parameters
    kwargs = {}
    
    if 'url_format' in service:
        url = service['url_format'](ioc_value)
    else:
        url = service['url']
        
    if 'params' in service:
        kwargs['params'] = service['params'](ioc_value)
        
    if 'data' in service:
        kwargs['data'] = service['data'](ioc_value)
        
    if 'json' in service:
        kwargs['json'] = service['json'](ioc_value)
        
    if 'headers' in service:
        kwargs['headers'] = service['headers']()
    
    # Make the request
    response = requests.post(url, **kwargs) if 'data' in service or 'json' in service else requests.get(url, **kwargs)
    
    if response.status_code == 200:
        resp_data = response.json()
        score = service['extract_score'](resp_data)
        
        # If we got a positive score, return it
        if score > 0:
            return (score, service['name'], resp_data)
    else:
        logger.warning(f"Reputation service {service['name']} returned status {response.status_code}")
    
    return (0, "none", {})

def get_ip_geo_info(ip: str) -> Dict[str, Any]:
    """Get geolocation information for an IP address using a free service."""
    cache_key = f"ip_geo:{ip}"
    cached_result = shared_cache.get(cache_key)
    if cached_result:
        return cached_result
    
    try:
        # Use ipinfo.io free tier (50,000 requests/month)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            result = {
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'org': data.get('org'),
                'postal': data.get('postal'),
                'timezone': data.get('timezone'),
                'loc': data.get('loc'),
                'asn': data.get('asn')
            }
            shared_cache.set(cache_key, result, ttl=86400)  # Cache for 24 hours
            return result
    except Exception as e:
        logger.debug(f"Error getting IP geolocation: {str(e)}")
    
    # Fallback to minimal info
    result = {
        'country': None,
        'region': None,
        'city': None,
        'org': None
    }
    
    shared_cache.set(cache_key, result, ttl=3600)  # Cache for 1 hour
    return result

def add_domain_insights(domain: str) -> Dict[str, Any]:
    """Add insights for a domain."""
    insights = {
        'is_typosquat': False,
        'typosquat_target': None,
        'typosquat_technique': None,
        'typosquat_confidence': 0,
        'reputation_score': 0,
        'reputation_source': None,
        'has_valid_dns': False,
        'dns_records': [],
        'registered_date': None
    }
    
    # Check if domain is a typosquat of a popular domain
    for popular_domain in TOP_DOMAINS:
        is_typo, technique, confidence = is_potential_typosquat(domain, popular_domain)
        if is_typo and confidence > insights['typosquat_confidence']:
            insights['is_typosquat'] = True
            insights['typosquat_target'] = popular_domain
            insights['typosquat_technique'] = technique
            insights['typosquat_confidence'] = confidence
    
    # Get reputation score
    score, source, details = get_reputation_score('domain', domain)
    insights['reputation_score'] = score
    insights['reputation_source'] = source
    insights['reputation_details'] = details
    
    # Check DNS records
    try:
        dns_records = []
        
        # A records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                dns_records.append({'type': 'A', 'value': str(rdata)})
            insights['has_valid_dns'] = True
        except:
            pass
            
        # MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                dns_records.append({'type': 'MX', 'value': str(rdata.exchange)})
        except:
            pass
            
        # NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                dns_records.append({'type': 'NS', 'value': str(rdata)})
        except:
            pass
            
        insights['dns_records'] = dns_records
    except Exception as e:
        logger.debug(f"Error checking DNS records for {domain}: {str(e)}")
    
    return insights

def add_ip_insights(ip: str) -> Dict[str, Any]:
    """Add insights for an IP address."""
    insights = {
        'geo_info': get_ip_geo_info(ip),
        'reputation_score': 0,
        'reputation_source': None,
        'is_private': False,
        'reverse_dns': None,
        'port': None
    }
    
    # Check if IP is private
    try:
        ip_obj = ipaddress.ip_address(ip)
        insights['is_private'] = ip_obj.is_private
    except:
        pass
    
    # Extract port if this is an IP:port format
    if ':' in ip:
        ip_parts = ip.split(':')
        if len(ip_parts) == 2 and ip_parts[1].isdigit():
            insights['ip'] = ip_parts[0]
            insights['port'] = int(ip_parts[1])
    
    # Get reputation score
    ip_to_check = insights.get('ip', ip)
    score, source, details = get_reputation_score('ip', ip_to_check)
    insights['reputation_score'] = score
    insights['reputation_source'] = source
    insights['reputation_details'] = details
    
    # Get reverse DNS
    try:
        insights['reverse_dns'] = socket.gethostbyaddr(ip_to_check)[0]
    except:
        pass
    
    return insights

def add_url_insights(url: str) -> Dict[str, Any]:
    """Add insights for a URL."""
    insights = {
        'domain': Utils.extract_domain_from_url(url),
        'reputation_score': 0,
        'reputation_source': None,
        'path_length': 0,
        'query_params_count': 0,
        'contains_suspicious_keywords': False,
        'suspicious_keywords': []
    }
    
    # Extract URL components
    try:
        parsed = urlparse(url)
        insights['path_length'] = len(parsed.path)
        insights['query_params_count'] = len(parsed.query.split('&')) if parsed.query else 0
        
        # Check for suspicious keywords in URL
        suspicious_keywords = [
            'login', 'account', 'secure', 'bank', 'verify', 'password', 'credential',
            'wallet', 'update', 'confirm', 'billing', 'payment', 'authentication'
        ]
        
        found_keywords = []
        for keyword in suspicious_keywords:
            if keyword in parsed.path.lower() or keyword in parsed.query.lower():
                found_keywords.append(keyword)
                
        if found_keywords:
            insights['contains_suspicious_keywords'] = True
            insights['suspicious_keywords'] = found_keywords
    except:
        pass
    
    # Get reputation score
    score, source, details = get_reputation_score('url', url)
    insights['reputation_score'] = score
    insights['reputation_source'] = source
    insights['reputation_details'] = details
    
    return insights

def calculate_ioc_risk_score(ioc: Dict[str, Any], insights: Dict[str, Any]) -> int:
    """Calculate risk score based on IOC data and insights."""
    base_score = ioc.get('risk_score', 50)
    
    # Start with any existing risk score or default of 50
    risk_score = base_score
    
    # Add reputation score
    reputation_score = insights.get('reputation_score', 0)
    if reputation_score > 0:
        # Weight reputation service scores highly
        risk_score = max(risk_score, reputation_score)
    
    # Adjust based on IOC type and insights
    ioc_type = ioc.get('type')
    
    if ioc_type == 'domain':
        # Typosquatting is a strong signal
        if insights.get('is_typosquat', False):
            typo_confidence = insights.get('typosquat_confidence', 0)
            typo_score = int(75 + (typo_confidence * 25))  # 75-100 based on confidence
            risk_score = max(risk_score, typo_score)
        
        # DNs records check
        if not insights.get('has_valid_dns', True):
            # Suspicious if no valid DNS
            risk_score += 10
    
    elif ioc_type == 'ip' or ioc_type == 'ip:port':
        # Location-based risk adjustments
        high_risk_countries = {'RU', 'CN', 'IR', 'KP', 'SY'}
        country = insights.get('geo_info', {}).get('country')
        
        if country in high_risk_countries:
            risk_score += 15
        
        # Private IPs aren't usually external threats
        if insights.get('is_private', False):
            risk_score = min(risk_score, 30)
        
        # Specific ports increase risk
        high_risk_ports = {22, 23, 25, 3389, 445, 135, 137, 138, 139, 67, 68}
        port = insights.get('port')
        if port in high_risk_ports:
            risk_score += 15
    
    elif ioc_type == 'url':
        # Suspicious URL characteristics
        if insights.get('contains_suspicious_keywords', False):
            risk_score += 15
        
        # Long paths and many query params are suspicious
        if insights.get('path_length', 0) > 30:
            risk_score += 10
            
        if insights.get('query_params_count', 0) > 5:
            risk_score += 10
    
    # Ensure within bounds
    return max(0, min(100, risk_score))

def identify_infrastructure_clusters(iocs: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Identify clusters of related infrastructure in the IOCs.
    Returns a dictionary of cluster_id -> list of IOCs.
    """
    clusters = defaultdict(list)
    
    # Create mappings from domains to IPs and vice versa
    domain_to_ips = defaultdict(set)
    ip_to_domains = defaultdict(set)
    
    # First pass: build relationships
    for ioc in iocs:
        ioc_type = ioc.get('type')
        value = ioc.get('value')
        
        if ioc_type == 'domain' and 'insights' in ioc:
            # Get IPs from DNS records
            for record in ioc.get('insights', {}).get('dns_records', []):
                if record.get('type') == 'A':
                    domain_to_ips[value].add(record.get('value'))
                    ip_to_domains[record.get('value')].add(value)
        
        elif (ioc_type == 'ip' or ioc_type == 'ip:port') and 'insights' in ioc:
            # Get domain from reverse DNS
            reverse_dns = ioc.get('insights', {}).get('reverse_dns')
            if reverse_dns:
                ip_value = ioc.get('insights', {}).get('ip', value)
                ip_to_domains[ip_value].add(reverse_dns)
                domain_to_ips[reverse_dns].add(ip_value)
    
    # Second pass: create clusters
    processed = set()
    cluster_id = 0
    
    for ioc in iocs:
        ioc_type = ioc.get('type')
        value = ioc.get('value')
        
        if value in processed:
            continue
            
        if ioc_type == 'domain':
            # Start a new cluster with this domain
            cluster = []
            to_process = {value}
            
            while to_process:
                current = to_process.pop()
                if current in processed:
                    continue
                    
                # Find matching IOC
                for candidate in iocs:
                    if candidate.get('value') == current:
                        cluster.append(candidate)
                        processed.add(current)
                        
                        # Add related IPs to processing queue
                        if current in domain_to_ips:
                            for ip in domain_to_ips[current]:
                                if ip not in processed:
                                    to_process.add(ip)
                        
                        break
                else:
                    # No matching IOC found, just mark as processed
                    processed.add(current)
            
            if cluster:
                clusters[f"cluster_{cluster_id}"] = cluster
                cluster_id += 1
                
        elif ioc_type == 'ip' or ioc_type == 'ip:port':
            ip_value = ioc.get('insights', {}).get('ip', value)
            
            # Skip if already processed
            if ip_value in processed:
                continue
                
            # Start a new cluster with this IP
            cluster = []
            to_process = {ip_value}
            
            while to_process:
                current = to_process.pop()
                if current in processed:
                    continue
                    
                # Find matching IOC
                for candidate in iocs:
                    candidate_value = candidate.get('value')
                    candidate_ip = candidate.get('insights', {}).get('ip', candidate_value)
                    
                    if candidate_ip == current:
                        cluster.append(candidate)
                        processed.add(current)
                        
                        # Add related domains to processing queue
                        if current in ip_to_domains:
                            for domain in ip_to_domains[current]:
                                if domain not in processed:
                                    to_process.add(domain)
                        
                        break
                else:
                    # No matching IOC found, just mark as processed
                    processed.add(current)
            
            if cluster:
                clusters[f"cluster_{cluster_id}"] = cluster
                cluster_id += 1
    
    # Filter out single-item clusters
    return {k: v for k, v in clusters.items() if len(v) > 1}

# ==================== AI Model Initialization ====================

def initialize_ai_models_background():
    """Initialize AI models in background thread without blocking service startup."""
    global text_model, generative_model, _ai_models_initialized
    
    def _init_models():
        global text_model, generative_model, _ai_models_initialized
        
        with _ai_models_lock:
            if _ai_models_initialized:
                return
                
            service_manager = Config.get_service_manager()
            
            try:
                logger.info("Starting background AI model initialization...")
                service_manager.update_status('ai_models', ServiceStatus.INITIALIZING)
                
                # Update global status
                with _analysis_lock:
                    analysis_status["ai_model_status"] = "initializing"
                
                import vertexai
                from vertexai.language_models import TextGenerationModel
                from vertexai.preview.generative_models import GenerativeModel
                
                vertexai.init(project=Config.GCP_PROJECT, location=Config.VERTEXAI_LOCATION)
                
                # Initialize text model with fallback
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
                
                # Initialize generative model
                try:
                    generative_model = GenerativeModel("gemini-1.0-pro")
                    logger.info("Initialized Gemini model for advanced analysis")
                except Exception as e:
                    logger.warning(f"Could not load Gemini model: {str(e)}")
                    generative_model = None
                
                # Update status
                if text_model or generative_model:
                    service_manager.update_status('ai_models', ServiceStatus.READY)
                    _ai_models_initialized = True
                    with _analysis_lock:
                        analysis_status["ai_model_status"] = "ready"
                    logger.info("AI models initialization completed successfully")
                else:
                    service_manager.update_status('ai_models', ServiceStatus.DEGRADED, "No AI models available")
                    with _analysis_lock:
                        analysis_status["ai_model_status"] = "degraded"
                    logger.warning("No AI models available - will use statistical analysis only")
                    
            except Exception as e:
                logger.error(f"Error initializing Vertex AI: {str(e)}")
                service_manager.update_status('ai_models', ServiceStatus.ERROR, str(e))
                with _analysis_lock:
                    analysis_status["ai_model_status"] = "error"
                    analysis_status["errors"].append(f"AI initialization failed: {str(e)}")
    
    # Start initialization in background thread
    if Config.NLP_ENABLED:
        thread = threading.Thread(target=_init_models, daemon=True)
        thread.start()
        logger.info("Started AI model initialization in background")
    else:
        logger.info("NLP analysis is disabled in configuration")
        service_manager = Config.get_service_manager()
        service_manager.update_status('ai_models', ServiceStatus.READY)
        with _analysis_lock:
            analysis_status["ai_model_status"] = "disabled"

def ensure_ai_models() -> bool:
    """Ensure AI models are initialized before use."""
    global _ai_models_initialized
    
    if not Config.NLP_ENABLED:
        return False
    
    if _ai_models_initialized:
        return text_model is not None or generative_model is not None
    
    # If not initialized, wait a bit
    with _ai_models_lock:
        if not _ai_models_initialized:
            logger.info("AI models not ready, waiting...")
            return False
    
    return text_model is not None or generative_model is not None

# ==================== Core Analysis Functions ====================

def analyze_high_value_indicators(limit: int = 1000) -> Dict[str, Any]:
    """
    Analyze recently ingested indicators focused on high-value targets
    like domains, IPs, and URLs. Prioritizes suspicious patterns and
    infrastructure correlation over batch scanning all IOCs.
    
    Args:
        limit: Maximum number of IOCs to analyze
        
    Returns:
        Analysis results containing patterns, insights, and risks
    """
    logger.info(f"Starting high-value indicator analysis (limit: {limit})")
    
    start_time = time.time()
    
    bq_client, _, _, _ = get_clients()
    if not bq_client:
        return {"error": "BigQuery client not initialized"}
    
    # Get recent IOCs focusing on domains, IPs, and URLs
    table_id = Config.get_table_name('indicators')
    if not table_id:
        return {"error": "Indicators table not configured"}
    
    try:
        from google.cloud import bigquery
        
        query = f"""
        SELECT *
        FROM `{table_id}`
        WHERE type IN ('domain', 'ip', 'ip:port', 'url')
        AND created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 DAY)
        ORDER BY created_at DESC
        LIMIT @limit
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("limit", "INT64", limit)
            ]
        )
        
        results = list(bq_client.query(query, job_config=job_config))
        
        if not results:
            logger.warning("No recent data found for analysis")
            return {"error": "No recent data found for analysis"}
        
        # Convert to list of dictionaries
        iocs = []
        for row in results:
            ioc = dict(row)
            # Convert datetime objects to ISO strings
            for key, value in ioc.items():
                if isinstance(value, datetime):
                    ioc[key] = value.isoformat()
            iocs.append(ioc)
        
        query_time = time.time() - start_time
        logger.info(f"Retrieved {len(iocs)} indicators in {query_time:.2f}s")
        
        # Initialize analysis result
        analysis_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "iocs_analyzed": len(iocs),
            "domains_analyzed": sum(1 for ioc in iocs if ioc.get('type') == 'domain'),
            "ips_analyzed": sum(1 for ioc in iocs if ioc.get('type') in ('ip', 'ip:port')),
            "urls_analyzed": sum(1 for ioc in iocs if ioc.get('type') == 'url'),
            "high_risk_iocs": [],
            "typosquatting_domains": [],
            "infrastructure_clusters": {},
            "patterns_detected": [],
            "tld_distribution": {},
            "execution_time": 0,
            "ai_analysis": None
        }
        
        # Process indicators by type
        domains = []
        ips = []
        urls = []
        
        for ioc in iocs:
            ioc_type = ioc.get('type')
            
            if ioc_type == 'domain':
                domains.append(ioc)
            elif ioc_type in ('ip', 'ip:port'):
                ips.append(ioc)
            elif ioc_type == 'url':
                urls.append(ioc)
        
        # Domain analysis
        logger.info(f"Analyzing {len(domains)} domains")
        for domain in domains:
            domain_value = domain.get('value')
            if not Utils.is_valid_domain(domain_value):
                continue
                
            # Add domain-specific insights
            domain['insights'] = add_domain_insights(domain_value)
            
            # Update risk score based on insights
            domain['risk_score'] = calculate_ioc_risk_score(domain, domain['insights'])
            
            # Track high-risk domains
            if domain['risk_score'] > 70:
                analysis_result['high_risk_iocs'].append({
                    'id': domain.get('id'),
                    'type': 'domain',
                    'value': domain_value,
                    'risk_score': domain['risk_score'],
                    'insights': domain['insights']
                })
            
            # Track typosquatting domains
            if domain['insights'].get('is_typosquat', False):
                analysis_result['typosquatting_domains'].append({
                    'domain': domain_value,
                    'target': domain['insights'].get('typosquat_target'),
                    'technique': domain['insights'].get('typosquat_technique'),
                    'confidence': domain['insights'].get('typosquat_confidence')
                })
                
            # Track TLD distribution
            tld = tldextract.extract(domain_value).suffix
            analysis_result['tld_distribution'][tld] = analysis_result['tld_distribution'].get(tld, 0) + 1
            
            # Update domain in iocs list to include insights
            for i, ioc in enumerate(iocs):
                if ioc.get('id') == domain.get('id'):
                    iocs[i] = domain
                    break
        
        # IP analysis
        logger.info(f"Analyzing {len(ips)} IP addresses")
        for ip in ips:
            ip_value = ip.get('value')
            
            # Add IP-specific insights
            ip['insights'] = add_ip_insights(ip_value)
            
            # Update risk score based on insights
            ip['risk_score'] = calculate_ioc_risk_score(ip, ip['insights'])
            
            # Track high-risk IPs
            if ip['risk_score'] > 70:
                analysis_result['high_risk_iocs'].append({
                    'id': ip.get('id'),
                    'type': ip.get('type'),
                    'value': ip_value,
                    'risk_score': ip['risk_score'],
                    'insights': ip['insights']
                })
                
            # Update ip in iocs list to include insights
            for i, ioc in enumerate(iocs):
                if ioc.get('id') == ip.get('id'):
                    iocs[i] = ip
                    break
        
        # URL analysis
        logger.info(f"Analyzing {len(urls)} URLs")
        for url in urls:
            url_value = url.get('value')
            if not Utils.is_valid_url(url_value):
                continue
                
            # Add URL-specific insights
            url['insights'] = add_url_insights(url_value)
            
            # Update risk score based on insights
            url['risk_score'] = calculate_ioc_risk_score(url, url['insights'])
            
            # Track high-risk URLs
            if url['risk_score'] > 70:
                analysis_result['high_risk_iocs'].append({
                    'id': url.get('id'),
                    'type': 'url',
                    'value': url_value,
                    'risk_score': url['risk_score'],
                    'insights': url['insights']
                })
                
            # Update url in iocs list to include insights
            for i, ioc in enumerate(iocs):
                if ioc.get('id') == url.get('id'):
                    iocs[i] = url
                    break
        
        # Find infrastructure clusters
        logger.info("Identifying infrastructure clusters")
        analysis_result['infrastructure_clusters'] = identify_infrastructure_clusters(iocs)
        cluster_count = len(analysis_result['infrastructure_clusters'])
        logger.info(f"Found {cluster_count} infrastructure clusters")
        
        # Identify patterns
        patterns = []
        
        # Pattern: Many domains with the same TLD
        tld_counts = Counter(analysis_result['tld_distribution'])
        unusual_tlds = [tld for tld, count in tld_counts.items() 
                        if count > 5 and tld not in ('com', 'org', 'net', 'gov')]
        if unusual_tlds:
            patterns.append({
                'type': 'unusual_tld_usage',
                'description': f"Unusual TLD usage: {', '.join(unusual_tlds)}",
                'details': {tld: count for tld, count in tld_counts.items() if tld in unusual_tlds}
            })
        
        # Pattern: Typosquatting campaign
        if len(analysis_result['typosquatting_domains']) > 3:
            # Group by target
            targets = Counter(d['target'] for d in analysis_result['typosquatting_domains'])
            for target, count in targets.most_common():
                if count >= 3:  # At least 3 typosquats targeting the same domain
                    patterns.append({
                        'type': 'typosquat_campaign',
                        'description': f"Typosquatting campaign targeting {target} with {count} domains",
                        'details': {
                            'target': target,
                            'domains': [d['domain'] for d in analysis_result['typosquatting_domains'] 
                                        if d['target'] == target]
                        }
                    })
        
        # Pattern: Large infrastructure cluster
        large_clusters = {k: v for k, v in analysis_result['infrastructure_clusters'].items() 
                          if len(v) > 5}
        if large_clusters:
            for cluster_id, cluster in large_clusters.items():
                patterns.append({
                    'type': 'large_infrastructure_cluster',
                    'description': f"Large infrastructure cluster with {len(cluster)} IOCs",
                    'details': {
                        'cluster_id': cluster_id,
                        'size': len(cluster),
                        'ioc_types': Counter(ioc.get('type') for ioc in cluster)
                    }
                })
        
        analysis_result['patterns_detected'] = patterns
        
        # Use AI for pattern analysis if available and we have interesting patterns
        if Config.NLP_ENABLED and ensure_ai_models() and (patterns or len(analysis_result['high_risk_iocs']) > 5):
            logger.info("Running AI analysis on patterns and high-risk IOCs")
            ai_result = perform_ai_pattern_analysis(
                patterns=patterns,
                high_risk_iocs=analysis_result['high_risk_iocs'],
                typosquatting_domains=analysis_result['typosquatting_domains'],
                clusters=analysis_result['infrastructure_clusters']
            )
            analysis_result['ai_analysis'] = ai_result
        
        # Update database with new risk scores and insights
        update_ioc_analysis_results(iocs)
        
        # Calculate execution time
        analysis_result['execution_time'] = time.time() - start_time
        logger.info(f"Analysis completed in {analysis_result['execution_time']:.2f}s")
        
        # Save analysis results
        store_analysis_results(analysis_result)
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error in high-value indicators analysis: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return {"error": str(e)}

def update_ioc_analysis_results(iocs: List[Dict]) -> bool:
    """Update IOC records in BigQuery with new analysis results."""
    bq_client, _, _, _ = get_clients()
    if not bq_client:
        return False
    
    table_id = Config.get_table_name('indicators')
    if not table_id:
        return False
    
    # Prepare updates in batches
    batch_size = 50
    success_count = 0
    
    for i in range(0, len(iocs), batch_size):
        batch = iocs[i:i+batch_size]
        updates = []
        
        for ioc in batch:
            # Only update if we have new insights or risk score
            if 'insights' in ioc or 'risk_score' in ioc:
                ioc_id = ioc.get('id')
                if not ioc_id:
                    continue
                
                # Prepare update data
                update_data = {
                    'risk_score': ioc.get('risk_score', 50),
                    'last_analyzed': datetime.utcnow().isoformat()
                }
                
                # Convert insights to string for storage
                if 'insights' in ioc:
                    update_data['analysis_summary'] = json.dumps(ioc['insights'])
                
                updates.append({
                    'id': ioc_id,
                    'updates': update_data
                })
        
        if not updates:
            continue
        
        # Execute batch update
        try:
            from google.cloud import bigquery
            
            # Create temporary table for updates
            temp_table_id = f"{table_id}_updates_{int(time.time())}"
            
            # Define schema for temp table
            schema = [
                bigquery.SchemaField("id", "STRING"),
                bigquery.SchemaField("risk_score", "INTEGER"),
                bigquery.SchemaField("last_analyzed", "TIMESTAMP"),
                bigquery.SchemaField("analysis_summary", "STRING")
            ]
            
            # Create temp table
            temp_table = bigquery.Table(temp_table_id, schema=schema)
            bq_client.create_table(temp_table, exists_ok=False)
            
            # Prepare rows for temp table
            rows = []
            for update in updates:
                row = {
                    'id': update['id'],
                    'risk_score': update['updates'].get('risk_score'),
                    'last_analyzed': update['updates'].get('last_analyzed'),
                    'analysis_summary': update['updates'].get('analysis_summary', '')
                }
                rows.append(row)
            
            # Insert data into temp table
            job_config = bigquery.LoadJobConfig()
            job_config.write_disposition = bigquery.WriteDisposition.WRITE_TRUNCATE
            job = bq_client.load_table_from_json(rows, temp_table_id, job_config=job_config)
            job.result()  # Wait for completion
            
            # Update main table with MERGE
            update_query = f"""
            MERGE `{table_id}` T
            USING `{temp_table_id}` S
            ON T.id = S.id
            WHEN MATCHED THEN
              UPDATE SET
                risk_score = S.risk_score,
                last_analyzed = S.last_analyzed,
                analysis_summary = S.analysis_summary
            """
            
            bq_client.query(update_query).result()
            
            # Delete temp table
            bq_client.delete_table(temp_table_id)
            
            success_count += len(updates)
            
        except Exception as e:
            logger.error(f"Error updating IOC analysis results: {str(e)}")
            if Config.ENVIRONMENT != 'production':
                logger.error(traceback.format_exc())
            report_error(e)
            return False
    
    logger.info(f"Updated {success_count} IOCs with analysis results")
    return success_count > 0

def store_analysis_results(analysis_result: Dict[str, Any]) -> bool:
    """Store analysis results in BigQuery."""
    bq_client, _, _, _ = get_clients()
    if not bq_client:
        return False
    
    try:
        from google.cloud import bigquery
        
        # Define analysis results table if it doesn't exist
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.analysis_results"
        
        try:
            bq_client.get_table(table_id)
        except Exception:
            # Create table
            schema = [
                bigquery.SchemaField("id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("iocs_analyzed", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("high_risk_count", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("patterns_count", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("execution_time", "FLOAT", mode="REQUIRED"),
                bigquery.SchemaField("domains_analyzed", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("ips_analyzed", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("urls_analyzed", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("typosquatting_count", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("clusters_count", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("analysis_data", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("ai_analyzed", "BOOLEAN", mode="NULLABLE"),
            ]
            
            table = bigquery.Table(table_id, schema=schema)
            bq_client.create_table(table)
            logger.info(f"Created analysis_results table: {table_id}")
        
        # Prepare record
        analysis_id = hashlib.md5(f"analysis:{analysis_result['timestamp']}".encode()).hexdigest()
        
        record = {
            "id": analysis_id,
            "timestamp": analysis_result.get('timestamp'),
            "iocs_analyzed": analysis_result.get('iocs_analyzed', 0),
            "high_risk_count": len(analysis_result.get('high_risk_iocs', [])),
            "patterns_count": len(analysis_result.get('patterns_detected', [])),
            "execution_time": analysis_result.get('execution_time', 0),
            "domains_analyzed": analysis_result.get('domains_analyzed', 0),
            "ips_analyzed": analysis_result.get('ips_analyzed', 0),
            "urls_analyzed": analysis_result.get('urls_analyzed', 0),
            "typosquatting_count": len(analysis_result.get('typosquatting_domains', [])),
            "clusters_count": len(analysis_result.get('infrastructure_clusters', {})),
            "analysis_data": json.dumps(analysis_result),
            "ai_analyzed": analysis_result.get('ai_analysis') is not None
        }
        
        # Insert record
        job = bq_client.load_table_from_json([record], table_id)
        job.result()
        
        if job.errors:
            logger.error(f"Error storing analysis results: {job.errors}")
            return False
            
        logger.info(f"Stored analysis results with ID {analysis_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error storing analysis results: {str(e)}")
        if Config.ENVIRONMENT != 'production':
            logger.error(traceback.format_exc())
        report_error(e)
        return False

def perform_ai_pattern_analysis(patterns: List[Dict], high_risk_iocs: List[Dict], 
                              typosquatting_domains: List[Dict], clusters: Dict) -> Dict:
    """
    Use AI to analyze patterns and high-risk IOCs for insights.
    This uses AI efficiently by only analyzing aggregated patterns,
    not individual IOCs.
    """
    if not (text_model or generative_model):
        return None
    
    try:
        # Prepare input data by sampling
        sample_high_risk = high_risk_iocs[:10]  # Limit to 10 high-risk IOCs
        sample_typosquatting = typosquatting_domains[:5]  # Limit to 5 typosquatting examples
        
        # Format clusters concisely
        clusters_summary = []
        for cluster_id, iocs in list(clusters.items())[:3]:  # Limit to 3 clusters
            cluster_summary = {
                'id': cluster_id,
                'size': len(iocs),
                'types': Counter(ioc.get('type') for ioc in iocs),
                'sample': [ioc.get('value') for ioc in iocs[:3]]
            }
            clusters_summary.append(cluster_summary)
        
        # Create detailed but concise input for AI
        ai_input = {
            'patterns': patterns,
            'high_risk_sample': sample_high_risk,
            'typosquatting_sample': sample_typosquatting,
            'clusters_sample': clusters_summary
        }
        
        # Create analysis prompt
        analysis_prompt = f"""
        Analyze these threat intelligence findings and provide an expert threat assessment.
        You'll receive pattern detections, high-risk IOCs, typosquatting domains, and infrastructure clusters.
        
        ## Data Summary
        - Patterns detected: {len(patterns)}
        - High-risk IOCs: {len(high_risk_iocs)} (sample of {len(sample_high_risk)} provided)
        - Typosquatting domains: {len(typosquatting_domains)} (sample of {len(sample_typosquatting)} provided)
        - Infrastructure clusters: {len(clusters)} (sample of {len(clusters_summary)} provided)
        
        ## Data
        {json.dumps(ai_input, indent=2)}
        
        Provide analysis in JSON format:
        {{
            "threat_assessment": {{
                "level": "low|medium|high|critical",
                "confidence": 0-100,
                "summary": "concise executive summary of the threat landscape"
            }},
            "key_findings": ["finding1", "finding2", "finding3"],
            "potential_campaign": {{
                "detected": true|false,
                "name": "suggested_campaign_name_if_detected",
                "confidence": 0-100,
                "description": "brief description of the campaign",
                "tactics": ["tactic1", "tactic2"]
            }},
            "recommendations": ["recommendation1", "recommendation2", "recommendation3"]
        }}
        """
        
        # Use AI model to analyze
        if generative_model:
            response = generative_model.generate_content(analysis_prompt)
            response_text = response.text
        elif text_model:
            response = text_model.predict(
                prompt=analysis_prompt,
                temperature=0.2,
                max_output_tokens=1024,
                top_p=0.8,
                top_k=40
            )
            response_text = response.text
        else:
            return None
        
        # Parse JSON response
        json_match = re.search(r'({[\s\S]*})', response_text)
        if json_match:
            ai_result = json.loads(json_match.group(0))
            ai_result['model_used'] = 'gemini' if generative_model else 'text-bison'
            return ai_result
        else:
            logger.warning("Could not parse JSON from AI response")
            return {"error": "Invalid AI response format", "raw_response": response_text[:500]}
            
    except Exception as e:
        logger.error(f"Error in AI pattern analysis: {str(e)}")
        return {"error": str(e)}

def get_latest_analysis_results() -> Dict[str, Any]:
    """Get the latest analysis results from BigQuery."""
    bq_client, _, _, _ = get_clients()
    if not bq_client:
        return {'error': 'BigQuery client not initialized'}
    
    try:
        dataset_id = f"{Config.GCP_PROJECT}.{Config.BIGQUERY_DATASET}"
        table_id = f"{dataset_id}.analysis_results"
        
        # Check if table exists
        try:
            bq_client.get_table(table_id)
        except Exception:
            return {'error': 'Analysis results table not found'}
        
        # Query for latest analysis
        query = f"""
        SELECT *
        FROM `{table_id}`
        ORDER BY timestamp DESC
        LIMIT 1
        """
        
        results = list(bq_client.query(query))
        
        if not results:
            return {'error': 'No analysis results found'}
        
        # Get the analysis data
        analysis_data = json.loads(results[0].analysis_data)
        
        # Add summary metadata
        analysis_data['summary'] = {
            'timestamp': results[0].timestamp.isoformat(),
            'iocs_analyzed': results[0].iocs_analyzed,
            'high_risk_count': results[0].high_risk_count,
            'patterns_count': results[0].patterns_count,
            'execution_time': results[0].execution_time,
            'ai_analyzed': results[0].ai_analyzed
        }
        
        return analysis_data
        
    except Exception as e:
        logger.error(f"Error getting latest analysis results: {str(e)}")
        return {'error': str(e)}

def get_analysis_status() -> Dict:
    """
    Get current analysis status.
    
    Returns:
        Current analysis status dictionary
    """
    with _analysis_lock:
        status_copy = dict(analysis_status)
    
    # Add current timestamp
    status_copy["current_time"] = datetime.utcnow().isoformat()
    
    # Add service manager status
    service_manager = Config.get_service_manager()
    service_status = service_manager.get_status()
    
    status_copy["service_status"] = {
        "analysis": service_status['services'].get('analysis', 'unknown'),
        "ai_models": service_status['services'].get('ai_models', 'unknown'),
        "overall": service_status['overall']
    }
    
    # Add latest analysis summary if available
    latest_analysis = get_latest_analysis_results()
    if not latest_analysis.get('error'):
        status_copy["latest_analysis"] = latest_analysis.get('summary', {})
        
        # Extract high-level indicators
        high_risk_iocs = len(latest_analysis.get('high_risk_iocs', []))
        patterns_detected = len(latest_analysis.get('patterns_detected', []))
        status_copy["high_value_detections"] = high_risk_iocs + patterns_detected
    
    return status_copy

# ==================== Background Processing ====================

def start_background_analysis(interval_hours: int = 4):
    """
    Start background analysis for high-value indicators.
    
    Args:
        interval_hours: Interval between analysis runs
    
    Returns:
        Thread object
    """
    def analysis_thread():
        service_manager = Config.get_service_manager()
        
        while True:
            try:
                logger.info("Starting background analysis cycle")
                
                # Update service status
                update_service_status(ServiceStatus.READY)
                
                with _analysis_lock:
                    analysis_status["running"] = True
                    analysis_status["last_run"] = datetime.utcnow().isoformat()
                    analysis_status["domains_analyzed"] = 0
                    analysis_status["ips_analyzed"] = 0
                    analysis_status["urls_analyzed"] = 0
                    analysis_status["total_iocs"] = 0
                    analysis_status["pattern_discoveries"] = 0
                    analysis_status["errors"] = []
                
                # Run analysis
                result = analyze_high_value_indicators(limit=2000)
                
                # Update status with results
                with _analysis_lock:
                    if 'error' in result:
                        analysis_status["errors"].append(result['error'])
                    else:
                        analysis_status["domains_analyzed"] = result.get('domains_analyzed', 0)
                        analysis_status["ips_analyzed"] = result.get('ips_analyzed', 0)
                        analysis_status["urls_analyzed"] = result.get('urls_analyzed', 0)
                        analysis_status["total_iocs"] = result.get('iocs_analyzed', 0)
                        analysis_status["pattern_discoveries"] = len(result.get('patterns_detected', []))
                        analysis_status["high_value_detections"] = len(result.get('high_risk_iocs', []))
                    
                    analysis_status["running"] = False
                
                # Publish completion event
                publish_event('analysis_completed', {
                    'total_iocs': result.get('iocs_analyzed', 0),
                    'high_risk_iocs': len(result.get('high_risk_iocs', [])),
                    'patterns_detected': len(result.get('patterns_detected', []))
                })
                
                logger.info(f"Background analysis completed: analyzed {result.get('iocs_analyzed', 0)} IOCs")
                
                # Sleep until next cycle
                time.sleep(interval_hours * 3600)
                
            except Exception as e:
                logger.error(f"Error in background analysis: {str(e)}")
                update_service_status(ServiceStatus.ERROR, str(e))
                with _analysis_lock:
                    analysis_status["running"] = False
                    analysis_status["errors"].append(f"Background analysis error: {str(e)}")
                time.sleep(300)  # Wait 5 minutes on error
    
    thread = threading.Thread(target=analysis_thread, daemon=True)
    thread.start()
    logger.info(f"Started background analysis thread (interval: {interval_hours} hours)")
    return thread

# ==================== Initialization ====================

# Module initialization
if __name__ != "__main__":
    logger.info("Initializing analysis module")
    
    # Initialize AI models in background
    if Config.NLP_ENABLED:
        initialize_ai_models_background()
        
        # Start analysis if enabled
        if Config.AUTO_ANALYZE:
            # Delay start to allow services to initialize
            def delayed_start():
                time.sleep(30)
                start_background_analysis(interval_hours=6)
            
            threading.Thread(target=delayed_start, daemon=True).start()
            logger.info("Scheduled background analysis to start in 30 seconds")
    else:
        logger.info("NLP analysis disabled in configuration")
        service_manager = Config.get_service_manager()
        service_manager.update_status('ai_models', ServiceStatus.READY)
    
    # Update analysis service status
    update_service_status(ServiceStatus.READY)
    logger.info("Analysis module initialization completed")

# CLI mode
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Threat Intelligence Analysis Tool')
    parser.add_argument('--analyze', action='store_true', help='Run high-value indicator analysis')
    parser.add_argument('--limit', type=int, default=1000, help='Maximum number of IOCs to analyze')
    parser.add_argument('--status', action='store_true', help='Show analysis status')
    parser.add_argument('--results', action='store_true', help='Show latest analysis results')
    args = parser.parse_args()
    
    # Initialize configuration
    Config.init_app()
    
    # Initialize AI models if needed
    if Config.NLP_ENABLED:
        initialize_ai_models_background()
        time.sleep(5)  # Give models time to initialize
    
    if args.status:
        status = get_analysis_status()
        print(json.dumps(status, indent=2, default=str))
        
    elif args.results:
        results = get_latest_analysis_results()
        print(json.dumps(results, indent=2, default=str))
        
    elif args.analyze:
        logger.info(f"Running high-value indicator analysis (limit: {args.limit})")
        result = analyze_high_value_indicators(limit=args.limit)
        
        # Print summary
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Analysis completed in {result['execution_time']:.2f}s")
            print(f"Analyzed {result['iocs_analyzed']} IOCs ({result['domains_analyzed']} domains, {result['ips_analyzed']} IPs, {result['urls_analyzed']} URLs)")
            print(f"Found {len(result['high_risk_iocs'])} high-risk IOCs")
            print(f"Detected {len(result['patterns_detected'])} patterns")
            print(f"Found {len(result['typosquatting_domains'])} typosquatting domains")
            print(f"Identified {len(result['infrastructure_clusters'])} infrastructure clusters")
        
    else:
        logger.info("No action specified. Use --help for options.")
