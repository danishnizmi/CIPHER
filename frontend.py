from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Simple cache for performance
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 15  # 15 seconds for fresh data

def get_cache(key: str) -> Any:
    """Get cached value if still valid"""
    if key in _cache and key in _cache_ttl and time.time() < _cache_ttl[key]:
        return _cache[key]
    return None

def set_cache(key: str, value: Any, duration: int = CACHE_DURATION):
    """Set cache with TTL"""
    _cache[key] = value
    _cache_ttl[key] = time.time() + duration

def get_utils():
    """Safely import utils module"""
    try:
        import utils
        return utils
    except ImportError:
        logger.warning("Utils module not available")
        return None

@router.get("/dashboard", response_class=HTMLResponse)
async def public_dashboard(request: Request):
    """Clean public cybersecurity intelligence dashboard"""
    try:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "PROJECT_ID": "primal-chariot-382610"
        })
    except Exception as e:
        logger.error(f"Dashboard template error: {e}")
        return HTMLResponse(content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIPHER - Cybersecurity Intelligence</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Segoe UI', monospace;
                    background: linear-gradient(135deg, #0a0a0a, #1a1a2e); 
                    color: #00ff00; 
                    padding: 50px; 
                    text-align: center; 
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .container {
                    background: rgba(0, 0, 0, 0.8);
                    border: 2px solid #00ff00;
                    border-radius: 15px;
                    padding: 40px;
                    max-width: 600px;
                }
                h1 { color: #00ff00; text-shadow: 0 0 10px #00ff00; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ CIPHER Intelligence</h1>
                <p>Loading cybersecurity threat intelligence...</p>
                <script>setTimeout(() => location.reload(), 5000);</script>
            </div>
        </body>
        </html>
        """, status_code=200)

@router.get("/api/dashboard/data")
async def get_public_dashboard_data():
    """Get clean dashboard data for public display - FIXED VERSION"""
    cache_key = "public_dashboard_data"
    cached_data = get_cache(cache_key)
    
    if cached_data:
        logger.info("Returning cached dashboard data")
        return cached_data
    
    utils = get_utils()
    if not utils:
        return {
            "error": "Intelligence system initializing",
            "message": "CIPHER platform is starting up",
            "retry_after": 10
        }
    
    try:
        logger.info("Fetching fresh dashboard data...")
        
        # Get raw data from backend
        stats_data = await utils.get_comprehensive_stats()
        insights_data = await utils.get_threat_insights()
        analytics_data = await utils.get_threat_analytics()
        
        logger.info(f"Raw insights retrieved: {len(insights_data.get('insights', []))}")
        
        # Clean and sanitize data for public display
        public_stats = sanitize_stats(stats_data)
        public_insights = sanitize_insights_fixed(insights_data)  # FIXED FUNCTION
        public_analytics = sanitize_analytics(analytics_data)
        
        logger.info(f"Public insights after processing: {len(public_insights.get('data', []))}")
        
        dashboard_data = {
            "stats": public_stats,
            "insights": public_insights,
            "analytics": public_analytics,
            "status": "operational",
            "channels": [
                {"name": "@DarkfeedNews", "icon": "🔴", "type": "Advanced Threats"},
                {"name": "@breachdetector", "icon": "🟠", "type": "Data Breaches"},
                {"name": "@secharvester", "icon": "🔵", "type": "Security News"}
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Cache for 15 seconds to get fresh data
        set_cache(cache_key, dashboard_data, 15)
        
        logger.info("Dashboard data prepared successfully")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        return {
            "error": "Data temporarily unavailable",
            "message": "Please try again in a moment",
            "retry_after": 15
        }

def sanitize_stats(raw_stats: Dict[str, Any]) -> Dict[str, Any]:
    """Clean stats data for public display"""
    if not raw_stats:
        return {
            "total_messages": 0,
            "processed_today": 0,
            "high_priority_threats": 0,
            "avg_threat_level": "low"
        }
    
    return {
        "total_messages": raw_stats.get("total_messages", 0),
        "processed_today": raw_stats.get("processed_today", 0),
        "high_priority_threats": (raw_stats.get("critical_threats", 0) + 
                                raw_stats.get("high_threats", 0)),
        "critical_threats": raw_stats.get("critical_threats", 0),
        "cve_references": raw_stats.get("cve_mentions", 0),
        "avg_urgency": round(raw_stats.get("avg_urgency", 0.0), 2),
        "status": "active" if raw_stats.get("monitoring_active") else "standby"
    }

def sanitize_insights_fixed(raw_insights: Dict[str, Any]) -> Dict[str, Any]:
    """FIXED insights sanitization - Show actual data with minimal filtering"""
    if not raw_insights or not raw_insights.get("insights"):
        logger.warning("No raw insights available")
        return {"data": [], "count": 0}
    
    logger.info(f"Processing {len(raw_insights['insights'])} raw insights")
    
    public_insights = []
    insights_list = raw_insights.get("insights", [])
    
    # Sort by date to get most recent first
    try:
        insights_list.sort(key=lambda x: x.get("processed_date", ""), reverse=True)
    except Exception as e:
        logger.warning(f"Could not sort insights: {e}")
    
    for i, insight in enumerate(insights_list[:100]):  # Process up to 100 most recent
        try:
            # Get basic message info
            message_text = insight.get("message_text", "")
            message_id = insight.get("message_id", f"unknown_{i}")
            source = insight.get("chat_username", "@Unknown")
            
            # Skip if no meaningful content (very minimal filtering)
            if not message_text or len(message_text.strip()) < 10:
                logger.debug(f"Skipping insight {i}: insufficient content")
                continue
            
            # Get threat data with real-time enhancement
            threat_level = insight.get("threat_level", "").lower()
            urgency_score = insight.get("urgency_score", 0.0)
            category = insight.get("category", "")
            analysis = insight.get("gemini_analysis", "")
            
            # ENHANCED REAL-TIME ANALYSIS FOR POOR DATA
            if (threat_level in ["", "low", "unknown"] or 
                urgency_score == 0.0 or 
                category in ["", "other", "unknown"] or
                not analysis or analysis == "Analysis not available"):
                
                logger.info(f"Enhancing poor analysis for insight {i}")
                enhanced = enhance_threat_analysis(message_text, source)
                
                # Use enhanced data
                threat_level = enhanced["threat_level"]
                urgency_score = enhanced["urgency_score"]
                category = enhanced["category"]
                analysis = enhanced["analysis"]
            
            # Get indicators (enhanced extraction)
            indicators = extract_indicators_enhanced(insight, message_text)
            
            # Create clean public insight
            clean_insight = {
                "id": str(message_id)[:8],
                "source": source,
                "threat_level": threat_level,
                "category": category,
                "urgency": int(urgency_score * 100) if urgency_score else 0,
                "time": format_time_ago(insight.get("message_date")),
                "summary": clean_message_text(message_text),
                "analysis": clean_analysis(analysis),
                "indicators": indicators,
                "severity": map_threat_severity(threat_level),
                "sentiment": insight.get("sentiment", "neutral") or "neutral",
                "raw_date": insight.get("message_date"),
                "processed_date": insight.get("processed_date")
            }
            
            # MINIMAL FILTERING - Show most threats
            should_include = (
                len(clean_insight["summary"]) >= 10 or  # Has some content
                clean_insight["urgency"] >= 1 or        # Any urgency
                clean_insight["indicators"]["count"] > 0 or  # Has indicators
                source in ["@DarkfeedNews", "@breachdetector", "@secharvester"]  # From our sources
            )
            
            if should_include:
                public_insights.append(clean_insight)
                logger.info(f"Added insight {i}: {source} - {threat_level}/{category} - urgency: {clean_insight['urgency']}%")
            else:
                logger.debug(f"Filtered out insight {i}: minimal content")
        
        except Exception as e:
            logger.error(f"Error processing insight {i}: {e}")
            continue
    
    logger.info(f"Final public insights count: {len(public_insights)}")
    
    return {
        "data": public_insights,
        "count": len(public_insights)
    }

def enhance_threat_analysis(text: str, source: str) -> Dict[str, Any]:
    """Enhanced real-time threat analysis for poor BigQuery data"""
    text_lower = text.lower()
    
    # Initialize with defaults
    threat_level = "low"
    urgency_score = 0.1
    category = "other"
    
    # Enhanced threat scoring with cybersecurity context
    threat_score = 0.0
    
    # Critical cybersecurity indicators
    critical_indicators = {
        "zero-day": 0.8, "0day": 0.8, "exploit": 0.6, "ransomware": 0.7,
        "apt": 0.6, "breach": 0.6, "compromise": 0.5, "attack": 0.4,
        "malware": 0.5, "trojan": 0.5, "backdoor": 0.5, "phishing": 0.4,
        "vulnerability": 0.4, "cve-": 0.4, "critical": 0.5, "urgent": 0.4,
        "lockbit": 0.7, "maze": 0.7, "conti": 0.7, "ryuk": 0.7,
        "darkfeed": 0.5, "threat": 0.3, "security": 0.2, "hack": 0.4
    }
    
    # Score based on keywords
    for keyword, weight in critical_indicators.items():
        if keyword in text_lower:
            threat_score += weight
    
    # Source-based multipliers
    source_multipliers = {
        "@DarkfeedNews": 1.5,    # Premium threat intel
        "@breachdetector": 1.3,   # Data breach focus
        "@secharvester": 1.0      # General security news
    }
    
    multiplier = source_multipliers.get(source, 1.0)
    threat_score *= multiplier
    
    # Determine threat level and urgency
    if threat_score >= 1.0:
        threat_level = "critical"
        urgency_score = min(0.95, threat_score * 0.5 + 0.4)
    elif threat_score >= 0.6:
        threat_level = "high"
        urgency_score = min(0.8, threat_score * 0.5 + 0.3)
    elif threat_score >= 0.3:
        threat_level = "medium"
        urgency_score = min(0.6, threat_score * 0.5 + 0.2)
    else:
        threat_level = "low"
        urgency_score = max(0.1, threat_score * 0.5 + 0.1)
    
    # Enhanced category detection
    if any(word in text_lower for word in ["ransomware", "lockbit", "maze", "conti", "ryuk"]):
        category = "ransomware"
    elif any(word in text_lower for word in ["breach", "leak", "stolen", "database", "dump"]):
        category = "data_breach"
    elif any(word in text_lower for word in ["apt", "advanced persistent", "nation state"]):
        category = "apt"
    elif any(word in text_lower for word in ["malware", "trojan", "virus", "backdoor"]):
        category = "malware"
    elif any(word in text_lower for word in ["vulnerability", "cve-", "patch", "exploit"]):
        category = "vulnerability"
    elif any(word in text_lower for word in ["phishing", "scam", "social engineering"]):
        category = "phishing"
    elif any(word in text_lower for word in ["ddos", "dos", "attack"]):
        category = "ddos"
    
    # Generate enhanced analysis
    analysis_parts = []
    
    if threat_level == "critical":
        analysis_parts.append(f"Critical {category} threat detected from {source}.")
    elif threat_level == "high":
        analysis_parts.append(f"High-priority {category} identified from {source}.")
    elif threat_level == "medium":
        analysis_parts.append(f"Medium-level {category} alert from {source}.")
    else:
        analysis_parts.append(f"{category.title()} intelligence from {source}.")
    
    # Add context based on content
    if "cve-" in text_lower:
        analysis_parts.append("Contains vulnerability information requiring attention.")
    if any(word in text_lower for word in ["exploit", "poc", "proof of concept"]):
        analysis_parts.append("Includes exploitation details.")
    if any(word in text_lower for word in ["ioc", "indicator", "hash"]):
        analysis_parts.append("Contains threat indicators.")
    
    analysis = " ".join(analysis_parts) or "Threat intelligence processed for security monitoring."
    
    return {
        "threat_level": threat_level,
        "urgency_score": urgency_score,
        "category": category,
        "analysis": analysis
    }

def extract_indicators_enhanced(insight: Dict[str, Any], message_text: str) -> Dict[str, Any]:
    """Enhanced indicator extraction"""
    indicators = {
        "cves": [],
        "malware": [],
        "count": 0
    }
    
    # Get from insight data first
    cve_refs = insight.get("cve_references", []) or []
    malware_families = insight.get("malware_families", []) or []
    
    # If empty, extract from text
    if not cve_refs and not malware_families:
        import re
        
        # Extract CVEs
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        cve_matches = cve_pattern.findall(message_text)
        cve_refs = list(set(cve_matches))[:3]
        
        # Extract malware families
        malware_keywords = [
            "lockbit", "maze", "ryuk", "conti", "emotet", "trickbot",
            "qakbot", "cobalt strike", "ransomware", "malware", "trojan"
        ]
        
        text_lower = message_text.lower()
        malware_families = [malware for malware in malware_keywords if malware in text_lower][:3]
    
    indicators["cves"] = cve_refs[:3] if cve_refs else []
    indicators["malware"] = malware_families[:3] if malware_families else []
    indicators["count"] = len(indicators["cves"]) + len(indicators["malware"])
    
    return indicators

def sanitize_analytics(raw_analytics: Dict[str, Any]) -> Dict[str, Any]:
    """Clean analytics for public display"""
    if not raw_analytics:
        return {
            "threat_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "categories": {},
            "trends": {"increasing": False, "stable": True}
        }
    
    return {
        "threat_distribution": raw_analytics.get("threat_levels", {}),
        "categories": raw_analytics.get("categories", {}),
        "summary": {
            "total_threats": raw_analytics.get("summary", {}).get("total_threats", 0),
            "high_priority": raw_analytics.get("summary", {}).get("high_priority", 0)
        }
    }

def clean_message_text(text: str) -> str:
    """Clean message text for public display"""
    if not text:
        return "No summary available"
    
    # Remove special formatting and limit length
    cleaned = text.replace("🚨", "").replace("**", "").replace("*", "")
    cleaned = " ".join(cleaned.split())  # Clean whitespace
    
    # Limit length and add ellipsis
    if len(cleaned) > 250:
        cleaned = cleaned[:247] + "..."
    
    return cleaned

def clean_analysis(analysis: str) -> str:
    """Clean analysis for public display"""
    if not analysis or analysis in ["Analysis not available", "No analysis available", ""]:
        return "Threat analysis completed - monitoring for indicators and impact assessment."
    
    # Remove technical jargon and backend references
    cleaned = analysis.replace("Gemini AI", "AI")
    cleaned = cleaned.replace("BigQuery", "system")
    cleaned = cleaned.replace("processing", "analysis")
    
    # Limit length
    if len(cleaned) > 400:
        cleaned = cleaned[:397] + "..."
    
    return cleaned

def map_threat_severity(threat_level: str) -> str:
    """Map threat level to severity description"""
    severity_map = {
        "critical": "Critical",
        "high": "High", 
        "medium": "Medium",
        "low": "Low",
        "info": "Informational"
    }
    return severity_map.get(threat_level, "Unknown")

def format_time_ago(timestamp) -> str:
    """Format time in human-readable way"""
    if not timestamp:
        return "Unknown"
    
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        else:
            dt = timestamp
        
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        diff = now - dt
        
        if diff.days > 7:
            return f"{diff.days} days ago"
        elif diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"
    except Exception:
        return "Unknown"

# API endpoints remain the same
@router.get("/api/stats")
async def get_public_stats():
    """Get basic public statistics"""
    utils = get_utils()
    if not utils:
        return {"error": "Service initializing"}
    
    try:
        raw_stats = await utils.get_comprehensive_stats()
        return sanitize_stats(raw_stats)
    except Exception as e:
        logger.error(f"Public stats error: {e}")
        return {"error": "Stats temporarily unavailable"}

@router.get("/api/insights")
async def get_public_insights(limit: int = Query(20, ge=1, le=50)):
    """Get recent public threat insights"""
    utils = get_utils()
    if not utils:
        return {"insights": [], "count": 0, "error": "Service initializing"}
    
    try:
        raw_insights = await utils.get_threat_insights()
        public_insights = sanitize_insights_fixed(raw_insights)  # Use fixed function
        
        # Apply limit
        public_insights["data"] = public_insights["data"][:limit]
        public_insights["count"] = len(public_insights["data"])
        
        return public_insights
    except Exception as e:
        logger.error(f"Public insights error: {e}")
        return {"insights": [], "count": 0, "error": "Insights temporarily unavailable"}

@router.get("/api/threat-levels")
async def get_threat_levels():
    """Get current threat level distribution"""
    utils = get_utils()
    if not utils:
        return {"distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
    
    try:
        raw_analytics = await utils.get_threat_analytics()
        return {
            "distribution": raw_analytics.get("threat_levels", {}),
            "total": sum(raw_analytics.get("threat_levels", {}).values()),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Threat levels error: {e}")
        return {"distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

@router.get("/api/monitoring/status")
async def get_public_monitoring_status():
    """Get basic monitoring status for public display"""
    utils = get_utils()
    if not utils:
        return {"status": "initializing", "channels": 3}
    
    try:
        return {
            "status": "active" if utils.is_monitoring_active() else "standby",
            "channels": 3,
            "sources": ["DarkfeedNews", "BreachDetector", "SecHarvester"],
            "last_update": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Public monitoring status error: {e}")
        return {"status": "unknown", "channels": 3}
