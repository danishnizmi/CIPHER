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
CACHE_DURATION = 30  # 30 seconds for public data

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
    """Get clean dashboard data for public display"""
    cache_key = "public_dashboard_data"
    cached_data = get_cache(cache_key)
    
    if cached_data:
        return cached_data
    
    utils = get_utils()
    if not utils:
        return {
            "error": "Intelligence system initializing",
            "message": "CIPHER platform is starting up",
            "retry_after": 10
        }
    
    try:
        # Get basic stats without backend details
        stats_data = await utils.get_comprehensive_stats()
        insights_data = await utils.get_threat_insights()
        analytics_data = await utils.get_threat_analytics()
        
        # Clean and sanitize data for public display
        public_stats = sanitize_stats(stats_data)
        public_insights = sanitize_insights(insights_data)
        public_analytics = sanitize_analytics(analytics_data)
        
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
        
        # Cache for 30 seconds
        set_cache(cache_key, dashboard_data, 30)
        
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

def sanitize_insights(raw_insights: Dict[str, Any]) -> Dict[str, Any]:
    """Clean insights data for public display"""
    if not raw_insights or not raw_insights.get("insights"):
        return {"data": [], "count": 0}
    
    public_insights = []
    for insight in raw_insights.get("insights", [])[:20]:  # Limit to 20 most recent
        
        # Skip if no meaningful content
        message_text = insight.get("message_text", "")
        if not message_text or len(message_text.strip()) < 20:
            continue
            
        # Create clean public insight
        clean_insight = {
            "id": insight.get("message_id", "")[:8],  # Short ID only
            "source": insight.get("chat_username", "@Unknown"),
            "threat_level": insight.get("threat_level", "low"),
            "category": insight.get("category", "other"),
            "urgency": round(insight.get("urgency_score", 0.0) * 100),
            "time": format_time_ago(insight.get("message_date")),
            "summary": clean_message_text(message_text),
            "analysis": clean_analysis(insight.get("gemini_analysis", "")),
            "indicators": extract_public_indicators(insight),
            "severity": map_threat_severity(insight.get("threat_level", "low"))
        }
        
        # Only add if we have real threat content
        if (clean_insight["urgency"] > 10 or 
            clean_insight["threat_level"] in ["medium", "high", "critical"] or
            clean_insight["indicators"]["count"] > 0):
            public_insights.append(clean_insight)
    
    return {
        "data": public_insights,
        "count": len(public_insights)
    }

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
    if len(cleaned) > 200:
        cleaned = cleaned[:197] + "..."
    
    return cleaned

def clean_analysis(analysis: str) -> str:
    """Clean Gemini analysis for public display"""
    if not analysis or analysis == "Analysis not available":
        return "Threat analysis pending"
    
    # Remove technical jargon and backend references
    cleaned = analysis.replace("Gemini AI", "AI")
    cleaned = cleaned.replace("BigQuery", "system")
    cleaned = cleaned.replace("processing", "analysis")
    
    # Limit length
    if len(cleaned) > 300:
        cleaned = cleaned[:297] + "..."
    
    return cleaned

def extract_public_indicators(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Extract safe public indicators"""
    indicators = {
        "cves": insight.get("cve_references", [])[:3],  # Max 3 CVEs
        "malware": insight.get("malware_families", [])[:2],  # Max 2 malware families
        "count": 0
    }
    
    # Count total indicators
    indicators["count"] = len(indicators["cves"]) + len(indicators["malware"])
    
    return indicators

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
async def get_public_insights(limit: int = Query(10, ge=1, le=25)):
    """Get recent public threat insights"""
    utils = get_utils()
    if not utils:
        return {"insights": [], "count": 0, "error": "Service initializing"}
    
    try:
        raw_insights = await utils.get_threat_insights()
        public_insights = sanitize_insights(raw_insights)
        
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
