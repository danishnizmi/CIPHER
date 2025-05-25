from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import logging
import time
import json
import csv
import io
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Reduced cache for real-time updates
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 5  # 5 seconds only for real-time data

def get_cache(key: str) -> Any:
    """Get cached value if still valid"""
    if key in _cache and key in _cache_ttl and time.time() < _cache_ttl[key]:
        return _cache[key]
    return None

def set_cache(key: str, value: Any, duration: int = CACHE_DURATION):
    """Set cache with TTL"""
    _cache[key] = value
    _cache_ttl[key] = time.time() + duration

def clear_cache():
    """Clear all cached data"""
    global _cache, _cache_ttl
    _cache.clear()
    _cache_ttl.clear()
    logger.info("Cache cleared")

def get_utils():
    """Safely import utils module"""
    try:
        import utils
        return utils
    except ImportError:
        logger.warning("Utils module not available")
        return None

@router.get("/dashboard", response_class=HTMLResponse)
async def cipher_dashboard(request: Request):
    """CIPHER Dashboard - Real data only"""
    try:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "PROJECT_ID": "primal-chariot-382610"
        })
    except Exception as e:
        logger.error(f"Dashboard template error: {e}")
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIPHER Dashboard - Loading</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ 
                    font-family: 'Segoe UI', monospace;
                    background: linear-gradient(135deg, #0a0a0a, #1a1a2e); 
                    color: #00ff00; 
                    padding: 50px; 
                    text-align: center; 
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .loading-container {{
                    background: rgba(0, 0, 0, 0.8);
                    border: 2px solid #00ff00;
                    border-radius: 15px;
                    padding: 40px;
                    max-width: 600px;
                }}
                h1 {{ color: #00ff00; text-shadow: 0 0 10px #00ff00; }}
                .spinner {{
                    border: 4px solid #333;
                    border-top: 4px solid #00ff00;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="loading-container">
                <h1>🛡️ CIPHER Dashboard</h1>
                <div class="spinner"></div>
                <p>Loading cybersecurity intelligence platform...</p>
                <script>setTimeout(() => location.reload(), 10000);</script>
            </div>
        </body>
        </html>
        """, status_code=200)

@router.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get comprehensive dashboard data - FIXED VERSION"""
    cache_key = "dashboard_real_data"
    cached_data = get_cache(cache_key)
    
    if cached_data:
        logger.info("Returning cached dashboard data")
        return cached_data
    
    utils = get_utils()
    if not utils:
        return JSONResponse(
            status_code=503,
            content={
                "error": "System initializing",
                "message": "CIPHER platform is starting up. Please wait...",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "retry_after": 10
            }
        )
    
    try:
        # Check system readiness
        system_ready = utils.is_bigquery_available()
        
        if not system_ready:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "BigQuery not ready",
                    "message": "Waiting for BigQuery connection",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "retry_after": 5
                }
            )
        
        logger.info("Fetching real dashboard data from all subsystems")
        
        # Fetch all real data
        try:
            stats = await utils.get_comprehensive_stats()
        except Exception as e:
            logger.error(f"Stats error: {e}")
            stats = {"total_messages": 0, "data_source": "error"}
        
        try:
            insights_raw = await utils.get_threat_insights()
        except Exception as e:
            logger.error(f"Insights error: {e}")
            insights_raw = {"insights": [], "total": 0, "source": "error"}
        
        try:
            monitoring = await utils.get_monitoring_status()
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            monitoring = {"active": False}
        
        try:
            analytics = await utils.get_threat_analytics()
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            analytics = {"threat_levels": {}, "categories": {}}
        
        # Process insights for frontend - FIXED PROCESSING
        processed_insights = []
        if insights_raw and "insights" in insights_raw and insights_raw["insights"]:
            logger.info(f"Processing {len(insights_raw['insights'])} raw insights")
            
            for i, insight in enumerate(insights_raw["insights"][:100]):  # Process up to 100
                try:
                    processed_insight = process_insight_for_display(insight)
                    if processed_insight:  # Only add valid insights
                        processed_insights.append(processed_insight)
                        
                        # Log first few insights for debugging
                        if i < 3:
                            logger.info(f"Processed insight {i}: {insight.get('chat_username', 'unknown')} - {processed_insight.get('threat_level', 'unknown')}")
                    
                except Exception as e:
                    logger.error(f"Error processing insight {i}: {e}")
                    continue
        
        logger.info(f"Successfully processed {len(processed_insights)} insights for display")
        
        # Build comprehensive dashboard data
        dashboard_data = {
            "stats": stats or {"total_messages": 0},
            "insights": {
                "data": processed_insights,
                "total_count": len(processed_insights),
                "source": insights_raw.get("source", "unknown") if insights_raw else "unavailable",
                "last_updated": insights_raw.get("last_updated") if insights_raw else None,
                "raw_count": len(insights_raw.get("insights", [])) if insights_raw else 0
            },
            "monitoring": monitoring or {"active": False},
            "analytics": analytics or {"threat_levels": {}, "categories": {}},
            "system_status": {
                "operational": utils.is_monitoring_active() if utils else False,
                "bigquery_connected": utils.is_bigquery_available() if utils else False,
                "gemini_available": utils.is_gemini_available() if utils else False,
                "telegram_connected": utils.is_telegram_connected() if utils else False,
                "threat_level": calculate_overall_threat_level(stats),
                "data_quality": assess_data_quality(stats, insights_raw),
                "last_updated": datetime.now(timezone.utc).isoformat()
            },
            "meta": {
                "platform": "CIPHER Cybersecurity Intelligence Platform",
                "version": "1.0.0",
                "data_sources": get_active_data_sources(utils),
                "refresh_interval": 10,  # Faster refresh
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "debug_info": {
                    "raw_insights_count": len(insights_raw.get("insights", [])) if insights_raw else 0,
                    "processed_insights_count": len(processed_insights),
                    "stats_source": stats.get("data_source", "unknown") if stats else "unknown"
                }
            }
        }
        
        # Cache successful response briefly
        set_cache(cache_key, dashboard_data, 3)  # 3 seconds only
        
        logger.info(f"Dashboard data assembled: {len(processed_insights)} insights displayed, {stats.get('total_messages', 0)} total messages")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error assembling dashboard data: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return JSONResponse(
            status_code=503,
            content={
                "error": "Data assembly failed",
                "message": f"Unable to assemble dashboard data: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "retry_after": 10
            }
        )

def process_insight_for_display(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Process individual insight for display - FIXED VERSION"""
    try:
        if not insight or not isinstance(insight, dict):
            return None
        
        # Extract basic info with safe defaults
        message_id = insight.get("message_id", "unknown")
        chat_username = insight.get("chat_username", "@Unknown")
        message_text = insight.get("message_text", "")
        threat_level = insight.get("threat_level", "low")
        category = insight.get("category", "other")
        urgency_score = float(insight.get("urgency_score", 0.0))
        
        # Skip insights with no meaningful content
        if not message_text or len(message_text.strip()) < 10:
            return None
        
        # Format dates
        formatted_date = format_message_date(insight.get("message_date"))
        time_ago = calculate_time_ago(insight.get("message_date"))
        
        # Process analysis text
        gemini_analysis = insight.get("gemini_analysis", "")
        if not gemini_analysis or gemini_analysis == "No analysis available":
            # Generate basic analysis from content
            gemini_analysis = f"Threat intelligence from {chat_username}: {category} categorized as {threat_level} priority."
        
        # Truncate analysis for display
        truncated_analysis = truncate_analysis(gemini_analysis, 200)
        has_more_analysis = len(gemini_analysis) > 200
        
        # Process intelligence arrays safely
        cve_references = ensure_array(insight.get("cve_references", []))
        iocs_detected = ensure_array(insight.get("iocs_detected", []))
        malware_families = ensure_array(insight.get("malware_families", []))
        threat_actors = ensure_array(insight.get("threat_actors", []))
        affected_systems = ensure_array(insight.get("affected_systems", []))
        key_topics = ensure_array(insight.get("key_topics", []))
        
        # Create intelligence summary
        intelligence_summary = {
            "has_cves": len(cve_references) > 0,
            "cve_count": len(cve_references),
            "has_iocs": len(iocs_detected) > 0,
            "ioc_count": len(iocs_detected),
            "has_malware": len(malware_families) > 0,
            "malware_count": len(malware_families),
            "has_actors": len(threat_actors) > 0,
            "actor_count": len(threat_actors),
            "has_intelligence": any([len(cve_references) > 0, len(iocs_detected) > 0, len(malware_families) > 0, len(threat_actors) > 0]),
            "intelligence_score": calculate_intelligence_score({
                "cve_references": cve_references,
                "iocs_detected": iocs_detected,
                "malware_families": malware_families,
                "threat_actors": threat_actors,
                "affected_systems": affected_systems
            })
        }
        
        # Build enhanced insight
        processed_insight = {
            "message_id": message_id,
            "chat_username": chat_username,
            "message_text": message_text[:1000],  # Limit text length
            "message_date": insight.get("message_date"),
            "processed_date": insight.get("processed_date"),
            
            # Display formatting
            "formatted_date": formatted_date,
            "time_ago": time_ago,
            "urgency_percentage": int(urgency_score * 100),
            "threat_badge_class": get_threat_css_class(threat_level),
            "channel_icon": get_channel_icon(chat_username),
            
            # Analysis and content
            "gemini_analysis": gemini_analysis,
            "truncated_analysis": truncated_analysis,
            "has_more_analysis": has_more_analysis,
            "sentiment": insight.get("sentiment", "neutral"),
            "threat_level": threat_level,
            "category": category,
            "threat_type": insight.get("threat_type", "unknown"),
            "urgency_score": urgency_score,
            
            # Intelligence data
            "key_topics": key_topics,
            "cve_references": cve_references,
            "iocs_detected": iocs_detected,
            "malware_families": malware_families,
            "threat_actors": threat_actors,
            "affected_systems": affected_systems,
            "intelligence_summary": intelligence_summary
        }
        
        return processed_insight
        
    except Exception as e:
        logger.error(f"Error processing insight for display: {e}")
        return None

def ensure_array(value) -> List[str]:
    """Ensure value is a list of strings"""
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [value] if value else []
    return []

@router.get("/api/stats")
async def get_system_stats():
    """Get real system statistics"""
    utils = get_utils()
    if not utils:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Stats unavailable",
                "message": "System is initializing",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    try:
        stats = await utils.get_comprehensive_stats()
        if not stats:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "No data available",
                    "message": "No statistics data found",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        
        # Add real-time metadata
        stats.update({
            "last_fetched": datetime.now(timezone.utc).isoformat(),
            "system_health": {
                "bigquery": utils.is_bigquery_available(),
                "monitoring": utils.is_monitoring_active(),
                "telegram": utils.is_telegram_connected()
            }
        })
        
        return stats
        
    except Exception as e:
        logger.error(f"Stats retrieval error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Stats retrieval failed",
                "details": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

@router.get("/api/insights")
async def get_threat_insights(
    limit: int = Query(100, ge=1, le=200, description="Number of insights to return"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    hours_back: int = Query(48, ge=1, le=168, description="Hours back to look")
):
    """Get real threat insights with filtering"""
    utils = get_utils()
    if not utils:
        return JSONResponse(
            status_code=503,
            content={
                "insights": [],
                "total": 0,
                "error": "Insights service unavailable",
                "message": "System is initializing"
            }
        )
    
    try:
        # Get raw insights from BigQuery
        insights_data = await utils.get_threat_insights()
        
        if not insights_data or "insights" not in insights_data:
            return {
                "insights": [],
                "total": 0,
                "message": "No threat intelligence data available yet",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        insights = insights_data["insights"]
        original_count = len(insights)
        
        # Apply filters
        if threat_level:
            insights = [i for i in insights if i.get("threat_level", "").lower() == threat_level.lower()]
        
        if category:
            insights = [i for i in insights if i.get("category", "").lower() == category.lower()]
        
        # Filter by time
        cutoff_time = datetime.now(timezone.utc).timestamp() - (hours_back * 3600)
        insights = [i for i in insights if is_recent_insight(i, cutoff_time)]
        
        # Limit results
        insights = insights[:limit]
        
        # Process insights for display
        enhanced_insights = []
        for insight in insights:
            processed = process_insight_for_display(insight)
            if processed:
                enhanced_insights.append(processed)
        
        return {
            "insights": enhanced_insights,
            "total": len(enhanced_insights),
            "total_before_filters": original_count,
            "filters_applied": {
                "threat_level": threat_level,
                "category": category,
                "hours_back": hours_back,
                "limit": limit
            },
            "source": insights_data.get("source", "bigquery"),
            "last_updated": insights_data.get("last_updated"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Insights retrieval error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "insights": [],
                "total": 0,
                "error": "Insights retrieval failed",
                "details": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

@router.get("/api/analytics")
async def get_threat_analytics():
    """Get real threat analytics data"""
    utils = get_utils()
    if not utils:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Analytics unavailable",
                "message": "System is initializing",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    try:
        analytics = await utils.get_threat_analytics()
        
        if not analytics:
            return {
                "message": "No analytics data available yet",
                "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Add computed metrics
        analytics.update({
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return analytics
        
    except Exception as e:
        logger.error(f"Analytics retrieval error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Analytics retrieval failed",
                "details": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

@router.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get monitoring system status"""
    utils = get_utils()
    if not utils:
        return {
            "active": False,
            "message": "Monitoring system initializing",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    try:
        status = await utils.get_monitoring_status()
        
        if status:
            status.update({
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        
        return status or {
            "active": False,
            "message": "Monitoring status unavailable",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return {
            "active": False,
            "error": "Status retrieval failed",
            "details": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@router.post("/api/cache/clear")
async def clear_dashboard_cache():
    """Clear dashboard cache"""
    try:
        clear_cache()
        return {
            "message": "Cache cleared successfully",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Cache clear error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to clear cache", "details": str(e)}
        )

# === UTILITY FUNCTIONS ===

def format_message_date(date_str: str) -> str:
    """Format message date for display"""
    if not date_str:
        return "Unknown"
    try:
        if isinstance(date_str, str):
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        else:
            dt = date_str
        return dt.strftime("%m/%d %H:%M")
    except Exception:
        return str(date_str)[:16] if date_str else "Unknown"

def calculate_time_ago(date_str: str) -> str:
    """Calculate human-readable time ago"""
    if not date_str:
        return "Unknown"
    try:
        if isinstance(date_str, str):
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        else:
            dt = date_str
        
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        diff = now - dt
        
        if diff.days > 0:
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

def get_threat_css_class(threat_level: str) -> str:
    """Get CSS class for threat level"""
    level_map = {
        "critical": "threat-critical",
        "high": "threat-high",
        "medium": "threat-medium",
        "low": "threat-low",
        "info": "threat-info"
    }
    return level_map.get(str(threat_level).lower(), "threat-unknown")

def get_channel_icon(channel_username: str) -> str:
    """Get icon for channel"""
    channel_icons = {
        "@DarkfeedNews": "🔴",
        "@breachdetector": "🟠", 
        "@secharvester": "🔵"
    }
    return channel_icons.get(channel_username, "📡")

def truncate_analysis(text: str, max_length: int = 200) -> str:
    """Truncate analysis text intelligently"""
    if not text or len(text) <= max_length:
        return text or ""
    
    truncated = text[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.8:
        return truncated[:last_space] + "..."
    return truncated + "..."

def calculate_intelligence_score(insight: Dict[str, Any]) -> float:
    """Calculate intelligence richness score"""
    score = 0.0
    
    if insight.get("cve_references"):
        score += 0.3
    if insight.get("iocs_detected"):
        score += 0.25
    if insight.get("malware_families"):
        score += 0.2
    if insight.get("threat_actors"):
        score += 0.15
    if insight.get("affected_systems"):
        score += 0.1
    
    return min(score, 1.0)

def calculate_overall_threat_level(stats: Dict[str, Any]) -> str:
    """Calculate overall system threat level"""
    if not stats:
        return "UNKNOWN"
    
    avg_urgency = stats.get("avg_urgency", 0.0)
    critical_count = stats.get("critical_threats", 0)
    high_count = stats.get("high_threats", 0)
    total_messages = stats.get("total_messages", 0)
    
    if total_messages > 0:
        threat_ratio = (critical_count + high_count) / total_messages
        
        if avg_urgency >= 0.8 or threat_ratio >= 0.3:
            return "CRITICAL"
        elif avg_urgency >= 0.6 or threat_ratio >= 0.2:
            return "HIGH"
        elif avg_urgency >= 0.4 or threat_ratio >= 0.1:
            return "MEDIUM"
        else:
            return "LOW"
    
    return "LOW"

def assess_data_quality(stats: Dict[str, Any], insights_data: Dict[str, Any]) -> Dict[str, Any]:
    """Assess overall data quality"""
    quality = {
        "score": 0.0,
        "factors": {
            "data_availability": False,
            "recent_data": False,
            "intelligence_richness": False,
            "processing_active": False
        }
    }
    
    if stats and stats.get("total_messages", 0) > 0:
        quality["factors"]["data_availability"] = True
        quality["score"] += 0.3
    
    if stats and stats.get("processed_today", 0) > 0:
        quality["factors"]["recent_data"] = True
        quality["score"] += 0.3
    
    if insights_data and len(insights_data.get("insights", [])) > 0:
        quality["factors"]["intelligence_richness"] = True
        quality["score"] += 0.2
    
    if stats and stats.get("monitoring_active", False):
        quality["factors"]["processing_active"] = True
        quality["score"] += 0.2
    
    return quality

def get_active_data_sources(utils) -> List[str]:
    """Get list of active data sources"""
    if not utils:
        return []
    
    sources = []
    
    if utils.is_bigquery_available():
        sources.append("BigQuery")
    if utils.is_telegram_connected():
        sources.append("Telegram")
    if utils.is_gemini_available():
        sources.append("Gemini AI")
    if utils.is_monitoring_active():
        sources.append("Live Monitoring")
    
    return sources

def is_recent_insight(insight: Dict[str, Any], cutoff_timestamp: float) -> bool:
    """Check if insight is recent"""
    message_date = insight.get("message_date")
    if not message_date:
        return False
    
    try:
        if isinstance(message_date, str):
            dt = datetime.fromisoformat(message_date.replace("Z", "+00:00"))
        else:
            dt = message_date
        
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        return dt.timestamp() >= cutoff_timestamp
    except Exception:
        return False
