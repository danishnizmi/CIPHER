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

# Optimized cache settings for real data
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 10  # Reduced for real-time data updates

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
                .retry-btn {{
                    background: #6366f1;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    margin: 20px 10px;
                    text-decoration: none;
                    display: inline-block;
                }}
            </style>
        </head>
        <body>
            <div class="loading-container">
                <h1>🛡️ CIPHER Dashboard</h1>
                <div class="spinner"></div>
                <p>Loading cybersecurity intelligence platform...</p>
                <a class="retry-btn" href="/dashboard">🔄 Retry</a>
                <a class="retry-btn" href="/health">🏥 System Health</a>
                <script>
                    setTimeout(() => location.reload(), 10000);
                </script>
            </div>
        </body>
        </html>
        """, status_code=200)

@router.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get comprehensive dashboard data - REAL DATA ONLY"""
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
                "retry_after": 15
            }
        )
    
    try:
        # Check system readiness
        system_ready = (
            utils.is_bigquery_available() and 
            utils._clients_initialized
        )
        
        if not system_ready:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "System not ready",
                    "message": "CIPHER components are still initializing",
                    "subsystems": {
                        "bigquery": utils.is_bigquery_available(),
                        "clients": utils._clients_initialized,
                        "monitoring": utils.is_monitoring_active()
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "retry_after": 10
                }
            )
        
        logger.info("Fetching real dashboard data from all subsystems")
        
        # Fetch all real data
        stats_task = utils.get_comprehensive_stats()
        insights_task = utils.get_threat_insights()
        monitoring_task = utils.get_monitoring_status()
        analytics_task = utils.get_threat_analytics()
        
        # Wait for all data
        stats = await stats_task
        insights_raw = await insights_task
        monitoring = await monitoring_task
        analytics = await analytics_task
        
        # Process insights for frontend - INCREASED LIMIT
        processed_insights = []
        if insights_raw and "insights" in insights_raw:
            for insight in insights_raw["insights"][:75]:  # Increased from 25 to 75
                processed_insight = {
                    **insight,
                    "formatted_date": format_message_date(insight.get("message_date")),
                    "urgency_percentage": int(insight.get("urgency_score", 0) * 100),
                    "threat_badge_class": get_threat_css_class(insight.get("threat_level", "low")),
                    "truncated_analysis": truncate_analysis(insight.get("gemini_analysis", "")),
                    "has_more_analysis": len(insight.get("gemini_analysis", "")) > 200,
                    "intelligence_summary": create_intelligence_summary(insight),
                    "channel_icon": get_channel_icon(insight.get("chat_username", "")),
                    "time_ago": calculate_time_ago(insight.get("message_date"))
                }
                processed_insights.append(processed_insight)
        
        # Build comprehensive dashboard data
        dashboard_data = {
            "stats": stats or {},
            "insights": {
                "data": processed_insights,
                "total_count": len(processed_insights),
                "source": insights_raw.get("source", "unknown") if insights_raw else "unavailable",
                "last_updated": insights_raw.get("last_updated") if insights_raw else None
            },
            "monitoring": monitoring or {},
            "analytics": analytics or {},
            "system_status": {
                "operational": utils.is_monitoring_active(),
                "bigquery_connected": utils.is_bigquery_available(),
                "gemini_available": utils.is_gemini_available(),
                "telegram_connected": utils.is_telegram_connected(),
                "threat_level": calculate_overall_threat_level(stats),
                "data_quality": assess_data_quality(stats, insights_raw),
                "last_updated": datetime.now(timezone.utc).isoformat()
            },
            "meta": {
                "platform": "CIPHER Cybersecurity Intelligence Platform",
                "version": "1.0.0",
                "data_sources": get_active_data_sources(utils),
                "refresh_interval": 15,  # Faster refresh for real data
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        
        # Cache successful response with shorter duration for real-time updates
        set_cache(cache_key, dashboard_data, 5)  # 5 seconds only
        
        logger.info(f"Dashboard data assembled: {len(processed_insights)} insights, {stats.get('total_messages', 0)} total messages")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error assembling dashboard data: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Data retrieval failed",
                "message": f"Unable to fetch dashboard data: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "retry_after": 15
            }
        )

@router.get("/api/stats")
async def get_system_stats():
    """Get real system statistics only"""
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
                    "message": "No statistics data found in the system",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        
        # Add real-time metadata
        stats.update({
            "last_fetched": datetime.now(timezone.utc).isoformat(),
            "data_age_seconds": calculate_data_freshness(stats),
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
    limit: int = Query(75, ge=1, le=200, description="Number of insights to return"),  # Increased default
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    hours_back: int = Query(48, ge=1, le=168, description="Hours back to look for insights")  # Increased default
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
                "filters_applied": {
                    "threat_level": threat_level,
                    "category": category,
                    "hours_back": hours_back
                },
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
        
        # Enhance each insight with display data
        enhanced_insights = []
        for insight in insights:
            enhanced = enhance_insight_for_display(insight)
            enhanced_insights.append(enhanced)
        
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
            "computed_metrics": compute_threat_metrics(analytics),
            "data_freshness": assess_analytics_freshness(analytics),
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
    """Get real monitoring system status"""
    utils = get_utils()
    if not utils:
        return {
            "active": False,
            "message": "Monitoring system initializing",
            "subsystems": {"bigquery": False, "gemini": False, "telegram": False},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    try:
        status = await utils.get_monitoring_status()
        
        # Enhance with real-time data
        if status:
            status.update({
                "real_time_metrics": get_real_time_metrics(utils),
                "system_health_score": calculate_system_health_score(status),
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

@router.get("/api/insights/{insight_id}")
async def get_insight_detail(insight_id: str):
    """Get detailed view of a specific insight"""
    utils = get_utils()
    if not utils:
        raise HTTPException(status_code=503, detail="Insight service unavailable")
    
    try:
        insights_data = await utils.get_threat_insights()
        
        if not insights_data or "insights" not in insights_data:
            raise HTTPException(status_code=404, detail="Insight not found")
        
        # Find the specific insight
        insight = None
        for item in insights_data["insights"]:
            if item.get("message_id") == insight_id:
                insight = item
                break
        
        if not insight:
            raise HTTPException(status_code=404, detail="Insight not found")
        
        # Return enhanced detailed view
        return {
            "insight": enhance_insight_for_detail(insight),
            "related_insights": find_related_insights(insight, insights_data["insights"]),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Insight detail error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve insight details")

@router.get("/api/export/threats")
async def export_threats(
    format: str = Query("json", regex="^(json|csv)$"),
    limit: int = Query(1000, ge=1, le=5000),
    threat_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    hours_back: int = Query(48, ge=1, le=720)  # Increased default
):
    """Export real threat intelligence data"""
    utils = get_utils()
    if not utils:
        return JSONResponse(
            status_code=503,
            content={"error": "Export service unavailable", "message": "System initializing"}
        )
    
    try:
        # Get insights with filters
        insights_response = await get_threat_insights(
            limit=limit,
            threat_level=threat_level,
            category=category,
            hours_back=hours_back
        )
        
        if isinstance(insights_response, JSONResponse):
            return insights_response
        
        insights = insights_response.get("insights", [])
        
        if not insights:
            return {
                "message": "No threat data available for export with current filters",
                "filters": {
                    "threat_level": threat_level,
                    "category": category,
                    "hours_back": hours_back,
                    "limit": limit
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        if format == "json":
            return {
                "export_metadata": {
                    "generated": datetime.now(timezone.utc).isoformat(),
                    "platform": "CIPHER Cybersecurity Intelligence Platform",
                    "total_records": len(insights),
                    "filters": {
                        "threat_level": threat_level,
                        "category": category,
                        "hours_back": hours_back
                    },
                    "data_source": insights_response.get("source", "bigquery")
                },
                "threat_intelligence": insights
            }
        
        elif format == "csv":
            return generate_csv_export(insights, {
                "threat_level": threat_level,
                "category": category,
                "hours_back": hours_back
            })
        
    except Exception as e:
        logger.error(f"Export error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Export failed",
                "details": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

# Clear cache endpoint for debugging
@router.post("/api/cache/clear")
async def clear_dashboard_cache():
    """Clear dashboard cache (for debugging)"""
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

# === UTILITY FUNCTIONS FOR REAL DATA PROCESSING ===

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

def create_intelligence_summary(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Create intelligence summary from insight data"""
    return {
        "has_cves": len(insight.get("cve_references", [])) > 0,
        "cve_count": len(insight.get("cve_references", [])),
        "has_iocs": len(insight.get("iocs_detected", [])) > 0,
        "ioc_count": len(insight.get("iocs_detected", [])),
        "has_malware": len(insight.get("malware_families", [])) > 0,
        "malware_count": len(insight.get("malware_families", [])),
        "has_actors": len(insight.get("threat_actors", [])) > 0,
        "actor_count": len(insight.get("threat_actors", [])),
        "intelligence_score": calculate_intelligence_score(insight),
        "has_intelligence": any([
            len(insight.get("cve_references", [])) > 0,
            len(insight.get("iocs_detected", [])) > 0,
            len(insight.get("malware_families", [])) > 0,
            len(insight.get("threat_actors", [])) > 0
        ])
    }

def calculate_intelligence_score(insight: Dict[str, Any]) -> float:
    """Calculate intelligence richness score"""
    score = 0.0
    
    # Weight different types of intelligence data
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
    
    # Calculate threat ratio
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

def calculate_data_freshness(stats: Dict[str, Any]) -> int:
    """Calculate data freshness in seconds"""
    last_updated = stats.get("last_updated")
    if not last_updated:
        return 3600  # Default to 1 hour
    
    try:
        last_update_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return int((now - last_update_dt).total_seconds())
    except Exception:
        return 3600

def is_recent_insight(insight: Dict[str, Any], cutoff_timestamp: float) -> bool:
    """Check if insight is recent based on cutoff"""
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

def enhance_insight_for_display(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance insight with display-specific data"""
    enhanced = insight.copy()
    
    enhanced.update({
        "formatted_date": format_message_date(insight.get("message_date")),
        "time_ago": calculate_time_ago(insight.get("message_date")),
        "urgency_percentage": int(insight.get("urgency_score", 0) * 100),
        "threat_badge_class": get_threat_css_class(insight.get("threat_level", "low")),
        "channel_icon": get_channel_icon(insight.get("chat_username", "")),
        "truncated_analysis": truncate_analysis(insight.get("gemini_analysis", "")),
        "has_more_analysis": len(insight.get("gemini_analysis", "")) > 200,
        "intelligence_summary": create_intelligence_summary(insight)
    })
    
    return enhanced

def enhance_insight_for_detail(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance insight for detailed view"""
    enhanced = enhance_insight_for_display(insight)
    
    # Add additional detail-specific enhancements
    enhanced.update({
        "full_analysis": insight.get("gemini_analysis", ""),
        "complete_iocs": insight.get("iocs_detected", []),
        "all_cves": insight.get("cve_references", []),
        "threat_context": build_threat_context(insight),
        "risk_assessment": assess_insight_risk(insight)
    })
    
    return enhanced

def find_related_insights(insight: Dict[str, Any], all_insights: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find insights related to the given insight"""
    related = []
    
    insight_actors = set(insight.get("threat_actors", []))
    insight_malware = set(insight.get("malware_families", []))
    insight_category = insight.get("category", "")
    
    for other in all_insights[:50]:  # Limit search
        if other.get("message_id") == insight.get("message_id"):
            continue
        
        # Find similar threats
        other_actors = set(other.get("threat_actors", []))
        other_malware = set(other.get("malware_families", []))
        
        if (insight_actors & other_actors or
            insight_malware & other_malware or
            other.get("category") == insight_category):
            related.append(enhance_insight_for_display(other))
            
        if len(related) >= 5:  # Limit related insights
            break
    
    return related

def build_threat_context(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Build threat context information"""
    return {
        "attack_lifecycle": insight.get("attack_stage", "unknown"),
        "kill_chain": insight.get("kill_chain_phase", "unknown"),
        "confidence": insight.get("confidence_score", 0.0),
        "geographical_scope": insight.get("geographical_targets", []),
        "industry_impact": insight.get("industry_targets", [])
    }

def assess_insight_risk(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Assess risk level of insight"""
    urgency = insight.get("urgency_score", 0.0)
    threat_level = insight.get("threat_level", "low")
    has_iocs = len(insight.get("iocs_detected", [])) > 0
    has_exploits = "exploit" in insight.get("gemini_analysis", "").lower()
    
    risk_score = urgency
    if threat_level in ["critical", "high"]:
        risk_score += 0.2
    if has_iocs:
        risk_score += 0.1
    if has_exploits:
        risk_score += 0.1
    
    risk_score = min(risk_score, 1.0)
    
    return {
        "score": risk_score,
        "level": "high" if risk_score >= 0.7 else "medium" if risk_score >= 0.4 else "low",
        "factors": {
            "has_iocs": has_iocs,
            "has_exploits": has_exploits,
            "threat_level": threat_level,
            "urgency": urgency
        }
    }

def get_real_time_metrics(utils) -> Dict[str, Any]:
    """Get real-time system metrics"""
    return {
        "bigquery_status": utils.is_bigquery_available(),
        "monitoring_active": utils.is_monitoring_active(),
        "telegram_connected": utils.is_telegram_connected(),
        "gemini_available": utils.is_gemini_available(),
        "clients_initialized": getattr(utils, '_clients_initialized', False)
    }

def calculate_system_health_score(status: Dict[str, Any]) -> float:
    """Calculate overall system health score"""
    score = 0.0
    
    if status.get("active", False):
        score += 0.4
    
    subsystems = status.get("subsystems", {})
    if subsystems.get("bigquery", False):
        score += 0.3
    if subsystems.get("telegram", False):
        score += 0.2
    if subsystems.get("gemini", False):
        score += 0.1
    
    return score

def compute_threat_metrics(analytics: Dict[str, Any]) -> Dict[str, Any]:
    """Compute additional threat metrics"""
    threat_levels = analytics.get("threat_levels", {})
    total_threats = sum(threat_levels.values())
    
    if total_threats == 0:
        return {"threat_density": 0.0, "severity_ratio": 0.0, "risk_index": 0.0}
    
    critical_high = threat_levels.get("critical", 0) + threat_levels.get("high", 0)
    severity_ratio = critical_high / total_threats
    
    # Calculate risk index
    risk_index = (
        threat_levels.get("critical", 0) * 1.0 +
        threat_levels.get("high", 0) * 0.7 +
        threat_levels.get("medium", 0) * 0.4 +
        threat_levels.get("low", 0) * 0.1
    ) / max(total_threats, 1)
    
    return {
        "threat_density": total_threats / 30,  # threats per day (30-day window)
        "severity_ratio": severity_ratio,
        "risk_index": risk_index,
        "total_threats": total_threats
    }

def assess_analytics_freshness(analytics: Dict[str, Any]) -> Dict[str, Any]:
    """Assess analytics data freshness"""
    last_updated = analytics.get("last_updated")
    
    if not last_updated:
        return {"status": "unknown", "age_minutes": 0}
    
    try:
        last_update_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_minutes = (now - last_update_dt).total_seconds() / 60
        
        if age_minutes < 5:
            status = "fresh"
        elif age_minutes < 30:
            status = "recent"
        elif age_minutes < 120:
            status = "stale"
        else:
            status = "old"
        
        return {"status": status, "age_minutes": int(age_minutes)}
    except Exception:
        return {"status": "unknown", "age_minutes": 0}

def generate_csv_export(insights: List[Dict[str, Any]], filters: Dict[str, Any]) -> StreamingResponse:
    """Generate CSV export of insights"""
    output = io.StringIO()
    
    if not insights:
        # Empty CSV with headers
        writer = csv.writer(output)
        writer.writerow([
            'message_id', 'source', 'timestamp', 'threat_level', 'category', 
            'threat_type', 'urgency_score', 'sentiment', 'analysis', 'cves', 'iocs'
        ])
    else:
        fieldnames = [
            'message_id', 'source', 'timestamp', 'threat_level', 'category', 
            'threat_type', 'urgency_score', 'sentiment', 'analysis', 'cves', 'iocs',
            'malware_families', 'threat_actors', 'affected_systems'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for insight in insights:
            writer.writerow({
                'message_id': insight.get('message_id', ''),
                'source': insight.get('chat_username', ''),
                'timestamp': insight.get('message_date', ''),
                'threat_level': insight.get('threat_level', ''),
                'category': insight.get('category', ''),
                'threat_type': insight.get('threat_type', ''),
                'urgency_score': insight.get('urgency_score', ''),
                'sentiment': insight.get('sentiment', ''),
                'analysis': insight.get('gemini_analysis', ''),
                'cves': '; '.join(insight.get('cve_references', [])),
                'iocs': '; '.join(insight.get('iocs_detected', [])),
                'malware_families': '; '.join(insight.get('malware_families', [])),
                'threat_actors': '; '.join(insight.get('threat_actors', [])),
                'affected_systems': '; '.join(insight.get('affected_systems', []))
            })
    
    output.seek(0)
    filename = f"cipher_threat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
