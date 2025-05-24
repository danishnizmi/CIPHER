from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Cache for performance
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 60

def is_cache_valid(key: str) -> bool:
    """Check if cache entry is still valid"""
    return key in _cache and key in _cache_ttl and datetime.now() < _cache_ttl[key]

def set_cache(key: str, value: Any, duration: int = CACHE_DURATION):
    """Set cache entry with TTL"""
    _cache[key] = value
    _cache_ttl[key] = datetime.now() + timedelta(seconds=duration)

def get_cache(key: str) -> Any:
    """Get cache entry if valid"""
    if is_cache_valid(key):
        return _cache[key]
    return None

def get_safe_utils():
    """Safely import utils with fallback"""
    try:
        from utils import (
            get_recent_insights, 
            get_message_stats,
            MONITORED_CHANNELS,
            CHANNEL_METADATA,
            telegram_client
        )
        return {
            'get_recent_insights': get_recent_insights,
            'get_message_stats': get_message_stats,
            'MONITORED_CHANNELS': MONITORED_CHANNELS,
            'CHANNEL_METADATA': CHANNEL_METADATA,
            'telegram_client': telegram_client
        }
    except Exception as e:
        logger.warning(f"Utils not available: {e}")
        return None

@router.get("/", response_class=HTMLResponse)
async def cipher_dashboard(request: Request):
    """CIPHER main dashboard with graceful degradation"""
    try:
        # Check cache first
        cache_key = "dashboard_data"
        cached_data = get_cache(cache_key)
        
        if cached_data:
            insights, stats, monitoring_status, threat_analytics = cached_data
        else:
            # Try to get utils safely
            utils = get_safe_utils()
            
            if utils:
                # Get data from backend services
                try:
                    insights = await utils['get_recent_insights'](limit=25)
                except Exception as e:
                    logger.warning(f"Could not get insights: {e}")
                    insights = []
                
                try:
                    stats = await utils['get_message_stats']()
                except Exception as e:
                    logger.warning(f"Could not get stats: {e}")
                    stats = _get_empty_stats()
                
                # Monitoring status
                monitoring_status = {
                    "active": utils['telegram_client'] is not None and utils['telegram_client'].is_connected() if utils['telegram_client'] else False,
                    "channels": utils['MONITORED_CHANNELS'],
                    "channel_details": utils['CHANNEL_METADATA'],
                    "total_channels": len(utils['MONITORED_CHANNELS']),
                    "last_check": datetime.now().isoformat()
                }
                
                # Calculate threat analytics
                threat_analytics = calculate_threat_analytics(insights, stats)
            else:
                # Fallback when utils not available
                insights = []
                stats = _get_empty_stats()
                monitoring_status = {
                    "active": False,
                    "channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"],
                    "channel_details": {},
                    "total_channels": 3,
                    "last_check": datetime.now().isoformat(),
                    "status": "initializing"
                }
                threat_analytics = _get_empty_threat_analytics()
            
            # Cache the data
            set_cache(cache_key, (insights, stats, monitoring_status, threat_analytics))
        
        # Calculate dashboard metrics
        dashboard_metrics = {
            "high_priority_threats": len([i for i in insights if i.get("threat_level") in ["critical", "high"]]),
            "active_campaigns": len(set(i.get("threat_type", "") for i in insights if i.get("threat_type") and i.get("threat_level") in ["critical", "high"])),
            "recent_cves": len([i for i in insights if i.get("cve_references") and len(i.get("cve_references", [])) > 0]),
            "iocs_detected": sum(len(i.get("iocs_detected", [])) for i in insights),
            "malware_families": len(set(family for i in insights for family in i.get("malware_families", []))),
        }
        
        # Determine system status
        system_status = "operational" if monitoring_status.get("active") else "initializing"
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
                "monitoring": monitoring_status,
                "threat_analytics": threat_analytics,
                "dashboard_metrics": dashboard_metrics,
                "system_status": system_status,
                "current_time": datetime.now().isoformat(),
                "page_title": "CIPHER - Cybersecurity Intelligence Dashboard",
                "PROJECT_ID": "primal-chariot-382610"
            }
        )
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "insights": [],
                "stats": _get_empty_stats(),
                "monitoring": {"active": False, "channels": [], "total_channels": 0, "channel_details": {}, "status": "error"},
                "threat_analytics": _get_empty_threat_analytics(),
                "dashboard_metrics": _get_empty_dashboard_metrics(),
                "system_status": "error",
                "error": f"Dashboard temporarily unavailable: {str(e)}",
                "page_title": "CIPHER - System Error",
                "PROJECT_ID": "primal-chariot-382610"
            }
        )

def calculate_threat_analytics(insights: List[Dict], stats: Dict) -> Dict[str, Any]:
    """Calculate threat analytics with error handling"""
    try:
        analytics = {
            "threat_levels": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "categories": {
                "threat_intel": 0,
                "data_breach": 0,
                "vulnerability": 0,
                "malware": 0,
                "ransomware": 0,
                "apt": 0,
                "phishing": 0,
                "other": 0
            },
            "channel_activity": {},
            "hourly_activity": {str(i): 0 for i in range(24)},
            "top_threats": [],
            "active_campaigns": [],
            "affected_systems": {},
            "urgency_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "overall_threat_score": 0.0,
            "max_threat_score": 0.0
        }
        
        if not insights:
            return analytics
        
        # Process insights
        threat_types = {}
        urgency_scores = []
        
        for insight in insights:
            try:
                # Threat level distribution
                threat_level = insight.get("threat_level", "low")
                if threat_level in analytics["threat_levels"]:
                    analytics["threat_levels"][threat_level] += 1
                
                # Category distribution
                category = insight.get("category", "other")
                if category in analytics["categories"]:
                    analytics["categories"][category] += 1
                
                # Urgency distribution
                urgency = insight.get("urgency_score", 0.0)
                urgency_scores.append(urgency)
                if urgency >= 0.8:
                    analytics["urgency_distribution"]["critical"] += 1
                elif urgency >= 0.6:
                    analytics["urgency_distribution"]["high"] += 1
                elif urgency >= 0.4:
                    analytics["urgency_distribution"]["medium"] += 1
                else:
                    analytics["urgency_distribution"]["low"] += 1
                
                # Track threat types
                threat_type = insight.get("threat_type", "unknown")
                if threat_type != "unknown":
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
            except Exception as e:
                logger.warning(f"Error processing insight: {e}")
                continue
        
        # Top threats
        analytics["top_threats"] = [
            {"type": threat_type, "count": count}
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Calculate scores
        if urgency_scores:
            analytics["overall_threat_score"] = sum(urgency_scores) / len(urgency_scores)
            analytics["max_threat_score"] = max(urgency_scores)
        
        # Summary
        analytics["summary"] = {
            "total_threats": len(insights),
            "high_priority": analytics["threat_levels"]["critical"] + analytics["threat_levels"]["high"],
            "avg_urgency": analytics["overall_threat_score"],
            "threat_categories": len([cat for cat, count in analytics["categories"].items() if count > 0])
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Error calculating threat analytics: {e}")
        return _get_empty_threat_analytics()

def _get_empty_stats() -> Dict[str, Any]:
    """Return empty stats structure"""
    return {
        "total_messages": 0,
        "processed_today": 0,
        "avg_urgency": 0.0,
        "unique_channels": 3,
        "unique_users": 0,
        "high_threats": 0,
        "critical_threats": 0,
        "data_breaches": 0,
        "malware_alerts": 0,
        "vulnerabilities": 0,
        "cve_mentions": 0,
        "monitoring_active": False
    }

def _get_empty_threat_analytics() -> Dict[str, Any]:
    """Return empty threat analytics structure"""
    return {
        "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "categories": {"threat_intel": 0, "data_breach": 0, "vulnerability": 0, "malware": 0, "ransomware": 0, "apt": 0, "phishing": 0, "other": 0},
        "channel_activity": {},
        "hourly_activity": {str(i): 0 for i in range(24)},
        "top_threats": [],
        "active_campaigns": [],
        "affected_systems": {},
        "urgency_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "overall_threat_score": 0.0,
        "max_threat_score": 0.0,
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0, "threat_categories": 0}
    }

def _get_empty_dashboard_metrics() -> Dict[str, Any]:
    """Return empty dashboard metrics"""
    return {
        "high_priority_threats": 0,
        "active_campaigns": 0,
        "recent_cves": 0,
        "iocs_detected": 0,
        "malware_families": 0
    }

@router.get("/api/insights")
async def get_cybersecurity_insights_api(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """API endpoint for cybersecurity insights with graceful degradation"""
    try:
        utils = get_safe_utils()
        
        if utils:
            insights = await utils['get_recent_insights'](limit=limit, offset=offset)
        else:
            insights = []
        
        return {
            "insights": insights,
            "count": len(insights),
            "status": "operational" if utils else "initializing",
            "metadata": {
                "high_priority": len([i for i in insights if i.get("threat_level") in ["critical", "high"]]),
                "avg_urgency": sum(i.get("urgency_score", 0) for i in insights) / len(insights) if insights else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Insights API error: {e}")
        return {
            "insights": [],
            "count": 0,
            "status": "error",
            "error": str(e)
        }

@router.get("/api/stats")
async def get_cybersecurity_stats_api():
    """API endpoint for cybersecurity statistics"""
    try:
        utils = get_safe_utils()
        
        if utils:
            stats = await utils['get_message_stats']()
        else:
            stats = _get_empty_stats()
        
        stats["last_updated"] = datetime.now().isoformat()
        stats["system_status"] = "operational" if utils else "initializing"
        
        return stats
        
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return {
            **_get_empty_stats(),
            "system_status": "error",
            "error": str(e)
        }

@router.get("/api/health")
async def frontend_health_check():
    """Frontend health check"""
    try:
        utils = get_safe_utils()
        backend_available = utils is not None
        
        if backend_available:
            try:
                stats = await utils['get_message_stats']()
                database_connected = True
            except:
                database_connected = False
        else:
            database_connected = False
        
        return {
            "status": "healthy",
            "component": "CIPHER Frontend",
            "timestamp": datetime.now().isoformat(),
            "backend_available": backend_available,
            "database_connected": database_connected,
            "system_phase": "operational" if backend_available else "initializing"
        }
    except Exception as e:
        return {
            "status": "degraded", 
            "component": "CIPHER Frontend",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Export the router
__all__ = ["router"]
