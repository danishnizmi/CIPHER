from fastapi import APIRouter, Request, HTTPException, BackgroundTasks, Query, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from utils import (
    get_recent_insights, 
    get_message_stats,
    MONITORED_CHANNELS,
    CHANNEL_METADATA,
    telegram_client
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Optional security for production
security = HTTPBearer(auto_error=False)

# Cache for performance
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 60  # 60 seconds cache

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

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Optional authentication - implement as needed for production"""
    # For now, no authentication required
    # In production, validate JWT token or API key here
    return {"user": "cipher_analyst"}

@router.get("/", response_class=HTMLResponse)
async def cipher_dashboard(request: Request):
    """CIPHER main dashboard - Cybersecurity Intelligence Platform"""
    try:
        # Check cache first
        cache_key = "dashboard_data"
        cached_data = get_cache(cache_key)
        
        if cached_data:
            logger.debug("Using cached dashboard data")
            insights, stats, monitoring_status, threat_analytics = cached_data
        else:
            # Get recent cybersecurity insights
            insights = await get_recent_insights(limit=25)
            
            # Get comprehensive statistics
            stats = await get_message_stats()
            
            # Get monitoring status with enhanced details
            monitoring_status = {
                "active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False,
                "channels": MONITORED_CHANNELS,
                "channel_details": CHANNEL_METADATA,
                "total_channels": len(MONITORED_CHANNELS),
                "last_check": datetime.now().isoformat()
            }
            
            # Calculate comprehensive threat analytics
            threat_analytics = calculate_threat_analytics(insights, stats)
            
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
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
                "monitoring": monitoring_status,
                "threat_analytics": threat_analytics,
                "dashboard_metrics": dashboard_metrics,
                "current_time": datetime.now().isoformat(),
                "page_title": "CIPHER - Cybersecurity Intelligence Dashboard"
            }
        )
        
    except Exception as e:
        logger.error(f"CIPHER dashboard error: {e}")
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "insights": [],
                "stats": _get_empty_stats(),
                "monitoring": {"active": False, "channels": [], "total_channels": 0, "channel_details": {}},
                "threat_analytics": _get_empty_threat_analytics(),
                "dashboard_metrics": _get_empty_dashboard_metrics(),
                "error": f"Failed to load CIPHER dashboard: {str(e)}",
                "page_title": "CIPHER - Dashboard Error"
            }
        )

def calculate_threat_analytics(insights: List[Dict], stats: Dict) -> Dict[str, Any]:
    """Calculate comprehensive cybersecurity threat analytics"""
    analytics = {
        # Threat level distribution
        "threat_levels": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        
        # Category distribution
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
        
        # Channel analysis
        "channel_activity": {},
        
        # Time-based metrics
        "hourly_activity": {str(i): 0 for i in range(24)},
        "daily_trends": {},
        
        # Advanced metrics
        "top_threats": [],
        "active_campaigns": [],
        "affected_systems": {},
        "geographic_indicators": [],
        "urgency_distribution": {
            "critical": 0,  # 0.8-1.0
            "high": 0,      # 0.6-0.8
            "medium": 0,    # 0.4-0.6
            "low": 0        # 0.0-0.4
        }
    }
    
    # Initialize channel activity
    for channel in MONITORED_CHANNELS:
        analytics["channel_activity"][channel] = {
            "count": 0,
            "avg_urgency": 0.0,
            "threat_types": set(),
            "last_activity": None
        }
    
    # Process insights
    threat_types = {}
    urgency_scores = []
    
    for insight in insights:
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
        
        # Channel activity
        channel = insight.get("chat_username", "Unknown")
        if channel in analytics["channel_activity"]:
            analytics["channel_activity"][channel]["count"] += 1
            analytics["channel_activity"][channel]["threat_types"].add(insight.get("threat_type", "unknown"))
            analytics["channel_activity"][channel]["last_activity"] = insight.get("message_date")
        
        # Hourly activity
        if insight.get("message_date"):
            try:
                dt = datetime.fromisoformat(insight["message_date"].replace("Z", "+00:00"))
                hour = str(dt.hour)
                analytics["hourly_activity"][hour] += 1
            except:
                pass
        
        # Track threat types
        threat_type = insight.get("threat_type", "unknown")
        if threat_type != "unknown":
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Affected systems
        for system in insight.get("affected_systems", []):
            analytics["affected_systems"][system] = analytics["affected_systems"].get(system, 0) + 1
    
    # Calculate channel averages
    for channel_data in analytics["channel_activity"].values():
        if channel_data["count"] > 0:
            # Convert set to list for JSON serialization
            channel_data["threat_types"] = list(channel_data["threat_types"])
        else:
            channel_data["threat_types"] = []
    
    # Top threats by frequency
    analytics["top_threats"] = [
        {"type": threat_type, "count": count, "severity": _assess_threat_severity(threat_type)}
        for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Active campaigns (group similar threat types)
    campaigns = {}
    for threat_type, count in threat_types.items():
        campaign_key = _categorize_campaign(threat_type)
        campaigns[campaign_key] = campaigns.get(campaign_key, 0) + count
    
    analytics["active_campaigns"] = [
        {"campaign": campaign, "incidents": count}
        for campaign, count in sorted(campaigns.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    
    # Calculate overall threat score
    if urgency_scores:
        analytics["overall_threat_score"] = sum(urgency_scores) / len(urgency_scores)
        analytics["max_threat_score"] = max(urgency_scores)
    else:
        analytics["overall_threat_score"] = 0.0
        analytics["max_threat_score"] = 0.0
    
    # Add statistical summary
    analytics["summary"] = {
        "total_threats": len(insights),
        "high_priority": analytics["threat_levels"]["critical"] + analytics["threat_levels"]["high"],
        "avg_urgency": analytics["overall_threat_score"],
        "channels_active": len([ch for ch in analytics["channel_activity"].values() if ch["count"] > 0]),
        "threat_categories": len([cat for cat, count in analytics["categories"].items() if count > 0])
    }
    
    return analytics

def _assess_threat_severity(threat_type: str) -> str:
    """Assess threat severity based on threat type"""
    critical_threats = ["zero-day", "apt", "ransomware", "critical"]
    high_threats = ["malware", "exploit", "breach", "backdoor"]
    medium_threats = ["vulnerability", "phishing", "trojan"]
    
    threat_lower = threat_type.lower()
    
    if any(keyword in threat_lower for keyword in critical_threats):
        return "critical"
    elif any(keyword in threat_lower for keyword in high_threats):
        return "high"
    elif any(keyword in threat_lower for keyword in medium_threats):
        return "medium"
    else:
        return "low"

def _categorize_campaign(threat_type: str) -> str:
    """Categorize threat types into campaigns"""
    threat_lower = threat_type.lower()
    
    if "ransomware" in threat_lower:
        return "Ransomware Campaign"
    elif "apt" in threat_lower or "advanced" in threat_lower:
        return "APT Activity"
    elif "phishing" in threat_lower:
        return "Phishing Campaign"
    elif "malware" in threat_lower:
        return "Malware Distribution"
    elif "vulnerability" in threat_lower or "exploit" in threat_lower:
        return "Exploitation Activity"
    elif "breach" in threat_lower or "leak" in threat_lower:
        return "Data Breach"
    else:
        return "General Threats"

def _get_empty_stats() -> Dict[str, Any]:
    """Return empty stats structure"""
    return {
        "total_messages": 0,
        "processed_today": 0,
        "avg_urgency": 0.0,
        "unique_channels": 0,
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
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0, "channels_active": 0, "threat_categories": 0}
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
    limit: int = Query(20, ge=1, le=100, description="Number of insights to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    category: Optional[str] = Query(None, description="Filter by category"),
    channel: Optional[str] = Query(None, description="Filter by channel"),
    min_urgency: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum urgency score"),
    hours: Optional[int] = Query(None, ge=1, le=168, description="Hours to look back")
):
    """API endpoint to get cybersecurity insights with advanced filtering"""
    try:
        # Check cache
        cache_key = f"insights_{limit}_{offset}_{threat_level}_{category}_{channel}_{min_urgency}_{hours}"
        cached_insights = get_cache(cache_key)
        
        if cached_insights:
            return cached_insights
        
        # Get insights from database
        all_insights = await get_recent_insights(limit=limit*2, offset=offset)  # Get extra for filtering
        
        # Apply filters
        filtered_insights = all_insights
        
        if threat_level:
            filtered_insights = [i for i in filtered_insights if i.get("threat_level") == threat_level.lower()]
        
        if category:
            filtered_insights = [i for i in filtered_insights if i.get("category") == category.lower()]
        
        if channel:
            filtered_insights = [i for i in filtered_insights if i.get("chat_username") == channel]
        
        if min_urgency is not None:
            filtered_insights = [i for i in filtered_insights if i.get("urgency_score", 0) >= min_urgency]
        
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
            filtered_insights = [
                i for i in filtered_insights 
                if i.get("message_date") and datetime.fromisoformat(i["message_date"].replace("Z", "+00:00")) > cutoff
            ]
        
        # Limit results
        filtered_insights = filtered_insights[:limit]
        
        # Add metadata
        result = {
            "insights": filtered_insights,
            "count": len(filtered_insights),
            "total_available": len(all_insights),
            "filters_applied": {
                "threat_level": threat_level,
                "category": category,
                "channel": channel,
                "min_urgency": min_urgency,
                "hours": hours
            },
            "metadata": {
                "high_priority": len([i for i in filtered_insights if i.get("threat_level") in ["critical", "high"]]),
                "avg_urgency": sum(i.get("urgency_score", 0) for i in filtered_insights) / len(filtered_insights) if filtered_insights else 0,
                "channels_represented": len(set(i.get("chat_username") for i in filtered_insights)),
                "threat_types": len(set(i.get("threat_type") for i in filtered_insights if i.get("threat_type")))
            }
        }
        
        # Cache result
        set_cache(cache_key, result, 30)  # 30 second cache for API
        
        return result
        
    except Exception as e:
        logger.error(f"Cybersecurity insights API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch cybersecurity insights: {str(e)}")

@router.get("/api/stats")
async def get_cybersecurity_stats_api():
    """API endpoint to get comprehensive cybersecurity statistics"""
    try:
        # Check cache
        cache_key = "cybersecurity_stats"
        cached_stats = get_cache(cache_key)
        
        if cached_stats:
            return cached_stats
        
        stats = await get_message_stats()
        
        # Add derived metrics and metadata
        enhanced_stats = {
            **stats,
            "threat_density": stats["high_threats"] / max(stats["total_messages"], 1),
            "critical_ratio": stats["critical_threats"] / max(stats["high_threats"], 1),
            "vulnerability_ratio": stats["vulnerabilities"] / max(stats["total_messages"], 1),
            "breach_ratio": stats["data_breaches"] / max(stats["total_messages"], 1),
            "cve_coverage": stats["cve_mentions"] / max(stats["vulnerabilities"], 1),
            "last_updated": datetime.now().isoformat(),
            "monitoring_channels": MONITORED_CHANNELS,
            "channel_metadata": CHANNEL_METADATA
        }
        
        # Cache result
        set_cache(cache_key, enhanced_stats, 60)  # 1 minute cache
        
        return enhanced_stats
        
    except Exception as e:
        logger.error(f"Cybersecurity stats API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch cybersecurity statistics: {str(e)}")

@router.get("/api/threat-analytics")
async def get_threat_analytics_api():
    """API endpoint for detailed threat analytics"""
    try:
        # Check cache
        cache_key = "threat_analytics"
        cached_analytics = get_cache(cache_key)
        
        if cached_analytics:
            return cached_analytics
        
        insights = await get_recent_insights(limit=100)  # Get more for better analytics
        stats = await get_message_stats()
        analytics = calculate_threat_analytics(insights, stats)
        
        # Cache result
        set_cache(cache_key, analytics, 120)  # 2 minute cache
        
        return analytics
        
    except Exception as e:
        logger.error(f"Threat analytics API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat analytics: {str(e)}")

@router.get("/api/monitoring/status")
async def get_monitoring_status():
    """API endpoint to get detailed monitoring status"""
    try:
        telegram_connected = telegram_client is not None and telegram_client.is_connected() if telegram_client else False
        
        status = {
            "active": telegram_connected,
            "telegram_connected": telegram_connected,
            "channels": MONITORED_CHANNELS,
            "channel_metadata": CHANNEL_METADATA,
            "total_channels": len(MONITORED_CHANNELS),
            "last_check": datetime.now().isoformat(),
            "monitoring_health": "healthy" if telegram_connected else "error",
            "system_info": {
                "platform": "CIPHER Cybersecurity Intelligence",
                "version": "1.0.0",
                "focus": "Threat Intelligence Monitoring"
            }
        }
        
        # Add per-channel status
        channel_status = []
        for channel_username, metadata in CHANNEL_METADATA.items():
            channel_status.append({
                "username": channel_username,
                "type": metadata["type"],
                "priority": metadata["priority"], 
                "focus": metadata["focus"],
                "status": "monitoring" if telegram_connected else "disconnected",
                "threat_multiplier": metadata["threat_multiplier"]
            })
        
        status["channel_status"] = channel_status
        
        return status
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get monitoring status: {str(e)}")

@router.get("/api/channels")
async def get_monitored_channels():
    """API endpoint to get cybersecurity channels with metadata"""
    try:
        channels_info = []
        for channel_username in MONITORED_CHANNELS:
            metadata = CHANNEL_METADATA.get(channel_username, {})
            channels_info.append({
                "username": channel_username,
                "display_name": channel_username.replace("@", "").title(),
                "type": metadata.get("type", "unknown"),
                "priority": metadata.get("priority", "medium"),
                "focus": metadata.get("focus", "general"),
                "threat_multiplier": metadata.get("threat_multiplier", 1.0),
                "keywords": metadata.get("keywords", []),
                "monitoring": True,
                "status": "active" if telegram_client and telegram_client.is_connected() else "inactive"
            })
        
        return {
            "channels": channels_info,
            "total": len(channels_info),
            "types": list(set(ch["type"] for ch in channels_info)),
            "priorities": list(set(ch["priority"] for ch in channels_info)),
            "monitoring_active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False
        }
        
    except Exception as e:
        logger.error(f"Channels API error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch channels: {str(e)}")

@router.get("/channels", response_class=HTMLResponse)
async def cybersecurity_channels_page(request: Request):
    """Cybersecurity channels management page"""
    try:
        telegram_connected = telegram_client is not None and telegram_client.is_connected() if telegram_client else False
        
        channels_info = []
        for channel_username in MONITORED_CHANNELS:
            metadata = CHANNEL_METADATA.get(channel_username, {})
            channels_info.append({
                "username": channel_username,
                "display_name": channel_username.replace("@", "").title(),
                "type": metadata.get("type", "unknown"),
                "priority": metadata.get("priority", "medium"),
                "focus": metadata.get("focus", "general"),
                "threat_multiplier": metadata.get("threat_multiplier", 1.0),
                "keywords": metadata.get("keywords", []),
                "monitoring": True,
                "status": "active" if telegram_connected else "inactive",
                "color": _get_channel_color(metadata.get("type", "unknown"))
            })
        
        # Group channels by type
        channels_by_type = {}
        for channel in channels_info:
            channel_type = channel["type"]
            if channel_type not in channels_by_type:
                channels_by_type[channel_type] = []
            channels_by_type[channel_type].append(channel)
        
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": channels_info,
                "channels_by_type": channels_by_type,
                "total_channels": len(channels_info),
                "monitoring_active": telegram_connected,
                "page_title": "CIPHER - Channel Management"
            }
        )
        
    except Exception as e:
        logger.error(f"Channels page error: {e}")
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": [],
                "channels_by_type": {},
                "total_channels": 0,
                "monitoring_active": False,
                "error": f"Failed to load channels data: {str(e)}",
                "page_title": "CIPHER - Channels Error"
            }
        )

def _get_channel_color(channel_type: str) -> str:
    """Get color scheme for channel type"""
    color_map = {
        "cyber_threat_intelligence": "red",
        "data_breach_monitor": "orange", 
        "security_news": "blue",
        "vulnerability": "yellow",
        "malware": "purple",
        "unknown": "gray"
    }
    return color_map.get(channel_type, "gray")

@router.get("/threats", response_class=HTMLResponse)
async def threat_intelligence_page(request: Request):
    """Dedicated threat intelligence analysis page"""
    try:
        # Get high-priority insights
        all_insights = await get_recent_insights(limit=100)
        
        # Filter for high-priority threats
        high_priority_insights = [
            insight for insight in all_insights 
            if (insight.get("threat_level") in ["critical", "high"] or 
                insight.get("urgency_score", 0) > 0.6)
        ]
        
        # Sort by urgency and recency
        high_priority_insights.sort(
            key=lambda x: (x.get("urgency_score", 0), x.get("message_date", "")), 
            reverse=True
        )
        
        stats = await get_message_stats()
        threat_analytics = calculate_threat_analytics(all_insights, stats)
        
        # Calculate threat intelligence metrics
        threat_metrics = {
            "active_threats": len(high_priority_insights),
            "critical_alerts": len([i for i in high_priority_insights if i.get("threat_level") == "critical"]),
            "apt_activity": len([i for i in high_priority_insights if "apt" in i.get("threat_type", "").lower()]),
            "zero_days": len([i for i in high_priority_insights if "zero-day" in i.get("threat_type", "").lower()]),
            "active_malware": len(set(family for i in high_priority_insights for family in i.get("malware_families", []))),
            "recent_cves": len([i for i in high_priority_insights if i.get("cve_references")]),
            "iocs_total": sum(len(i.get("iocs_detected", [])) for i in high_priority_insights),
            "affected_sectors": len(set(sys for i in high_priority_insights for sys in i.get("affected_systems", [])))
        }
        
        return templates.TemplateResponse(
            "threats.html",
            {
                "request": request,
                "insights": high_priority_insights[:50],  # Limit display
                "stats": stats,
                "threat_analytics": threat_analytics,
                "threat_metrics": threat_metrics,
                "total_insights": len(all_insights),
                "high_priority_count": len(high_priority_insights),
                "page_title": "CIPHER - Threat Intelligence"
            }
        )
        
    except Exception as e:
        logger.error(f"Threat intelligence page error: {e}")
        return templates.TemplateResponse(
            "threats.html",
            {
                "request": request,
                "insights": [],
                "stats": _get_empty_stats(),
                "threat_analytics": _get_empty_threat_analytics(),
                "threat_metrics": {"active_threats": 0, "critical_alerts": 0, "apt_activity": 0, "zero_days": 0, "active_malware": 0, "recent_cves": 0, "iocs_total": 0, "affected_sectors": 0},
                "total_insights": 0,
                "high_priority_count": 0,
                "error": f"Failed to load threat intelligence: {str(e)}",
                "page_title": "CIPHER - Threats Error"
            }
        )

@router.get("/analytics", response_class=HTMLResponse)
async def cybersecurity_analytics_page(request: Request):
    """Advanced cybersecurity analytics page"""
    try:
        # Get comprehensive data for analytics
        insights = await get_recent_insights(limit=500)  # More data for better analytics
        stats = await get_message_stats()
        threat_analytics = calculate_threat_analytics(insights, stats)
        
        # Calculate advanced analytics
        advanced_analytics = {
            "trend_analysis": _calculate_trend_analysis(insights),
            "threat_evolution": _calculate_threat_evolution(insights),
            "channel_performance": _calculate_channel_performance(insights),
            "geographic_distribution": _calculate_geographic_indicators(insights),
            "temporal_patterns": _calculate_temporal_patterns(insights),
            "correlation_analysis": _calculate_threat_correlations(insights)
        }
        
        return templates.TemplateResponse(
            "analytics.html",
            {
                "request": request,
                "analytics": threat_analytics,
                "advanced_analytics": advanced_analytics,
                "stats": stats,
                "total_insights": len(insights),
                "page_title": "CIPHER - Advanced Analytics"
            }
        )
        
    except Exception as e:
        logger.error(f"Analytics page error: {e}")
        return templates.TemplateResponse(
            "analytics.html",
            {
                "request": request,
                "analytics": _get_empty_threat_analytics(),
                "advanced_analytics": {},
                "stats": _get_empty_stats(),
                "total_insights": 0,
                "error": f"Failed to load analytics: {str(e)}",
                "page_title": "CIPHER - Analytics Error"
            }
        )

def _calculate_trend_analysis(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate threat trends over time"""
    # Group by day
    daily_threats = {}
    for insight in insights:
        if insight.get("message_date"):
            try:
                dt = datetime.fromisoformat(insight["message_date"].replace("Z", "+00:00"))
                date_key = dt.date().isoformat()
                if date_key not in daily_threats:
                    daily_threats[date_key] = {"total": 0, "high_priority": 0, "avg_urgency": []}
                daily_threats[date_key]["total"] += 1
                if insight.get("threat_level") in ["critical", "high"]:
                    daily_threats[date_key]["high_priority"] += 1
                daily_threats[date_key]["avg_urgency"].append(insight.get("urgency_score", 0))
            except:
                continue
    
    # Calculate averages
    for date_data in daily_threats.values():
        if date_data["avg_urgency"]:
            date_data["avg_urgency"] = sum(date_data["avg_urgency"]) / len(date_data["avg_urgency"])
        else:
            date_data["avg_urgency"] = 0.0
    
    return daily_threats

def _calculate_threat_evolution(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate how threats are evolving"""
    evolution = {
        "emerging_threats": {},
        "declining_threats": {},
        "persistent_threats": {}
    }
    
    # Simple implementation - can be enhanced
    threat_counts = {}
    for insight in insights:
        threat_type = insight.get("threat_type", "unknown")
        if threat_type != "unknown":
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
    
    # Top threats are considered persistent
    sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
    evolution["persistent_threats"] = dict(sorted_threats[:5])
    
    return evolution

def _calculate_channel_performance(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate channel performance metrics"""
    performance = {}
    
    for channel in MONITORED_CHANNELS:
        channel_insights = [i for i in insights if i.get("chat_username") == channel]
        if channel_insights:
            performance[channel] = {
                "total_insights": len(channel_insights),
                "avg_urgency": sum(i.get("urgency_score", 0) for i in channel_insights) / len(channel_insights),
                "high_priority_ratio": len([i for i in channel_insights if i.get("threat_level") in ["critical", "high"]]) / len(channel_insights),
                "unique_threats": len(set(i.get("threat_type") for i in channel_insights if i.get("threat_type")))
            }
        else:
            performance[channel] = {
                "total_insights": 0,
                "avg_urgency": 0.0,
                "high_priority_ratio": 0.0,
                "unique_threats": 0
            }
    
    return performance

def _calculate_geographic_indicators(insights: List[Dict]) -> List[str]:
    """Extract geographic indicators from insights"""
    # Simple implementation - look for country/region mentions
    geographic_terms = []
    common_regions = ["china", "russia", "usa", "ukraine", "iran", "north korea", "europe", "asia", "america"]
    
    for insight in insights:
        text = insight.get("message_text", "").lower()
        for region in common_regions:
            if region in text and region not in geographic_terms:
                geographic_terms.append(region)
    
    return geographic_terms

def _calculate_temporal_patterns(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate temporal patterns in threats"""
    patterns = {
        "peak_hours": {},
        "day_of_week": {},
        "threat_timing": {}
    }
    
    # Simple hour-based analysis
    for insight in insights:
        if insight.get("message_date"):
            try:
                dt = datetime.fromisoformat(insight["message_date"].replace("Z", "+00:00"))
                hour = dt.hour
                day = dt.strftime("%A")
                
                patterns["peak_hours"][hour] = patterns["peak_hours"].get(hour, 0) + 1
                patterns["day_of_week"][day] = patterns["day_of_week"].get(day, 0) + 1
            except:
                continue
    
    return patterns

def _calculate_threat_correlations(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate correlations between threat types and other factors"""
    correlations = {
        "threat_category_correlation": {},
        "urgency_threat_correlation": {},
        "channel_threat_correlation": {}
    }
    
    # Simple correlation analysis
    for insight in insights:
        threat_level = insight.get("threat_level", "low")
        category = insight.get("category", "other")
        channel = insight.get("chat_username", "unknown")
        
        # Threat level to category correlation
        if threat_level not in correlations["threat_category_correlation"]:
            correlations["threat_category_correlation"][threat_level] = {}
        correlations["threat_category_correlation"][threat_level][category] = \
            correlations["threat_category_correlation"][threat_level].get(category, 0) + 1
        
        # Channel to threat correlation
        if channel not in correlations["channel_threat_correlation"]:
            correlations["channel_threat_correlation"][channel] = {}
        correlations["channel_threat_correlation"][channel][threat_level] = \
            correlations["channel_threat_correlation"][channel].get(threat_level, 0) + 1
    
    return correlations

# Health check endpoint for the frontend
@router.get("/api/health")
async def frontend_health_check():
    """Frontend health check"""
    try:
        # Test database connectivity
        stats = await get_message_stats()
        
        return {
            "status": "healthy",
            "component": "CIPHER Frontend",
            "timestamp": datetime.now().isoformat(),
            "database_connected": True,
            "monitoring_active": stats.get("monitoring_active", False),
            "channels_configured": len(MONITORED_CHANNELS)
        }
    except Exception as e:
        return {
            "status": "unhealthy", 
            "component": "CIPHER Frontend",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Export the router
__all__ = ["router"]
