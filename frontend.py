from fastapi import APIRouter, Request, HTTPException, Query, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Cache for performance optimization
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 60  # 60 seconds default cache

def is_cache_valid(key: str) -> bool:
    """Check if cache entry is still valid"""
    return key in _cache and key in _cache_ttl and time.time() < _cache_ttl[key]

def set_cache(key: str, value: Any, duration: int = CACHE_DURATION):
    """Set cache entry with TTL"""
    _cache[key] = value
    _cache_ttl[key] = time.time() + duration

def get_cache(key: str) -> Any:
    """Get cache entry if valid"""
    if is_cache_valid(key):
        return _cache[key]
    return None

def get_safe_utils():
    """Safely import utils module with error handling"""
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
        logger.warning(f"Utils module not available: {e}")
        return None

@router.get("/", response_class=HTMLResponse)
async def cipher_dashboard(request: Request):
    """CIPHER main cybersecurity intelligence dashboard"""
    try:
        # Check cache first for performance
        cache_key = "dashboard_data"
        cached_data = get_cache(cache_key)
        
        if cached_data:
            logger.debug("Using cached dashboard data")
            insights, stats, monitoring_status, threat_analytics = cached_data
        else:
            # Get utils safely
            utils = get_safe_utils()
            
            if utils:
                # Get cybersecurity insights
                try:
                    insights = await utils['get_recent_insights'](limit=25)
                except Exception as e:
                    logger.warning(f"Could not get insights: {e}")
                    insights = []
                
                # Get statistics
                try:
                    stats = await utils['get_message_stats']()
                except Exception as e:
                    logger.warning(f"Could not get stats: {e}")
                    stats = _get_empty_stats()
                
                # Get monitoring status
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
                # Fallback when utils not available (during initialization)
                insights = []
                stats = _get_empty_stats()
                monitoring_status = {
                    "active": False,
                    "channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"],
                    "channel_details": _get_fallback_channel_metadata(),
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
            "apt_activity": len([i for i in insights if i.get("category") == "apt" or "apt" in i.get("threat_type", "").lower()]),
            "data_breaches": len([i for i in insights if i.get("category") == "data_breach"]),
            "ransomware_incidents": len([i for i in insights if i.get("category") == "ransomware"]),
        }
        
        # Determine system status
        if monitoring_status.get("active"):
            system_status = "operational"
        elif monitoring_status.get("status") == "initializing":
            system_status = "initializing"
        else:
            system_status = "degraded"
        
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
    """Calculate comprehensive cybersecurity threat analytics"""
    try:
        analytics = {
            # Threat level distribution
            "threat_levels": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            
            # Cybersecurity categories
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
            
            # Advanced threat metrics
            "top_threats": [],
            "active_campaigns": [],
            "threat_actors": {},
            "affected_systems": {},
            "geographic_indicators": [],
            "attack_vectors": {},
            "urgency_distribution": {
                "critical": 0,  # 0.8-1.0
                "high": 0,      # 0.6-0.8
                "medium": 0,    # 0.4-0.6
                "low": 0        # 0.0-0.4
            },
            
            # IOC tracking
            "cve_count": 0,
            "ioc_count": 0,
            "malware_families_count": 0,
        }
        
        if not insights:
            return analytics
        
        # Initialize channel activity
        channels = ["@DarkfeedNews", "@breachdetector", "@secharvester"]
        for channel in channels:
            analytics["channel_activity"][channel] = {
                "count": 0,
                "avg_urgency": 0.0,
                "threat_types": set(),
                "last_activity": None,
                "high_priority": 0
            }
        
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
                
                # Channel activity analysis
                channel = insight.get("chat_username", "Unknown")
                if channel in analytics["channel_activity"]:
                    channel_data = analytics["channel_activity"][channel]
                    channel_data["count"] += 1
                    channel_data["threat_types"].add(insight.get("threat_type", "unknown"))
                    channel_data["last_activity"] = insight.get("message_date")
                    if threat_level in ["critical", "high"]:
                        channel_data["high_priority"] += 1
                
                # Hourly activity pattern
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
                
                # Track threat actors
                for actor in insight.get("threat_actors", []):
                    analytics["threat_actors"][actor] = analytics["threat_actors"].get(actor, 0) + 1
                
                # Track affected systems
                for system in insight.get("affected_systems", []):
                    analytics["affected_systems"][system] = analytics["affected_systems"].get(system, 0) + 1
                
                # Track attack vectors
                for vector in insight.get("attack_vectors", []):
                    analytics["attack_vectors"][vector] = analytics["attack_vectors"].get(vector, 0) + 1
                
                # Count IOCs
                analytics["cve_count"] += len(insight.get("cve_references", []))
                analytics["ioc_count"] += len(insight.get("iocs_detected", []))
                analytics["malware_families_count"] += len(insight.get("malware_families", []))
                
            except Exception as e:
                logger.warning(f"Error processing insight for analytics: {e}")
                continue
        
        # Calculate channel averages
        for channel_data in analytics["channel_activity"].values():
            if channel_data["count"] > 0:
                # Convert set to list for JSON serialization
                channel_data["threat_types"] = list(channel_data["threat_types"])
                # Calculate average urgency for channel
                channel_urgencies = [i.get("urgency_score", 0) for i in insights if i.get("chat_username") == channel]
                channel_data["avg_urgency"] = sum(channel_urgencies) / len(channel_urgencies) if channel_urgencies else 0.0
            else:
                channel_data["threat_types"] = []
                channel_data["avg_urgency"] = 0.0
        
        # Top threats by frequency
        analytics["top_threats"] = [
            {
                "type": threat_type, 
                "count": count, 
                "severity": _assess_threat_severity(threat_type),
                "percentage": round((count / len(insights)) * 100, 1) if insights else 0
            }
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Active campaigns (group similar threat types)
        campaigns = {}
        for threat_type, count in threat_types.items():
            campaign_key = _categorize_campaign(threat_type)
            campaigns[campaign_key] = campaigns.get(campaign_key, 0) + count
        
        analytics["active_campaigns"] = [
            {"campaign": campaign, "incidents": count, "threat_level": _assess_campaign_severity(campaign)}
            for campaign, count in sorted(campaigns.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Calculate overall threat scores
        if urgency_scores:
            analytics["overall_threat_score"] = sum(urgency_scores) / len(urgency_scores)
            analytics["max_threat_score"] = max(urgency_scores)
        else:
            analytics["overall_threat_score"] = 0.0
            analytics["max_threat_score"] = 0.0
        
        # Geographic indicators (simplified)
        geographic_terms = []
        for insight in insights:
            geographic_terms.extend(insight.get("geographical_targets", []))
        analytics["geographic_indicators"] = list(set(geographic_terms))[:10]
        
        # Summary statistics
        analytics["summary"] = {
            "total_threats": len(insights),
            "high_priority": analytics["threat_levels"]["critical"] + analytics["threat_levels"]["high"],
            "avg_urgency": analytics["overall_threat_score"],
            "channels_active": len([ch for ch in analytics["channel_activity"].values() if ch["count"] > 0]),
            "threat_categories": len([cat for cat, count in analytics["categories"].items() if count > 0]),
            "unique_threat_actors": len(analytics["threat_actors"]),
            "cve_total": analytics["cve_count"],
            "ioc_total": analytics["ioc_count"]
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Error calculating threat analytics: {e}")
        return _get_empty_threat_analytics()

def _assess_threat_severity(threat_type: str) -> str:
    """Assess threat severity based on threat type"""
    critical_threats = ["zero-day", "0-day", "apt", "ransomware", "critical", "breach"]
    high_threats = ["malware", "exploit", "backdoor", "trojan", "vulnerability"]
    medium_threats = ["phishing", "advisory", "patch", "update"]
    
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
    """Categorize threat types into campaign categories"""
    threat_lower = threat_type.lower()
    
    if "ransomware" in threat_lower:
        return "Ransomware Operations"
    elif "apt" in threat_lower or "advanced" in threat_lower:
        return "APT Campaigns"
    elif "phishing" in threat_lower:
        return "Phishing Campaigns"
    elif "malware" in threat_lower:
        return "Malware Distribution"
    elif "vulnerability" in threat_lower or "exploit" in threat_lower:
        return "Exploit Activity"
    elif "breach" in threat_lower or "leak" in threat_lower:
        return "Data Breaches"
    else:
        return "Other Threats"

def _assess_campaign_severity(campaign: str) -> str:
    """Assess campaign severity"""
    high_severity = ["Ransomware", "APT", "Breach"]
    medium_severity = ["Exploit", "Malware"]
    
    if any(keyword in campaign for keyword in high_severity):
        return "high"
    elif any(keyword in campaign for keyword in medium_severity):
        return "medium"
    else:
        return "low"

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
        "apt_activity": 0,
        "ransomware_alerts": 0,
        "attributed_threats": 0,
        "monitoring_active": False,
        "monitored_channels": 3
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
        "threat_actors": {},
        "affected_systems": {},
        "geographic_indicators": [],
        "attack_vectors": {},
        "urgency_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "overall_threat_score": 0.0,
        "max_threat_score": 0.0,
        "cve_count": 0,
        "ioc_count": 0,
        "malware_families_count": 0,
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0, "channels_active": 0, "threat_categories": 0, "unique_threat_actors": 0, "cve_total": 0, "ioc_total": 0}
    }

def _get_empty_dashboard_metrics() -> Dict[str, Any]:
    """Return empty dashboard metrics"""
    return {
        "high_priority_threats": 0,
        "active_campaigns": 0,
        "recent_cves": 0,
        "iocs_detected": 0,
        "malware_families": 0,
        "apt_activity": 0,
        "data_breaches": 0,
        "ransomware_incidents": 0
    }

def _get_fallback_channel_metadata() -> Dict[str, Any]:
    """Return fallback channel metadata when utils not available"""
    return {
        "@DarkfeedNews": {
            "type": "cyber_threat_intelligence",
            "priority": "critical",
            "focus": "advanced_persistent_threats",
            "description": "Premium threat intelligence feed"
        },
        "@breachdetector": {
            "type": "data_breach_monitor", 
            "priority": "high",
            "focus": "data_breaches",
            "description": "Real-time data breach monitoring"
        },
        "@secharvester": {
            "type": "security_news",
            "priority": "medium", 
            "focus": "security_updates",
            "description": "Security news and CVE tracking"
        }
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
    """API endpoint for cybersecurity insights with advanced filtering"""
    try:
        # Check cache
        cache_key = f"insights_{limit}_{offset}_{threat_level}_{category}_{channel}_{min_urgency}_{hours}"
        cached_insights = get_cache(cache_key)
        
        if cached_insights:
            return cached_insights
        
        utils = get_safe_utils()
        
        if utils:
            # Get insights from backend
            all_insights = await utils['get_recent_insights'](limit=limit*2, offset=offset)
        else:
            all_insights = []
        
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
            "status": "operational" if utils else "initializing",
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
        set_cache(cache_key, result, 30)
        
        return result
        
    except Exception as e:
        logger.error(f"Insights API error: {e}")
        return {
            "insights": [],
            "count": 0,
            "status": "error",
            "error": str(e),
            "metadata": {"high_priority": 0, "avg_urgency": 0.0, "channels_represented": 0, "threat_types": 0}
        }

@router.get("/api/stats")
async def get_cybersecurity_stats_api():
    """API endpoint for comprehensive cybersecurity statistics"""
    try:
        utils = get_safe_utils()
        
        if utils:
            stats = await utils['get_message_stats']()
        else:
            stats = _get_empty_stats()
        
        # Add enhanced metadata
        stats["last_updated"] = time.time()
        stats["system_status"] = "operational" if utils else "initializing"
        stats["monitored_channels"] = ["@DarkfeedNews", "@breachdetector", "@secharvester"]
        stats["channel_metadata"] = _get_fallback_channel_metadata()
        
        return stats
        
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return {
            **_get_empty_stats(),
            "system_status": "error",
            "error": str(e),
            "last_updated": time.time()
        }

@router.get("/api/threat-analytics")
async def get_threat_analytics_api():
    """API endpoint for detailed threat analytics"""
    try:
        cache_key = "threat_analytics"
        cached_analytics = get_cache(cache_key)
        
        if cached_analytics:
            return cached_analytics
        
        utils = get_safe_utils()
        
        if utils:
            insights = await utils['get_recent_insights'](limit=100)
            stats = await utils['get_message_stats']()
        else:
            insights = []
            stats = _get_empty_stats()
        
        analytics = calculate_threat_analytics(insights, stats)
        
        # Cache result
        set_cache(cache_key, analytics, 120)
        
        return analytics
        
    except Exception as e:
        logger.error(f"Threat analytics API error: {e}")
        return _get_empty_threat_analytics()

@router.get("/api/monitoring/status")
async def get_monitoring_status():
    """API endpoint for detailed monitoring status"""
    try:
        utils = get_safe_utils()
        
        if utils:
            telegram_connected = utils['telegram_client'] is not None and utils['telegram_client'].is_connected() if utils['telegram_client'] else False
            channels = utils['MONITORED_CHANNELS']
            channel_metadata = utils['CHANNEL_METADATA']
        else:
            telegram_connected = False
            channels = ["@DarkfeedNews", "@breachdetector", "@secharvester"]
            channel_metadata = _get_fallback_channel_metadata()
        
        status = {
            "active": telegram_connected,
            "telegram_connected": telegram_connected,
            "channels": channels,
            "channel_metadata": channel_metadata,
            "total_channels": len(channels),
            "last_check": datetime.now().isoformat(),
            "monitoring_health": "healthy" if telegram_connected else "initializing",
            "system_info": {
                "platform": "CIPHER Cybersecurity Intelligence Platform",
                "version": "1.0.0",
                "focus": "Threat Intelligence Monitoring",
                "capabilities": [
                    "Real-time threat intelligence",
                    "APT campaign tracking", 
                    "Data breach monitoring",
                    "CVE and vulnerability tracking",
                    "IOC extraction and analysis",
                    "Threat actor attribution"
                ]
            }
        }
        
        # Add per-channel status
        channel_status = []
        for channel_username in channels:
            metadata = channel_metadata.get(channel_username, {})
            channel_status.append({
                "username": channel_username,
                "type": metadata.get("type", "unknown"),
                "priority": metadata.get("priority", "medium"), 
                "focus": metadata.get("focus", "general"),
                "status": "monitoring" if telegram_connected else "disconnected",
                "threat_multiplier": metadata.get("threat_multiplier", 1.0),
                "description": metadata.get("description", "Cybersecurity intelligence source")
            })
        
        status["channel_status"] = channel_status
        
        return status
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return {
            "active": False,
            "error": str(e),
            "system_info": {"platform": "CIPHER", "status": "error"}
        }

@router.get("/api/channels")
async def get_monitored_channels():
    """API endpoint for cybersecurity channels with metadata"""
    try:
        utils = get_safe_utils()
        
        if utils:
            channels = utils['MONITORED_CHANNELS']
            metadata = utils['CHANNEL_METADATA']
            monitoring_active = utils['telegram_client'] is not None and utils['telegram_client'].is_connected() if utils['telegram_client'] else False
        else:
            channels = ["@DarkfeedNews", "@breachdetector", "@secharvester"]
            metadata = _get_fallback_channel_metadata()
            monitoring_active = False
        
        channels_info = []
        for channel_username in channels:
            channel_meta = metadata.get(channel_username, {})
            channels_info.append({
                "username": channel_username,
                "display_name": channel_username.replace("@", "").title(),
                "type": channel_meta.get("type", "unknown"),
                "priority": channel_meta.get("priority", "medium"),
                "focus": channel_meta.get("focus", "general"),
                "threat_multiplier": channel_meta.get("threat_multiplier", 1.0),
                "keywords": channel_meta.get("keywords", []),
                "description": channel_meta.get("description", "Cybersecurity intelligence source"),
                "monitoring": True,
                "status": "active" if monitoring_active else "inactive",
                "color": _get_channel_color(channel_meta.get("type", "unknown"))
            })
        
        return {
            "channels": channels_info,
            "total": len(channels_info),
            "types": list(set(ch["type"] for ch in channels_info)),
            "priorities": list(set(ch["priority"] for ch in channels_info)),
            "monitoring_active": monitoring_active,
            "capabilities": [
                "Advanced Persistent Threat (APT) tracking",
                "Real-time data breach alerts",
                "CVE and vulnerability monitoring",
                "Malware family identification",
                "IOC extraction and correlation",
                "Threat actor attribution",
                "Campaign tracking and analysis"
            ]
        }
        
    except Exception as e:
        logger.error(f"Channels API error: {e}")
        return {
            "channels": [],
            "total": 0,
            "error": str(e),
            "monitoring_active": False
        }

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

@router.get("/api/health")
async def frontend_health_check():
    """Frontend component health check"""
    try:
        utils = get_safe_utils()
        backend_available = utils is not None
        
        if backend_available:
            try:
                stats = await utils['get_message_stats']()
                database_connected = True
                monitoring_active = stats.get("monitoring_active", False)
            except Exception as e:
                database_connected = False
                monitoring_active = False
        else:
            database_connected = False
            monitoring_active = False
        
        return {
            "status": "healthy",
            "component": "CIPHER Frontend",
            "timestamp": time.time(),
            "backend_available": backend_available,
            "database_connected": database_connected,
            "monitoring_active": monitoring_active,
            "system_phase": "operational" if backend_available else "initializing",
            "capabilities": {
                "dashboard": True,
                "api_endpoints": True,
                "real_time_updates": backend_available,
                "threat_analytics": backend_available,
                "monitoring_status": True
            }
        }
    except Exception as e:
        return {
            "status": "degraded", 
            "component": "CIPHER Frontend",
            "error": str(e),
            "timestamp": time.time()
        }

# Export the router
__all__ = ["router"]
