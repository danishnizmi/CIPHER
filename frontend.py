from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import logging
from typing import Dict, Any
from datetime import datetime
from utils import (
    get_recent_insights, 
    get_message_stats,
    MONITORED_CHANNELS,
    telegram_client
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """CIPHER dashboard showing cybersecurity intelligence from monitored channels"""
    try:
        # Get recent insights from BigQuery
        insights = await get_recent_insights(limit=20)
        
        # Get message statistics
        stats = await get_message_stats()
        
        # Get monitoring status
        monitoring_status = {
            "active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False,
            "channels": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS)
        }
        
        # Calculate cybersecurity-specific metrics
        threat_metrics = calculate_threat_metrics(insights)
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
                "monitoring": monitoring_status,
                "threat_metrics": threat_metrics,
                "current_time": datetime.now().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "insights": [],
                "stats": {
                    "total_messages": 0, 
                    "processed_today": 0, 
                    "unique_channels": 0, 
                    "unique_users": 0, 
                    "avg_urgency": 0.0,
                    "high_threats": 0
                },
                "monitoring": {"active": False, "channels": [], "total_channels": 0},
                "threat_metrics": {
                    "critical_threats": 0,
                    "high_threats": 0,
                    "medium_threats": 0,
                    "low_threats": 0,
                    "data_breaches": 0,
                    "malware_alerts": 0,
                    "vulnerability_reports": 0
                },
                "error": "Failed to load dashboard data"
            }
        )

def calculate_threat_metrics(insights: list) -> Dict[str, int]:
    """Calculate cybersecurity-specific threat metrics"""
    metrics = {
        "critical_threats": 0,
        "high_threats": 0, 
        "medium_threats": 0,
        "low_threats": 0,
        "data_breaches": 0,
        "malware_alerts": 0,
        "vulnerability_reports": 0,
        "ransomware_incidents": 0,
        "threat_intel": 0
    }
    
    for insight in insights:
        # Count by threat level
        threat_level = insight.get("threat_level", "low")
        if threat_level == "critical":
            metrics["critical_threats"] += 1
        elif threat_level == "high":
            metrics["high_threats"] += 1
        elif threat_level == "medium":
            metrics["medium_threats"] += 1
        else:
            metrics["low_threats"] += 1
        
        # Count by category
        category = insight.get("category", "other")
        if category == "data_breach":
            metrics["data_breaches"] += 1
        elif category == "malware":
            metrics["malware_alerts"] += 1
        elif category == "vulnerability":
            metrics["vulnerability_reports"] += 1
        elif category == "ransomware":
            metrics["ransomware_incidents"] += 1
        elif category == "threat_intel":
            metrics["threat_intel"] += 1
    
    return metrics

@router.get("/api/insights")
async def get_insights_api(limit: int = 10, offset: int = 0):
    """API endpoint to get processed cybersecurity insights"""
    try:
        insights = await get_recent_insights(limit=limit, offset=offset)
        return {"insights": insights, "count": len(insights)}
    except Exception as e:
        logger.error(f"API insights error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch insights")

@router.get("/api/stats")
async def get_stats_api():
    """API endpoint to get cybersecurity message statistics"""
    try:
        stats = await get_message_stats()
        return stats
    except Exception as e:
        logger.error(f"API stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")

@router.get("/api/monitoring/status")
async def get_monitoring_status():
    """API endpoint to get monitoring status"""
    try:
        status = {
            "active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False,
            "channels": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS),
            "last_check": datetime.now().isoformat()
        }
        return status
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get monitoring status")

@router.get("/api/channels")
async def get_monitored_channels():
    """API endpoint to get list of monitored cybersecurity channels"""
    try:
        channels_info = []
        channel_descriptions = {
            "@DarkfeedNews": {"type": "Cyber Threat Intelligence", "description": "Advanced threat actor monitoring"},
            "@breachdetector": {"type": "Data Leak Monitor", "description": "Real-time breach detection"},
            "@secharvester": {"type": "Security News", "description": "Cybersecurity news aggregation"},
            "@bbcbreaking": {"type": "Breaking News", "description": "Global breaking news"},
            "@cnn": {"type": "News", "description": "CNN news updates"},
            "@reuters": {"type": "News", "description": "Reuters news wire"}
        }
        
        for channel in MONITORED_CHANNELS:
            channel_info = channel_descriptions.get(channel, {"type": "Unknown", "description": "Channel monitoring"})
            channels_info.append({
                "username": channel,
                "display_name": channel.replace("@", "").title(),
                "type": channel_info["type"],
                "description": channel_info["description"],
                "monitoring": True
            })
        
        return {
            "channels": channels_info,
            "total": len(channels_info)
        }
    except Exception as e:
        logger.error(f"Channels API error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch channels")

@router.get("/channels", response_class=HTMLResponse)
async def channels_page(request: Request):
    """Cybersecurity channels management page"""
    try:
        channels_info = []
        channel_descriptions = {
            "@DarkfeedNews": {"type": "Cyber Threat Intelligence", "description": "Advanced threat actor monitoring", "color": "red"},
            "@breachdetector": {"type": "Data Leak Monitor", "description": "Real-time breach detection", "color": "orange"},
            "@secharvester": {"type": "Security News", "description": "Cybersecurity news aggregation", "color": "blue"},
            "@bbcbreaking": {"type": "Breaking News", "description": "Global breaking news", "color": "purple"},
            "@cnn": {"type": "News", "description": "CNN news updates", "color": "green"},
            "@reuters": {"type": "News", "description": "Reuters news wire", "color": "gray"}
        }
        
        for channel in MONITORED_CHANNELS:
            channel_info = channel_descriptions.get(channel, {"type": "Unknown", "description": "Channel monitoring", "color": "gray"})
            channels_info.append({
                "username": channel,
                "display_name": channel.replace("@", "").title(),
                "type": channel_info["type"],
                "description": channel_info["description"],
                "color": channel_info["color"],
                "monitoring": True,
                "status": "active" if telegram_client and telegram_client.is_connected() else "inactive"
            })
        
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": channels_info,
                "total_channels": len(channels_info),
                "monitoring_active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False
            }
        )
    except Exception as e:
        logger.error(f"Channels page error: {e}")
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": [],
                "total_channels": 0,
                "monitoring_active": False,
                "error": "Failed to load channels data"
            }
        )

@router.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request):
    """Threat intelligence analysis page"""
    try:
        # Get high-priority insights
        all_insights = await get_recent_insights(limit=100)
        high_priority_insights = [
            insight for insight in all_insights 
            if insight.get("threat_level") in ["critical", "high"] or insight.get("urgency_score", 0) > 0.6
        ]
        
        stats = await get_message_stats()
        threat_metrics = calculate_threat_metrics(all_insights)
        
        return templates.TemplateResponse(
            "threats.html",
            {
                "request": request,
                "insights": high_priority_insights,
                "stats": stats,
                "threat_metrics": threat_metrics,
                "total_insights": len(all_insights)
            }
        )
    except Exception as e:
        logger.error(f"Threats page error: {e}")
        return templates.TemplateResponse(
            "threats.html",
            {
                "request": request,
                "insights": [],
                "stats": {},
                "threat_metrics": {},
                "total_insights": 0,
                "error": "Failed to load threat data"
            }
        )
