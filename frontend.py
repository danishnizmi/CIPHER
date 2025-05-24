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
    """Main dashboard page showing processed insights from monitored channels"""
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
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
                "monitoring": monitoring_status,
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
                "stats": {"total_messages": 0, "processed_today": 0, "unique_channels": 0, "unique_users": 0, "avg_urgency": 0.0},
                "monitoring": {"active": False, "channels": [], "total_channels": 0},
                "error": "Failed to load dashboard data"
            }
        )

@router.get("/api/insights")
async def get_insights_api(limit: int = 10, offset: int = 0):
    """API endpoint to get processed insights"""
    try:
        insights = await get_recent_insights(limit=limit, offset=offset)
        return {"insights": insights, "count": len(insights)}
    except Exception as e:
        logger.error(f"API insights error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch insights")

@router.get("/api/stats")
async def get_stats_api():
    """API endpoint to get message statistics"""
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
    """API endpoint to get list of monitored channels"""
    try:
        channels_info = []
        for channel in MONITORED_CHANNELS:
            channels_info.append({
                "username": channel,
                "display_name": channel.replace("@", "").title(),
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
    """Channels management page"""
    try:
        channels_info = []
        for channel in MONITORED_CHANNELS:
            channels_info.append({
                "username": channel,
                "display_name": channel.replace("@", "").title(),
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
