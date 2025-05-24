from fastapi import APIRouter, Request, HTTPException, BackgroundTasks, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.dependencies import Depends
import structlog
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from utils import (
    get_recent_insights, 
    get_message_stats,
    MONITORED_CHANNELS,
    telegram_client
)

logger = structlog.get_logger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Optional security for production
security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Optional authentication - implement as needed for production"""
    # For now, no authentication required
    # In production, validate JWT token or API key here
    return {"user": "anonymous"}

@router.get("/", response_class=HTMLResponse, tags=["frontend"])
async def dashboard(request: Request):
    """Main dashboard page showing processed insights from monitored channels"""
    try:
        # Get recent insights from BigQuery
        insights = await get_recent_insights(limit=20)
        
        # Get message statistics
        stats = await get_message_stats()
        
        # Get monitoring status with enhanced details
        monitoring_status = {
            "active": telegram_client is not None and telegram_client.is_connected() if telegram_client else False,
            "channels": [ch["username"] for ch in MONITORED_CHANNELS],
            "channel_details": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS),
            "last_check": datetime.now().isoformat()
        }
        
        # Calculate additional metrics
        dashboard_metrics = {
            "high_urgency_messages": len([i for i in insights if i.get("urgency_score", 0) > 0.7]),
            "recent_channels": len(set(i.get("chat_username", "") for i in insights if i.get("chat_username"))),
            "sentiment_distribution": _calculate_sentiment_distribution(insights),
            "category_distribution": _calculate_category_distribution(insights)
        }
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
                "monitoring": monitoring_status,
                "metrics": dashboard_metrics,
                "current_time": datetime.now().isoformat(),
                "page_title": "Dashboard"
            }
        )
    except Exception as e:
        logger.error("Dashboard error", error=str(e))
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
                    "high_urgency_count": 0,
                    "monitoring_active": False
                },
                "monitoring": {
                    "active": False, 
                    "channels": [], 
                    "total_channels": 0,
                    "channel_details": []
                },
                "metrics": {
                    "high_urgency_messages": 0,
                    "recent_channels": 0,
                    "sentiment_distribution": {},
                    "category_distribution": {}
                },
                "error": f"Failed to load dashboard data: {str(e)}",
                "page_title": "Dashboard - Error"
            }
        )

def _calculate_sentiment_distribution(insights: List[Dict]) -> Dict[str, int]:
    """Calculate sentiment distribution from insights"""
    distribution = {"positive": 0, "negative": 0, "neutral": 0}
    for insight in insights:
        sentiment = insight.get("sentiment", "neutral")
        if sentiment in distribution:
            distribution[sentiment] += 1
    return distribution

def _calculate_category_distribution(insights: List[Dict]) -> Dict[str, int]:
    """Calculate category distribution from insights"""
    distribution = {}
    for insight in insights:
        category = insight.get("category", "other")
        distribution[category] = distribution.get(category, 0) + 1
    return distribution

@router.get("/api/insights", tags=["api"])
async def get_insights_api(
    limit: int = Query(10, ge=1, le=100, description="Number of insights to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_urgency: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum urgency score"),
    hours: Optional[int] = Query(None, ge=1, le=168, description="Hours to look back")
):
    """API endpoint to get processed insights with filtering"""
    try:
        # For now, get all insights and filter in Python
        # In production, push filtering to BigQuery for better performance
        all_insights = await get_recent_insights(limit=limit*2, offset=offset)
        
        # Apply filters
        filtered_insights = all_insights
        
        if category:
            filtered_insights = [i for i in filtered_insights if i.get("category") == category.lower()]
        
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
        
        return {
            "insights": filtered_insights, 
            "count": len(filtered_insights),
            "total_available": len(all_insights),
            "filters_applied": {
                "category": category,
                "min_urgency": min_urgency,
                "hours": hours
            }
        }
    except Exception as e:
        logger.error("API insights error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to fetch insights: {str(e)}")

@router.get("/api/stats", tags=["api"])
async def get_stats_api():
    """API endpoint to get comprehensive message statistics"""
    try:
        stats = await get_message_stats()
        
        # Add derived metrics
        stats["uptime_status"] = "healthy" if stats.get("monitoring_active") else "degraded"
        stats["last_updated"] = datetime.now().isoformat()
        
        # Calculate performance metrics
        if stats["total_messages"] > 0:
            stats["urgency_ratio"] = stats.get("high_urgency_count", 0) / stats["total_messages"]
            stats["daily_average"] = stats.get("processed_today", 0)  # Could calculate based on historical data
        else:
            stats["urgency_ratio"] = 0.0
            stats["daily_average"] = 0
        
        return stats
    except Exception as e:
        logger.error("API stats error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to fetch statistics: {str(e)}")

@router.get("/api/monitoring/status", tags=["api"])
async def get_monitoring_status():
    """API endpoint to get detailed monitoring status"""
    try:
        telegram_connected = telegram_client is not None and telegram_client.is_connected() if telegram_client else False
        
        status = {
            "active": telegram_connected,
            "telegram_connected": telegram_connected,
            "channels": [ch["username"] for ch in MONITORED_CHANNELS],
            "channel_details": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS),
            "last_check": datetime.now().isoformat(),
            "monitoring_health": "healthy" if telegram_connected else "error"
        }
        
        # Add per-channel status (if we could check individual channel access)
        channel_status = []
        for channel in MONITORED_CHANNELS:
            channel_status.append({
                "username": channel["username"],
                "category": channel["category"], 
                "priority": channel["priority"],
                "status": "monitoring" if telegram_connected else "disconnected"
            })
        
        status["channel_status"] = channel_status
        
        return status
    except Exception as e:
        logger.error("Monitoring status error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get monitoring status: {str(e)}")

@router.get("/api/channels", tags=["api"])
async def get_monitored_channels():
    """API endpoint to get list of monitored channels with metadata"""
    try:
        channels_info = []
        for channel in MONITORED_CHANNELS:
            channels_info.append({
                "username": channel["username"],
                "display_name": channel["username"].replace("@", "").title(),
                "category": channel["category"],
                "priority": channel["priority"],
                "monitoring": True,
                "status": "active" if telegram_client and telegram_client.is_connected() else "inactive"
            })
        
        return {
            "channels": channels_info,
            "total": len(channels_info),
            "categories": list(set(ch["category"] for ch in MONITORED_CHANNELS)),
            "priorities": list(set(ch["priority"] for ch in MONITORED_CHANNELS))
        }
    except Exception as e:
        logger.error("Channels API error", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to fetch channels: {str(e)}")

@router.get("/channels", response_class=HTMLResponse, tags=["frontend"])
async def channels_page(request: Request):
    """Channels management page"""
    try:
        telegram_connected = telegram_client is not None and telegram_client.is_connected() if telegram_client else False
        
        channels_info = []
        for channel in MONITORED_CHANNELS:
            channels_info.append({
                "username": channel["username"],
                "display_name": channel["username"].replace("@", "").title(),
                "category": channel["category"],
                "priority": channel["priority"],
                "monitoring": True,
                "status": "active" if telegram_connected else "inactive"
            })
        
        # Group channels by category
        channels_by_category = {}
        for channel in channels_info:
            category = channel["category"]
            if category not in channels_by_category:
                channels_by_category[category] = []
            channels_by_category[category].append(channel)
        
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": channels_info,
                "channels_by_category": channels_by_category,
                "total_channels": len(channels_info),
                "monitoring_active": telegram_connected,
                "page_title": "Channels"
            }
        )
    except Exception as e:
        logger.error("Channels page error", error=str(e))
        return templates.TemplateResponse(
            "channels.html",
            {
                "request": request,
                "channels": [],
                "channels_by_category": {},
                "total_channels": 0,
                "monitoring_active": False,
                "error": f"Failed to load channels data: {str(e)}",
                "page_title": "Channels - Error"
            }
        )

@router.get("/insights", response_class=HTMLResponse, tags=["frontend"])
async def insights_page(request: Request):
    """Dedicated insights page with filtering and pagination"""
    try:
        # Get query parameters
        page = int(request.query_params.get("page", 1))
        limit = int(request.query_params.get("limit", 50))
        category = request.query_params.get("category")
        
        offset = (page - 1) * limit
        
        # Get insights
        insights = await get_recent_insights(limit=limit, offset=offset)
        
        # Apply category filter if specified
        if category:
            insights = [i for i in insights if i.get("category") == category.lower()]
        
        # Get available categories for filter dropdown
        all_insights = await get_recent_insights(limit=1000)  # Get more for category list
        categories = list(set(i.get("category", "other") for i in all_insights))
        categories.sort()
        
        return templates.TemplateResponse(
            "insights.html",
            {
                "request": request,
                "insights": insights,
                "categories": categories,
                "current_category": category,
                "current_page": page,
                "limit": limit,
                "has_more": len(insights) == limit,
                "page_title": "Insights"
            }
        )
    except Exception as e:
        logger.error("Insights page error", error=str(e))
        return templates.TemplateResponse(
            "insights.html",
            {
                "request": request,
                "insights": [],
                "categories": [],
                "current_category": None,
                "current_page": 1,
                "limit": 50,
                "has_more": False,
                "error": f"Failed to load insights: {str(e)}",
                "page_title": "Insights - Error"
            }
        )

@router.get("/analytics", response_class=HTMLResponse, tags=["frontend"])
async def analytics_page(request: Request):
    """Analytics dashboard with charts and trends"""
    try:
        # Get recent insights for analysis
        insights = await get_recent_insights(limit=500)
        stats = await get_message_stats()
        
        # Calculate analytics data
        analytics_data = {
            "sentiment_distribution": _calculate_sentiment_distribution(insights),
            "category_distribution": _calculate_category_distribution(insights),
            "urgency_stats": _calculate_urgency_stats(insights),
            "channel_activity": _calculate_channel_activity(insights),
            "hourly_activity": _calculate_hourly_activity(insights),
            "trend_data": _calculate_trend_data(insights)
        }
        
        return templates.TemplateResponse(
            "analytics.html",
            {
                "request": request,
                "analytics": analytics_data,
                "stats": stats,
                "total_insights": len(insights),
                "page_title": "Analytics"
            }
        )
    except Exception as e:
        logger.error("Analytics page error", error=str(e))
        return templates.TemplateResponse(
            "analytics.html",
            {
                "request": request,
                "analytics": {},
                "stats": {},
                "total_insights": 0,
                "error": f"Failed to load analytics: {str(e)}",
                "page_title": "Analytics - Error"
            }
        )

def _calculate_urgency_stats(insights: List[Dict]) -> Dict[str, Any]:
    """Calculate urgency statistics"""
    if not insights:
        return {"high": 0, "medium": 0, "low": 0, "average": 0.0}
    
    urgency_scores = [i.get("urgency_score", 0) for i in insights]
    
    return {
        "high": len([s for s in urgency_scores if s > 0.7]),
        "medium": len([s for s in urgency_scores if 0.3 <= s <= 0.7]),
        "low": len([s for s in urgency_scores if s < 0.3]),
        "average": sum(urgency_scores) / len(urgency_scores) if urgency_scores else 0.0
    }

def _calculate_channel_activity(insights: List[Dict]) -> Dict[str, int]:
    """Calculate activity per channel"""
    activity = {}
    for insight in insights:
        channel = insight.get("chat_username", "Unknown")
        activity[channel] = activity.get(channel, 0) + 1
    return activity

def _calculate_hourly_activity(insights: List[Dict]) -> Dict[int, int]:
    """Calculate activity by hour of day"""
    hourly = {hour: 0 for hour in range(24)}
    
    for insight in insights:
        if insight.get("message_date"):
            try:
                dt = datetime.fromisoformat(insight["message_date"].replace("Z", "+00:00"))
                hour = dt.hour
                hourly[hour] += 1
            except:
                continue
    
    return hourly

def _calculate_trend_data(insights: List[Dict]) -> Dict[str, List]:
    """Calculate trend data for charts"""
    # Group insights by date
    daily_counts = {}
    daily_urgency = {}
    
    for insight in insights:
        if insight.get("message_date"):
            try:
                dt = datetime.fromisoformat(insight["message_date"].replace("Z", "+00:00"))
                date_str = dt.date().isoformat()
                
                daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
                
                if date_str not in daily_urgency:
                    daily_urgency[date_str] = []
                daily_urgency[date_str].append(insight.get("urgency_score", 0))
            except:
                continue
    
    # Calculate average urgency per day
    daily_avg_urgency = {}
    for date, urgency_list in daily_urgency.items():
        daily_avg_urgency[date] = sum(urgency_list) / len(urgency_list) if urgency_list else 0
    
    return {
        "daily_counts": daily_counts,
        "daily_avg_urgency": daily_avg_urgency
    }

# WebSocket endpoint for real-time updates (optional)
@router.websocket("/ws/updates")
async def websocket_endpoint(websocket):
    """WebSocket endpoint for real-time dashboard updates"""
    try:
        await websocket.accept()
        while True:
            # Send periodic updates
            stats = await get_message_stats()
            await websocket.send_json({
                "type": "stats_update",
                "data": stats,
                "timestamp": datetime.now().isoformat()
            })
            
            # Wait before next update
            await asyncio.sleep(30)  # Update every 30 seconds
            
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
        await websocket.close()

# Export router
__all__ = ["router"]
