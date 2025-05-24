from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from utils import (
    process_telegram_message, 
    get_recent_insights, 
    get_message_stats,
    verify_telegram_webhook
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page showing processed insights"""
    try:
        # Get recent insights from BigQuery
        insights = await get_recent_insights(limit=20)
        
        # Get message statistics
        stats = await get_message_stats()
        
        return templates.TemplateResponse(
            "dashboard.html", 
            {
                "request": request,
                "insights": insights,
                "stats": stats,
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
                "stats": {"total_messages": 0, "processed_today": 0},
                "error": "Failed to load dashboard data"
            }
        )

@router.post("/webhook/telegram")
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle incoming Telegram webhook messages"""
    try:
        # Get the raw body for webhook verification
        body = await request.body()
        
        # Verify webhook authenticity
        if not verify_telegram_webhook(request.headers, body):
            raise HTTPException(status_code=401, detail="Unauthorized webhook")
        
        # Parse JSON data
        data = await request.json()
        
        # Process message in background
        background_tasks.add_task(process_telegram_message, data)
        
        return {"status": "ok"}
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

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

@router.post("/api/reprocess/{message_id}")
async def reprocess_message(message_id: str, background_tasks: BackgroundTasks):
    """Reprocess a specific message with Gemini AI"""
    try:
        # Add reprocessing task to background
        background_tasks.add_task(reprocess_single_message, message_id)
        return {"status": "processing", "message_id": message_id}
    except Exception as e:
        logger.error(f"Reprocess error: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue reprocessing")

async def reprocess_single_message(message_id: str):
    """Background task to reprocess a single message"""
    try:
        # This would fetch the original message and reprocess it
        logger.info(f"Reprocessing message {message_id}")
        # Implementation would go here
    except Exception as e:
        logger.error(f"Failed to reprocess message {message_id}: {e}")
