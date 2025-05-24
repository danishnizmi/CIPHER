import os
import asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging
from frontend import router as frontend_router
from utils import setup_bigquery_tables, start_background_monitoring, stop_background_monitoring

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Telegram AI Processor...")
    
    # Initialize BigQuery tables
    try:
        await setup_bigquery_tables()
        logger.info("BigQuery tables initialized")
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery: {e}")
    
    # Start Telegram monitoring
    try:
        await start_background_monitoring()
        logger.info("Telegram monitoring started")
    except Exception as e:
        logger.error(f"Failed to start Telegram monitoring: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Telegram AI Processor...")
    try:
        await stop_background_monitoring()
        logger.info("Telegram monitoring stopped")
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")

# Initialize FastAPI app
app = FastAPI(
    title="Telegram AI Channel Monitor",
    description="Monitor public Telegram channels with Gemini AI analysis and display insights",
    version="1.0.0",
    lifespan=lifespan
)

# Include routers
app.include_router(frontend_router)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "telegram-ai-processor",
        "mode": "mtproto-monitoring"
    }

# Monitoring status endpoint
@app.get("/monitoring/status")
async def monitoring_status():
    """Get current monitoring status"""
    from utils import telegram_client, MONITORED_CHANNELS
    
    status = {
        "monitoring_active": telegram_client is not None and telegram_client.is_connected(),
        "monitored_channels": MONITORED_CHANNELS,
        "total_channels": len(MONITORED_CHANNELS)
    }
    
    return status

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
