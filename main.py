import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
from frontend import router as frontend_router
from utils import setup_bigquery_tables, setup_telegram_webhook

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting application...")
    
    # Initialize BigQuery tables
    try:
        await setup_bigquery_tables()
        logger.info("BigQuery tables initialized")
    except Exception as e:
        logger.error(f"Failed to initialize BigQuery: {e}")
    
    # Setup Telegram webhook
    try:
        await setup_telegram_webhook()
        logger.info("Telegram webhook configured")
    except Exception as e:
        logger.error(f"Failed to setup Telegram webhook: {e}")
    
    yield
    
    # Shutdown
    logger.info("Application shutting down...")

# Initialize FastAPI app
app = FastAPI(
    title="Telegram AI Data Processor",
    description="Process Telegram data with Gemini AI and display insights",
    version="1.0.0",
    lifespan=lifespan
)

# Include routers
app.include_router(frontend_router)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "telegram-ai-processor"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
