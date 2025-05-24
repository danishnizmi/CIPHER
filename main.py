import os
import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import structlog
import uvicorn

from frontend import router as frontend_router
from utils import (
    setup_bigquery_tables, 
    start_background_monitoring, 
    stop_background_monitoring,
    get_message_stats,
    telegram_client
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global state
app_state = {
    "startup_complete": False,
    "bigquery_ready": False,
    "telegram_ready": False,
    "monitoring_active": False,
    "startup_errors": [],
    "version": "1.0.0"
}

async def graceful_shutdown(signum=None):
    """Handle graceful shutdown"""
    logger.info("Received shutdown signal", signal=signum)
    try:
        await stop_background_monitoring()
        logger.info("Graceful shutdown completed")
    except Exception as e:
        logger.error("Error during shutdown", error=str(e))

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    if sys.platform != "win32":
        loop = asyncio.get_event_loop()
        for sig in [signal.SIGTERM, signal.SIGINT]:
            loop.add_signal_handler(
                sig, 
                lambda s=sig: asyncio.create_task(graceful_shutdown(s))
            )

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management with comprehensive initialization"""
    
    # Startup
    logger.info("Starting Telegram AI Processor", version=app_state["version"])
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Initialize BigQuery tables
    try:
        await setup_bigquery_tables()
        app_state["bigquery_ready"] = True
        logger.info("BigQuery initialization successful")
    except Exception as e:
        error_msg = f"BigQuery initialization failed: {str(e)}"
        app_state["startup_errors"].append(error_msg)
        logger.error("BigQuery initialization failed", error=str(e))
        # Continue startup - app can still serve frontend
    
    # Start Telegram monitoring
    try:
        await start_background_monitoring()
        
        # Give it a moment to initialize
        await asyncio.sleep(2)
        
        # Check if monitoring actually started
        if telegram_client and telegram_client.is_connected():
            app_state["telegram_ready"] = True
            app_state["monitoring_active"] = True
            logger.info("Telegram monitoring initialization successful")
        else:
            error_msg = "Telegram monitoring failed to connect"
            app_state["startup_errors"].append(error_msg)
            logger.warning("Telegram monitoring initialization incomplete")
            
    except Exception as e:
        error_msg = f"Telegram monitoring initialization failed: {str(e)}"
        app_state["startup_errors"].append(error_msg)
        logger.error("Telegram monitoring initialization failed", error=str(e))
        # Continue startup - app can still serve dashboard with error status
    
    app_state["startup_complete"] = True
    
    # Log startup summary
    if app_state["bigquery_ready"] and app_state["telegram_ready"]:
        logger.info("Application startup completed successfully")
    else:
        logger.warning("Application started with issues", 
                      bigquery_ready=app_state["bigquery_ready"],
                      telegram_ready=app_state["telegram_ready"],
                      errors=app_state["startup_errors"])
    
    yield
    
    # Shutdown
    logger.info("Shutting down Telegram AI Processor")
    try:
        await stop_background_monitoring()
        app_state["monitoring_active"] = False
        logger.info("Application shutdown completed")
    except Exception as e:
        logger.error("Error during application shutdown", error=str(e))

# Initialize FastAPI app with comprehensive configuration
app = FastAPI(
    title="Telegram AI Channel Monitor",
    description="Monitor public Telegram channels with Gemini AI analysis and display insights",
    version=app_state["version"],
    lifespan=lifespan,
    docs_url="/api/docs" if os.getenv("ENVIRONMENT") == "development" else None,
    redoc_url="/api/redoc" if os.getenv("ENVIRONMENT") == "development" else None,
)

# Add security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # Configure for production
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with logging"""
    logger.error("Unhandled exception", 
                path=request.url.path,
                method=request.method,
                error=str(exc),
                exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred. Please check the logs.",
            "path": request.url.path
        }
    )

# Include routers
app.include_router(frontend_router, tags=["frontend"])

# Health check endpoints
@app.get("/health", tags=["monitoring"])
async def health_check():
    """Comprehensive health check endpoint"""
    try:
        # Get current stats to test BigQuery connectivity
        stats = await get_message_stats()
        
        health_status = {
            "status": "healthy" if app_state["startup_complete"] else "starting",
            "service": "telegram-ai-processor",
            "version": app_state["version"],
            "mode": "mtproto-monitoring",
            "startup_complete": app_state["startup_complete"],
            "components": {
                "bigquery": {
                    "status": "healthy" if app_state["bigquery_ready"] else "error",
                    "ready": app_state["bigquery_ready"]
                },
                "telegram": {
                    "status": "healthy" if app_state["telegram_ready"] else "error", 
                    "ready": app_state["telegram_ready"],
                    "connected": telegram_client.is_connected() if telegram_client else False
                },
                "monitoring": {
                    "status": "active" if app_state["monitoring_active"] else "inactive",
                    "active": app_state["monitoring_active"]
                }
            },
            "stats": stats,
            "startup_errors": app_state["startup_errors"] if app_state["startup_errors"] else None
        }
        
        # Determine overall status
        if not app_state["startup_complete"]:
            health_status["status"] = "starting"
        elif app_state["startup_errors"]:
            health_status["status"] = "degraded"
        elif app_state["bigquery_ready"] and app_state["telegram_ready"]:
            health_status["status"] = "healthy"
        else:
            health_status["status"] = "unhealthy"
        
        # Return appropriate HTTP status
        status_code = 200
        if health_status["status"] in ["unhealthy", "degraded"]:
            status_code = 503
        elif health_status["status"] == "starting":
            status_code = 202
            
        return JSONResponse(content=health_status, status_code=status_code)
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            content={
                "status": "error",
                "service": "telegram-ai-processor", 
                "error": str(e),
                "components": {
                    "bigquery": {"status": "unknown"},
                    "telegram": {"status": "unknown"},
                    "monitoring": {"status": "unknown"}
                }
            },
            status_code=503
        )

@app.get("/health/ready", tags=["monitoring"])
async def readiness_check():
    """Kubernetes readiness probe"""
    if app_state["startup_complete"] and app_state["bigquery_ready"]:
        return {"status": "ready"}
    else:
        raise HTTPException(
            status_code=503, 
            detail="Service not ready"
        )

@app.get("/health/live", tags=["monitoring"])
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"status": "alive", "timestamp": asyncio.get_event_loop().time()}

# Monitoring and status endpoints
@app.get("/monitoring/status", tags=["monitoring"])
async def monitoring_status():
    """Get detailed monitoring status"""
    try:
        from utils import MONITORED_CHANNELS
        
        status = {
            "monitoring_active": app_state["monitoring_active"],
            "telegram_connected": telegram_client.is_connected() if telegram_client else False,
            "monitored_channels": [ch["username"] for ch in MONITORED_CHANNELS],
            "channel_details": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS),
            "startup_complete": app_state["startup_complete"],
            "component_status": {
                "bigquery": app_state["bigquery_ready"],
                "telegram": app_state["telegram_ready"], 
                "monitoring": app_state["monitoring_active"]
            },
            "errors": app_state["startup_errors"] if app_state["startup_errors"] else None
        }
        
        return status
        
    except Exception as e:
        logger.error("Failed to get monitoring status", error=str(e))
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to get monitoring status: {str(e)}"
        )

@app.get("/api/system/info", tags=["system"])
async def system_info():
    """Get system information"""
    return {
        "service": "telegram-ai-processor",
        "version": app_state["version"],
        "environment": os.getenv("ENVIRONMENT", "production"),
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", "unknown"),
        "region": os.getenv("REGION", "unknown"),
        "startup_time": app_state.get("startup_time"),
        "python_version": sys.version,
    }

@app.post("/api/monitoring/restart", tags=["monitoring"])
async def restart_monitoring():
    """Restart monitoring (admin endpoint)"""
    try:
        logger.info("Restarting monitoring via API request")
        
        # Stop current monitoring
        await stop_background_monitoring()
        app_state["monitoring_active"] = False
        
        # Wait a moment
        await asyncio.sleep(2)
        
        # Start monitoring again
        await start_background_monitoring()
        
        # Check if it started successfully
        await asyncio.sleep(2)
        if telegram_client and telegram_client.is_connected():
            app_state["monitoring_active"] = True
            status = "success"
            message = "Monitoring restarted successfully"
        else:
            status = "partial"
            message = "Monitoring restart initiated but connection not confirmed"
        
        return {
            "status": status,
            "message": message,
            "monitoring_active": app_state["monitoring_active"]
        }
        
    except Exception as e:
        logger.error("Failed to restart monitoring", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Failed to restart monitoring: {str(e)}"
        )

# Metrics endpoint for monitoring
@app.get("/metrics", tags=["monitoring"])
async def metrics():
    """Prometheus-style metrics endpoint"""
    try:
        stats = await get_message_stats()
        
        metrics_text = f"""# HELP telegram_messages_total Total messages processed
# TYPE telegram_messages_total counter
telegram_messages_total {stats.get('total_messages', 0)}

# HELP telegram_messages_today Messages processed today
# TYPE telegram_messages_today gauge
telegram_messages_today {stats.get('processed_today', 0)}

# HELP telegram_urgency_average Average urgency score
# TYPE telegram_urgency_average gauge
telegram_urgency_average {stats.get('avg_urgency', 0.0)}

# HELP telegram_channels_monitored Number of channels being monitored
# TYPE telegram_channels_monitored gauge
telegram_channels_monitored {stats.get('unique_channels', 0)}

# HELP telegram_monitoring_active Whether monitoring is active
# TYPE telegram_monitoring_active gauge
telegram_monitoring_active {1 if stats.get('monitoring_active') else 0}

# HELP telegram_high_urgency_messages High urgency messages
# TYPE telegram_high_urgency_messages counter
telegram_high_urgency_messages {stats.get('high_urgency_count', 0)}
"""
        
        return JSONResponse(
            content=metrics_text,
            media_type="text/plain"
        )
        
    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate metrics")

if __name__ == "__main__":
    # Production server configuration
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    workers = int(os.environ.get("WORKERS", 1))
    
    # Configure uvicorn with production settings
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=workers,
        loop="uvloop" if sys.platform != "win32" else "asyncio",
        http="httptools",
        access_log=True,
        log_level="info",
        timeout_keep_alive=30,
        timeout_graceful_shutdown=30,
    )
    
    server = uvicorn.Server(config)
    
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error("Server error", error=str(e))
        sys.exit(1)
