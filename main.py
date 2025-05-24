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
import logging

from frontend import router as frontend_router
from utils import (
    setup_bigquery_tables, 
    start_background_monitoring, 
    stop_background_monitoring,
    get_message_stats,
    telegram_client
)

# Configure structured logging for Cloud Run
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

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
    "version": "1.0.0",
    "startup_time": None
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
        try:
            loop = asyncio.get_event_loop()
            for sig in [signal.SIGTERM, signal.SIGINT]:
                loop.add_signal_handler(
                    sig, 
                    lambda s=sig: asyncio.create_task(graceful_shutdown(s))
                )
        except Exception as e:
            logger.warning("Could not setup signal handlers", error=str(e))

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management with comprehensive initialization"""
    
    # Startup
    import datetime
    app_state["startup_time"] = datetime.datetime.now().isoformat()
    logger.info("Starting CIPHER Cybersecurity Intelligence Platform", version=app_state["version"])
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Verify environment variables
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        error_msg = "GOOGLE_CLOUD_PROJECT environment variable not set"
        app_state["startup_errors"].append(error_msg)
        logger.error(error_msg)
    else:
        logger.info("Environment configured", project_id=project_id)
    
    # Initialize BigQuery tables with retry
    bigquery_retries = 3
    for attempt in range(bigquery_retries):
        try:
            logger.info(f"BigQuery initialization attempt {attempt + 1}/{bigquery_retries}")
            await setup_bigquery_tables()
            app_state["bigquery_ready"] = True
            logger.info("BigQuery initialization successful")
            break
        except Exception as e:
            error_msg = f"BigQuery initialization attempt {attempt + 1} failed: {str(e)}"
            logger.warning(error_msg)
            if attempt == bigquery_retries - 1:
                app_state["startup_errors"].append(f"BigQuery initialization failed after {bigquery_retries} attempts")
                logger.error("BigQuery initialization failed completely", error=str(e))
            else:
                await asyncio.sleep(5)  # Wait before retry
    
    # Start Telegram monitoring with retry
    telegram_retries = 2
    for attempt in range(telegram_retries):
        try:
            logger.info(f"Telegram monitoring initialization attempt {attempt + 1}/{telegram_retries}")
            success = await start_background_monitoring()
            
            if success:
                # Give it a moment to initialize
                await asyncio.sleep(3)
                
                # Check if monitoring actually started
                if telegram_client and telegram_client.is_connected():
                    app_state["telegram_ready"] = True
                    app_state["monitoring_active"] = True
                    logger.info("Telegram cybersecurity monitoring initialization successful")
                    break
                else:
                    logger.warning("Telegram client not connected after initialization")
            else:
                logger.warning("Telegram monitoring initialization returned false")
            
            if attempt == telegram_retries - 1:
                error_msg = "Telegram monitoring failed to connect after retries"
                app_state["startup_errors"].append(error_msg)
                logger.error(error_msg)
                
        except Exception as e:
            error_msg = f"Telegram monitoring initialization attempt {attempt + 1} failed: {str(e)}"
            logger.warning(error_msg)
            if attempt == telegram_retries - 1:
                app_state["startup_errors"].append(f"Telegram monitoring failed after {telegram_retries} attempts: {str(e)}")
                logger.error("Telegram monitoring initialization failed completely", error=str(e))
            else:
                await asyncio.sleep(5)  # Wait before retry
    
    app_state["startup_complete"] = True
    
    # Log startup summary
    if app_state["bigquery_ready"] and app_state["telegram_ready"]:
        logger.info("CIPHER application startup completed successfully")
    elif app_state["bigquery_ready"]:
        logger.warning("CIPHER started with partial functionality - BigQuery ready, Telegram issues")
    else:
        logger.warning("CIPHER started with limited functionality", 
                      bigquery_ready=app_state["bigquery_ready"],
                      telegram_ready=app_state["telegram_ready"],
                      errors=app_state["startup_errors"])
    
    yield
    
    # Shutdown
    logger.info("Shutting down CIPHER Cybersecurity Intelligence Platform")
    try:
        await stop_background_monitoring()
        app_state["monitoring_active"] = False
        logger.info("CIPHER application shutdown completed")
    except Exception as e:
        logger.error("Error during CIPHER application shutdown", error=str(e))

# Initialize FastAPI app with comprehensive configuration
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring and analysis platform",
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
            "path": request.url.path,
            "service": "CIPHER"
        }
    )

# Include routers
app.include_router(frontend_router, tags=["frontend"])

# Health check endpoints
@app.get("/health", tags=["monitoring"])
async def health_check():
    """Comprehensive health check endpoint"""
    try:
        # Basic health check that doesn't require external services
        health_status = {
            "status": "healthy" if app_state["startup_complete"] else "starting",
            "service": "CIPHER Cybersecurity Intelligence Platform",
            "version": app_state["version"],
            "mode": "cybersecurity-monitoring",
            "startup_complete": app_state["startup_complete"],
            "startup_time": app_state.get("startup_time"),
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
            "startup_errors": app_state["startup_errors"] if app_state["startup_errors"] else None
        }
        
        # Try to get stats if possible, but don't fail health check if this fails
        try:
            if app_state["bigquery_ready"]:
                stats = await get_message_stats()
                health_status["stats"] = stats
        except Exception as e:
            logger.warning("Could not get stats for health check", error=str(e))
            health_status["stats_error"] = str(e)
        
        # Determine overall status
        if not app_state["startup_complete"]:
            health_status["status"] = "starting"
            status_code = 202  # Accepted - still starting
        elif app_state["startup_errors"]:
            health_status["status"] = "degraded"
            status_code = 200  # OK but degraded
        elif app_state["bigquery_ready"]:
            health_status["status"] = "healthy"
            status_code = 200  # OK
        else:
            health_status["status"] = "unhealthy"
            status_code = 503  # Service unavailable
            
        return JSONResponse(content=health_status, status_code=status_code)
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            content={
                "status": "error",
                "service": "CIPHER Cybersecurity Intelligence Platform", 
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
    if app_state["startup_complete"]:
        return {"status": "ready", "service": "CIPHER"}
    else:
        raise HTTPException(
            status_code=503, 
            detail="CIPHER service not ready"
        )

@app.get("/health/live", tags=["monitoring"])
async def liveness_check():
    """Kubernetes liveness probe"""
    return {
        "status": "alive", 
        "service": "CIPHER",
        "timestamp": asyncio.get_event_loop().time()
    }

# Simple startup endpoint that always responds
@app.get("/", tags=["frontend"])
async def root_redirect():
    """Root endpoint that redirects to dashboard"""
    if app_state["startup_complete"]:
        # Use frontend router for full dashboard
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/dashboard")
    else:
        return {
            "service": "CIPHER Cybersecurity Intelligence Platform",
            "status": "initializing",
            "message": "System is starting up. Please wait a moment and try again.",
            "health_check": "/health"
        }

# Add a simple dashboard route that doesn't require complex initialization
@app.get("/dashboard", tags=["frontend"])
async def simple_dashboard():
    """Simple dashboard status"""
    if not app_state["startup_complete"]:
        return JSONResponse({
            "service": "CIPHER",
            "status": "initializing",
            "message": "Cybersecurity intelligence platform is starting up...",
            "components": {
                "bigquery": app_state["bigquery_ready"],
                "telegram": app_state["telegram_ready"],
                "monitoring": app_state["monitoring_active"]
            }
        })
    
    # If startup complete, let frontend router handle it
    from fastapi import Request
    from fastapi.templating import Jinja2Templates
    
    # This is a fallback - the frontend router should handle the full dashboard
    return JSONResponse({
        "service": "CIPHER Cybersecurity Intelligence Platform",
        "status": "operational",
        "redirect": "Use /api endpoints or full frontend routes"
    })

# Monitoring and status endpoints
@app.get("/monitoring/status", tags=["monitoring"])
async def monitoring_status():
    """Get detailed monitoring status"""
    try:
        from utils import MONITORED_CHANNELS
        
        status = {
            "service": "CIPHER Cybersecurity Intelligence Platform",
            "monitoring_active": app_state["monitoring_active"],
            "telegram_connected": telegram_client.is_connected() if telegram_client else False,
            "monitored_channels": MONITORED_CHANNELS,
            "total_channels": len(MONITORED_CHANNELS),
            "startup_complete": app_state["startup_complete"],
            "component_status": {
                "bigquery": app_state["bigquery_ready"],
                "telegram": app_state["telegram_ready"], 
                "monitoring": app_state["monitoring_active"]
            },
            "errors": app_state["startup_errors"] if app_state["startup_errors"] else None,
            "startup_time": app_state.get("startup_time")
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
        "service": "CIPHER Cybersecurity Intelligence Platform",
        "version": app_state["version"],
        "environment": os.getenv("ENVIRONMENT", "production"),
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", "unknown"),
        "region": os.getenv("REGION", "unknown"),
        "startup_time": app_state.get("startup_time"),
        "python_version": sys.version,
        "platform": "Google Cloud Run"
    }

@app.post("/api/monitoring/restart", tags=["monitoring"])
async def restart_monitoring():
    """Restart monitoring (admin endpoint)"""
    try:
        logger.info("Restarting CIPHER monitoring via API request")
        
        # Stop current monitoring
        await stop_background_monitoring()
        app_state["monitoring_active"] = False
        
        # Wait a moment
        await asyncio.sleep(2)
        
        # Start monitoring again
        success = await start_background_monitoring()
        
        # Check if it started successfully
        await asyncio.sleep(2)
        if success and telegram_client and telegram_client.is_connected():
            app_state["monitoring_active"] = True
            app_state["telegram_ready"] = True
            status = "success"
            message = "CIPHER monitoring restarted successfully"
        else:
            status = "partial"
            message = "CIPHER monitoring restart initiated but connection not confirmed"
        
        return {
            "status": status,
            "message": message,
            "monitoring_active": app_state["monitoring_active"],
            "service": "CIPHER"
        }
        
    except Exception as e:
        logger.error("Failed to restart CIPHER monitoring", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Failed to restart CIPHER monitoring: {str(e)}"
        )

# Metrics endpoint for monitoring
@app.get("/metrics", tags=["monitoring"])
async def metrics():
    """Prometheus-style metrics endpoint"""
    try:
        # Basic metrics that don't require external calls
        metrics_text = f"""# HELP cipher_startup_complete Whether CIPHER startup is complete
# TYPE cipher_startup_complete gauge
cipher_startup_complete {1 if app_state["startup_complete"] else 0}

# HELP cipher_bigquery_ready Whether BigQuery is ready
# TYPE cipher_bigquery_ready gauge
cipher_bigquery_ready {1 if app_state["bigquery_ready"] else 0}

# HELP cipher_telegram_ready Whether Telegram is ready
# TYPE cipher_telegram_ready gauge
cipher_telegram_ready {1 if app_state["telegram_ready"] else 0}

# HELP cipher_monitoring_active Whether monitoring is active
# TYPE cipher_monitoring_active gauge
cipher_monitoring_active {1 if app_state["monitoring_active"] else 0}

# HELP cipher_startup_errors Number of startup errors
# TYPE cipher_startup_errors gauge
cipher_startup_errors {len(app_state["startup_errors"])}
"""
        
        # Try to add stats if available
        try:
            if app_state["bigquery_ready"]:
                stats = await get_message_stats()
                metrics_text += f"""
# HELP cipher_messages_total Total messages processed
# TYPE cipher_messages_total counter
cipher_messages_total {stats.get('total_messages', 0)}

# HELP cipher_threats_high High threat messages
# TYPE cipher_threats_high counter
cipher_threats_high {stats.get('high_threats', 0)}

# HELP cipher_channels_monitored Number of channels monitored
# TYPE cipher_channels_monitored gauge
cipher_channels_monitored {stats.get('unique_channels', 0)}
"""
        except Exception as e:
            logger.debug("Could not get detailed stats for metrics", error=str(e))
        
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
    
    logger.info("Starting CIPHER server", port=port, host=host)
    
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
        logger.info("CIPHER server interrupted by user")
    except Exception as e:
        logger.error("CIPHER server error", error=str(e))
        sys.exit(1)
