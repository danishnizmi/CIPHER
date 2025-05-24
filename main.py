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
    "version": "1.0.0",
    "startup_phase": "web_server_starting",
    "initialization_progress": 0,
    "last_health_check": None
}

# Background initialization task
_background_init_task = None

async def background_initialization():
    """Initialize services in background after web server starts"""
    global app_state
    
    try:
        logger.info("Starting background initialization")
        app_state["startup_phase"] = "importing_modules"
        app_state["initialization_progress"] = 10
        
        # Import utils module (heavy imports happen here)
        from utils import (
            setup_bigquery_tables, 
            start_background_monitoring, 
            stop_background_monitoring,
            get_message_stats,
            telegram_client
        )
        
        app_state["initialization_progress"] = 25
        app_state["startup_phase"] = "bigquery_setup"
        
        # Initialize BigQuery
        try:
            await setup_bigquery_tables()
            app_state["bigquery_ready"] = True
            app_state["initialization_progress"] = 50
            logger.info("BigQuery setup completed")
        except Exception as e:
            error_msg = f"BigQuery setup failed: {str(e)}"
            app_state["startup_errors"].append(error_msg)
            logger.error("BigQuery setup failed", error=str(e))
        
        app_state["startup_phase"] = "telegram_initialization"
        app_state["initialization_progress"] = 60
        
        # Initialize Telegram monitoring
        try:
            await start_background_monitoring()
            
            # Give it time to connect
            await asyncio.sleep(5)
            
            # Check connection status
            if telegram_client and telegram_client.is_connected():
                app_state["telegram_ready"] = True
                app_state["monitoring_active"] = True
                app_state["initialization_progress"] = 100
                app_state["startup_phase"] = "fully_operational"
                logger.info("CIPHER monitoring system fully operational")
            else:
                app_state["startup_phase"] = "telegram_connection_issues"
                app_state["initialization_progress"] = 75
                logger.warning("Telegram monitoring partially initialized")
                
        except Exception as e:
            error_msg = f"Telegram monitoring failed: {str(e)}"
            app_state["startup_errors"].append(error_msg)
            app_state["startup_phase"] = "telegram_failed"
            app_state["initialization_progress"] = 75
            logger.error("Telegram monitoring failed", error=str(e))
        
        app_state["startup_complete"] = True
        logger.info("Background initialization completed", 
                   phase=app_state["startup_phase"],
                   progress=app_state["initialization_progress"])
        
    except Exception as e:
        app_state["startup_errors"].append(f"Background initialization failed: {str(e)}")
        app_state["startup_phase"] = "initialization_failed"
        logger.error("Background initialization failed", error=str(e))

async def graceful_shutdown():
    """Handle graceful shutdown"""
    global _background_init_task
    logger.info("Starting graceful shutdown")
    
    try:
        # Cancel background initialization if still running
        if _background_init_task and not _background_init_task.done():
            _background_init_task.cancel()
            try:
                await _background_init_task
            except asyncio.CancelledError:
                pass
        
        # Stop monitoring if it was started
        if app_state.get("monitoring_active"):
            from utils import stop_background_monitoring
            await stop_background_monitoring()
        
        logger.info("Graceful shutdown completed")
    except Exception as e:
        logger.error("Error during shutdown", error=str(e))

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan - start web server IMMEDIATELY"""
    global _background_init_task
    
    # Startup - WEB SERVER STARTS FIRST
    logger.info("CIPHER Platform starting - web server priority")
    
    # Start background initialization immediately but don't wait
    _background_init_task = asyncio.create_task(background_initialization())
    
    # Web server is ready NOW - no blocking initialization
    logger.info("Web server ready - background initialization started")
    
    yield
    
    # Shutdown
    await graceful_shutdown()

# Initialize FastAPI app - MINIMAL CONFIG FOR FAST STARTUP
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring",
    version=app_state["version"],
    lifespan=lifespan
)

# Essential middleware only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error("Unhandled exception", 
                path=str(request.url.path),
                error=str(exc))
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "Service temporarily unavailable",
            "phase": app_state.get("startup_phase", "unknown")
        }
    )

# Include routers
app.include_router(frontend_router, tags=["frontend"])

# CRITICAL: Immediate health checks for Cloud Run
@app.get("/health", tags=["health"])
async def health_check():
    """Primary health check - responds immediately"""
    import time
    app_state["last_health_check"] = time.time()
    
    # Always return 200 if web server is running
    return {
        "status": "healthy",
        "service": "cipher-intelligence-platform",
        "version": app_state["version"],
        "phase": app_state["startup_phase"],
        "progress": app_state["initialization_progress"],
        "web_server": "operational",
        "bigquery": "ready" if app_state["bigquery_ready"] else "initializing",
        "telegram": "ready" if app_state["telegram_ready"] else "initializing",
        "monitoring": "active" if app_state["monitoring_active"] else "starting"
    }

@app.get("/health/live", tags=["health"])
async def liveness_check():
    """Kubernetes liveness probe - always healthy if server running"""
    return {"status": "alive"}

@app.get("/health/ready", tags=["health"]) 
async def readiness_check():
    """Readiness check - web server always ready"""
    return {
        "status": "ready",
        "web_server": "ready",
        "initialization": app_state["startup_phase"]
    }

@app.get("/health/startup", tags=["health"])
async def startup_check():
    """Startup probe - responds immediately for Cloud Run"""
    return {
        "status": "started",
        "phase": app_state["startup_phase"],
        "progress": f"{app_state['initialization_progress']}%"
    }

# Status endpoints
@app.get("/status", tags=["status"])
async def detailed_status():
    """Detailed system status"""
    return {
        "system": "CIPHER Cybersecurity Intelligence Platform",
        "status": app_state["startup_phase"],
        "progress": app_state["initialization_progress"],
        "components": {
            "web_server": "operational",
            "bigquery": "ready" if app_state["bigquery_ready"] else "initializing",
            "telegram": "ready" if app_state["telegram_ready"] else "initializing", 
            "monitoring": "active" if app_state["monitoring_active"] else "starting"
        },
        "errors": app_state["startup_errors"] if app_state["startup_errors"] else None,
        "startup_complete": app_state["startup_complete"]
    }

@app.get("/api/system/status", tags=["api"])
async def api_system_status():
    """API endpoint for system status"""
    try:
        # Try to get monitoring stats if available
        stats = {}
        if app_state["startup_complete"] and app_state["bigquery_ready"]:
            try:
                from utils import get_message_stats
                stats = await get_message_stats()
            except Exception as e:
                logger.warning("Could not get stats", error=str(e))
                stats = {"error": "Stats unavailable during initialization"}
        
        return {
            "status": "operational",
            "phase": app_state["startup_phase"], 
            "initialization_progress": app_state["initialization_progress"],
            "monitoring_active": app_state["monitoring_active"],
            "stats": stats
        }
    except Exception as e:
        return {
            "status": "initializing",
            "error": str(e),
            "phase": app_state["startup_phase"]
        }

# Root endpoint that works immediately
@app.get("/", tags=["frontend"])
async def root():
    """Root endpoint - redirects to dashboard"""
    try:
        # Try to load frontend if it's available
        if app_state["initialization_progress"] > 25:
            from frontend import router
        return JSONResponse({
            "service": "CIPHER Intelligence Platform",
            "status": app_state["startup_phase"],
            "progress": f"{app_state['initialization_progress']}%",
            "dashboard": "/dashboard" if app_state["initialization_progress"] > 50 else "initializing",
            "message": "Cybersecurity Intelligence Platform"
        })
    except Exception as e:
        return JSONResponse({
            "service": "CIPHER Intelligence Platform", 
            "status": "web_server_ready",
            "message": "Platform initializing"
        })

if __name__ == "__main__":
    # Production server configuration
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    
    # Start server immediately with minimal config
    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=1,
        access_log=True,
        log_level="info"
    )
