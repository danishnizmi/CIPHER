import os
import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state
app_state = {
    "startup_complete": False,
    "bigquery_ready": False,
    "telegram_ready": False,
    "monitoring_active": False,
    "startup_errors": [],
    "version": "1.0.0",
    "startup_phase": "web_server_starting",
    "initialization_progress": 0
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
        try:
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
                logger.error("BigQuery setup failed", exc_info=True)
            
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
                logger.error("Telegram monitoring failed", exc_info=True)
            
        except ImportError as e:
            logger.error(f"Failed to import utils module: {e}")
            app_state["startup_errors"].append(f"Module import failed: {str(e)}")
            app_state["startup_phase"] = "import_failed"
        
        app_state["startup_complete"] = True
        logger.info("Background initialization completed", 
                   extra={
                       "phase": app_state["startup_phase"],
                       "progress": app_state["initialization_progress"]
                   })
        
    except Exception as e:
        app_state["startup_errors"].append(f"Background initialization failed: {str(e)}")
        app_state["startup_phase"] = "initialization_failed"
        logger.error("Background initialization failed", exc_info=True)

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
            try:
                from utils import stop_background_monitoring
                await stop_background_monitoring()
            except Exception as e:
                logger.error(f"Error stopping monitoring: {e}")
        
        logger.info("Graceful shutdown completed")
    except Exception as e:
        logger.error("Error during shutdown", exc_info=True)

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
                extra={"path": str(request.url.path), "error": str(exc)},
                exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "Service temporarily unavailable",
            "phase": app_state.get("startup_phase", "unknown")
        }
    )

# CRITICAL: Immediate health checks for Cloud Run - NO BigQuery dependency
@app.get("/health", tags=["health"])
async def health_check():
    """Primary health check - responds immediately WITHOUT BigQuery"""
    import time
    
    # Always return 200 if web server is running - DO NOT call BigQuery
    return {
        "status": "healthy",
        "service": "cipher-intelligence-platform",
        "version": app_state["version"],
        "phase": app_state["startup_phase"],
        "progress": app_state["initialization_progress"],
        "web_server": "operational",
        "timestamp": time.time(),
        "bigquery": "ready" if app_state["bigquery_ready"] else "initializing",
        "telegram": "ready" if app_state["telegram_ready"] else "initializing",
        "monitoring": "active" if app_state["monitoring_active"] else "starting"
    }

@app.get("/health/live", tags=["health"])
async def liveness_check():
    """Kubernetes liveness probe - always healthy if server running"""
    return {"status": "alive", "timestamp": asyncio.get_event_loop().time()}

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
    """API endpoint for system status - NO BigQuery dependency"""
    try:
        # Only try to get stats if BigQuery is ready
        stats = {}
        if app_state["startup_complete"] and app_state["bigquery_ready"]:
            try:
                from utils import get_message_stats
                stats = await get_message_stats()
            except Exception as e:
                logger.warning(f"Could not get stats: {e}")
                stats = {"error": "Stats unavailable during initialization"}
        else:
            stats = {"note": "Statistics will be available after initialization"}
        
        return {
            "status": "operational",
            "phase": app_state["startup_phase"], 
            "initialization_progress": app_state["initialization_progress"],
            "monitoring_active": app_state["monitoring_active"],
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Error in system status: {e}")
        return {
            "status": "initializing",
            "error": str(e),
            "phase": app_state["startup_phase"]
        }

# Include frontend router
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router, tags=["frontend"])
    logger.info("Frontend router included successfully")
except Exception as e:
    logger.warning(f"Frontend router not available: {e}")
    
    # Minimal fallback dashboard endpoint
    @app.get("/", tags=["frontend"])
    async def fallback_dashboard():
        """Fallback dashboard when frontend not available"""
        return JSONResponse({
            "service": "CIPHER Intelligence Platform",
            "status": app_state["startup_phase"],
            "progress": f"{app_state['initialization_progress']}%",
            "message": "Cybersecurity Intelligence Platform",
            "dashboard": "Frontend loading...",
            "health": "/health",
            "status_api": "/status"
        })

# Root endpoint that works immediately
@app.get("/api/health/full", tags=["health"])
async def full_health_check():
    """Full health check with all component status"""
    try:
        components = {
            "web_server": {"status": "healthy", "message": "Operational"},
            "bigquery": {
                "status": "healthy" if app_state["bigquery_ready"] else "initializing",
                "message": "Ready" if app_state["bigquery_ready"] else "Initializing..."
            },
            "telegram": {
                "status": "healthy" if app_state["telegram_ready"] else "initializing", 
                "message": "Connected" if app_state["telegram_ready"] else "Connecting..."
            },
            "monitoring": {
                "status": "active" if app_state["monitoring_active"] else "starting",
                "message": "Monitoring channels" if app_state["monitoring_active"] else "Starting up..."
            }
        }
        
        # Overall status
        if app_state["startup_phase"] == "fully_operational":
            overall_status = "healthy"
        elif app_state["startup_phase"] in ["web_server_starting", "importing_modules", "bigquery_setup", "telegram_initialization"]:
            overall_status = "initializing"
        else:
            overall_status = "degraded"
        
        return {
            "status": overall_status,
            "service": "CIPHER Intelligence Platform",
            "version": app_state["version"],
            "phase": app_state["startup_phase"],
            "progress": app_state["initialization_progress"],
            "components": components,
            "errors": app_state["startup_errors"] if app_state["startup_errors"] else None,
            "timestamp": asyncio.get_event_loop().time()
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "phase": app_state["startup_phase"]
        }

if __name__ == "__main__":
    # Production server configuration
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    
    import uvicorn
    
    # Start server immediately with minimal config
    uvicorn.run(
        app,
        host=host,
        port=port,
        access_log=True,
        log_level="info"
    )
