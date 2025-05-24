import os
import asyncio
import signal
import sys
import time
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global application state
app_state = {
    "startup_complete": False,
    "bigquery_ready": False,
    "telegram_ready": False,
    "monitoring_active": False,
    "startup_errors": [],
    "version": "1.0.0",
    "startup_phase": "web_server_starting",
    "initialization_progress": 0,
    "last_health_check": time.time(),
    "startup_time": time.time()
}

# Background task reference
_background_init_task = None
_utils_module = None

async def safe_import_utils():
    """Safely import utils module"""
    global _utils_module
    try:
        if _utils_module is None:
            import utils as _utils_module
            logger.info("Utils module imported successfully")
        return _utils_module
    except Exception as e:
        logger.error(f"Failed to import utils module: {e}")
        return None

async def background_initialization():
    """Initialize services in background after web server starts"""
    global app_state
    
    try:
        logger.info("Starting CIPHER background initialization")
        app_state["startup_phase"] = "importing_modules"
        app_state["initialization_progress"] = 10
        
        # Import utils module (heavy imports happen here)
        utils = await safe_import_utils()
        if not utils:
            raise Exception("Utils module not available")
        
        app_state["initialization_progress"] = 25
        app_state["startup_phase"] = "bigquery_setup"
        
        # Initialize BigQuery
        try:
            await utils.setup_bigquery_tables()
            app_state["bigquery_ready"] = True
            app_state["initialization_progress"] = 50
            logger.info("BigQuery setup completed successfully")
        except Exception as e:
            error_msg = f"BigQuery setup failed: {str(e)}"
            app_state["startup_errors"].append(error_msg)
            logger.error(f"BigQuery setup failed: {e}")
        
        app_state["startup_phase"] = "telegram_initialization"
        app_state["initialization_progress"] = 60
        
        # Initialize Telegram monitoring
        try:
            success = await utils.start_background_monitoring()
            if success:
                # Give it time to connect
                await asyncio.sleep(5)
                
                # Check connection status
                if utils.telegram_client and utils.telegram_client.is_connected():
                    app_state["telegram_ready"] = True
                    app_state["monitoring_active"] = True
                    app_state["initialization_progress"] = 100
                    app_state["startup_phase"] = "fully_operational"
                    logger.info("CIPHER monitoring system fully operational")
                else:
                    app_state["startup_phase"] = "telegram_connection_partial"
                    app_state["initialization_progress"] = 80
                    logger.warning("Telegram monitoring partially initialized")
            else:
                app_state["startup_phase"] = "telegram_failed"
                app_state["initialization_progress"] = 75
                logger.error("Telegram monitoring failed to start")
                    
        except Exception as e:
            error_msg = f"Telegram monitoring failed: {str(e)}"
            app_state["startup_errors"].append(error_msg)
            app_state["startup_phase"] = "telegram_failed"
            app_state["initialization_progress"] = 75
            logger.error(f"Telegram monitoring failed: {e}")
        
        app_state["startup_complete"] = True
        logger.info(f"CIPHER background initialization completed - Phase: {app_state['startup_phase']}")
        
    except Exception as e:
        app_state["startup_errors"].append(f"Background initialization failed: {str(e)}")
        app_state["startup_phase"] = "initialization_failed"
        app_state["initialization_progress"] = 25
        logger.error(f"Background initialization failed: {e}")

async def graceful_shutdown():
    """Handle graceful shutdown"""
    global _background_init_task
    logger.info("Starting CIPHER graceful shutdown")
    
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
                utils = await safe_import_utils()
                if utils:
                    await utils.stop_background_monitoring()
                    logger.info("Monitoring stopped successfully")
            except Exception as e:
                logger.error(f"Error stopping monitoring: {e}")
        
        logger.info("CIPHER graceful shutdown completed")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan - web server starts immediately, background init separately"""
    global _background_init_task
    
    # Startup
    logger.info("🛡️ CIPHER Cybersecurity Intelligence Platform starting")
    logger.info("Web server starting immediately for Cloud Run health checks")
    
    # Start background initialization but don't wait for it
    _background_init_task = asyncio.create_task(background_initialization())
    
    logger.info("✅ Web server ready - background initialization started")
    
    yield
    
    # Shutdown
    await graceful_shutdown()

# Initialize FastAPI app with minimal startup time
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring and analysis",
    version=app_state["version"],
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Essential middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with logging"""
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "Service temporarily unavailable",
            "phase": app_state.get("startup_phase", "unknown"),
            "timestamp": time.time()
        }
    )

# Critical health endpoints - NO external dependencies
@app.get("/health", tags=["health"])
async def health_check():
    """Primary health check - always responds immediately"""
    app_state["last_health_check"] = time.time()
    
    return {
        "status": "healthy",
        "service": "cipher-cybersecurity-platform",
        "version": app_state["version"],
        "phase": app_state["startup_phase"],
        "progress": app_state["initialization_progress"],
        "uptime": time.time() - app_state["startup_time"],
        "web_server": "operational",
        "bigquery": "ready" if app_state["bigquery_ready"] else "initializing",
        "telegram": "ready" if app_state["telegram_ready"] else "initializing",
        "monitoring": "active" if app_state["monitoring_active"] else "starting",
        "timestamp": time.time()
    }

@app.get("/health/live", tags=["health"])
async def liveness_check():
    """Kubernetes/Cloud Run liveness probe"""
    return {
        "status": "alive",
        "timestamp": time.time(),
        "uptime": time.time() - app_state["startup_time"]
    }

@app.get("/health/ready", tags=["health"]) 
async def readiness_check():
    """Kubernetes/Cloud Run readiness probe"""
    return {
        "status": "ready",
        "web_server": "ready",
        "initialization": app_state["startup_phase"],
        "progress": app_state["initialization_progress"]
    }

@app.get("/health/startup", tags=["health"])
async def startup_check():
    """Kubernetes/Cloud Run startup probe"""
    return {
        "status": "started",
        "phase": app_state["startup_phase"],
        "progress": f"{app_state['initialization_progress']}%",
        "web_server": "operational"
    }

# System status endpoints
@app.get("/status", tags=["system"])
async def system_status():
    """Detailed system status"""
    return {
        "system": "CIPHER Cybersecurity Intelligence Platform",
        "status": app_state["startup_phase"],
        "progress": app_state["initialization_progress"],
        "uptime": time.time() - app_state["startup_time"],
        "components": {
            "web_server": "operational",
            "bigquery": "ready" if app_state["bigquery_ready"] else "initializing",
            "telegram": "ready" if app_state["telegram_ready"] else "initializing", 
            "monitoring": "active" if app_state["monitoring_active"] else "starting"
        },
        "errors": app_state["startup_errors"] if app_state["startup_errors"] else None,
        "startup_complete": app_state["startup_complete"],
        "version": app_state["version"],
        "last_health_check": app_state["last_health_check"]
    }

@app.get("/api/system/info", tags=["system"])
async def system_info():
    """System information"""
    return {
        "service": "CIPHER Cybersecurity Intelligence Platform",
        "version": app_state["version"],
        "environment": os.getenv("ENVIRONMENT", "production"),
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", "unknown"),
        "region": os.getenv("REGION", "us-central1"),
        "startup_time": app_state["startup_time"],
        "python_version": sys.version,
        "phase": app_state["startup_phase"],
        "monitoring_channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"]
    }

@app.get("/api/stats", tags=["api"])
async def get_stats():
    """Get system statistics"""
    try:
        utils = await safe_import_utils()
        if utils and app_state["bigquery_ready"]:
            stats = await utils.get_message_stats()
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "avg_urgency": 0.0,
                "unique_channels": 3,
                "unique_users": 0,
                "high_threats": 0,
                "critical_threats": 0,
                "monitoring_active": app_state["monitoring_active"],
                "note": "Statistics will be available after initialization"
            }
        
        stats["system_status"] = app_state["startup_phase"]
        stats["last_updated"] = time.time()
        return stats
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {
            "error": "Stats temporarily unavailable",
            "system_status": app_state["startup_phase"],
            "monitoring_active": app_state["monitoring_active"]
        }

@app.get("/api/insights", tags=["api"])
async def get_insights(limit: int = 20):
    """Get cybersecurity insights"""
    try:
        utils = await safe_import_utils()
        if utils and app_state["bigquery_ready"]:
            insights = await utils.get_recent_insights(limit=limit)
        else:
            insights = []
        
        return {
            "insights": insights,
            "count": len(insights),
            "status": app_state["startup_phase"],
            "system_ready": app_state["startup_complete"]
        }
        
    except Exception as e:
        logger.error(f"Error getting insights: {e}")
        return {
            "insights": [],
            "count": 0,
            "error": "Insights temporarily unavailable",
            "status": app_state["startup_phase"]
        }

# Include frontend router safely
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router, tags=["frontend"])
    logger.info("Frontend router included successfully")
except Exception as e:
    logger.warning(f"Frontend router not available: {e}")
    
    # Fallback root endpoint
    @app.get("/", tags=["fallback"])
    async def fallback_root():
        """Fallback root endpoint when frontend not available"""
        return {
            "service": "CIPHER Cybersecurity Intelligence Platform",
            "status": app_state["startup_phase"],
            "progress": f"{app_state['initialization_progress']}%",
            "message": "Cybersecurity threat intelligence monitoring",
            "endpoints": {
                "health": "/health",
                "status": "/status",
                "api_stats": "/api/stats",
                "api_insights": "/api/insights",
                "docs": "/api/docs"
            },
            "monitoring": {
                "active": app_state["monitoring_active"],
                "channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"]
            }
        }

# Metrics endpoint for monitoring
@app.get("/metrics", tags=["monitoring"])
async def metrics():
    """Prometheus-style metrics"""
    try:
        utils = await safe_import_utils()
        stats = {}
        if utils and app_state["bigquery_ready"]:
            try:
                stats = await utils.get_message_stats()
            except:
                stats = {}
        
        metrics_text = f"""# HELP cipher_service_status Service status
# TYPE cipher_service_status gauge
cipher_service_status{{phase="{app_state['startup_phase']}"}} 1

# HELP cipher_initialization_progress Initialization progress percentage
# TYPE cipher_initialization_progress gauge
cipher_initialization_progress {app_state['initialization_progress']}

# HELP cipher_uptime_seconds Service uptime in seconds
# TYPE cipher_uptime_seconds counter
cipher_uptime_seconds {time.time() - app_state['startup_time']}

# HELP cipher_monitoring_active Whether monitoring is active
# TYPE cipher_monitoring_active gauge
cipher_monitoring_active {1 if app_state['monitoring_active'] else 0}

# HELP cipher_total_messages Total messages processed
# TYPE cipher_total_messages counter
cipher_total_messages {stats.get('total_messages', 0)}

# HELP cipher_high_threats High threat messages
# TYPE cipher_high_threats counter
cipher_high_threats {stats.get('high_threats', 0)}
"""
        
        return JSONResponse(content=metrics_text, media_type="text/plain")
        
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return JSONResponse(content="# Metrics temporarily unavailable\n", media_type="text/plain")

if __name__ == "__main__":
    # Production server configuration
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    
    import uvicorn
    
    logger.info(f"🚀 Starting CIPHER on {host}:{port}")
    
    # Start server with production configuration
    uvicorn.run(
        app,
        host=host,
        port=port,
        access_log=True,
        log_level="info"
    )
