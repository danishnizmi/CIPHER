from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
import asyncio
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app with enhanced metadata
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring and analysis platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add CORS middleware for API access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global state variables
_system_startup_time = datetime.now(timezone.utc)
_initialization_task = None
_utils_available = False
_monitoring_active = False
_initialization_error = None
_last_health_check = None
_system_status = "starting"

async def initialize_system_background():
    """Initialize all system components in background with enhanced error handling"""
    global _utils_available, _monitoring_active, _initialization_error, _system_status
    
    try:
        logger.info("🛡️ Initializing CIPHER Platform...")
        _system_status = "initializing"
        
        # Wait for HTTP server to start
        await asyncio.sleep(2)
        
        # Initialize utils module with detailed error tracking
        try:
            logger.info("📦 Importing utils module...")
            import utils
            
            logger.info("🔧 Initializing all systems...")
            success = await utils.initialize_all_systems()
            
            if success:
                _utils_available = True
                logger.info("✅ Utils module initialized successfully")
                
                # Start monitoring system
                logger.info("🛡️ Starting monitoring system...")
                _monitoring_active = await utils.start_monitoring_system()
                
                if _monitoring_active:
                    logger.info("✅ CIPHER monitoring system operational")
                    _system_status = "operational"
                else:
                    logger.warning("⚠️ CIPHER running in limited mode")
                    _system_status = "limited"
            else:
                raise Exception("System initialization returned False")
                
        except ImportError as e:
            error_msg = f"Utils module import failed: {e}"
            logger.error(error_msg)
            _initialization_error = error_msg
            _utils_available = False
            _system_status = "error"
            
        except Exception as e:
            error_msg = f"System initialization failed: {e}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            _initialization_error = error_msg
            _utils_available = False
            _monitoring_active = False
            _system_status = "error"
        
        # Log final status
        if _system_status == "operational":
            logger.info("🎉 CIPHER Platform initialization completed successfully")
        elif _system_status == "limited":
            logger.warning("⚠️ CIPHER Platform running with limited functionality")
        else:
            logger.error("❌ CIPHER Platform initialization failed")
        
    except Exception as e:
        error_msg = f"Background initialization error: {e}"
        logger.error(error_msg)
        logger.error(f"Traceback: {traceback.format_exc()}")
        _initialization_error = error_msg
        _system_status = "error"

@app.on_event("startup")
async def startup_event():
    """Fast startup with background initialization and enhanced logging"""
    global _initialization_task
    
    try:
        logger.info("🛡️ CIPHER Platform starting up...")
        logger.info(f"Python version: {os.sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")
        logger.info(f"Environment: {os.environ.get('GOOGLE_CLOUD_PROJECT', 'local')}")
        
        # Log environment variables (without sensitive data)
        env_vars = {
            'GOOGLE_CLOUD_PROJECT': os.environ.get('GOOGLE_CLOUD_PROJECT', 'not_set'),
            'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'not_set'),
            'PORT': os.environ.get('PORT', 'not_set'),
            'DATASET_ID': os.environ.get('DATASET_ID', 'not_set'),
            'TABLE_ID': os.environ.get('TABLE_ID', 'not_set')
        }
        logger.info(f"Environment configuration: {env_vars}")
        
        # Start background initialization
        _initialization_task = asyncio.create_task(initialize_system_background())
        
        logger.info("✅ CIPHER Platform HTTP server ready")
        logger.info("🔄 Background initialization started")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown with enhanced cleanup"""
    try:
        logger.info("🛑 Shutting down CIPHER Platform...")
        
        # Cancel initialization if still running
        if _initialization_task and not _initialization_task.done():
            _initialization_task.cancel()
            try:
                await _initialization_task
            except asyncio.CancelledError:
                logger.info("Background initialization cancelled")
        
        # Stop monitoring system
        if _utils_available:
            try:
                import utils
                await utils.stop_monitoring_system()
                logger.info("✅ CIPHER monitoring stopped")
            except Exception as e:
                logger.warning(f"Error stopping monitoring: {e}")
        
        logger.info("✅ CIPHER Platform shutdown complete")
                
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

@app.get("/", response_class=RedirectResponse)
async def root():
    """Redirect root to dashboard"""
    return RedirectResponse(url="/dashboard", status_code=307)

@app.get("/health/live")
async def liveness_check():
    """Lightweight liveness check - just confirms the server is running"""
    global _last_health_check
    _last_health_check = datetime.now(timezone.utc)
    
    return JSONResponse(
        status_code=200,
        content={
            "status": "alive",
            "service": "cipher-intelligence",
            "timestamp": _last_health_check.isoformat(),
            "uptime_seconds": int((_last_health_check - _system_startup_time).total_seconds()),
            "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
            "system_status": _system_status
        }
    )

@app.get("/health")
async def readiness_check():
    """Comprehensive health check with detailed system status"""
    global _last_health_check
    _last_health_check = datetime.now(timezone.utc)
    
    health_status = {
        "status": "healthy" if _system_status in ["operational", "limited"] else "unhealthy",
        "service": "cipher-intelligence",
        "version": "1.0.0",
        "timestamp": _last_health_check.isoformat(),
        "uptime_seconds": int((_last_health_check - _system_startup_time).total_seconds()),
        "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
        "system_status": _system_status,
        "checks": {
            "utils_available": _utils_available,
            "monitoring_active": _monitoring_active,
            "initialization": "complete" if _initialization_task and _initialization_task.done() else "running"
        }
    }
    
    # Add initialization error if present
    if _initialization_error:
        health_status["initialization_error"] = _initialization_error
    
    # Check subsystems if utils available
    if _utils_available:
        try:
            import utils
            health_status["checks"]["bigquery"] = "connected" if utils.is_bigquery_available() else "unavailable"
            health_status["checks"]["telegram"] = "connected" if utils.is_telegram_connected() else "disconnected"
            health_status["checks"]["gemini"] = "available" if utils.is_gemini_available() else "unavailable"
            
            # Get detailed monitoring status
            if hasattr(utils, 'get_monitoring_status'):
                try:
                    monitoring_status = await utils.get_monitoring_status()
                    health_status["monitoring_details"] = monitoring_status
                except Exception as e:
                    health_status["monitoring_error"] = str(e)
                    
        except Exception as e:
            logger.warning(f"Health check subsystem error: {e}")
            health_status["checks"]["subsystems"] = "error"
            health_status["subsystem_error"] = str(e)
            if health_status["status"] == "healthy":
                health_status["status"] = "degraded"
    else:
        health_status["checks"]["bigquery"] = "initializing"
        health_status["checks"]["telegram"] = "initializing"
        health_status["checks"]["gemini"] = "initializing"
    
    # Determine HTTP status code
    status_code = 200
    if health_status["status"] == "unhealthy":
        status_code = 503
    elif health_status["status"] == "degraded":
        status_code = 200  # Still functional
    
    return JSONResponse(status_code=status_code, content=health_status)

@app.get("/api/stats")
async def get_system_stats():
    """Get comprehensive system statistics with enhanced error handling"""
    try:
        if _utils_available:
            import utils
            stats = await utils.get_comprehensive_stats()
            stats["system_status"] = _system_status
            stats["initialization_time"] = _system_startup_time.isoformat()
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "high_threats": 0,
                "critical_threats": 0,
                "monitoring_active": False,
                "system_status": _system_status,
                "initialization_time": _system_startup_time.isoformat(),
                "data_source": "system_initializing",
                "error": _initialization_error if _initialization_error else "System still initializing"
            }
        
        stats["last_updated"] = datetime.now(timezone.utc).isoformat()
        stats["uptime_seconds"] = int((datetime.now(timezone.utc) - _system_startup_time).total_seconds())
        
        return stats
        
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        error_response = {
            "error": "Stats temporarily unavailable",
            "error_detail": str(e),
            "system_status": _system_status,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
        # Return 503 if system is in error state, 200 if just temporarily unavailable
        status_code = 503 if _system_status == "error" else 200
        return JSONResponse(status_code=status_code, content=error_response)

@app.get("/api/insights")
async def get_threat_insights():
    """Get latest threat intelligence insights with enhanced error handling"""
    try:
        if _utils_available:
            import utils
            insights_data = await utils.get_threat_insights()
            return {
                "insights": insights_data["insights"],
                "count": len(insights_data["insights"]),
                "status": _system_status,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "source": insights_data.get("source", "bigquery")
            }
        else:
            return {
                "insights": [],
                "count": 0,
                "status": _system_status,
                "message": f"System {_system_status} - threat intelligence will be available shortly",
                "error": _initialization_error if _initialization_error else None
            }
            
    except Exception as e:
        logger.error(f"Insights API error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "insights": [],
                "count": 0,
                "status": "error",
                "error": str(e),
                "error_detail": "Threat insights temporarily unavailable"
            }
        )

@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get detailed monitoring system status with enhanced error handling"""
    try:
        if _utils_available:
            import utils
            status = await utils.get_monitoring_status()
        else:
            status = {
                "active": False,
                "status": _system_status,
                "channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"],
                "message": f"Monitoring system {_system_status}",
                "error": _initialization_error if _initialization_error else None
            }
        
        # Add system-level information
        status["service_info"] = {
            "platform": "CIPHER Cybersecurity Intelligence Platform",
            "version": "1.0.0",
            "project": "primal-chariot-382610",
            "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
            "startup_time": _system_startup_time.isoformat(),
            "system_status": _system_status,
            "utils_available": _utils_available
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "active": False,
                "status": "error",
                "error": str(e),
                "error_detail": "Monitoring status temporarily unavailable"
            }
        )

@app.get("/api/analytics")
async def get_threat_analytics():
    """Get comprehensive threat analytics with enhanced error handling"""
    try:
        if _utils_available:
            import utils
            analytics = await utils.get_threat_analytics()
            analytics["system_status"] = _system_status
            analytics["last_updated"] = datetime.now(timezone.utc).isoformat()
            return analytics
        else:
            return {
                "status": _system_status,
                "message": f"Analytics will be available after system initialization (currently {_system_status})",
                "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "summary": {"total_threats": 0, "high_priority": 0},
                "error": _initialization_error if _initialization_error else None
            }
            
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "error", 
                "error": str(e),
                "error_detail": "Analytics temporarily unavailable"
            }
        )

@app.get("/api/system/debug")
async def get_debug_info():
    """Debug endpoint for troubleshooting (only in development)"""
    try:
        debug_info = {
            "system_status": _system_status,
            "utils_available": _utils_available,
            "monitoring_active": _monitoring_active,
            "initialization_error": _initialization_error,
            "startup_time": _system_startup_time.isoformat(),
            "last_health_check": _last_health_check.isoformat() if _last_health_check else None,
            "initialization_task": {
                "done": _initialization_task.done() if _initialization_task else None,
                "cancelled": _initialization_task.cancelled() if _initialization_task else None,
                "exception": str(_initialization_task.exception()) if _initialization_task and _initialization_task.done() and _initialization_task.exception() else None
            },
            "environment": {
                "GOOGLE_CLOUD_PROJECT": os.environ.get("GOOGLE_CLOUD_PROJECT"),
                "LOG_LEVEL": os.environ.get("LOG_LEVEL"),
                "PORT": os.environ.get("PORT"),
                "DATASET_ID": os.environ.get("DATASET_ID"),
                "TABLE_ID": os.environ.get("TABLE_ID")
            },
            "python_path": os.sys.path[:5],  # First 5 entries
            "working_directory": os.getcwd()
        }
        
        # Add utils module information if available
        if _utils_available:
            try:
                import utils
                debug_info["utils_info"] = {
                    "bigquery_available": utils.is_bigquery_available(),
                    "gemini_available": utils.is_gemini_available(),
                    "telegram_connected": utils.is_telegram_connected(),
                    "monitoring_active": utils.is_monitoring_active()
                }
            except Exception as e:
                debug_info["utils_error"] = str(e)
        
        return debug_info
        
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}

# Include frontend router with error handling
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router)
    logger.info("✅ Frontend router included")
except ImportError as e:
    logger.error(f"Frontend router not available: {e}")
    
    # Provide a basic fallback dashboard endpoint
    @app.get("/dashboard", response_class=HTMLResponse)
    async def fallback_dashboard():
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIPHER Platform - Initializing</title>
            <style>
                body { 
                    font-family: monospace; 
                    background: #0a0a0a; 
                    color: #00ff00; 
                    text-align: center; 
                    padding: 50px; 
                }
                .status { color: #ffaa00; }
                .error { color: #ff4444; }
            </style>
        </head>
        <body>
            <h1>🛡️ CIPHER Platform</h1>
            <h2 class="status">System Initializing...</h2>
            <p>Frontend module unavailable. Basic API endpoints are functional.</p>
            <p><a href="/api/docs" style="color: #6366f1;">API Documentation</a></p>
            <p><a href="/health" style="color: #6366f1;">Health Check</a></p>
            <script>
                setTimeout(() => location.reload(), 10000);
            </script>
        </body>
        </html>
        """)
        
except Exception as e:
    logger.error(f"Frontend router error: {e}")

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception: {exc}")
    logger.error(f"Request: {request.method} {request.url}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "system_status": _system_status,
            "request_id": str(datetime.now().timestamp())
        }
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    
    logger.info(f"Starting CIPHER Platform on port {port}")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port,
        log_level="info",
        access_log=True
    )
