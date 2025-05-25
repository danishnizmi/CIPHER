from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
import asyncio
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration - centralized in main.py
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "primal-chariot-382610")
SERVICE_ACCOUNT = f"cloud-build-service@{PROJECT_ID}.iam.gserviceaccount.com"

# Create FastAPI app
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring and analysis platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
_system_status = "starting"

# Standard response templates
def create_success_response(data: Any, message: str = "Success") -> Dict[str, Any]:
    """Create standardized success response"""
    return {
        "status": "success",
        "message": message,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": "CIPHER Cybersecurity Intelligence Platform"
    }

def create_error_response(error: str, details: str = None, status: str = "error") -> Dict[str, Any]:
    """Create standardized error response"""
    response = {
        "error": error,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": "CIPHER Cybersecurity Intelligence Platform"
    }
    if details:
        response["details"] = details
    return response

async def initialize_system_background():
    """Initialize all system components in background"""
    global _utils_available, _monitoring_active, _initialization_error, _system_status
    
    try:
        logger.info("🛡️ Initializing CIPHER Platform...")
        _system_status = "initializing"
        
        # Wait for HTTP server to start
        await asyncio.sleep(2)
        
        # Initialize utils module
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
    """Fast startup with background initialization"""
    global _initialization_task
    
    try:
        logger.info("🛡️ CIPHER Platform starting up...")
        logger.info(f"Python version: {os.sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")
        logger.info(f"Project: {PROJECT_ID}")
        
        # Start background initialization
        _initialization_task = asyncio.create_task(initialize_system_background())
        
        logger.info("✅ CIPHER Platform HTTP server ready")
        logger.info("🔄 Background initialization started")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown"""
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
    """Lightweight liveness check"""
    return JSONResponse(
        status_code=200,
        content={
            "status": "alive",
            "service": "cipher-intelligence", 
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
            "service_account": SERVICE_ACCOUNT,
            "system_status": _system_status
        }
    )

@app.get("/health")
async def readiness_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy" if _system_status in ["operational", "limited"] else "unhealthy",
        "service": "cipher-intelligence",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
        "service_account": SERVICE_ACCOUNT,
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
        except Exception as e:
            logger.warning(f"Health check subsystem error: {e}")
            health_status["checks"]["subsystems"] = "error"
    
    # Determine HTTP status code
    status_code = 200 if health_status["status"] in ["healthy"] else 503
    
    return JSONResponse(status_code=status_code, content=health_status)

@app.get("/api/stats")
async def get_system_stats():
    """Get comprehensive system statistics"""
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
        return JSONResponse(
            status_code=503,
            content=create_error_response(
                "Stats temporarily unavailable",
                str(e)
            )
        )

@app.get("/api/insights")
async def get_threat_insights():
    """Get latest threat intelligence insights"""
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
            content=create_error_response(
                "Threat insights temporarily unavailable",
                str(e)
            )
        )

@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get detailed monitoring system status"""
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
            "project": PROJECT_ID,
            "service_account": SERVICE_ACCOUNT,
            "startup_time": _system_startup_time.isoformat(),
            "system_status": _system_status,
            "utils_available": _utils_available
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return JSONResponse(
            status_code=503,
            content=create_error_response(
                "Monitoring status temporarily unavailable",
                str(e)
            )
        )

@app.get("/api/analytics")
async def get_threat_analytics():
    """Get comprehensive threat analytics"""
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
            content=create_error_response(
                "Analytics temporarily unavailable", 
                str(e)
            )
        )

# Include frontend router - THIS IS THE KEY FIX
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router)
    logger.info("✅ Frontend router included successfully")
except ImportError as e:
    logger.error(f"Frontend router not available: {e}")
    
    # Provide a basic fallback dashboard endpoint
    @app.get("/dashboard", response_class=HTMLResponse)
    async def fallback_dashboard():
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIPHER Platform - Initializing</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ 
                    font-family: 'Segoe UI', monospace;
                    background: linear-gradient(135deg, #0a0a0a, #1a1a2e, #16213e);
                    color: #00ff00; 
                    text-align: center; 
                    padding: 50px;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .container {{
                    background: rgba(0, 0, 0, 0.8);
                    border: 2px solid #00ff00;
                    border-radius: 15px;
                    padding: 40px;
                    max-width: 600px;
                    box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
                }}
                h1 {{ color: #00ff00; text-shadow: 0 0 10px #00ff00; }}
                .status {{ color: #ffaa00; }}
                .loading {{
                    display: inline-flex;
                    gap: 4px;
                    margin: 20px 0;
                }}
                .loading span {{
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background: #6366f1;
                    animation: loading 1.4s ease-in-out infinite both;
                }}
                .loading span:nth-child(1) {{ animation-delay: -0.32s; }}
                .loading span:nth-child(2) {{ animation-delay: -0.16s; }}
                @keyframes loading {{
                    0%, 80%, 100% {{ transform: scale(0); }}
                    40% {{ transform: scale(1); }}
                }}
                a {{ color: #6366f1; text-decoration: none; }}
                a:hover {{ color: #00ff00; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ CIPHER Platform</h1>
                <h2 class="status">System Status: {_system_status.upper()}</h2>
                <div class="loading"><span></span><span></span><span></span></div>
                <p>Frontend module is loading. Core API endpoints are functional.</p>
                <p><a href="/api/docs">📚 API Documentation</a></p>
                <p><a href="/health">🏥 Health Check</a></p>
                <p><a href="/api/stats">📊 System Stats</a></p>
                <script>
                    // Auto-refresh every 10 seconds until frontend loads
                    setTimeout(() => location.reload(), 10000);
                </script>
            </div>
        </body>
        </html>
        """, status_code=200)
        
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
        content=create_error_response(
            "Internal server error",
            "An unexpected error occurred in CIPHER platform"
        )
    )

# Custom 404 handler
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Custom 404 handler with helpful information"""
    return JSONResponse(
        status_code=404,
        content={
            "error": "Endpoint not found",
            "message": f"The requested endpoint {request.url.path} does not exist",
            "available_endpoints": [
                "/", "/dashboard", "/health", "/health/live",
                "/api/stats", "/api/insights", "/api/analytics", 
                "/api/monitoring/status", "/api/docs"
            ],
            "platform": "CIPHER Cybersecurity Intelligence Platform"
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
