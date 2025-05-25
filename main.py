from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import logging
import os
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat intelligence monitoring and analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Global state variables
_system_startup_time = datetime.now(timezone.utc)
_initialization_task = None
_utils_available = False
_monitoring_active = False

async def initialize_system_background():
    """Initialize all system components in background"""
    global _utils_available, _monitoring_active
    
    try:
        logger.info("🛡️ Initializing CIPHER Platform...")
        
        # Wait for HTTP server to start
        await asyncio.sleep(2)
        
        # Initialize utils module
        try:
            import utils
            await utils.initialize_all_systems()
            _utils_available = True
            logger.info("✅ Utils module initialized")
            
            # Start monitoring system
            _monitoring_active = await utils.start_monitoring_system()
            if _monitoring_active:
                logger.info("✅ CIPHER monitoring system operational")
            else:
                logger.warning("⚠️ CIPHER running in data-only mode")
                
        except Exception as e:
            logger.error(f"System initialization failed: {e}")
            _utils_available = False
            _monitoring_active = False
        
        logger.info("🎉 CIPHER Platform initialization completed")
        
    except Exception as e:
        logger.error(f"Background initialization error: {e}")

@app.on_event("startup")
async def startup_event():
    """Fast startup with background initialization"""
    global _initialization_task
    
    try:
        logger.info("🛡️ CIPHER Platform starting...")
        
        # Start background initialization
        _initialization_task = asyncio.create_task(initialize_system_background())
        
        logger.info("✅ CIPHER Platform HTTP server ready")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown"""
    try:
        logger.info("🛑 Shutting down CIPHER Platform...")
        
        if _initialization_task and not _initialization_task.done():
            _initialization_task.cancel()
        
        if _utils_available:
            try:
                import utils
                await utils.stop_monitoring_system()
                logger.info("✅ CIPHER monitoring stopped")
            except Exception as e:
                logger.warning(f"Error stopping monitoring: {e}")
                
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
            "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com"
        }
    )

@app.get("/health")
async def readiness_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy",
        "service": "cipher-intelligence",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
        "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
        "checks": {
            "utils_available": _utils_available,
            "monitoring_active": _monitoring_active,
            "initialization": "complete" if _initialization_task and _initialization_task.done() else "running"
        }
    }
    
    # Check subsystems if utils available
    if _utils_available:
        try:
            import utils
            health_status["checks"]["bigquery"] = "connected" if utils.is_bigquery_available() else "unavailable"
            health_status["checks"]["telegram"] = "connected" if utils.is_telegram_connected() else "disconnected"
            health_status["checks"]["gemini"] = "available" if utils.is_gemini_available() else "unavailable"
        except Exception as e:
            logger.warning(f"Health check error: {e}")
            health_status["checks"]["subsystems"] = "error"
            health_status["status"] = "degraded"
    else:
        health_status["checks"]["bigquery"] = "initializing"
        health_status["checks"]["telegram"] = "initializing"
        health_status["checks"]["gemini"] = "initializing"
    
    return JSONResponse(status_code=200, content=health_status)

@app.get("/api/stats")
async def get_system_stats():
    """Get comprehensive system statistics"""
    try:
        if _utils_available:
            import utils
            stats = await utils.get_comprehensive_stats()
            stats["system_status"] = "operational" if _monitoring_active else "data_only"
        else:
            stats = {
                "total_messages": 0,
                "processed_today": 0,
                "high_threats": 0,
                "critical_threats": 0,
                "monitoring_active": False,
                "system_status": "initializing",
                "data_source": "system_initializing"
            }
        
        stats["last_updated"] = datetime.now(timezone.utc).isoformat()
        return stats
        
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return {
            "error": "Stats temporarily unavailable",
            "system_status": "error",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

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
                "status": "operational" if _monitoring_active else "data_only",
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
        else:
            return {
                "insights": [],
                "count": 0,
                "status": "initializing",
                "message": "System initializing, threat intelligence will be available shortly"
            }
            
    except Exception as e:
        logger.error(f"Insights API error: {e}")
        return {
            "insights": [],
            "count": 0,
            "status": "error",
            "error": str(e)
        }

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
                "status": "initializing",
                "channels": ["@DarkfeedNews", "@breachdetector", "@secharvester"],
                "message": "Monitoring system initializing"
            }
        
        status["service_info"] = {
            "platform": "CIPHER Cybersecurity Intelligence Platform",
            "version": "1.0.0",
            "project": "primal-chariot-382610",
            "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com"
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return {
            "active": False,
            "status": "error",
            "error": str(e)
        }

@app.get("/api/analytics")
async def get_threat_analytics():
    """Get comprehensive threat analytics"""
    try:
        if _utils_available:
            import utils
            analytics = await utils.get_threat_analytics()
            return analytics
        else:
            return {
                "status": "initializing",
                "message": "Analytics will be available after system initialization",
                "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "categories": {},
                "summary": {"total_threats": 0, "high_priority": 0}
            }
            
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return {"status": "error", "error": str(e)}

# Include frontend router
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router)
    logger.info("✅ Frontend router included")
except ImportError as e:
    logger.error(f"Frontend router not available: {e}")
except Exception as e:
    logger.error(f"Frontend router error: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
