from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import logging
from google.cloud import bigquery
from google.auth import default
import os
import time
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CIPHER - Cybersecurity Intelligence Platform")

# Templates
templates = Jinja2Templates(directory="templates")

# Global state variables
_bigquery_client = None
_bigquery_available = False
_last_bigquery_check = None
_system_startup_time = datetime.now(timezone.utc)
_monitoring_initialized = False
_utils_available = False
_initialization_task = None

def get_bigquery_client() -> Optional[bigquery.Client]:
    """Get BigQuery client with proper error handling and caching"""
    global _bigquery_client, _bigquery_available, _last_bigquery_check
    
    # Check every 5 minutes to avoid constant retries
    now = datetime.now(timezone.utc)
    if _last_bigquery_check and (now - _last_bigquery_check).seconds < 300:
        return _bigquery_client if _bigquery_available else None
    
    _last_bigquery_check = now
    
    if _bigquery_client is None:
        try:
            credentials, project = default()
            _bigquery_client = bigquery.Client(project=project, credentials=credentials)
            
            # Test with a simple query
            test_query = "SELECT 1 as test"
            query_job = _bigquery_client.query(test_query)
            query_job.result(timeout=10)
            
            _bigquery_available = True
            logger.info("BigQuery client initialized successfully")
            
        except Exception as e:
            logger.warning(f"BigQuery initialization failed: {e}")
            _bigquery_available = False
            _bigquery_client = None
    
    return _bigquery_client if _bigquery_available else None

async def initialize_system_background():
    """Initialize system components in background after HTTP server starts"""
    global _monitoring_initialized, _utils_available
    
    try:
        logger.info("🛡️ Starting CIPHER Platform background initialization...")
        
        # Give HTTP server time to start first
        await asyncio.sleep(3)
        
        # Initialize BigQuery client
        get_bigquery_client()
        
        # Try to initialize utils module and monitoring system
        try:
            import utils
            _utils_available = True
            logger.info("✅ Utils module available")
            
            # Initialize BigQuery tables
            await utils.setup_bigquery_tables()
            logger.info("✅ BigQuery tables initialized")
            
            # Start background monitoring
            monitoring_success = await utils.start_background_monitoring()
            if monitoring_success:
                logger.info("✅ CIPHER monitoring system started successfully")
                _monitoring_initialized = True
            else:
                logger.warning("⚠️ CIPHER monitoring system failed to start - running in data-only mode")
                _monitoring_initialized = False
                
        except ImportError as e:
            logger.warning(f"Utils module not available: {e}")
            _utils_available = False
            _monitoring_initialized = False
        except Exception as e:
            logger.error(f"Monitoring initialization failed: {e}")
            _monitoring_initialized = False
        
        logger.info("🎉 CIPHER Platform initialization completed")
        
    except Exception as e:
        logger.error(f"Background initialization error: {e}")

@app.on_event("startup")
async def startup_event():
    """Fast startup - defer heavy initialization to background"""
    global _initialization_task
    
    try:
        logger.info("🛡️ CIPHER Platform HTTP server starting...")
        
        # Start background initialization without waiting
        _initialization_task = asyncio.create_task(initialize_system_background())
        
        logger.info("✅ CIPHER Platform HTTP server ready")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    try:
        logger.info("🛑 Shutting down CIPHER Platform...")
        
        # Cancel background initialization if still running
        if _initialization_task and not _initialization_task.done():
            _initialization_task.cancel()
        
        if _utils_available:
            try:
                import utils
                await utils.stop_background_monitoring()
                logger.info("✅ CIPHER monitoring stopped")
            except Exception as e:
                logger.warning(f"Error stopping monitoring: {e}")
                
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

@app.get("/health/live")
async def liveness_check():
    """Lightweight liveness check - confirms service is running"""
    return JSONResponse(
        status_code=200,
        content={
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "cipher-intelligence",
            "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
            "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com"
        }
    )

@app.get("/health")
async def readiness_check():
    """Readiness check with graceful BigQuery handling"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "cipher-intelligence",
        "version": "1.0.0",
        "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
        "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
        "checks": {
            "bigquery": "unknown",
            "monitoring": "active" if _monitoring_initialized else "initializing",
            "api_endpoints": "ready",
            "utils_available": _utils_available,
            "initialization": "complete" if _initialization_task and _initialization_task.done() else "running"
        }
    }
    
    # Non-blocking BigQuery check
    try:
        client = get_bigquery_client()
        if client and _bigquery_available:
            health_status["checks"]["bigquery"] = "connected"
        else:
            health_status["checks"]["bigquery"] = "unavailable"
            health_status["status"] = "degraded"
    except Exception as e:
        logger.warning(f"BigQuery health check error: {e}")
        health_status["checks"]["bigquery"] = "error"
        health_status["status"] = "degraded"
    
    return JSONResponse(status_code=200, content=health_status)

@app.get("/api/stats")
async def get_stats():
    """Get cybersecurity statistics with robust fallback - FIXED SCHEMA"""
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610')
    dataset_id = os.getenv('DATASET_ID', 'telegram_data')
    table_id = os.getenv('TABLE_ID', 'processed_messages')
    
    # Default empty stats
    empty_stats = {
        "total_messages": 0,
        "processed_today": 0,
        "high_threats": 0,
        "critical_threats": 0,
        "unique_channels": 3,
        "avg_urgency": 0.0,
        "data_breaches": 0,
        "malware_alerts": 0,
        "vulnerabilities": 0,
        "cve_mentions": 0,
        "apt_activity": 0,
        "ransomware_alerts": 0,
        "monitoring_active": _monitoring_initialized,
        "data_source": "bigquery_empty",
        "last_updated": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        client = get_bigquery_client()
        if not client or not _bigquery_available:
            logger.info("BigQuery unavailable, returning empty stats")
            empty_stats["data_source"] = "bigquery_unavailable"
            return empty_stats
        
        # FIXED: Use correct field names from schema (processed_date instead of timestamp)
        query = f"""
        SELECT 
            COUNT(*) as total_messages,
            COUNTIF(DATE(processed_date) = CURRENT_DATE()) as processed_today,
            COUNTIF(threat_level IN ('high', 'critical')) as high_threats,
            COUNTIF(threat_level = 'critical') as critical_threats,
            COUNT(DISTINCT chat_username) as unique_channels,
            AVG(COALESCE(urgency_score, 0)) as avg_urgency,
            COUNTIF(category = 'data_breach') as data_breaches,
            COUNTIF(category = 'malware') as malware_alerts,
            COUNTIF(category = 'vulnerability') as vulnerabilities,
            COUNTIF(ARRAY_LENGTH(cve_references) > 0) as cve_mentions,
            COUNTIF(category = 'apt') as apt_activity,
            COUNTIF(category = 'ransomware') as ransomware_alerts
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
        """
        
        try:
            query_job = client.query(query)
            row = next(iter(query_job.result(timeout=30)), None)
            
            if row:
                stats = {
                    "total_messages": int(row.total_messages) if row.total_messages else 0,
                    "processed_today": int(row.processed_today) if row.processed_today else 0,
                    "high_threats": int(row.high_threats) if row.high_threats else 0,
                    "critical_threats": int(row.critical_threats) if row.critical_threats else 0,
                    "unique_channels": int(row.unique_channels) if row.unique_channels else 3,
                    "avg_urgency": float(row.avg_urgency) if row.avg_urgency else 0.0,
                    "data_breaches": int(row.data_breaches) if row.data_breaches else 0,
                    "malware_alerts": int(row.malware_alerts) if row.malware_alerts else 0,
                    "vulnerabilities": int(row.vulnerabilities) if row.vulnerabilities else 0,
                    "cve_mentions": int(row.cve_mentions) if row.cve_mentions else 0,
                    "apt_activity": int(row.apt_activity) if row.apt_activity else 0,
                    "ransomware_alerts": int(row.ransomware_alerts) if row.ransomware_alerts else 0,
                    "monitoring_active": _monitoring_initialized,
                    "data_source": "bigquery",
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
                logger.info(f"✅ BigQuery stats retrieved: {stats['total_messages']} messages, {stats['high_threats']} high threats")
            else:
                stats = empty_stats
                
        except Exception as query_error:
            logger.error(f"BigQuery stats error: {query_error}")
            stats = empty_stats
            stats["data_source"] = "bigquery_error"
            stats["error"] = str(query_error)
        
        return stats

    except Exception as e:
        logger.error(f"Failed to get cybersecurity stats: {e}")
        empty_stats["data_source"] = "error"
        return empty_stats

@app.get("/api/insights")
async def get_cybersecurity_insights():
    """Get latest cybersecurity insights - FIXED SCHEMA"""
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610')
    dataset_id = os.getenv('DATASET_ID', 'telegram_data')
    table_id = os.getenv('TABLE_ID', 'processed_messages')
    
    empty_response = {
        "insights": [],
        "count": 0,
        "status": "no_data",
        "data_source": "bigquery_empty"
    }
    
    try:
        client = get_bigquery_client()
        if not client or not _bigquery_available:
            empty_response["data_source"] = "bigquery_unavailable"
            return empty_response
        
        # FIXED: Use correct field names from schema
        query = f"""
        SELECT 
            message_id,
            chat_username,
            message_text,
            message_date,
            processed_date,
            gemini_analysis,
            sentiment,
            key_topics,
            urgency_score,
            category,
            threat_level,
            threat_type,
            channel_type,
            cve_references,
            malware_families,
            threat_actors
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE processed_date >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        ORDER BY processed_date DESC, urgency_score DESC
        LIMIT 50
        """
        
        query_job = client.query(query)
        results = query_job.result(timeout=30)
        
        insights = []
        for row in results:
            insight = {
                "message_id": row.message_id,
                "chat_username": row.chat_username or "@Unknown",
                "message_text": (row.message_text or "")[:1000],
                "message_date": row.message_date.isoformat() if row.message_date else None,
                "processed_date": row.processed_date.isoformat() if row.processed_date else None,
                "gemini_analysis": row.gemini_analysis or "",
                "sentiment": row.sentiment or "neutral",
                "key_topics": list(row.key_topics) if row.key_topics else [],
                "urgency_score": float(row.urgency_score) if row.urgency_score is not None else 0.0,
                "category": row.category or "other",
                "threat_level": row.threat_level or "low",
                "threat_type": row.threat_type or "unknown",
                "channel_type": row.channel_type or "unknown",
                "cve_references": list(row.cve_references) if row.cve_references else [],
                "malware_families": list(row.malware_families) if row.malware_families else [],
                "threat_actors": list(row.threat_actors) if row.threat_actors else []
            }
            insights.append(insight)
        
        logger.info(f"✅ Retrieved {len(insights)} cybersecurity insights")
        
        return {
            "insights": insights,
            "count": len(insights),
            "status": "operational" if _monitoring_initialized and insights else "data_only",
            "data_source": "bigquery",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get cybersecurity insights: {e}")
        empty_response["data_source"] = "error"
        empty_response["error"] = str(e)
        return empty_response

@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get monitoring status"""
    return {
        "active": _monitoring_initialized,
        "channels": [
            {"name": "@DarkfeedNews", "status": "active" if _monitoring_initialized else "inactive", "type": "threat_intelligence"},
            {"name": "@breachdetector", "status": "active" if _monitoring_initialized else "inactive", "type": "breach_monitor"},
            {"name": "@secharvester", "status": "active" if _monitoring_initialized else "inactive", "type": "security_news"}
        ],
        "last_update": datetime.now(timezone.utc).isoformat(),
        "system_health": "operational" if _monitoring_initialized else "data_only",
        "service_account": "cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com",
        "utils_available": _utils_available,
        "bigquery_available": _bigquery_available,
        "telegram_session": "authenticated" if _utils_available else "checking"
    }

@app.get("/api/threat-analytics")
async def get_threat_analytics():
    """Get threat analytics summary"""
    try:
        if _utils_available:
            import utils
            insights = await utils.get_recent_insights(limit=100)
            stats = await get_stats()
            
            # Use frontend.py analytics if available
            try:
                from frontend import calculate_threat_analytics
                analytics = calculate_threat_analytics(insights, stats)
                return analytics
            except ImportError:
                pass
        
        # Fallback empty analytics
        return {
            "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "categories": {"threat_intel": 0, "data_breach": 0, "vulnerability": 0, "malware": 0, "ransomware": 0, "apt": 0, "phishing": 0, "other": 0},
            "channel_activity": {},
            "top_threats": [],
            "active_campaigns": [],
            "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0}
        }
        
    except Exception as e:
        logger.error(f"Threat analytics error: {e}")
        return {"error": "Analytics unavailable"}

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CIPHER - Cybersecurity Intelligence Platform</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; background: #0f1419; color: white; text-align: center; padding: 50px; }
            .logo { font-size: 3em; color: #6366f1; margin-bottom: 20px; }
            .subtitle { color: #888; margin-bottom: 30px; }
            .links a { color: #6366f1; text-decoration: none; margin: 0 20px; font-size: 1.2em; }
            .status { background: rgba(99, 102, 241, 0.1); padding: 20px; border-radius: 10px; margin: 20px 0; }
            .service-info { background: rgba(0, 255, 0, 0.1); padding: 10px; border-radius: 5px; margin: 10px 0; font-size: 0.8em; }
        </style>
    </head>
    <body>
        <div class="logo">🛡️ CIPHER</div>
        <div class="subtitle">Cybersecurity Intelligence Platform</div>
        <div class="status">
            <p>✅ System Operational</p>
            <p>🔍 Monitoring Active</p>
        </div>
        <div class="service-info">
            <p>🔧 Service Account: cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com</p>
            <p>📊 BigQuery Dataset: telegram_data</p>
        </div>
        <div class="links">
            <a href="/dashboard">📊 Dashboard</a>
            <a href="/api/stats">📈 Stats API</a>
            <a href="/health">🏥 Health Check</a>
        </div>
    </body>
    </html>
    """

@app.get("/dashboard", response_class=HTMLResponse)
async def production_dashboard(request: Request):
    """Production CIPHER dashboard"""
    try:
        # Try to use the frontend module if available
        if _utils_available:
            try:
                from frontend import cipher_dashboard
                # Use the frontend dashboard function directly
                return await cipher_dashboard(request)
            except ImportError:
                logger.warning("Frontend module not available, using fallback")
            except Exception as e:
                logger.error(f"Frontend dashboard error: {e}")
        
        # Fallback to template if available
        try:
            stats = await get_stats()
            monitoring = await get_monitoring_status()
            insights_response = await get_cybersecurity_insights()
            insights = insights_response.get("insights", [])
            
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "stats": stats,
                "insights": insights,
                "monitoring": monitoring,
                "system_status": "operational" if monitoring.get("active") else "initializing",
                "page_title": "CIPHER - Cybersecurity Intelligence Dashboard",
                "current_time": datetime.now().isoformat(),
                "PROJECT_ID": "primal-chariot-382610"
            })
        except Exception as e:
            logger.warning(f"Template dashboard failed: {e}")
            
            # Simple HTML fallback
            stats = await get_stats()
            monitoring = await get_monitoring_status()
            
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>CIPHER Dashboard</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }}
                    .container {{ max-width: 1200px; margin: 0 auto; }}
                    .header {{ text-align: center; border: 2px solid #00ff00; padding: 30px; margin-bottom: 30px; }}
                    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                    .card {{ border: 1px solid #00ff00; padding: 20px; background: rgba(0, 255, 0, 0.05); }}
                    .metric {{ font-size: 2em; color: #ffffff; margin: 10px 0; }}
                    .status-online {{ color: #00ff00; }}
                    .status-warning {{ color: #ffff00; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🛡️ CIPHER - Cybersecurity Intelligence Dashboard</h1>
                        <p>Real-time Threat Monitoring System</p>
                    </div>
                    
                    <div class="grid">
                        <div class="card">
                            <h3>📊 Intelligence Summary</h3>
                            <div class="metric">{stats['total_messages']:,}</div>
                            <p>Total Messages Processed</p>
                            <p>Today: {stats['processed_today']}</p>
                            <p>High Threats: {stats['high_threats']}</p>
                        </div>
                        
                        <div class="card">
                            <h3>🚨 Threat Levels</h3>
                            <div class="metric">{stats['critical_threats']}</div>
                            <p>Critical Threats</p>
                            <p>APT Activity: {stats['apt_activity']}</p>
                            <p>Ransomware: {stats['ransomware_alerts']}</p>
                        </div>
                        
                        <div class="card">
                            <h3>🔍 Vulnerabilities</h3>
                            <div class="metric">{stats['cve_mentions']}</div>
                            <p>CVE References</p>
                            <p>Vulnerabilities: {stats['vulnerabilities']}</p>
                            <p>Data Breaches: {stats['data_breaches']}</p>
                        </div>
                        
                        <div class="card">
                            <h3>📡 Monitoring Status</h3>
                            <p class="{'status-online' if monitoring['active'] else 'status-warning'}">
                                ● {'ACTIVE' if monitoring['active'] else 'INITIALIZING'}
                            </p>
                            <p>Channels: {len(monitoring['channels'])}</p>
                            <p>System: {monitoring['system_health'].upper()}</p>
                        </div>
                    </div>
                    
                    <div class="card" style="margin-top: 20px;">
                        <h3>📡 Monitored Channels</h3>
                        <p>🔴 @DarkfeedNews - Advanced Threat Intelligence</p>
                        <p>🟠 @breachdetector - Data Breach Monitor</p>
                        <p>🔵 @secharvester - Security News & CVEs</p>
                    </div>
                </div>
                
                <script>
                    // Auto-refresh every 30 seconds
                    setTimeout(() => location.reload(), 30000);
                </script>
            </body>
            </html>
            """)
            
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return HTMLResponse("<h1>CIPHER Dashboard - Loading...</h1><script>setTimeout(() => location.reload(), 5000);</script>")

# Include the frontend router for additional API endpoints
try:
    from frontend import router as frontend_router
    app.include_router(frontend_router)
    logger.info("✅ Frontend router included successfully")
except ImportError as e:
    logger.warning(f"Frontend router not available: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
