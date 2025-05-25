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
import json

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app with fast startup
app = FastAPI(
    title="CIPHER - Cybersecurity Intelligence Platform",
    description="Real-time cybersecurity threat monitoring and analysis",
    version="1.0.0"
)

# Global state - designed for fast startup
_system_startup_time = datetime.now(timezone.utc)
_app_status = {
    "startup_complete": False,
    "bigquery_available": False,
    "monitoring_active": False,
    "utils_available": False,
    "initialization_started": False,
    "last_check": None
}

# Lightweight clients for fast startup
_bigquery_client = None
_templates = None

def get_app_status() -> Dict[str, Any]:
    """Get current application status"""
    return {
        **_app_status,
        "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def init_templates():
    """Initialize templates if directory exists"""
    global _templates
    try:
        if os.path.exists("templates"):
            _templates = Jinja2Templates(directory="templates")
            logger.info("Templates initialized")
        else:
            logger.warning("Templates directory not found")
    except Exception as e:
        logger.warning(f"Template initialization failed: {e}")

def init_bigquery_client() -> Optional[bigquery.Client]:
    """Initialize BigQuery client with quick timeout"""
    global _bigquery_client, _app_status
    
    try:
        if _bigquery_client is None:
            credentials, project = default()
            _bigquery_client = bigquery.Client(project=project, credentials=credentials)
            
            # Quick test with short timeout
            test_query = "SELECT 1 as test"
            query_job = _bigquery_client.query(test_query)
            query_job.result(timeout=5)  # Short timeout for startup
            
            _app_status["bigquery_available"] = True
            logger.info("✅ BigQuery client initialized")
            
        return _bigquery_client
    except Exception as e:
        logger.warning(f"BigQuery initialization failed (will retry later): {e}")
        _app_status["bigquery_available"] = False
        return None

async def background_initialization():
    """Initialize heavy components in background after startup"""
    global _app_status
    
    if _app_status["initialization_started"]:
        return
    
    _app_status["initialization_started"] = True
    logger.info("🚀 Starting background initialization...")
    
    try:
        # Give the HTTP server time to start
        await asyncio.sleep(2)
        
        # Initialize BigQuery with retries
        if not _app_status["bigquery_available"]:
            init_bigquery_client()
        
        # Try to initialize monitoring system
        try:
            logger.info("🔍 Attempting to initialize monitoring system...")
            import utils
            _app_status["utils_available"] = True
            
            # Setup BigQuery tables
            await utils.setup_bigquery_tables()
            logger.info("✅ BigQuery tables initialized")
            
            # Start monitoring (non-blocking)
            asyncio.create_task(start_monitoring_system())
            
        except ImportError as e:
            logger.warning(f"Utils module not available: {e}")
            _app_status["utils_available"] = False
        except Exception as e:
            logger.error(f"Monitoring initialization failed: {e}")
        
        _app_status["startup_complete"] = True
        logger.info("🎉 Background initialization completed")
        
    except Exception as e:
        logger.error(f"Background initialization error: {e}")
        # Don't fail the service, just log the error

async def start_monitoring_system():
    """Start monitoring system in background"""
    try:
        import utils
        monitoring_success = await utils.start_background_monitoring()
        if monitoring_success:
            _app_status["monitoring_active"] = True
            logger.info("✅ CIPHER monitoring system started")
        else:
            logger.warning("⚠️ Monitoring system failed to start")
    except Exception as e:
        logger.error(f"Monitoring system error: {e}")

@app.on_event("startup")
async def startup_event():
    """Fast startup - only essential components"""
    try:
        logger.info("🛡️ CIPHER Platform - Fast Startup Initiated")
        
        # Initialize templates
        init_templates()
        
        # Start background initialization (non-blocking)
        asyncio.create_task(background_initialization())
        
        logger.info("✅ CIPHER Platform HTTP server ready")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        # Don't fail startup, log and continue

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown"""
    try:
        logger.info("🛑 CIPHER Platform shutting down...")
        
        if _app_status["utils_available"]:
            try:
                import utils
                await utils.stop_background_monitoring()
            except:
                pass
                
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# FAST HEALTH CHECKS - Always respond quickly
@app.get("/health/live")
async def liveness_check():
    """Lightweight liveness check - always returns quickly"""
    return JSONResponse(
        status_code=200,
        content={
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "cipher-intelligence",
            "uptime_seconds": int((datetime.now(timezone.utc) - _system_startup_time).total_seconds())
        }
    )

@app.get("/health")
async def readiness_check():
    """Fast readiness check"""
    status = get_app_status()
    
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "cipher-intelligence",
        "version": "1.0.0",
        "uptime_seconds": status["uptime_seconds"],
        "checks": {
            "http_server": "ready",
            "bigquery": "connected" if status["bigquery_available"] else "initializing",
            "monitoring": "active" if status["monitoring_active"] else "starting",
            "background_init": "complete" if status["startup_complete"] else "running"
        },
        "app_status": status
    }
    
    return JSONResponse(status_code=200, content=health_status)

@app.get("/api/stats")
async def get_stats():
    """Get cybersecurity statistics with graceful fallback"""
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610')
    dataset_id = os.getenv('DATASET_ID', 'telegram_data')
    table_id = os.getenv('TABLE_ID', 'processed_messages')
    
    # Default stats for fast response
    default_stats = {
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
        "monitoring_active": _app_status["monitoring_active"],
        "data_source": "initializing",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "system_status": get_app_status()
    }
    
    # Quick return if BigQuery not ready
    if not _app_status["bigquery_available"] or not _bigquery_client:
        default_stats["data_source"] = "bigquery_initializing"
        return default_stats
    
    try:
        # Fast query with timeout
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
        
        query_job = _bigquery_client.query(query)
        row = next(iter(query_job.result(timeout=10)), None)  # 10 second timeout
        
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
                "monitoring_active": _app_status["monitoring_active"],
                "data_source": "bigquery",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "system_status": get_app_status()
            }
            logger.info(f"✅ Stats retrieved: {stats['total_messages']} messages")
            return stats
        else:
            default_stats["data_source"] = "bigquery_empty"
            return default_stats
            
    except Exception as e:
        logger.warning(f"Stats query failed: {e}")
        default_stats["data_source"] = "bigquery_error"
        default_stats["error"] = str(e)
        return default_stats

@app.get("/api/insights")
async def get_cybersecurity_insights():
    """Get latest cybersecurity insights with fast fallback"""
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610')
    dataset_id = os.getenv('DATASET_ID', 'telegram_data')
    table_id = os.getenv('TABLE_ID', 'processed_messages')
    
    default_response = {
        "insights": [],
        "count": 0,
        "status": "initializing",
        "data_source": "bigquery_initializing",
        "system_status": get_app_status()
    }
    
    if not _app_status["bigquery_available"] or not _bigquery_client:
        return default_response
    
    try:
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
        
        query_job = _bigquery_client.query(query)
        results = query_job.result(timeout=15)  # 15 second timeout
        
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
        
        return {
            "insights": insights,
            "count": len(insights),
            "status": "operational" if _app_status["monitoring_active"] and insights else "data_available",
            "data_source": "bigquery",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "system_status": get_app_status()
        }
        
    except Exception as e:
        logger.warning(f"Insights query failed: {e}")
        default_response["data_source"] = "bigquery_error"
        default_response["error"] = str(e)
        return default_response

@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get monitoring status - always fast response"""
    status = get_app_status()
    
    return {
        "active": status["monitoring_active"],
        "channels": [
            {"name": "@DarkfeedNews", "status": "active" if status["monitoring_active"] else "initializing", "type": "threat_intelligence"},
            {"name": "@breachdetector", "status": "active" if status["monitoring_active"] else "initializing", "type": "breach_monitor"},
            {"name": "@secharvester", "status": "active" if status["monitoring_active"] else "initializing", "type": "security_news"}
        ],
        "last_update": datetime.now(timezone.utc).isoformat(),
        "system_health": "operational" if status["startup_complete"] else "initializing",
        "utils_available": status["utils_available"],
        "bigquery_available": status["bigquery_available"],
        "initialization_phase": "complete" if status["startup_complete"] else "running",
        "telegram_session": "authenticated" if status["utils_available"] else "checking"
    }

@app.get("/api/system/status")
async def get_system_status():
    """Detailed system status for debugging"""
    return {
        "cipher_platform": "active",
        "app_status": get_app_status(),
        "environment": {
            "project_id": os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610'),
            "dataset_id": os.getenv('DATASET_ID', 'telegram_data'),
            "table_id": os.getenv('TABLE_ID', 'processed_messages'),
            "port": os.getenv('PORT', '8080')
        },
        "capabilities": {
            "bigquery_integration": _app_status["bigquery_available"],
            "telegram_monitoring": _app_status["monitoring_active"],
            "ai_analysis": _app_status["utils_available"],
            "real_time_dashboard": True,
            "threat_intelligence": _app_status["monitoring_active"]
        }
    }

@app.get("/", response_class=HTMLResponse)
async def root():
    """Fast-loading root page"""
    status = get_app_status()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CIPHER - Cybersecurity Intelligence Platform</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .header {{ text-align: center; border: 2px solid #00ff00; padding: 30px; margin-bottom: 30px; }}
            .logo {{ font-size: 4em; margin-bottom: 10px; }}
            .status {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
            .card {{ border: 1px solid #00ff00; padding: 20px; background: rgba(0, 255, 0, 0.05); }}
            .online {{ color: #00ff00; }}
            .warning {{ color: #ffff00; }}
            .links a {{ color: #00ff00; text-decoration: none; margin: 0 15px; font-size: 1.1em; }}
            .links a:hover {{ background: #00ff00; color: #000; padding: 5px; }}
            .progress {{ background: #333; height: 20px; margin: 10px 0; }}
            .progress-bar {{ background: #00ff00; height: 100%; transition: width 2s; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ CIPHER</div>
                <h1>Cybersecurity Intelligence Platform</h1>
                <p>Real-time Threat Monitoring & Analysis System</p>
            </div>
            
            <div class="status">
                <div class="card">
                    <h3>🚀 System Status</h3>
                    <p class="{'online' if status['startup_complete'] else 'warning'}">
                        ● {'OPERATIONAL' if status['startup_complete'] else 'INITIALIZING'}
                    </p>
                    <p>Uptime: {status['uptime_seconds']} seconds</p>
                </div>
                
                <div class="card">
                    <h3>📊 Data Pipeline</h3>
                    <p class="{'online' if status['bigquery_available'] else 'warning'}">
                        ● BigQuery: {'CONNECTED' if status['bigquery_available'] else 'CONNECTING'}
                    </p>
                    <p>Dataset: telegram_data</p>
                </div>
                
                <div class="card">
                    <h3>📡 Monitoring</h3>
                    <p class="{'online' if status['monitoring_active'] else 'warning'}">
                        ● Telegram: {'ACTIVE' if status['monitoring_active'] else 'STARTING'}
                    </p>
                    <p>Channels: 3 cybersecurity feeds</p>
                </div>
                
                <div class="card">
                    <h3>🤖 AI Analysis</h3>
                    <p class="{'online' if status['utils_available'] else 'warning'}">
                        ● Gemini AI: {'READY' if status['utils_available'] else 'LOADING'}
                    </p>
                    <p>Threat Intelligence Processing</p>
                </div>
            </div>
            
            <div class="card">
                <h3>🔗 Quick Access</h3>
                <div class="links">
                    <a href="/dashboard">📊 Dashboard</a>
                    <a href="/api/stats">📈 Statistics</a>
                    <a href="/api/monitoring/status">📡 Monitoring</a>
                    <a href="/api/system/status">🔧 System Status</a>
                    <a href="/health">🏥 Health Check</a>
                </div>
            </div>
            
            <div class="card">
                <h3>📡 Monitored Channels</h3>
                <p>🔴 @DarkfeedNews - Advanced Threat Intelligence</p>
                <p>🟠 @breachdetector - Data Breach Monitoring</p>
                <p>🔵 @secharvester - Security News & CVEs</p>
            </div>
        </div>
        
        <script>
            // Auto-refresh every 10 seconds during initialization
            if (document.body.innerHTML.includes('INITIALIZING') || document.body.innerHTML.includes('CONNECTING')) {{
                setTimeout(() => location.reload(), 10000);
            }}
        </script>
    </body>
    </html>
    """

@app.get("/dashboard")
async def dashboard():
    """Dashboard endpoint with template fallback"""
    try:
        if _templates and os.path.exists("templates/dashboard.html"):
            # Use template if available
            stats = await get_stats()
            monitoring = await get_monitoring_status()
            insights_data = await get_cybersecurity_insights()
            
            return _templates.TemplateResponse("dashboard.html", {
                "request": {"url": {"path": "/dashboard"}},
                "stats": stats,
                "insights": insights_data.get("insights", []),
                "monitoring": monitoring,
                "system_status": "operational" if monitoring.get("active") else "initializing",
                "page_title": "CIPHER - Cybersecurity Intelligence Dashboard"
            })
        else:
            # Fallback dashboard
            return HTMLResponse(await get_simple_dashboard())
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return HTMLResponse(await get_simple_dashboard())

async def get_simple_dashboard():
    """Simple dashboard fallback"""
    stats = await get_stats()
    monitoring = await get_monitoring_status()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CIPHER Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ text-align: center; border: 2px solid #00ff00; padding: 20px; margin-bottom: 20px; }}
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
                {' '.join([f'<p>● {ch["name"]} - {ch["type"].replace("_", " ").title()}</p>' for ch in monitoring['channels']])}
            </div>
        </div>
        
        <script>
            // Auto-refresh every 30 seconds
            setTimeout(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    logger.info(f"🚀 Starting CIPHER Platform on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
