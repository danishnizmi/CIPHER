from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import logging
from google.cloud import bigquery
from google.auth import default
import os
import time
from datetime import datetime, timezone
import asyncio
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

@app.on_event("startup")
async def startup_event():
    """Initialize CIPHER monitoring system on startup"""
    global _monitoring_initialized, _utils_available
    
    try:
        logger.info("🛡️ Starting CIPHER Platform initialization...")
        
        # Try to initialize utils module and monitoring system
        try:
            import utils
            _utils_available = True
            
            # Initialize BigQuery tables first
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
        
        # Initialize BigQuery client separately
        get_bigquery_client()
        
        logger.info("🎉 CIPHER Platform startup completed")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    try:
        logger.info("🛑 Shutting down CIPHER Platform...")
        
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
            "api_endpoints": "ready"
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
            logger.info("Service healthy but BigQuery unavailable")
    except Exception as e:
        logger.warning(f"BigQuery health check error: {e}")
        health_status["checks"]["bigquery"] = "error"
        health_status["status"] = "degraded"
    
    return JSONResponse(status_code=200, content=health_status)

@app.get("/api/stats")
async def get_stats():
    """Get cybersecurity statistics with robust fallback"""
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'primal-chariot-382610')
    dataset_id = os.getenv('DATASET_ID', 'telegram_data')
    table_id = os.getenv('TABLE_ID', 'processed_messages')
    
    # Default empty stats
    empty_stats = {
        "total_messages": 0,
        "processed_today": 0,
        "high_threats": 0,
        "critical_threats": 0,
        "unique_channels": 0,
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
                    "unique_channels": int(row.unique_channels) if row.unique_channels else 0,
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
            else:
                stats = empty_stats
                
        except Exception as query_error:
            logger.error(f"BigQuery query failed: {query_error}")
            stats = empty_stats
            stats["data_source"] = "bigquery_error"
        
        return stats

    except Exception as e:
        logger.error(f"Failed to get cybersecurity stats: {e}")
        empty_stats["data_source"] = "error"
        return empty_stats

@app.get("/api/insights")
async def get_cybersecurity_insights():
    """Get latest cybersecurity insights"""
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
        "bigquery_available": _bigquery_available
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
async def production_dashboard():
    """Production CIPHER dashboard with real-time data integration"""
    return """<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIPHER - Cybersecurity Intelligence Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        'cipher-blue': '#0066ff',
                        'cipher-purple': '#6366f1',
                        'cipher-dark': '#0f172a',
                        'cipher-darker': '#020617',
                    },
                    fontFamily: {
                        'mono': ['JetBrains Mono', 'Fira Code', 'Monaco', 'monospace'],
                        'sans': ['Inter', 'system-ui', 'sans-serif'],
                    },
                    animation: {
                        'fade-in': 'fadeIn 0.6s ease-out',
                        'slide-up': 'slideUp 0.6s ease-out',
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                        'glow': 'glow 2s ease-in-out infinite alternate',
                        'neon-pulse': 'neonPulse 2s ease-in-out infinite',
                    },
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(40px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes glow {
            from { box-shadow: 0 0 5px rgba(99, 102, 241, 0.5), 0 0 10px rgba(99, 102, 241, 0.3); }
            to { box-shadow: 0 0 10px rgba(99, 102, 241, 0.8), 0 0 20px rgba(99, 102, 241, 0.5); }
        }
        
        @keyframes neonPulse {
            0%, 100% { text-shadow: 0 0 5px rgba(99, 102, 241, 0.5), 0 0 10px rgba(99, 102, 241, 0.3), 0 0 15px rgba(99, 102, 241, 0.1); }
            50% { text-shadow: 0 0 10px rgba(99, 102, 241, 0.8), 0 0 20px rgba(99, 102, 241, 0.5), 0 0 30px rgba(99, 102, 241, 0.3); }
        }
        
        .glass-effect {
            backdrop-filter: blur(16px) saturate(180%);
            background-color: rgba(17, 25, 40, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.125);
        }
        
        .neon-text {
            color: #6366f1;
            text-shadow: 0 0 5px rgba(99, 102, 241, 0.5), 0 0 10px rgba(99, 102, 241, 0.3);
        }
        
        .cyber-grid {
            background-image: 
                linear-gradient(rgba(6, 182, 212, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(6, 182, 212, 0.1) 1px, transparent 1px);
            background-size: 20px 20px;
        }
        
        .hover-lift {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .hover-lift:hover {
            transform: translateY(-4px) scale(1.02);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }
        
        .status-indicator {
            position: relative;
        }
        
        .status-indicator::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: inherit;
            transform: translate(-50%, -50%);
            animation: ping 2s cubic-bezier(0, 0, 0.2, 1) infinite;
        }

        .progress-bar {
            background: linear-gradient(90deg, #6366f1, #8b5cf6, #06b6d4);
            background-size: 200% 100%;
            animation: progressFlow 2s linear infinite;
        }
        
        @keyframes progressFlow {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        .terminal-window {
            background: #0a0a0a;
            border-radius: 8px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(255, 255, 255, 0.05);
        }
        
        .terminal-header {
            background: #1a1a1a;
            padding: 12px 16px;
            border-bottom: 1px solid #333;
            border-radius: 8px 8px 0 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .terminal-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .insight-card {
            transition: all 0.3s ease;
            border-left: 4px solid transparent;
        }
        
        .insight-card:hover {
            border-left-color: #6366f1;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.05), rgba(139, 92, 246, 0.05));
            transform: translateX(8px);
        }

        .loading-dots {
            display: inline-flex;
            gap: 4px;
        }
        
        .loading-dots span {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #6366f1;
            animation: loadingDots 1.4s ease-in-out infinite both;
        }
        
        .loading-dots span:nth-child(1) { animation-delay: -0.32s; }
        .loading-dots span:nth-child(2) { animation-delay: -0.16s; }
        
        @keyframes loadingDots {
            0%, 80%, 100% { transform: scale(0); opacity: 0.5; }
            40% { transform: scale(1); opacity: 1; }
        }
    </style>
</head>
<body class="bg-gradient-to-br from-cipher-darker via-slate-900 to-cipher-dark text-white font-sans overflow-x-hidden" x-data="cipherDashboard()">
    
    <!-- Animated Background -->
    <div class="fixed inset-0 cyber-grid opacity-20 pointer-events-none"></div>
    <div class="fixed inset-0 bg-gradient-radial from-cipher-purple/5 via-transparent to-transparent pointer-events-none"></div>
    
    <!-- Navigation Header -->
    <nav class="glass-effect border-b border-white/10 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16 items-center">
                <div class="flex items-center space-x-4">
                    <div class="flex items-center space-x-3">
                        <div class="relative">
                            <div class="w-10 h-10 bg-gradient-to-r from-cipher-blue to-cipher-purple rounded-lg flex items-center justify-center animate-glow">
                                <i class="fas fa-shield-alt text-white text-lg"></i>
                            </div>
                            <div class="absolute -top-1 -right-1 w-4 h-4 rounded-full animate-pulse" 
                                 :class="getSystemStatusColor()"></div>
                        </div>
                        <div>
                            <h1 class="text-xl font-bold neon-text animate-neon-pulse">CIPHER</h1>
                            <p class="text-xs text-gray-400 font-mono">Cybersecurity Intelligence Platform</p>
                        </div>
                    </div>
                </div>
                
                <div class="flex items-center space-x-4">
                    <div class="hidden md:flex items-center space-x-6">
                        <div class="text-gray-300 text-sm font-medium">
                            <i class="fas fa-chart-line mr-2"></i>
                            <span x-text="(stats.total_messages || 0).toLocaleString()"></span> Signals
                        </div>
                        <div class="text-gray-300 text-sm font-medium">
                            <i class="fas fa-exclamation-triangle mr-2"></i>
                            <span x-text="stats.high_threats || 0"></span> High Threats
                        </div>
                    </div>
                    
                    <div class="flex items-center space-x-3">
                        <div class="flex items-center">
                            <div class="status-indicator w-3 h-3 bg-green-400 rounded-full mr-2"></div>
                            <span class="text-sm text-gray-400 font-mono" x-text="currentTime"></span>
                        </div>
                        <div class="text-xs text-gray-500 font-mono px-2 py-1 bg-white/5 rounded" 
                             :class="getSystemStatusTextColor()">
                            <span x-text="getSystemStatusText()"></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Hero Section -->
        <div class="mb-8 text-center">
            <h2 class="text-4xl font-bold bg-gradient-to-r from-cipher-blue via-cipher-purple to-cyan-400 bg-clip-text text-transparent mb-4 animate-fade-in">
                Cybersecurity Intelligence Monitor
            </h2>
            <p class="text-gray-400 max-w-2xl mx-auto animate-fade-in">
                Real-time monitoring and AI analysis of cybersecurity threats and intelligence feeds
            </p>
        </div>

        <!-- System Status Banner -->
        <div class="glass-effect rounded-xl p-6 border border-white/10 hover-lift animate-slide-up mb-8">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <div class="relative">
                        <div class="w-16 h-16 rounded-full flex items-center justify-center"
                             :class="getMonitoringStatusClass()">
                            <i class="fas fa-satellite-dish text-white text-2xl"></i>
                        </div>
                        <div class="absolute inset-0 rounded-full animate-ping opacity-20"
                             :class="getMonitoringPingClass()"></div>
                    </div>
                    
                    <div>
                        <h3 class="text-xl font-semibold mb-1">
                            <span :class="getMonitoringTextClass()" 
                                  x-text="getMonitoringStatusText()"></span>
                        </h3>
                        <p class="text-gray-400 mb-2">
                            <span x-text="getStatusDescription()"></span>
                        </p>
                        <div class="flex flex-wrap gap-2">
                            <span class="px-2 py-1 bg-red-500/20 text-red-400 border-red-500/30 text-xs rounded-full border font-mono">
                                @DarkfeedNews
                            </span>
                            <span class="px-2 py-1 bg-orange-500/20 text-orange-400 border-orange-500/30 text-xs rounded-full border font-mono">
                                @breachdetector
                            </span>
                            <span class="px-2 py-1 bg-blue-500/20 text-blue-400 border-blue-500/30 text-xs rounded-full border font-mono">
                                @secharvester
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="flex space-x-3">
                    <button @click="refreshData()" 
                            class="px-4 py-2 bg-gradient-to-r from-cipher-blue to-cipher-purple rounded-lg hover:from-cipher-purple hover:to-cipher-blue transition-all duration-300 transform hover:scale-105 shadow-lg">
                        <i class="fas fa-sync-alt mr-2" :class="{'animate-spin': isRefreshing}"></i>
                        <span x-text="isRefreshing ? 'Refreshing...' : 'Refresh'"></span>
                    </button>
                </div>
            </div>
        </div>

        <!-- Statistics Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Total Intelligence -->
            <div class="glass-effect rounded-xl p-6 hover-lift border border-white/10 animate-fade-in">
                <div class="flex items-center justify-between mb-4">
                    <div class="w-12 h-12 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                        <i class="fas fa-database text-white text-xl"></i>
                    </div>
                    <div class="text-right">
                        <div class="text-2xl font-bold neon-text" x-text="(stats.total_messages || 0).toLocaleString()">0</div>
                        <div class="text-xs text-gray-400 font-mono">TOTAL INTEL</div>
                    </div>
                </div>
                <div class="w-full bg-gray-700/30 rounded-full h-2">
                    <div class="progress-bar h-2 rounded-full" :style="`width: ${getProgressWidth(stats.total_messages)}%`"></div>
                </div>
            </div>

            <!-- High Threats -->
            <div class="glass-effect rounded-xl p-6 hover-lift border border-white/10 animate-fade-in" style="animation-delay: 0.1s;">
                <div class="flex items-center justify-between mb-4">
                    <div class="w-12 h-12 rounded-lg flex items-center justify-center"
                         :class="getThreatIconClass()">
                        <i class="fas fa-exclamation-triangle text-white text-xl"></i>
                    </div>
                    <div class="text-right">
                        <div class="text-2xl font-bold" 
                             :class="getThreatTextClass()" 
                             x-text="stats.high_threats || 0">0</div>
                        <div class="text-xs text-gray-400 font-mono">HIGH THREATS</div>
                    </div>
                </div>
                <div class="flex items-center text-xs" 
                     :class="getThreatStatusClass()">
                    <i :class="getThreatStatusIcon()" class="mr-1"></i>
                    <span class="font-mono" x-text="getThreatStatusText()"></span>
                </div>
            </div>

            <!-- Active Channels -->
            <div class="glass-effect rounded-xl p-6 hover-lift border border-white/10 animate-fade-in" style="animation-delay: 0.2s;">
                <div class="flex items-center justify-between mb-4">
                    <div class="w-12 h-12 bg-gradient-to-r from-purple-500 to-indigo-500 rounded-lg flex items-center justify-center">
                        <i class="fas fa-satellite-dish text-white text-xl"></i>
                    </div>
                    <div class="text-right">
                        <div class="text-2xl font-bold text-purple-400">
                            <span x-text="getActiveChannels()">0</span>
                            <span class="text-gray-500">/3</span>
                        </div>
                        <div class="text-xs text-gray-400 font-mono">CHANNELS</div>
                    </div>
                </div>
                <div class="flex space-x-1">
                    <div class="flex-1 h-2 rounded-full bg-purple-500 animate-pulse"></div>
                    <div class="flex-1 h-2 rounded-full bg-purple-500 animate-pulse" style="animation-delay: 0.1s;"></div>
                    <div class="flex-1 h-2 rounded-full bg-purple-500 animate-pulse" style="animation-delay: 0.2s;"></div>
                </div>
            </div>

            <!-- Processed Today -->
            <div class="glass-effect rounded-xl p-6 hover-lift border border-white/10 animate-fade-in" style="animation-delay: 0.3s;">
                <div class="flex items-center justify-between mb-4">
                    <div class="w-12 h-12 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-lg flex items-center justify-center">
                        <i class="fas fa-clock text-white text-xl"></i>
                    </div>
                    <div class="text-right">
                        <div class="text-2xl font-bold text-cyan-400" x-text="stats.processed_today || 0">0</div>
                        <div class="text-xs text-gray-400 font-mono">TODAY</div>
                    </div>
                </div>
                <div class="text-xs text-cyan-400 font-mono">
                    <i class="fas fa-sync-alt mr-1" :class="monitoring.active ? 'animate-spin' : ''"></i>
                    <span x-text="monitoring.active ? 'LIVE MONITORING' : 'STANDBY'"></span>
                </div>
            </div>
        </div>

        <!-- Real-time Intelligence Feed -->
        <div class="glass-effect rounded-xl border border-white/10 hover-lift">
            <!-- Header -->
            <div class="terminal-header">
                <div class="terminal-dot bg-red-500"></div>
                <div class="terminal-dot bg-yellow-500"></div>
                <div class="terminal-dot bg-green-500"></div>
                <div class="flex-1 flex items-center justify-between ml-4">
                    <div class="flex items-center space-x-3">
                        <span class="text-green-400 font-mono text-sm">CIPHER@intelligence:~$</span>
                        <span class="text-gray-400 text-sm">Real-time Intelligence Feed</span>
                        <span class="px-2 py-0.5 text-xs rounded border" 
                              :class="getDataBadgeClass()" 
                              x-show="insights && insights.length > 0">
                            <span x-text="insights.length"></span> SIGNALS
                        </span>
                    </div>
                    <div class="flex items-center space-x-3">
                        <div class="loading-dots" x-show="isLoading">
                            <span></span>
                            <span></span>
                            <span></span>
                        </div>
                        <span class="text-xs text-gray-400" x-show="isLoading">Scanning...</span>
                        <button @click="refreshData()" class="text-cipher-blue hover:text-cipher-purple transition-colors">
                            <i class="fas fa-sync-alt text-sm" :class="{'animate-spin': isRefreshing}"></i>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Content -->
            <div class="p-6">
                <!-- Insights List -->
                <div class="space-y-4 max-h-96 overflow-y-auto" x-show="insights && insights.length > 0">
                    <template x-for="(insight, index) in insights.slice(0, 10)" :key="index">
                        <div class="insight-card glass-effect rounded-lg p-4 animate-fade-in" 
                             :style="`animation-delay: ${index * 0.1}s`">
                            <div class="flex items-start space-x-4">
                                <!-- Threat Indicator -->
                                <div class="flex-shrink-0 relative">
                                    <div class="w-12 h-12 rounded-full flex items-center justify-center"
                                         :class="getThreatIcon(insight)">
                                        <i :class="getThreatIconClass(insight)" class="text-white"></i>
                                    </div>
                                    <div class="absolute inset-0 rounded-full animate-ping opacity-20"
                                         :class="getThreatIconBg(insight)"
                                         x-show="insight.urgency_score > 0.7"></div>
                                </div>

                                <div class="flex-1 min-w-0">
                                    <!-- Header -->
                                    <div class="flex items-center justify-between mb-3">
                                        <div class="flex items-center space-x-3">
                                            <span class="font-semibold text-cipher-blue font-mono" x-text="insight.chat_username || '@Unknown'"></span>
                                            
                                            <!-- Category Badge -->
                                            <span class="px-2 py-1 text-xs rounded-full border font-mono"
                                                  :class="getCategoryColor(insight.category)"
                                                  x-text="(insight.category || 'other').toUpperCase()"></span>
                                            
                                            <!-- Threat Level Badge -->
                                            <span class="px-2 py-1 text-xs rounded-full border font-mono"
                                                  :class="getThreatLevelBadge(insight.threat_level)"
                                                  x-show="insight.threat_level && insight.threat_level !== 'low'"
                                                  x-text="(insight.threat_level || '').toUpperCase()"></span>
                                        </div>
                                        <span class="text-xs text-gray-500 font-mono" x-text="formatDate(insight.message_date)"></span>
                                    </div>

                                    <!-- AI Analysis -->
                                    <div class="mb-3 p-3 bg-cipher-blue/5 rounded-lg border-l-4 border-cipher-blue" x-show="insight.gemini_analysis">
                                        <div class="flex items-start space-x-2">
                                            <i class="fas fa-robot text-cipher-blue mt-0.5"></i>
                                            <p class="text-gray-300 text-sm leading-relaxed" x-text="insight.gemini_analysis || 'No analysis available'"></p>
                                        </div>
                                    </div>

                                    <!-- Content Preview -->
                                    <div class="mb-3 p-2 bg-white/5 rounded border-l-2 border-gray-600" x-show="insight.message_text">
                                        <p class="text-gray-300 text-sm" x-text="(insight.message_text || '').substring(0, 200) + (insight.message_text && insight.message_text.length > 200 ? '...' : '')"></p>
                                    </div>

                                    <!-- Topics -->
                                    <div class="mb-3 flex flex-wrap gap-2" x-show="insight.key_topics && insight.key_topics.length > 0">
                                        <template x-for="topic in insight.key_topics.slice(0, 5)">
                                            <span class="px-2 py-1 bg-white/5 text-gray-300 text-xs rounded border border-white/10 hover:border-cipher-blue/50 transition-colors font-mono"
                                                  x-text="`#${topic}`"></span>
                                        </template>
                                        <span class="text-xs text-gray-500 px-2 py-1" 
                                              x-show="insight.key_topics && insight.key_topics.length > 5"
                                              x-text="`+${insight.key_topics.length - 5} more`"></span>
                                    </div>

                                    <!-- Metrics -->
                                    <div class="flex items-center justify-between text-xs">
                                        <div class="flex items-center space-x-4 text-gray-500">
                                            <span class="font-mono">THREAT: <span x-text="Math.round((insight.urgency_score || 0) * 100)"></span>%</span>
                                            <span class="font-mono">TYPE: <span x-text="(insight.threat_type || 'unknown').toUpperCase()"></span></span>
                                            <span class="font-mono">SENTIMENT: <span x-text="(insight.sentiment || 'neutral').toUpperCase()"></span></span>
                                        </div>
                                        <div class="flex items-center space-x-2">
                                            <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                                            <span class="text-green-400 font-mono">ANALYZED</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </template>
                </div>

                <!-- Empty State -->
                <div class="text-center py-12" x-show="!insights || insights.length === 0">
                    <div class="w-24 h-24 bg-gradient-to-r from-gray-600 to-slate-600 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse">
                        <i class="fas fa-search text-4xl text-gray-400"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-gray-300 mb-3">No Threat Intelligence Data</h3>
                    <div class="text-gray-500 mb-6 max-w-md mx-auto">
                        <p x-show="!monitoring.active">
                            CIPHER cybersecurity monitoring system is offline. Real-time threat intelligence will appear here when monitoring is active.
                        </p>
                        <p x-show="monitoring.active && stats.total_messages === 0">
                            CIPHER is actively monitoring cybersecurity channels. Threat intelligence will appear here as data is collected.
                        </p>
                        <p x-show="monitoring.active && stats.total_messages > 0">
                            No recent threat intelligence detected. The system is monitoring <span x-text="getActiveChannels()"></span> channels.
                        </p>
                    </div>
                    <div class="text-xs text-gray-600 font-mono">
                        <i class="fas fa-shield-alt mr-2"></i>
                        Status: <span x-text="getSystemStatusText()"></span>
                    </div>
                </div>

                <!-- Footer -->
                <div class="mt-6 pt-4 border-t border-white/10 flex justify-between items-center">
                    <div class="text-sm text-gray-400 font-mono">
                        <i class="fas fa-database mr-2"></i>
                        <span x-text="(insights || []).length"></span> intelligence signals processed
                        <span x-show="stats.data_source" class="ml-2 text-xs">
                            (<span x-text="stats.data_source"></span>)
                        </span>
                    </div>
                    <div class="text-xs text-gray-500 font-mono">
                        Last updated: <span x-text="formatDate(stats.last_updated)"></span>
                    </div>
                </div>
            </div>
        </div>

    </main>

    <!-- Footer -->
    <footer class="glass-effect border-t border-white/10 mt-16">
        <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center">
                <div class="flex items-center space-x-4">
                    <div class="text-sm text-gray-400">
                        <span class="font-mono">CIPHER</span> v1.0.0 | Powered by 
                        <span class="text-cipher-blue">Google Cloud</span> & 
                        <span class="text-cipher-purple">Gemini AI</span>
                    </div>
                </div>
                <div class="flex items-center space-x-4 text-xs text-gray-500">
                    <span class="font-mono">SECURE</span>
                    <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                    <span class="font-mono" x-text="getSystemStatusText().toUpperCase()"></span>
                </div>
            </div>
        </div>
    </footer>

    <script>
        function cipherDashboard() {
            return {
                // State
                isRefreshing: false,
                isLoading: false,
                currentTime: '',
                
                // Data
                stats: {},
                insights: [],
                monitoring: {},
                
                // Initialize
                init() {
                    this.updateTime();
                    this.loadData();
                    
                    // Update time every second
                    setInterval(() => this.updateTime(), 1000);
                    
                    // Auto-refresh every 30 seconds
                    setInterval(() => this.loadData(), 30000);
                },
                
                // Update current time
                updateTime() {
                    const now = new Date();
                    this.currentTime = now.toLocaleTimeString('en-US', { 
                        hour12: false,
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });
                },
                
                // Load all data
                async loadData() {
                    this.isLoading = true;
                    
                    try {
                        await Promise.all([
                            this.fetchStats(),
                            this.fetchInsights(),
                            this.fetchMonitoring()
                        ]);
                        
                    } catch (error) {
                        console.error('Error loading data:', error);
                    }
                    
                    this.isLoading = false;
                },
                
                // Fetch statistics
                async fetchStats() {
                    try {
                        const response = await fetch('/api/stats');
                        if (response.ok) {
                            this.stats = await response.json();
                        }
                    } catch (error) {
                        console.error('Error fetching stats:', error);
                        this.stats = { total_messages: 0, processed_today: 0, high_threats: 0 };
                    }
                },
                
                // Fetch insights
                async fetchInsights() {
                    try {
                        const response = await fetch('/api/insights');
                        if (response.ok) {
                            const data = await response.json();
                            this.insights = data.insights || [];
                        }
                    } catch (error) {
                        console.error('Error fetching insights:', error);
                        this.insights = [];
                    }
                },
                
                // Fetch monitoring status
                async fetchMonitoring() {
                    try {
                        const response = await fetch('/api/monitoring/status');
                        if (response.ok) {
                            this.monitoring = await response.json();
                        }
                    } catch (error) {
                        console.error('Error fetching monitoring:', error);
                        this.monitoring = { active: false };
                    }
                },
                
                // Refresh data manually
                async refreshData() {
                    if (this.isRefreshing) return;
                    
                    this.isRefreshing = true;
                    await this.loadData();
                    
                    setTimeout(() => {
                        this.isRefreshing = false;
                    }, 1000);
                },
                
                // Status helper functions
                getSystemStatusColor() {
                    if (this.monitoring.active && this.stats.total_messages > 0) return 'bg-green-400';
                    if (this.monitoring.active) return 'bg-yellow-400';
                    return 'bg-red-400';
                },
                
                getSystemStatusText() {
                    if (this.monitoring.active && this.stats.total_messages > 0) return 'LIVE';
                    if (this.monitoring.active) return 'READY';
                    return 'OFFLINE';
                },
                
                getSystemStatusTextColor() {
                    if (this.monitoring.active && this.stats.total_messages > 0) return 'text-green-400';
                    if (this.monitoring.active) return 'text-yellow-400';
                    return 'text-red-400';
                },
                
                getMonitoringStatusClass() {
                    if (this.monitoring.active) return 'bg-gradient-to-r from-green-400 to-emerald-500 animate-pulse-slow';
                    return 'bg-gradient-to-r from-yellow-400 to-orange-500';
                },
                
                getMonitoringPingClass() {
                    return this.monitoring.active ? 'bg-green-400' : 'bg-yellow-400';
                },
                
                getMonitoringTextClass() {
                    return this.monitoring.active ? 'text-green-400' : 'text-yellow-400';
                },
                
                getMonitoringStatusText() {
                    if (this.monitoring.active && this.stats.total_messages > 0) return '🟢 CIPHER OPERATIONAL';
                    if (this.monitoring.active) return '🟡 CIPHER MONITORING';
                    return '🔴 CIPHER OFFLINE';
                },
                
                getStatusDescription() {
                    if (this.monitoring.active && this.stats.total_messages > 0) {
                        return `Processing cybersecurity intelligence from ${this.getActiveChannels()} channels`;
                    }
                    if (this.monitoring.active) {
                        return `Monitoring ${this.getActiveChannels()} cybersecurity intelligence channels`;
                    }
                    return 'Monitoring system offline';
                },
                
                getActiveChannels() {
                    return this.monitoring.active ? 3 : 0;
                },
                
                getProgressWidth(value) {
                    if (!value) return 0;
                    return Math.min(100, (value / 1000) * 100);
                },
                
                getThreatIconClass() {
                    const threats = this.stats.high_threats || 0;
                    if (threats > 0) return 'bg-gradient-to-r from-red-500 to-orange-500 animate-pulse';
                    return 'bg-gradient-to-r from-green-500 to-emerald-500';
                },
                
                getThreatTextClass() {
                    const threats = this.stats.high_threats || 0;
                    return threats > 0 ? 'text-red-400' : 'text-green-400';
                },
                
                getThreatStatusClass() {
                    const threats = this.stats.high_threats || 0;
                    return threats > 0 ? 'text-red-400' : 'text-green-400';
                },
                
                getThreatStatusIcon() {
                    const threats = this.stats.high_threats || 0;
                    return threats > 0 ? 'fas fa-shield-alt' : 'fas fa-check-circle';
                },
                
                getThreatStatusText() {
                    const threats = this.stats.high_threats || 0;
                    return threats > 0 ? 'ACTIVE THREATS' : 'SECURE';
                },
                
                getDataBadgeClass() {
                    if (this.insights.length > 0) return 'bg-green-500/20 text-green-400 border-green-500/30';
                    return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
                },
                
                // Insight styling functions
                getThreatIcon(insight) {
                    if (insight.urgency_score > 0.7) return 'bg-gradient-to-r from-red-500 to-orange-500 animate-pulse';
                    if (insight.urgency_score > 0.4) return 'bg-gradient-to-r from-yellow-500 to-orange-500';
                    return 'bg-gradient-to-r from-blue-500 to-cyan-500';
                },
                
                getThreatIconClass(insight) {
                    if (insight.urgency_score > 0.7) return 'fas fa-exclamation-triangle';
                    if (insight.urgency_score > 0.4) return 'fas fa-eye';
                    return 'fas fa-info-circle';
                },
                
                getThreatIconBg(insight) {
                    if (insight.urgency_score > 0.7) return 'bg-red-500';
                    return 'bg-yellow-500';
                },
                
                getCategoryColor(category) {
                    const colors = {
                        'threat_intel': 'bg-red-500/20 text-red-400 border-red-500/30',
                        'data_breach': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
                        'vulnerability': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
                        'malware': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
                        'apt': 'bg-red-600/20 text-red-300 border-red-600/30',
                        'ransomware': 'bg-red-700/20 text-red-300 border-red-700/30'
                    };
                    return colors[category] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
                },
                
                getThreatLevelBadge(level) {
                    const colors = {
                        'critical': 'bg-red-600/30 text-red-300 border-red-600/50 animate-pulse',
                        'high': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
                        'medium': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                    };
                    return colors[level] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
                },
                
                formatDate(dateString) {
                    if (!dateString) return '';
                    try {
                        return new Date(dateString).toLocaleString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                        });
                    } catch {
                        return dateString.substring(0, 19).replace('T', ' ');
                    }
                }
            }
        }
    </script>
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
