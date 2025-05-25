from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Cache for performance - simple in-memory cache
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 30  # 30 seconds cache

def get_cache(key: str) -> Any:
    """Get cached value if still valid"""
    if key in _cache and key in _cache_ttl and time.time() < _cache_ttl[key]:
        return _cache[key]
    return None

def set_cache(key: str, value: Any, duration: int = CACHE_DURATION):
    """Set cache with TTL"""
    _cache[key] = value
    _cache_ttl[key] = time.time() + duration

def get_utils():
    """Safely import utils module"""
    try:
        import utils
        return utils
    except ImportError:
        logger.warning("Utils module not available")
        return None

@router.get("/dashboard", response_class=HTMLResponse)
async def cipher_dashboard(request: Request):
    """CIPHER Dashboard - Uses template-based approach"""
    try:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "PROJECT_ID": "primal-chariot-382610"
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        # Return basic error page if template fails
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIPHER Dashboard - Error</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ 
                    font-family: monospace; 
                    background: linear-gradient(135deg, #0a0a0a, #1a1a2e); 
                    color: #ff4444; 
                    padding: 50px; 
                    text-align: center; 
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .error-container {{
                    background: rgba(0, 0, 0, 0.8);
                    border: 2px solid #ff4444;
                    border-radius: 15px;
                    padding: 40px;
                    max-width: 600px;
                }}
                h1 {{ color: #00ff00; text-shadow: 0 0 10px #00ff00; }}
                .retry-btn {{
                    background: #6366f1;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    margin: 20px 10px;
                    text-decoration: none;
                    display: inline-block;
                }}
                .retry-btn:hover {{ background: #8b5cf6; }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>🛡️ CIPHER Dashboard</h1>
                <h2>⚠️ Dashboard Temporarily Unavailable</h2>
                <p>Error: {str(e)}</p>
                <p>The CIPHER dashboard is experiencing a temporary issue.</p>
                <a class="retry-btn" href="/dashboard">🔄 Retry</a>
                <a class="retry-btn" href="/health">🏥 Check Health</a>
                <script>
                    setTimeout(() => location.reload(), 15000);
                </script>
            </div>
        </body>
        </html>
        """, status_code=200)

@router.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get all dashboard data as JSON - single endpoint for the frontend"""
    try:
        # Check cache first
        cache_key = "dashboard_full_data"
        cached_data = get_cache(cache_key)
        
        if cached_data:
            return cached_data
        
        utils = get_utils()
        if not utils:
            return _get_fallback_data()
        
        # Gather all data
        try:
            stats = await utils.get_comprehensive_stats()
            insights_data = await utils.get_threat_insights()
            monitoring = await utils.get_monitoring_status()
            analytics = await utils.get_threat_analytics()
            
            # Process insights for frontend consumption
            processed_insights = []
            for insight in insights_data.get("insights", [])[:20]:  # Limit to 20
                processed_insight = {
                    **insight,
                    "formatted_date": _format_date(insight.get("message_date")),
                    "urgency_percentage": int(insight.get("urgency_score", 0) * 100),
                    "threat_badge_class": _get_threat_badge_class(insight.get("threat_level", "low")),
                    "truncated_analysis": _truncate_text(insight.get("gemini_analysis", ""), 200),
                    "has_more_text": len(insight.get("gemini_analysis", "")) > 200,
                    "cybersec_summary": _create_cybersec_summary(insight)
                }
                processed_insights.append(processed_insight)
            
            dashboard_data = {
                "stats": stats,
                "insights": {
                    "data": processed_insights,
                    "count": len(processed_insights),
                    "source": insights_data.get("source", "bigquery")
                },
                "monitoring": monitoring,
                "analytics": analytics,
                "system_status": {
                    "operational": monitoring.get("active", False),
                    "bigquery": stats.get("data_source") == "bigquery",
                    "threat_level": _calculate_threat_level(stats.get("avg_urgency", 0)),
                    "last_updated": datetime.now().isoformat()
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # Cache the result
            set_cache(cache_key, dashboard_data)
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error gathering dashboard data: {e}")
            return _get_fallback_data()
            
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Dashboard data temporarily unavailable",
                "details": str(e),
                "platform": "CIPHER Cybersecurity Intelligence Platform",
                "timestamp": datetime.now().isoformat()
            }
        )

@router.get("/api/insights/detailed")
async def get_detailed_insights(
    limit: int = Query(50, ge=1, le=100),
    threat_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    include_raw: bool = Query(False, description="Include raw message text")
):
    """Get detailed insights with filtering options"""
    try:
        utils = get_utils()
        if not utils:
            return {"insights": [], "total": 0, "status": "utils_unavailable"}
        
        insights_data = await utils.get_threat_insights()
        insights = insights_data["insights"]
        
        # Apply filters
        if threat_level:
            insights = [i for i in insights if i.get("threat_level") == threat_level.lower()]
        if category:
            insights = [i for i in insights if i.get("category") == category.lower()]
        
        # Process insights with enhanced data
        enhanced_insights = []
        for insight in insights[:limit]:
            enhanced = {
                "message_id": insight.get("message_id"),
                "source": insight.get("chat_username", "@Unknown"),
                "timestamp": insight.get("message_date"),
                "processed_date": insight.get("processed_date"),
                "threat_level": insight.get("threat_level", "low"),
                "category": insight.get("category", "other"),
                "threat_type": insight.get("threat_type", "unknown"),
                "urgency_score": insight.get("urgency_score", 0.0),
                "sentiment": insight.get("sentiment", "neutral"),
                "full_analysis": insight.get("gemini_analysis", "No analysis available"),
                "formatted_date": _format_date(insight.get("message_date")),
                "urgency_percentage": int(insight.get("urgency_score", 0) * 100),
                "threat_badge_class": _get_threat_badge_class(insight.get("threat_level", "low")),
                "cybersecurity_data": {
                    "cve_references": insight.get("cve_references", []),
                    "iocs_detected": insight.get("iocs_detected", []),
                    "malware_families": insight.get("malware_families", []),
                    "threat_actors": insight.get("threat_actors", []),
                    "affected_systems": insight.get("affected_systems", []),
                    "attack_vectors": insight.get("attack_vectors", [])
                }
            }
            
            if include_raw:
                enhanced["raw_message"] = insight.get("message_text", "")
            
            enhanced_insights.append(enhanced)
        
        return {
            "insights": enhanced_insights,
            "total_returned": len(enhanced_insights),
            "total_available": len(insights_data["insights"]),
            "filters_applied": {"threat_level": threat_level, "category": category},
            "timestamp": datetime.now().isoformat(),
            "source": insights_data.get("source", "bigquery")
        }
        
    except Exception as e:
        logger.error(f"Detailed insights error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Detailed insights temporarily unavailable",
                "details": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )

@router.get("/api/export/threats")
async def export_threats(
    format: str = Query("json", description="Export format: json or csv"),
    limit: int = Query(100, ge=1, le=1000),
    threat_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None)
):
    """Export threat intelligence data"""
    try:
        utils = get_utils()
        if not utils:
            return JSONResponse(
                status_code=503,
                content={"error": "Export service unavailable", "status": "initializing"}
            )
        
        insights_data = await utils.get_threat_insights()
        insights = insights_data["insights"]
        
        # Apply filters
        if threat_level:
            insights = [i for i in insights if i.get("threat_level") == threat_level.lower()]
        if category:
            insights = [i for i in insights if i.get("category") == category.lower()]
        
        # Limit results
        insights = insights[:limit]
        
        if format.lower() == "json":
            return {
                "export_info": {
                    "generated": datetime.now().isoformat(),
                    "platform": "CIPHER Cybersecurity Intelligence Platform",
                    "total_records": len(insights),
                    "filters": {"threat_level": threat_level, "category": category}
                },
                "threat_intelligence": insights
            }
        elif format.lower() == "csv":
            # For CSV, create simplified flat structure
            from fastapi.responses import StreamingResponse
            import io
            import csv
            
            output = io.StringIO()
            if insights:
                fieldnames = [
                    'message_id', 'source', 'timestamp', 'threat_level', 'category', 
                    'threat_type', 'urgency_score', 'sentiment', 'analysis'
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for insight in insights:
                    writer.writerow({
                        'message_id': insight.get('message_id', ''),
                        'source': insight.get('chat_username', ''),
                        'timestamp': insight.get('message_date', ''),
                        'threat_level': insight.get('threat_level', ''),
                        'category': insight.get('category', ''),
                        'threat_type': insight.get('threat_type', ''),
                        'urgency_score': insight.get('urgency_score', ''),
                        'sentiment': insight.get('sentiment', ''),
                        'analysis': insight.get('gemini_analysis', '')
                    })
            
            output.seek(0)
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode()),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=cipher_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "Unsupported format", "supported_formats": ["json", "csv"]}
            )
            
    except Exception as e:
        logger.error(f"Export error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Export failed", "details": str(e)}
        )

# === UTILITY FUNCTIONS ===

def _get_fallback_data():
    """Fallback data when utils unavailable"""
    return {
        "stats": _get_empty_stats(),
        "insights": {"data": [], "count": 0, "source": "fallback"},
        "monitoring": _get_empty_monitoring(),
        "analytics": _get_empty_analytics(),
        "system_status": {
            "operational": False,
            "bigquery": False,
            "threat_level": "unknown",
            "last_updated": datetime.now().isoformat()
        },
        "status": "fallback_mode"
    }

def _calculate_threat_level(urgency: float) -> str:
    """Calculate threat level from urgency score"""
    if urgency >= 0.8:
        return "CRITICAL"
    elif urgency >= 0.6:
        return "HIGH" 
    elif urgency >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"

def _format_date(date_str: str) -> str:
    """Format date for display"""
    if not date_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%m/%d %H:%M")
    except:
        return date_str[:16] if date_str else "Unknown"

def _truncate_text(text: str, max_length: int) -> str:
    """Truncate text intelligently"""
    if not text or len(text) <= max_length:
        return text
    # Try to break at word boundary
    truncated = text[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.8:  # If we can break reasonably close to the limit
        return truncated[:last_space] + "..."
    return truncated + "..."

def _get_threat_badge_class(threat_level: str) -> str:
    """Get CSS class for threat level"""
    return {
        "critical": "threat-critical",
        "high": "threat-high", 
        "medium": "threat-medium",
        "low": "threat-low"
    }.get(threat_level.lower(), "threat-low")

def _create_cybersec_summary(insight: Dict) -> Dict:
    """Create summary of cybersecurity data for display"""
    return {
        "cve_count": len(insight.get("cve_references", [])),
        "ioc_count": len(insight.get("iocs_detected", [])),
        "malware_count": len(insight.get("malware_families", [])),
        "actor_count": len(insight.get("threat_actors", [])),
        "has_intelligence": any([
            insight.get("cve_references"),
            insight.get("iocs_detected"),
            insight.get("malware_families"),
            insight.get("threat_actors")
        ])
    }

def _get_empty_stats():
    """Empty stats structure"""
    return {
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
        "monitoring_active": False,
        "data_source": "unavailable"
    }

def _get_empty_monitoring():
    """Empty monitoring structure"""
    return {
        "active": False,
        "subsystems": {"bigquery": False, "gemini": False, "telegram": False},
        "channels": {"count": 3, "monitored": ["@DarkfeedNews", "@breachdetector", "@secharvester"]}
    }

def _get_empty_analytics():
    """Empty analytics structure"""
    return {
        "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "categories": {"threat_intel": 0, "data_breach": 0, "vulnerability": 0, "malware": 0},
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0}
    }
