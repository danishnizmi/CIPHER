from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
router = APIRouter()

# Cache for performance
_cache = {}
_cache_ttl = {}
CACHE_DURATION = 45  # 45 seconds cache

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
    """CIPHER Cybersecurity Intelligence Dashboard - Enhanced Production Version"""
    try:
        # Check cache first
        cache_key = "dashboard_full_data"
        cached_data = get_cache(cache_key)
        
        if cached_data:
            stats, insights, monitoring, analytics = cached_data
        else:
            # Get data from utils
            utils = get_utils()
            
            if utils:
                try:
                    stats = await utils.get_comprehensive_stats()
                    insights_data = await utils.get_threat_insights()
                    insights = insights_data["insights"][:20]  # Latest 20
                    monitoring = await utils.get_monitoring_status()
                    analytics = await utils.get_threat_analytics()
                except Exception as e:
                    logger.error(f"Error getting data: {e}")
                    stats = _get_empty_stats()
                    insights = []
                    monitoring = _get_empty_monitoring()
                    analytics = _get_empty_analytics()
            else:
                stats = _get_empty_stats()
                insights = []
                monitoring = _get_empty_monitoring()
                analytics = _get_empty_analytics()
            
            # Cache the data
            set_cache(cache_key, (stats, insights, monitoring, analytics))
        
        # Generate dashboard
        dashboard_html = _generate_dashboard_html(stats, insights, monitoring, analytics)
        return HTMLResponse(content=dashboard_html, status_code=200)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return HTMLResponse(content=_generate_error_dashboard(str(e)), status_code=200)

def _generate_dashboard_html(stats: Dict, insights: List, monitoring: Dict, analytics: Dict) -> str:
    """Generate comprehensive dashboard HTML with enhanced threat intelligence display"""
    
    # Calculate derived metrics
    system_status = "OPERATIONAL" if monitoring.get("active") else "STANDBY"
    threat_score = analytics.get("summary", {}).get("avg_urgency", 0.0)
    high_priority = stats.get("high_threats", 0) + stats.get("critical_threats", 0)
    
    # Status colors
    status_color = "#00ff00" if monitoring.get("active") else "#ffaa00"
    threat_color = "#ff4444" if threat_score > 0.7 else "#ffaa00" if threat_score > 0.4 else "#00ff00"
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CIPHER - Cybersecurity Intelligence Platform</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
            body {{
                font-family: 'Segoe UI', 'Consolas', monospace;
                background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
                color: #ffffff;
                min-height: 100vh;
                overflow-x: hidden;
            }}
            
            .cyber-grid {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image: 
                    linear-gradient(rgba(0, 255, 0, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 255, 0, 0.03) 1px, transparent 1px);
                background-size: 20px 20px;
                pointer-events: none;
                z-index: 0;
                animation: gridPulse 4s ease-in-out infinite;
            }}
            
            @keyframes gridPulse {{
                0%, 100% {{ opacity: 0.3; }}
                50% {{ opacity: 0.1; }}
            }}
            
            .container {{
                max-width: 1600px;
                margin: 0 auto;
                padding: 20px;
                position: relative;
                z-index: 1;
            }}
            
            .header {{
                text-align: center;
                background: rgba(0, 0, 0, 0.8);
                border: 2px solid #00ff00;
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 0 30px rgba(0, 255, 0, 0.2);
                backdrop-filter: blur(10px);
                position: relative;
                overflow: hidden;
            }}
            
            .header::before {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: conic-gradient(from 0deg, transparent, rgba(0, 255, 0, 0.1), transparent);
                animation: rotate 6s linear infinite;
                opacity: 0.3;
                z-index: -1;
            }}
            
            @keyframes rotate {{
                100% {{ transform: rotate(360deg); }}
            }}
            
            .header h1 {{
                font-size: 3em;
                color: #00ff00;
                text-shadow: 0 0 20px #00ff00;
                margin-bottom: 10px;
                animation: pulse 2s infinite;
                font-weight: 700;
            }}
            
            .status-bar {{
                display: flex;
                justify-content: center;
                gap: 30px;
                margin-top: 20px;
                flex-wrap: wrap;
            }}
            
            .status-item {{
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 8px 16px;
                background: rgba(0, 255, 0, 0.1);
                border: 1px solid #00ff00;
                border-radius: 20px;
                font-family: monospace;
                transition: all 0.3s ease;
            }}
            
            .status-item:hover {{
                background: rgba(0, 255, 0, 0.2);
                transform: translateY(-2px);
            }}
            
            .status-dot {{
                width: 12px;
                height: 12px;
                border-radius: 50%;
                animation: blink 2s infinite;
            }}
            
            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 25px;
                margin-bottom: 30px;
            }}
            
            .card {{
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid #00ff00;
                border-radius: 12px;
                padding: 25px;
                backdrop-filter: blur(10px);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }}
            
            .card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.1), transparent);
                transition: left 0.5s;
            }}
            
            .card:hover {{
                border-color: #6366f1;
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(99, 102, 241, 0.3);
            }}
            
            .card:hover::before {{
                left: 100%;
            }}
            
            .card-header {{
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 20px;
            }}
            
            .card-icon {{
                font-size: 1.8em;
                padding: 12px;
                background: linear-gradient(45deg, #6366f1, #8b5cf6);
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(99, 102, 241, 0.5);
            }}
            
            .card-title {{
                font-size: 1.2em;
                font-weight: 600;
                color: #6366f1;
            }}
            
            .metric {{
                font-size: 2.8em;
                font-weight: bold;
                color: #ffffff;
                text-shadow: 0 0 10px currentColor;
                margin: 15px 0;
            }}
            
            .metric.critical {{ color: #ff4444; }}
            .metric.warning {{ color: #ffaa00; }}
            .metric.good {{ color: #00ff00; }}
            .metric.info {{ color: #6366f1; }}
            
            .sub-metrics {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }}
            
            .sub-metric {{
                text-align: center;
                padding: 10px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                border-left: 3px solid #6366f1;
                transition: all 0.3s ease;
            }}
            
            .sub-metric:hover {{
                background: rgba(255, 255, 255, 0.1);
                border-left-color: #00ff00;
            }}
            
            .sub-metric-value {{
                font-size: 1.5em;
                font-weight: bold;
                color: #ffffff;
            }}
            
            .sub-metric-label {{
                font-size: 0.8em;
                color: #888;
                text-transform: uppercase;
            }}
            
            .insights-section {{
                background: rgba(0, 0, 0, 0.8);
                border: 1px solid #00ff00;
                border-radius: 15px;
                margin-top: 30px;
                overflow: hidden;
                backdrop-filter: blur(10px);
            }}
            
            .insights-header {{
                background: linear-gradient(45deg, rgba(0, 255, 0, 0.2), rgba(99, 102, 241, 0.2));
                padding: 20px 25px;
                border-bottom: 1px solid #00ff00;
            }}
            
            .insights-content {{
                max-height: 900px;
                overflow-y: auto;
                padding: 20px;
            }}
            
            .insights-content::-webkit-scrollbar {{
                width: 8px;
            }}
            
            .insights-content::-webkit-scrollbar-track {{
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
            }}
            
            .insights-content::-webkit-scrollbar-thumb {{
                background: #6366f1;
                border-radius: 4px;
            }}
            
            .insight {{
                background: rgba(99, 102, 241, 0.1);
                border-left: 4px solid #6366f1;
                border-radius: 0 8px 8px 0;
                padding: 20px;
                margin-bottom: 15px;
                transition: all 0.3s ease;
                position: relative;
            }}
            
            .insight:hover {{
                border-left-color: #00ff00;
                background: rgba(0, 255, 0, 0.1);
                transform: translateX(5px);
            }}
            
            .insight-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
                flex-wrap: wrap;
                gap: 10px;
            }}
            
            .insight-source {{
                font-weight: bold;
                color: #6366f1;
                font-family: monospace;
            }}
            
            .threat-badge {{
                padding: 4px 12px;
                border-radius: 15px;
                font-size: 0.75em;
                font-weight: bold;
                text-transform: uppercase;
                font-family: monospace;
            }}
            
            .threat-critical {{
                background: rgba(255, 68, 68, 0.2);
                color: #ff4444;
                border: 1px solid #ff4444;
                animation: blink 2s infinite;
            }}
            
            .threat-high {{
                background: rgba(255, 170, 0, 0.2);
                color: #ffaa00;
                border: 1px solid #ffaa00;
            }}
            
            .threat-medium {{
                background: rgba(255, 255, 0, 0.2);
                color: #ffff00;
                border: 1px solid #ffff00;
            }}
            
            .threat-low {{
                background: rgba(0, 255, 0, 0.2);
                color: #00ff00;
                border: 1px solid #00ff00;
            }}
            
            .insight-analysis {{
                line-height: 1.6;
                margin-bottom: 15px;
                color: #e0e0e0;
            }}
            
            .analysis-text {{
                line-height: 1.6;
                margin-bottom: 15px;
                color: #e0e0e0;
            }}
            
            .insight-meta {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-size: 0.85em;
                color: #888;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                padding-top: 12px;
                flex-wrap: wrap;
                gap: 15px;
            }}
            
            .urgency-bar {{
                width: 100px;
                height: 6px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 3px;
                overflow: hidden;
            }}
            
            .urgency-fill {{
                height: 100%;
                background: linear-gradient(90deg, #00ff00, #ffaa00, #ff4444);
                transition: width 0.3s ease;
            }}
            
            .analytics-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin: 30px 0;
            }}
            
            .chart-container {{
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid #6366f1;
                border-radius: 12px;
                padding: 20px;
                backdrop-filter: blur(10px);
            }}
            
            .chart-title {{
                color: #6366f1;
                font-weight: 600;
                margin-bottom: 15px;
                text-align: center;
            }}
            
            .bar-chart {{
                display: flex;
                flex-direction: column;
                gap: 10px;
            }}
            
            .bar-item {{
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .bar-label {{
                min-width: 80px;
                font-size: 0.8em;
                text-transform: uppercase;
                color: #888;
            }}
            
            .bar {{
                flex: 1;
                height: 20px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                overflow: hidden;
                position: relative;
            }}
            
            .bar-fill {{
                height: 100%;
                background: linear-gradient(90deg, #6366f1, #8b5cf6);
                border-radius: 10px;
                transition: width 0.8s ease;
            }}
            
            .bar-value {{
                min-width: 30px;
                text-align: right;
                font-weight: bold;
                color: #ffffff;
            }}
            
            .channels-section {{
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid #6366f1;
                border-radius: 15px;
                padding: 25px;
                margin: 30px 0;
                backdrop-filter: blur(10px);
            }}
            
            .channels-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }}
            
            .channel-card {{
                background: rgba(99, 102, 241, 0.1);
                border: 1px solid #6366f1;
                border-radius: 10px;
                padding: 20px;
                text-align: center;
                transition: all 0.3s ease;
            }}
            
            .channel-card:hover {{
                border-color: #00ff00;
                transform: scale(1.05);
            }}
            
            .channel-icon {{
                font-size: 2em;
                margin-bottom: 10px;
            }}
            
            .channel-name {{
                font-weight: bold;
                color: #6366f1;
                margin-bottom: 5px;
            }}
            
            .channel-desc {{
                font-size: 0.8em;
                color: #888;
            }}
            
            .footer {{
                text-align: center;
                margin-top: 50px;
                padding: 30px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                background: rgba(0, 0, 0, 0.5);
                border-radius: 15px;
            }}
            
            .footer-links {{
                display: flex;
                justify-content: center;
                gap: 30px;
                margin-top: 20px;
                flex-wrap: wrap;
            }}
            
            .footer-link {{
                color: #6366f1;
                text-decoration: none;
                padding: 8px 16px;
                border: 1px solid #6366f1;
                border-radius: 20px;
                transition: all 0.3s ease;
            }}
            
            .footer-link:hover {{
                background: #6366f1;
                color: #ffffff;
                transform: translateY(-2px);
            }}
            
            .expand-btn, .copy-btn {{
                margin-top: 10px;
                padding: 5px 12px;
                background: rgba(99, 102, 241, 0.2);
                border: 1px solid #6366f1;
                border-radius: 15px;
                color: #6366f1;
                cursor: pointer;
                font-size: 0.8em;
                transition: all 0.3s ease;
                margin-right: 8px;
            }}
            
            .expand-btn:hover, .copy-btn:hover {{
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }}
            
            .cybersec-data {{
                margin-top: 10px;
                padding-top: 10px;
                border-top: 1px solid rgba(255,255,255,0.1);
                font-size: 0.85em;
            }}
            
            .cybersec-data div {{
                margin: 5px 0;
            }}
            
            .cybersec-data strong {{
                color: #6366f1;
            }}
            
            .cve-ref {{
                font-family: monospace;
                color: #ff6666;
                background: rgba(255, 102, 102, 0.1);
                padding: 2px 6px;
                border-radius: 4px;
                margin: 0 3px;
            }}
            
            .ioc-item {{
                font-family: monospace;
                color: #ffaa00;
                background: rgba(255, 170, 0, 0.1);
                padding: 2px 6px;
                border-radius: 4px;
                margin: 0 3px;
            }}
            
            .malware-item {{
                color: #ff4444;
                background: rgba(255, 68, 68, 0.1);
                padding: 2px 6px;
                border-radius: 4px;
                margin: 0 3px;
            }}
            
            .actor-item {{
                color: #ffaa00;
                background: rgba(255, 170, 0, 0.1);
                padding: 2px 6px;
                border-radius: 4px;
                margin: 0 3px;
            }}
            
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.7; }}
            }}
            
            @keyframes blink {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.3; }}
            }}
            
            .loading {{
                display: inline-flex;
                gap: 4px;
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
            
            @media (max-width: 768px) {{
                .grid {{ grid-template-columns: 1fr; }}
                .analytics-grid {{ grid-template-columns: 1fr; }}
                .channels-grid {{ grid-template-columns: 1fr; }}
                .status-bar {{ flex-direction: column; align-items: center; }}
                .header h1 {{ font-size: 2em; }}
                .container {{ padding: 10px; }}
                .insights-content {{ max-height: 600px; }}
            }}
        </style>
    </head>
    <body>
        <div class="cyber-grid"></div>
        
        <div class="container">
            <!-- Header -->
            <div class="header">
                <h1>🛡️ CIPHER</h1>
                <p style="font-size: 1.3em; color: #888; margin-bottom: 20px;">
                    Cybersecurity Intelligence Platform
                </p>
                
                <div class="status-bar">
                    <div class="status-item">
                        <div class="status-dot" style="background-color: {status_color};"></div>
                        <span>System: {system_status}</span>
                    </div>
                    <div class="status-item">
                        <div class="status-dot" style="background-color: {'#00ff00' if stats.get('data_source') == 'bigquery' else '#ffaa00'};"></div>
                        <span>BigQuery: {'CONNECTED' if stats.get('data_source') == 'bigquery' else 'LIMITED'}</span>
                    </div>
                    <div class="status-item">
                        <div class="status-dot" style="background-color: {threat_color};"></div>
                        <span>Threat Level: {_get_threat_level_text(threat_score)}</span>
                    </div>
                    <div class="status-item">
                        <div class="status-dot" style="background-color: #6366f1;"></div>
                        <span>Channels: {monitoring.get('channels', {}).get('count', 3)}</span>
                    </div>
                </div>
            </div>
            
            <!-- Main Metrics Grid -->
            <div class="grid">
                <!-- Intelligence Summary -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-icon">📊</div>
                        <div class="card-title">Intelligence Summary</div>
                    </div>
                    <div class="metric {'good' if stats['total_messages'] > 0 else 'warning'}">{stats['total_messages']:,}</div>
                    <p style="color: #888; margin-bottom: 20px;">Total Messages Processed</p>
                    
                    <div class="sub-metrics">
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['processed_today']}</div>
                            <div class="sub-metric-label">Today</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['unique_channels']}</div>
                            <div class="sub-metric-label">Channels</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['avg_urgency']:.2f}</div>
                            <div class="sub-metric-label">Avg Urgency</div>
                        </div>
                    </div>
                </div>
                
                <!-- Threat Analysis -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-icon">🚨</div>
                        <div class="card-title">Threat Analysis</div>
                    </div>
                    <div class="metric {'critical' if high_priority > 0 else 'good'}">{high_priority}</div>
                    <p style="color: #888; margin-bottom: 20px;">High Priority Threats</p>
                    
                    <div class="sub-metrics">
                        <div class="sub-metric">
                            <div class="sub-metric-value" style="color: #ff4444;">{stats['critical_threats']}</div>
                            <div class="sub-metric-label">Critical</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value" style="color: #ffaa00;">{stats['high_threats']}</div>
                            <div class="sub-metric-label">High</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['apt_activity']}</div>
                            <div class="sub-metric-label">APT</div>
                        </div>
                    </div>
                </div>
                
                <!-- Security Intelligence -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-icon">🔍</div>
                        <div class="card-title">Security Intelligence</div>
                    </div>
                    <div class="metric {'warning' if stats['cve_mentions'] > 0 else 'good'}">{stats['cve_mentions']}</div>
                    <p style="color: #888; margin-bottom: 20px;">CVE References</p>
                    
                    <div class="sub-metrics">
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['vulnerabilities']}</div>
                            <div class="sub-metric-label">Vulnerabilities</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['data_breaches']}</div>
                            <div class="sub-metric-label">Breaches</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value">{stats['malware_alerts']}</div>
                            <div class="sub-metric-label">Malware</div>
                        </div>
                    </div>
                </div>
                
                <!-- System Status -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-icon">⚡</div>
                        <div class="card-title">System Status</div>
                    </div>
                    <div class="metric info">{monitoring.get('channels', {}).get('count', 3)}/3</div>
                    <p style="color: #888; margin-bottom: 20px;">Channels Active</p>
                    
                    <div class="sub-metrics">
                        <div class="sub-metric">
                            <div class="sub-metric-value" style="color: {'#00ff00' if monitoring.get('subsystems', {}).get('bigquery') else '#ffaa00'};">{'✓' if monitoring.get('subsystems', {}).get('bigquery') else '○'}</div>
                            <div class="sub-metric-label">BigQuery</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value" style="color: {'#00ff00' if monitoring.get('subsystems', {}).get('gemini') else '#ffaa00'};">{'✓' if monitoring.get('subsystems', {}).get('gemini') else '○'}</div>
                            <div class="sub-metric-label">Gemini AI</div>
                        </div>
                        <div class="sub-metric">
                            <div class="sub-metric-value" style="color: {'#00ff00' if monitoring.get('subsystems', {}).get('telegram') else '#ffaa00'};">{'✓' if monitoring.get('subsystems', {}).get('telegram') else '○'}</div>
                            <div class="sub-metric-label">Telegram</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Threat Analytics -->
            {_generate_analytics_section(analytics)}
            
            <!-- Recent Intelligence Feed -->
            <div class="insights-section">
                <div class="insights-header">
                    <h3 style="margin: 0; color: #00ff00;">🔍 Recent Threat Intelligence</h3>
                    <p style="margin: 5px 0 0 0; color: #888;">
                        {len(insights)} intelligence signals processed | Auto-refresh: 30s
                    </p>
                </div>
                
                <div class="insights-content">
                    {_generate_enhanced_insights_html(insights)}
                </div>
            </div>
            
            <!-- Monitored Channels -->
            {_generate_channels_section(monitoring)}
            
            <!-- Footer -->
            <div class="footer">
                <p><strong>CIPHER</strong> v1.0.0 | Powered by Google Cloud & Gemini AI</p>
                <p style="color: #666; margin: 10px 0;">
                    Project: primal-chariot-382610 | Service: cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com
                </p>
                
                <div class="footer-links">
                    <a href="/api/stats" class="footer-link">📈 Stats API</a>
                    <a href="/health" class="footer-link">🏥 Health Check</a>
                    <a href="/api/monitoring/status" class="footer-link">📡 Monitoring</a>
                    <a href="/api/analytics" class="footer-link">📊 Analytics API</a>
                    <a href="/api/docs" class="footer-link">📚 API Docs</a>
                </div>
            </div>
        </div>
        
        <script>
            // Auto-refresh dashboard every 30 seconds
            let refreshTimer = setTimeout(() => {{
                window.location.reload();
            }}, 30000);
            
            // Add loading indicators
            document.querySelectorAll('.card').forEach((card, index) => {{
                card.style.animationDelay = `${{index * 0.1}}s`;
                card.style.animation = 'fadeIn 0.6s ease-out';
            }});
            
            // Update timestamp
            function updateTime() {{
                const now = new Date();
                const timeStr = now.toLocaleTimeString();
                document.title = `CIPHER Dashboard - ${{timeStr}}`;
            }}
            
            setInterval(updateTime, 1000);
            updateTime();
            
            // Toggle analysis expansion
            function toggleAnalysis(index) {{
                const shortAnalysis = document.getElementById(`analysis-${{index}}`);
                const fullAnalysis = document.getElementById(`full-analysis-${{index}}`);
                const button = event.target;
                
                if (shortAnalysis.style.display === 'none') {{
                    // Show truncated, hide full
                    shortAnalysis.style.display = 'block';
                    fullAnalysis.style.display = 'none';
                    button.textContent = 'Show Full Analysis';
                    button.style.background = 'rgba(99, 102, 241, 0.2)';
                    button.style.borderColor = '#6366f1';
                    button.style.color = '#6366f1';
                }} else {{
                    // Show full, hide truncated
                    shortAnalysis.style.display = 'none';
                    fullAnalysis.style.display = 'block';
                    button.textContent = 'Show Less';
                    button.style.background = 'rgba(0, 255, 0, 0.2)';
                    button.style.borderColor = '#00ff00';
                    button.style.color = '#00ff00';
                }}
            }}
            
            // Copy threat intelligence to clipboard
            function copyInsight(index) {{
                const insight = document.querySelector(`#analysis-${{index}}`).closest('.insight');
                const source = insight.querySelector('.insight-source').textContent;
                const analysis = document.getElementById(`full-analysis-${{index}}`).style.display === 'block' 
                    ? document.getElementById(`full-analysis-${{index}}`).textContent.trim()
                    : document.getElementById(`analysis-${{index}}`).textContent.trim();
                const threatLevel = insight.querySelector('.threat-badge').textContent;
                const urgencyMatch = insight.querySelector('.insight-meta').textContent.match(/([0-9.]+)/);
                const urgency = urgencyMatch ? urgencyMatch[1] : 'N/A';
                
                const copyText = `🛡️ CIPHER Threat Intelligence
Source: ${{source}}
Threat Level: ${{threatLevel}}
Urgency Score: ${{urgency}}

Analysis:
${{analysis}}

Exported from CIPHER Platform - ${{new Date().toISOString()}}`;
                
                navigator.clipboard.writeText(copyText).then(() => {{
                    event.target.textContent = '✅ Copied!';
                    event.target.style.background = 'rgba(0, 255, 0, 0.2)';
                    event.target.style.borderColor = '#00ff00';
                    event.target.style.color = '#00ff00';
                    setTimeout(() => {{
                        event.target.textContent = '📋 Copy';
                        event.target.style.background = 'rgba(99, 102, 241, 0.1)';
                        event.target.style.borderColor = '#6366f1';
                        event.target.style.color = '#6366f1';
                    }}, 2000);
                }}).catch(err => {{
                    console.error('Copy failed:', err);
                    event.target.textContent = '❌ Failed';
                    setTimeout(() => {{
                        event.target.textContent = '📋 Copy';
                    }}, 2000);
                }});
            }}
            
            // Pause auto-refresh when user is interacting
            let userActivity = false;
            const resetTimer = () => {{
                clearTimeout(refreshTimer);
                if (!userActivity) {{
                    refreshTimer = setTimeout(() => window.location.reload(), 30000);
                }}
            }};

            ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {{
                document.addEventListener(event, () => {{
                    userActivity = true;
                    setTimeout(() => {{ userActivity = false; resetTimer(); }}, 5000);
                }}, {{ passive: true }});
            }});
            
            console.log('🛡️ CIPHER Dashboard loaded successfully - Enhanced Version');
        </script>
    </body>
    </html>
    """

def _generate_enhanced_insights_html(insights: List) -> str:
    """Generate enhanced insights HTML with full threat intelligence display"""
    if not insights:
        return """
        <div style="text-align: center; padding: 60px; color: #666;">
            <div style="font-size: 3em; margin-bottom: 20px; opacity: 0.5;">🔍</div>
            <h3 style="color: #888; margin-bottom: 15px;">No Recent Threat Intelligence</h3>
            <p style="margin-bottom: 10px;">CIPHER is monitoring cybersecurity channels for threats.</p>
            <p style="font-size: 0.9em;">Intelligence data will appear here as it's collected and analyzed.</p>
            <div style="margin-top: 30px;">
                <span class="loading"><span></span><span></span><span></span></span>
                <br><span style="font-size: 0.8em; color: #666;">Monitoring Active</span>
            </div>
        </div>
        """
    
    insights_html = ""
    for i, insight in enumerate(insights):
        threat_level = insight.get("threat_level", "low")
        urgency = insight.get("urgency_score", 0.0)
        full_analysis = insight.get('gemini_analysis', insight.get('message_text', 'No analysis available'))
        truncated_analysis = _truncate_text(full_analysis, 400)
        show_expand = len(full_analysis) > 400
        
        # Determine threat badge class
        if threat_level == "critical":
            badge_class = "threat-critical"
        elif threat_level == "high":
            badge_class = "threat-high"
        elif threat_level == "medium":
            badge_class = "threat-medium"
        else:
            badge_class = "threat-low"
        
        # Build cybersecurity data display
        cybersec_data = ""
        data_items = []
        
        if insight.get('cve_references'):
            cve_list = ", ".join([f'<span class="cve-ref">{cve}</span>' for cve in insight.get('cve_references', [])[:3]])
            data_items.append(f"<div><strong>CVE References:</strong> {cve_list}</div>")
        
        if insight.get('iocs_detected'):
            ioc_list = ", ".join([f'<span class="ioc-item">{ioc}</span>' for ioc in insight.get('iocs_detected', [])[:3]])
            data_items.append(f"<div><strong>IOCs:</strong> {ioc_list}</div>")
        
        if insight.get('malware_families'):
            malware_list = ", ".join([f'<span class="malware-item">{mal}</span>' for mal in insight.get('malware_families', [])[:2]])
            data_items.append(f"<div><strong>Malware:</strong> {malware_list}</div>")
        
        if insight.get('threat_actors'):
            actor_list = ", ".join([f'<span class="actor-item">{actor}</span>' for actor in insight.get('threat_actors', [])[:2]])
            data_items.append(f"<div><strong>Threat Actors:</strong> {actor_list}</div>")
        
        if data_items:
            cybersec_data = f'<div class="cybersec-data">{"".join(data_items)}</div>'
        
        insights_html += f"""
        <div class="insight">
            <div class="insight-header">
                <div style="display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
                    <span class="insight-source">{insight.get('chat_username', '@Unknown')}</span>
                    <span class="threat-badge {badge_class}">{threat_level.upper()}</span>
                    <span style="font-size: 0.8em; color: #888; font-family: monospace;">
                        {insight.get('category', 'other').upper()}
                    </span>
                </div>
                <div style="font-size: 0.8em; color: #666; display: flex; align-items: center; gap: 10px;">
                    {_format_date(insight.get('message_date', ''))}
                    <button onclick="copyInsight({i})" class="copy-btn">📋 Copy</button>
                </div>
            </div>
            
            <div class="insight-analysis">
                <div id="analysis-{i}" class="analysis-text">
                    {truncated_analysis}
                </div>
                <div id="full-analysis-{i}" class="analysis-text" style="display: none;">
                    {full_analysis}
                </div>
                {"<button onclick=\"toggleAnalysis(" + str(i) + ")\" class=\"expand-btn\">Show Full Analysis</button>" if show_expand else ""}
            </div>
            
            <div class="insight-meta">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span>Urgency:</span>
                    <div class="urgency-bar">
                        <div class="urgency-fill" style="width: {urgency*100}%;"></div>
                    </div>
                    <span style="font-family: monospace;">{urgency:.2f}</span>
                </div>
                <div>
                    Type: <span style="color: #6366f1;">{insight.get('threat_type', 'Unknown')}</span>
                </div>
                <div>
                    Sentiment: <span style="color: {'#00ff00' if insight.get('sentiment') == 'positive' else '#ff4444' if insight.get('sentiment') == 'negative' else '#ffaa00'};">
                        {insight.get('sentiment', 'neutral').upper()}
                    </span>
                </div>
                {cybersec_data}
            </div>
        </div>
        """
    
    return insights_html

def _generate_analytics_section(analytics: Dict) -> str:
    """Generate threat analytics section"""
    if not analytics or analytics.get("status") == "error":
        return """
        <div class="analytics-grid">
            <div class="chart-container">
                <div class="chart-title">Threat Analytics Initializing</div>
                <p style="text-align: center; color: #888; padding: 40px;">
                    <span class="loading"><span></span><span></span><span></span></span>
                    <br><br>Analytics will be available after data collection
                </p>
            </div>
        </div>
        """
    
    threat_levels = analytics.get("threat_levels", {})
    categories = analytics.get("categories", {})
    max_level = max(threat_levels.values()) if threat_levels.values() else 1
    max_cat = max(categories.values()) if categories.values() else 1
    
    return f"""
    <div class="analytics-grid">
        <!-- Threat Levels Chart -->
        <div class="chart-container">
            <div class="chart-title">Threat Level Distribution</div>
            <div class="bar-chart">
                <div class="bar-item">
                    <div class="bar-label">Critical</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(threat_levels.get('critical', 0)/max_level*100) if max_level else 0}%; background: linear-gradient(90deg, #ff4444, #ff6666);"></div>
                    </div>
                    <div class="bar-value">{threat_levels.get('critical', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">High</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(threat_levels.get('high', 0)/max_level*100) if max_level else 0}%; background: linear-gradient(90deg, #ffaa00, #ffcc44);"></div>
                    </div>
                    <div class="bar-value">{threat_levels.get('high', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Medium</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(threat_levels.get('medium', 0)/max_level*100) if max_level else 0}%; background: linear-gradient(90deg, #ffff00, #ffff88);"></div>
                    </div>
                    <div class="bar-value">{threat_levels.get('medium', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Low</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(threat_levels.get('low', 0)/max_level*100) if max_level else 0}%; background: linear-gradient(90deg, #00ff00, #44ff44);"></div>
                    </div>
                    <div class="bar-value">{threat_levels.get('low', 0)}</div>
                </div>
            </div>
        </div>
        
        <!-- Categories Chart -->
        <div class="chart-container">
            <div class="chart-title">Threat Categories</div>
            <div class="bar-chart">
                <div class="bar-item">
                    <div class="bar-label">Intel</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(categories.get('threat_intel', 0)/max_cat*100) if max_cat else 0}%;"></div>
                    </div>
                    <div class="bar-value">{categories.get('threat_intel', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Breach</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(categories.get('data_breach', 0)/max_cat*100) if max_cat else 0}%;"></div>
                    </div>
                    <div class="bar-value">{categories.get('data_breach', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Vuln</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(categories.get('vulnerability', 0)/max_cat*100) if max_cat else 0}%;"></div>
                    </div>
                    <div class="bar-value">{categories.get('vulnerability', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Malware</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(categories.get('malware', 0)/max_cat*100) if max_cat else 0}%;"></div>
                    </div>
                    <div class="bar-value">{categories.get('malware', 0)}</div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">APT</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: {(categories.get('apt', 0)/max_cat*100) if max_cat else 0}%;"></div>
                    </div>
                    <div class="bar-value">{categories.get('apt', 0)}</div>
                </div>
            </div>
        </div>
        
        <!-- Summary Stats -->
        <div class="chart-container">
            <div class="chart-title">Intelligence Summary</div>
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 2em; color: #6366f1; margin-bottom: 10px;">
                    {analytics.get('summary', {}).get('total_threats', 0)}
                </div>
                <div style="color: #888; margin-bottom: 20px;">Total Threats Analyzed</div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; text-align: center;">
                    <div>
                        <div style="font-size: 1.5em; color: #ff4444;">{analytics.get('summary', {}).get('high_priority', 0)}</div>
                        <div style="font-size: 0.8em; color: #888;">High Priority</div>
                    </div>
                    <div>
                        <div style="font-size: 1.5em; color: #ffaa00;">{analytics.get('summary', {}).get('avg_urgency', 0):.2f}</div>
                        <div style="font-size: 0.8em; color: #888;">Avg Urgency</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """

def _generate_channels_section(monitoring: Dict) -> str:
    """Generate monitored channels section"""
    channels_data = [
        {"name": "@DarkfeedNews", "icon": "🔴", "desc": "Advanced Persistent Threats", "type": "threat_intel"},
        {"name": "@breachdetector", "icon": "🟠", "desc": "Data Breach Monitor", "type": "breach_monitor"},
        {"name": "@secharvester", "icon": "🔵", "desc": "Security News & CVEs", "type": "security_news"}
    ]
    
    return f"""
    <div class="channels-section">
        <h3 style="color: #6366f1; margin-bottom: 10px;">📡 Monitored Intelligence Sources</h3>
        <p style="color: #888; margin-bottom: 20px;">
            Real-time monitoring of {len(channels_data)} premium cybersecurity intelligence channels
        </p>
        
        <div class="channels-grid">
            {''.join([f'''
            <div class="channel-card">
                <div class="channel-icon">{channel["icon"]}</div>
                <div class="channel-name">{channel["name"]}</div>
                <div class="channel-desc">{channel["desc"]}</div>
                <div style="margin-top: 10px; font-size: 0.7em; color: {'#00ff00' if monitoring.get('active') else '#ffaa00'};">
                    ● {'MONITORING' if monitoring.get('active') else 'STANDBY'}
                </div>
            </div>
            ''' for channel in channels_data])}
        </div>
    </div>
    """

def _generate_error_dashboard(error: str) -> str:
    """Generate error dashboard"""
    return f"""
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
            .error-details {{ 
                background: rgba(255, 68, 68, 0.1); 
                border: 1px solid #ff4444; 
                border-radius: 8px; 
                padding: 20px; 
                margin: 20px 0; 
                text-align: left;
            }}
            .retry-btn {{
                background: #6366f1;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                margin: 20px 10px;
                font-size: 16px;
            }}
            .retry-btn:hover {{ background: #8b5cf6; }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>🛡️ CIPHER Dashboard</h1>
            <h2>⚠️ System Temporarily Unavailable</h2>
            <div class="error-details">
                <strong>Error Details:</strong><br>
                {error}
            </div>
            <p>The CIPHER cybersecurity platform is experiencing a temporary issue.</p>
            <p>Please try again in a few moments.</p>
            
            <button class="retry-btn" onclick="location.reload()">🔄 Retry</button>
            <button class="retry-btn" onclick="location.href='/health'">🏥 Check Health</button>
            
            <script>
                // Auto-retry every 10 seconds
                setTimeout(() => location.reload(), 10000);
            </script>
        </div>
    </body>
    </html>
    """

# Helper functions
def _get_threat_level_text(score: float) -> str:
    """Convert threat score to text"""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.6:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"

def _format_date(date_str: str) -> str:
    """Format date string for display"""
    if not date_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%m/%d %H:%M")
    except:
        return date_str[:16] if date_str else "Unknown"

def _truncate_text(text: str, max_length: int) -> str:
    """Truncate text with ellipsis"""
    if not text:
        return "No content available"
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."

def _get_empty_stats() -> Dict:
    """Get empty stats structure"""
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
        "ransomware_alerts": 0,
        "monitoring_active": False,
        "data_source": "initializing"
    }

def _get_empty_monitoring() -> Dict:
    """Get empty monitoring structure"""
    return {
        "active": False,
        "subsystems": {"bigquery": False, "gemini": False, "telegram": False},
        "channels": {"count": 3, "monitored": ["@DarkfeedNews", "@breachdetector", "@secharvester"]}
    }

def _get_empty_analytics() -> Dict:
    """Get empty analytics structure"""
    return {
        "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "categories": {"threat_intel": 0, "data_breach": 0, "vulnerability": 0, "malware": 0, "ransomware": 0, "apt": 0, "other": 0},
        "summary": {"total_threats": 0, "high_priority": 0, "avg_urgency": 0.0}
    }

# Additional API endpoints
@router.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get dashboard data as JSON"""
    try:
        utils = get_utils()
        if utils:
            stats = await utils.get_comprehensive_stats()
            insights_data = await utils.get_threat_insights()
            monitoring = await utils.get_monitoring_status()
            analytics = await utils.get_threat_analytics()
            
            return {
                "stats": stats,
                "insights": insights_data["insights"][:10],
                "monitoring": monitoring,
                "analytics": analytics,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "stats": _get_empty_stats(),
                "insights": [],
                "monitoring": _get_empty_monitoring(),
                "analytics": _get_empty_analytics(),
                "status": "initializing"
            }
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        return {"error": str(e), "status": "error"}

@router.get("/api/insights/full")
async def get_full_insights(
    limit: int = Query(20, ge=1, le=100),
    threat_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    include_raw: bool = Query(False, description="Include raw message text")
):
    """Get full, untruncated threat intelligence insights"""
    try:
        utils = get_utils()
        if utils:
            insights_data = await utils.get_threat_insights()
            insights = insights_data["insights"]
            
            # Apply filters
            if threat_level:
                insights = [i for i in insights if i.get("threat_level") == threat_level.lower()]
            if category:
                insights = [i for i in insights if i.get("category") == category.lower()]
            
            # Prepare full insights without truncation
            full_insights = []
            for insight in insights[:limit]:
                full_insight = {
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
                    full_insight["raw_message"] = insight.get("message_text", "")
                
                full_insights.append(full_insight)
            
            return {
                "insights": full_insights,
                "total_returned": len(full_insights),
                "total_available": len(insights),
                "filters_applied": {"threat_level": threat_level, "category": category},
                "timestamp": datetime.now().isoformat(),
                "source": insights_data.get("source", "bigquery")
            }
        else:
            return {"insights": [], "total_returned": 0, "status": "initializing"}
    except Exception as e:
        logger.error(f"Full insights error: {e}")
        return {"insights": [], "total_returned": 0, "error": str(e)}

@router.get("/api/insights/detailed")
async def get_detailed_insights(
    limit: int = Query(50, ge=1, le=100),
    threat_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None)
):
    """Get detailed insights with filtering"""
    try:
        utils = get_utils()
        if utils:
            insights_data = await utils.get_threat_insights()
            insights = insights_data["insights"]
            
            # Apply filters
            if threat_level:
                insights = [i for i in insights if i.get("threat_level") == threat_level.lower()]
            if category:
                insights = [i for i in insights if i.get("category") == category.lower()]
            
            return {
                "insights": insights[:limit],
                "total": len(insights),
                "filtered": len(insights) < insights_data["total"],
                "filters": {"threat_level": threat_level, "category": category}
            }
        else:
            return {"insights": [], "total": 0, "status": "initializing"}
    except Exception as e:
        logger.error(f"Detailed insights error: {e}")
        return {"insights": [], "total": 0, "error": str(e)}

# Export the router
__all__ = ["router"]
