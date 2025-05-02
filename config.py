"""
Configuration module for the threat intelligence platform.
Contains settings for cloud services, feed sources, and application parameters.
"""

import os
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Base project paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = os.path.join(BASE_DIR, "data")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Environment settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
VERSION = os.getenv("VERSION", "1.0.2")

# Google Cloud Settings
GCP_PROJECT = os.getenv("GCP_PROJECT", "primal-chariot-382610")
GCP_REGION = os.getenv("GCP_REGION", "us-central1")
GCS_BUCKET = os.getenv("GCS_BUCKET", f"{GCP_PROJECT}-threat-data")
PUBSUB_TOPIC = os.getenv("PUBSUB_TOPIC", "threat-data-ingestion")

# BigQuery Settings
BIGQUERY_DATASET = os.getenv("BIGQUERY_DATASET", "threat_intelligence")
BQ_LOCATION = os.getenv("BQ_LOCATION", "US")

# Full table IDs for BigQuery
BQ_TABLES = {
    "threatfox": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.threatfox_iocs",
    "phishtank": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.phishtank_urls",
    "urlhaus": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.urlhaus_malware",
    "cisa_kev": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.cisa_vulnerabilities",
    "tor_exit_nodes": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.tor_exit_nodes",
    "threat_campaigns": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.threat_campaigns",
    "threat_analysis": f"{GCP_PROJECT}.{BIGQUERY_DATASET}.threat_analysis"
}

# Authentication settings
API_KEY = os.getenv("API_KEY", "b03bb05c6597c6473e83a271c0bb5d492061fea4c0e67cc7")
SECRET_KEY = os.getenv("SECRET_KEY", "5a92c3067bc4587d021925678ea071825973c85c2b824df3bfff14ff8bc803a9")

# API configuration
API_PORT = int(os.getenv("API_PORT", 8080))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
DEBUG_MODE = ENVIRONMENT != "production"
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

# Set up logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": LOG_LEVEL,
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": LOG_LEVEL,
            "formatter": "standard",
            "filename": os.path.join(DATA_DIR, "app.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
        }
    },
    "loggers": {
        "": {  # root logger
            "handlers": ["console", "file"],
            "level": LOG_LEVEL,
            "propagate": True
        },
    }
}

# Threat Intelligence Feed Configurations
THREAT_FEEDS = [
    {
        "name": "threatfox",
        "description": "ThreatFox IOCs from abuse.ch",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "format": "json",
        "storage_path": "feeds/threatfox",
        "bq_table": BQ_TABLES["threatfox"],
        "schedule": "hourly",
        "enabled": True,
        "headers": {
            "User-Agent": f"ThreatIntelligencePlatform/{VERSION}"
        }
    },
    {
        "name": "phishtank",
        "description": "PhishTank verified online URLs",
        "url": "https://cdn.phishtank.com/datadumps/verified_online.json",
        "format": "json",
        "storage_path": "feeds/phishtank",
        "bq_table": BQ_TABLES["phishtank"],
        "schedule": "daily",
        "enabled": True,
        "headers": {
            "User-Agent": f"ThreatIntelligencePlatform/{VERSION}"
        }
    },
    {
        "name": "urlhaus",
        "description": "URLhaus recent malware URLs",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "format": "csv",
        "storage_path": "feeds/urlhaus",
        "bq_table": BQ_TABLES["urlhaus"],
        "schedule": "hourly", 
        "enabled": True,
        "headers": {
            "User-Agent": f"ThreatIntelligencePlatform/{VERSION}"
        }
    },
    {
        "name": "cisa_kev",
        "description": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "format": "json",
        "storage_path": "feeds/cisa_kev",
        "bq_table": BQ_TABLES["cisa_kev"],
        "schedule": "daily",
        "enabled": True,
        "headers": {
            "User-Agent": f"ThreatIntelligencePlatform/{VERSION}"
        }
    },
    {
        "name": "tor_exit_nodes",
        "description": "Tor Project Exit Node List",
        "url": "https://check.torproject.org/torbulkexitlist",
        "format": "text",
        "storage_path": "feeds/tor_exit_nodes",
        "bq_table": BQ_TABLES["tor_exit_nodes"],
        "schedule": "daily",
        "enabled": True,
        "headers": {
            "User-Agent": f"ThreatIntelligencePlatform/{VERSION}"
        }
    }
]

# Feed parser configurations
FEED_PARSERS = {
    "threatfox": {
        "id_field": "threat_id",
        "timestamp_field": "first_seen_utc",
        "array_fields": ["tags"],
        "date_fields": ["first_seen_utc", "last_seen_utc"],
        "int_fields": ["confidence_level"],
        "transformations": {
            "tags": lambda x: x.split(",") if isinstance(x, str) else x
        }
    },
    "phishtank": {
        "id_field": "phish_id",
        "timestamp_field": "submission_time",
        "array_fields": ["details"],
        "date_fields": ["submission_time", "verification_time"],
        "bool_fields": ["verified", "online"],
        "transformations": {
            "verified": lambda x: x == "yes",
            "online": lambda x: x == "yes"
        }
    },
    "urlhaus": {
        "id_field": "id",
        "timestamp_field": "dateadded",
        "array_fields": ["tags"],
        "date_fields": ["dateadded", "last_online"],
        "skip_lines": 8,  # Skip header comments
        "transformations": {
            "tags": lambda x: x.split(",") if isinstance(x, str) and x else []
        }
    },
    "cisa_kev": {
        "root_element": "vulnerabilities",
        "id_field": "cveID",
        "timestamp_field": "dateAdded",
        "array_fields": ["cwes"],
        "date_fields": ["dateAdded", "dueDate"],
        "transformations": {}
    },
    "tor_exit_nodes": {
        "transformations": {
            "ip": lambda x: x.strip(),
            "source": lambda x: "torproject",
            "type": lambda x: "exit_node",
            "timestamp": lambda x: datetime.datetime.utcnow().isoformat()
        }
    }
}

# Analysis configuration
ANALYSIS_CONFIG = {
    "max_batch_size": 1000,
    "similarity_threshold": 0.75,
    "correlation_threshold": 0.5,
    "time_window_days": 30
}

# Dashboard configuration
DASHBOARD_CONFIG = {
    "refresh_interval": 300,  # seconds
    "time_ranges": ["1h", "6h", "24h", "7d", "30d", "90d"],
    "default_range": "24h",
    "max_items": 1000,
    "cache_ttl": 300  # seconds
}

# Helper functions
def get_feed_config(feed_name):
    """Get configuration for a specific feed"""
    for feed in THREAT_FEEDS:
        if feed["name"] == feed_name:
            return feed
    return None

def get_parser_config(feed_name):
    """Get parser configuration for a specific feed"""
    return FEED_PARSERS.get(feed_name, {})

def get_feeds_by_schedule(schedule):
    """Get all feeds that run on the specified schedule"""
    return [feed for feed in THREAT_FEEDS if feed["schedule"] == schedule and feed["enabled"]]

def get_enabled_feeds():
    """Get all enabled feeds"""
    return [feed for feed in THREAT_FEEDS if feed["enabled"]]

def get_bigquery_table(feed_name):
    """Get the BigQuery table name for a feed"""
    feed = get_feed_config(feed_name)
    if feed and "bq_table" in feed:
        return feed["bq_table"]
    return None

# Initialize logging
import logging.config
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

logger.info(f"Configuration loaded for environment: {ENVIRONMENT}")
