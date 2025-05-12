# Use Python 3.10 slim image for reduced image size
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables for optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    BIGQUERY_MAX_BYTES_BILLED=104857600 \
    GUNICORN_TIMEOUT=120 \
    STARTUP_TIMEOUT=60 \
    AUTO_ANALYZE=true \
    NLP_ENABLED=true \
    ANALYSIS_ENABLED=true

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    gcc \
    python3-dev \
    libpq-dev \
    netcat-traditional \
    procps \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first (for better caching)
COPY requirements.txt .

# Install Python dependencies with error handling
RUN pip install --no-cache-dir --upgrade pip==23.1.2 && \
    pip install --no-cache-dir --upgrade wheel setuptools && \
    pip install --no-cache-dir numpy==1.24.3 && \
    pip install --no-cache-dir pandas==1.5.3 && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn==21.2.0

# Create necessary directories with proper permissions
RUN mkdir -p /app/static/src \
    /app/static/dist \
    /app/templates \
    /app/data \
    /app/logs \
    /app/tmp \
    /app/cache && \
    chmod -R 755 /app

# Copy application code
COPY *.py /app/
COPY templates/ /app/templates/

# Create init-app.sh script for proper initialization
RUN echo '#!/bin/bash' > /app/init-app.sh && \
    echo 'set -e' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo 'echo "Starting Threat Intelligence Platform"' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo 'echo "Time: $(date)"' >> /app/init-app.sh && \
    echo 'echo "PORT: ${PORT:-8080}"' >> /app/init-app.sh && \
    echo 'echo "GCP_PROJECT: ${GCP_PROJECT}"' >> /app/init-app.sh && \
    echo 'echo "ENVIRONMENT: ${ENVIRONMENT}"' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Function to run a direct bigquery load to initialize the system' >> /app/init-app.sh && \
    echo 'initialize_platform() {' >> /app/init-app.sh && \
    echo '    echo "Running platform initialization..."' >> /app/init-app.sh && \
    echo '    # Run a quick initialization script to ensure data is loaded' >> /app/init-app.sh && \
    echo '    python3 -c "from config import Config; Config.init_app(); from ingestion import ensure_default_feeds, initialize_bigquery_tables, ensure_bucket_exists; initialize_bigquery_tables(); ensure_bucket_exists(Config.GCS_BUCKET); ensure_default_feeds()"' >> /app/init-app.sh && \
    echo '    echo "Initialization complete"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Initialize platform components' >> /app/init-app.sh && \
    echo 'initialize_platform &' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Function to check if port is available' >> /app/init-app.sh && \
    echo 'check_port() {' >> /app/init-app.sh && \
    echo '    local port=${1:-8080}' >> /app/init-app.sh && \
    echo '    if nc -z localhost $port; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: Port $port is already in use"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    echo "Port $port is available"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Basic health check function' >> /app/init-app.sh && \
    echo 'basic_health_check() {' >> /app/init-app.sh && \
    echo '    echo "Running basic health check..."' >> /app/init-app.sh && \
    echo '    if [ ! -f /app/app.py ]; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: app.py not found"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    if [ ! -d /app/templates ]; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: templates directory not found"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    if [ ! -f /app/templates/404.html ]; then' >> /app/init-app.sh && \
    echo '        echo "Creating 404.html template"' >> /app/init-app.sh && \
    echo '        cat > /app/templates/404.html << "EOF"' >> /app/init-app.sh && \
    echo '{% extends "base.html" %}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '{% block title %}' >> /app/init-app.sh && \
    echo 'Page Not Found - Threat Intelligence Platform' >> /app/init-app.sh && \
    echo '{% endblock %}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '{% block content %}' >> /app/init-app.sh && \
    echo '<div class="page-header mb-6">' >> /app/init-app.sh && \
    echo '    <h1 class="text-2xl font-bold mb-2 flex items-center">' >> /app/init-app.sh && \
    echo '        <i class="fas fa-exclamation-circle text-yellow-600 mr-3"></i>' >> /app/init-app.sh && \
    echo '        Page Not Found (404)' >> /app/init-app.sh && \
    echo '    </h1>' >> /app/init-app.sh && \
    echo '    <p class="text-gray-600">The requested page could not be found</p>' >> /app/init-app.sh && \
    echo '</div>' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '<div class="auth-card max-w-lg mx-auto">' >> /app/init-app.sh && \
    echo '    <div class="text-center mb-8">' >> /app/init-app.sh && \
    echo '        <div class="text-yellow-600 text-6xl mb-4 flex justify-center">' >> /app/init-app.sh && \
    echo '            <i class="fas fa-search-location"></i>' >> /app/init-app.sh && \
    echo '        </div>' >> /app/init-app.sh && \
    echo '        <h2 class="text-2xl font-bold text-gray-800 mb-3">Page Not Found</h2>' >> /app/init-app.sh && \
    echo '        <p class="text-gray-600">The page you'"'"'re looking for doesn'"'"'t exist or has been moved.</p>' >> /app/init-app.sh && \
    echo '    </div>' >> /app/init-app.sh && \
    echo '    ' >> /app/init-app.sh && \
    echo '    <div class="flex justify-center space-x-4">' >> /app/init-app.sh && \
    echo '        <a href="/" class="btn btn-primary flex items-center">' >> /app/init-app.sh && \
    echo '            <i class="fas fa-home mr-2"></i> Go to Dashboard' >> /app/init-app.sh && \
    echo '        </a>' >> /app/init-app.sh && \
    echo '        <a href="javascript:window.history.back()" class="btn btn-secondary flex items-center">' >> /app/init-app.sh && \
    echo '            <i class="fas fa-arrow-left mr-2"></i> Go Back' >> /app/init-app.sh && \
    echo '        </a>' >> /app/init-app.sh && \
    echo '    </div>' >> /app/init-app.sh && \
    echo '</div>' >> /app/init-app.sh && \
    echo '{% endblock %}' >> /app/init-app.sh && \
    echo 'EOF' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    echo "Basic health check passed"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Force ingestion script for testing' >> /app/init-app.sh && \
    echo 'cat > /app/force_ingestion.py << "EOF"' >> /app/init-app.sh && \
    echo '#!/usr/bin/env python3' >> /app/init-app.sh && \
    echo 'import os' >> /app/init-app.sh && \
    echo 'import sys' >> /app/init-app.sh && \
    echo 'import logging' >> /app/init-app.sh && \
    echo 'logging.basicConfig(level=logging.INFO)' >> /app/init-app.sh && \
    echo 'logger = logging.getLogger("force-ingestion")' >> /app/init-app.sh && \
    echo 'from config import Config' >> /app/init-app.sh && \
    echo 'Config.init_app()' >> /app/init-app.sh && \
    echo 'from ingestion import ensure_default_feeds, initialize_bigquery_tables, ensure_bucket_exists, ingest_all_feeds' >> /app/init-app.sh && \
    echo 'logger.info("Initializing...")' >> /app/init-app.sh && \
    echo 'initialize_bigquery_tables()' >> /app/init-app.sh && \
    echo 'ensure_bucket_exists(Config.GCS_BUCKET)' >> /app/init-app.sh && \
    echo 'ensure_default_feeds()' >> /app/init-app.sh && \
    echo 'logger.info("Running ingestion...")' >> /app/init-app.sh && \
    echo 'results = ingest_all_feeds()' >> /app/init-app.sh && \
    echo 'success = sum(1 for r in results if r.get("status") == "success")' >> /app/init-app.sh && \
    echo 'logger.info(f"Ingestion complete: {success}/{len(results)} feeds processed")' >> /app/init-app.sh && \
    echo 'EOF' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo 'chmod +x /app/force_ingestion.py' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Initialize application' >> /app/init-app.sh && \
    echo 'echo "Initializing application..."' >> /app/init-app.sh && \
    echo 'basic_health_check' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Check port availability' >> /app/init-app.sh && \
    echo 'check_port ${PORT:-8080}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Export environment variables' >> /app/init-app.sh && \
    echo 'export PYTHONPATH=/app' >> /app/init-app.sh && \
    echo 'export PYTHONDONTWRITEBYTECODE=1' >> /app/init-app.sh && \
    echo 'export PYTHONUNBUFFERED=1' >> /app/init-app.sh && \
    echo 'export AUTO_ANALYZE=true' >> /app/init-app.sh && \
    echo 'export NLP_ENABLED=true' >> /app/init-app.sh && \
    echo 'export ANALYSIS_ENABLED=true' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Log Python version and installed packages' >> /app/init-app.sh && \
    echo 'echo "Python version:"' >> /app/init-app.sh && \
    echo 'python --version' >> /app/init-app.sh && \
    echo 'echo "Installed packages:"' >> /app/init-app.sh && \
    echo 'pip list | grep -E "Flask|gunicorn|google-cloud"' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Run ingestion in background' >> /app/init-app.sh && \
    echo 'echo "Starting data ingestion in background..."' >> /app/init-app.sh && \
    echo 'nohup python3 /app/force_ingestion.py > /app/ingestion.log 2>&1 &' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo 'echo "Starting Gunicorn..."' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Start Gunicorn with the PORT environment variable' >> /app/init-app.sh && \
    echo 'exec gunicorn \' >> /app/init-app.sh && \
    echo '    --bind "0.0.0.0:${PORT:-8080}" \' >> /app/init-app.sh && \
    echo '    --workers 2 \' >> /app/init-app.sh && \
    echo '    --threads 4 \' >> /app/init-app.sh && \
    echo '    --timeout 120 \' >> /app/init-app.sh && \
    echo '    --worker-class gthread \' >> /app/init-app.sh && \
    echo '    --preload \' >> /app/init-app.sh && \
    echo '    --log-level info \' >> /app/init-app.sh && \
    echo '    --access-logfile - \' >> /app/init-app.sh && \
    echo '    --error-logfile - \' >> /app/init-app.sh && \
    echo '    --enable-stdio-inheritance \' >> /app/init-app.sh && \
    echo '    app:app' >> /app/init-app.sh

# Make startup script executable
RUN chmod +x /app/init-app.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/healthcheck.sh && \
    echo 'curl -f http://localhost:${PORT:-8080}/health || exit 1' >> /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Expose port (Cloud Run will override this with PORT env var)
EXPOSE 8080

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/app/healthcheck.sh"]

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Use startup script as entrypoint
ENTRYPOINT ["/app/init-app.sh"]
