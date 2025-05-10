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
    STARTUP_TIMEOUT=60

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

# Verify templates are copied
RUN ls -la /app/templates/ && \
    test -f /app/templates/base.html || echo "base.html missing" && \
    test -f /app/templates/500.html || echo "500.html missing" && \
    test -f /app/templates/dashboard.html || echo "dashboard.html missing" && \
    test -f /app/templates/detail.html || echo "detail.html missing" && \
    test -f /app/templates/content.html || echo "content.html missing"

# Create startup script directly in Dockerfile
RUN cat > /app/startup.sh << 'EOF'
#!/bin/bash
set -e

echo "======================================"
echo "Starting Threat Intelligence Platform"
echo "======================================"
echo "Time: $(date)"
echo "PORT: ${PORT:-8080}"
echo "GCP_PROJECT: ${GCP_PROJECT}"
echo "ENVIRONMENT: ${ENVIRONMENT}"
echo "======================================"

# Function to check if port is available
check_port() {
    local port=${1:-8080}
    if nc -z localhost $port; then
        echo "ERROR: Port $port is already in use"
        exit 1
    fi
    echo "Port $port is available"
}

# Basic health check function
basic_health_check() {
    echo "Running basic health check..."
    if [ ! -f /app/app.py ]; then
        echo "ERROR: app.py not found"
        exit 1
    fi
    if [ ! -d /app/templates ]; then
        echo "ERROR: templates directory not found"
        exit 1
    fi
    echo "Basic health check passed"
}

# Initialize application
echo "Initializing application..."
basic_health_check

# Check port availability
check_port ${PORT:-8080}

# Export environment variables
export PYTHONPATH=/app
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

# Log Python version and installed packages
echo "Python version:"
python --version
echo "Installed packages:"
pip list | grep -E "Flask|gunicorn|google-cloud"

echo "======================================"
echo "Starting Gunicorn..."
echo "======================================"

# Start Gunicorn with the PORT environment variable
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8080}" \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --worker-class gthread \
    --preload \
    --log-level info \
    --access-logfile - \
    --error-logfile - \
    --enable-stdio-inheritance \
    app:app
EOF

# Make startup script executable
RUN chmod +x /app/startup.sh

# Create health check script
RUN cat > /app/healthcheck.sh << 'EOF'
#!/bin/bash
curl -f http://localhost:${PORT:-8080}/health || exit 1
EOF

# Make health check script executable
RUN chmod +x /app/healthcheck.sh

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

# Set the working directory
WORKDIR /app

# Use startup script as entrypoint
ENTRYPOINT ["/app/startup.sh"]
