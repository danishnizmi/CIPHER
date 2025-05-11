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

# Create startup script separately to avoid heredoc issues
RUN echo '#!/bin/bash' > /app/startup.sh && \
    echo 'set -e' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo 'echo "======================================"' >> /app/startup.sh && \
    echo 'echo "Starting Threat Intelligence Platform"' >> /app/startup.sh && \
    echo 'echo "======================================"' >> /app/startup.sh && \
    echo 'echo "Time: $(date)"' >> /app/startup.sh && \
    echo 'echo "PORT: ${PORT:-8080}"' >> /app/startup.sh && \
    echo 'echo "GCP_PROJECT: ${GCP_PROJECT}"' >> /app/startup.sh && \
    echo 'echo "ENVIRONMENT: ${ENVIRONMENT}"' >> /app/startup.sh && \
    echo 'echo "======================================"' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Function to check if port is available' >> /app/startup.sh && \
    echo 'check_port() {' >> /app/startup.sh && \
    echo '    local port=${1:-8080}' >> /app/startup.sh && \
    echo '    if nc -z localhost $port; then' >> /app/startup.sh && \
    echo '        echo "ERROR: Port $port is already in use"' >> /app/startup.sh && \
    echo '        exit 1' >> /app/startup.sh && \
    echo '    fi' >> /app/startup.sh && \
    echo '    echo "Port $port is available"' >> /app/startup.sh && \
    echo '}' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Basic health check function' >> /app/startup.sh && \
    echo 'basic_health_check() {' >> /app/startup.sh && \
    echo '    echo "Running basic health check..."' >> /app/startup.sh && \
    echo '    if [ ! -f /app/app.py ]; then' >> /app/startup.sh && \
    echo '        echo "ERROR: app.py not found"' >> /app/startup.sh && \
    echo '        exit 1' >> /app/startup.sh && \
    echo '    fi' >> /app/startup.sh && \
    echo '    if [ ! -d /app/templates ]; then' >> /app/startup.sh && \
    echo '        echo "ERROR: templates directory not found"' >> /app/startup.sh && \
    echo '        exit 1' >> /app/startup.sh && \
    echo '    fi' >> /app/startup.sh && \
    echo '    echo "Basic health check passed"' >> /app/startup.sh && \
    echo '}' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Initialize application' >> /app/startup.sh && \
    echo 'echo "Initializing application..."' >> /app/startup.sh && \
    echo 'basic_health_check' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Check port availability' >> /app/startup.sh && \
    echo 'check_port ${PORT:-8080}' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Export environment variables' >> /app/startup.sh && \
    echo 'export PYTHONPATH=/app' >> /app/startup.sh && \
    echo 'export PYTHONDONTWRITEBYTECODE=1' >> /app/startup.sh && \
    echo 'export PYTHONUNBUFFERED=1' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Log Python version and installed packages' >> /app/startup.sh && \
    echo 'echo "Python version:"' >> /app/startup.sh && \
    echo 'python --version' >> /app/startup.sh && \
    echo 'echo "Installed packages:"' >> /app/startup.sh && \
    echo 'pip list | grep -E "Flask|gunicorn|google-cloud"' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo 'echo "======================================"' >> /app/startup.sh && \
    echo 'echo "Starting Gunicorn..."' >> /app/startup.sh && \
    echo 'echo "======================================"' >> /app/startup.sh && \
    echo '' >> /app/startup.sh && \
    echo '# Start Gunicorn with the PORT environment variable' >> /app/startup.sh && \
    echo 'exec gunicorn \' >> /app/startup.sh && \
    echo '    --bind "0.0.0.0:${PORT:-8080}" \' >> /app/startup.sh && \
    echo '    --workers 2 \' >> /app/startup.sh && \
    echo '    --threads 4 \' >> /app/startup.sh && \
    echo '    --timeout 120 \' >> /app/startup.sh && \
    echo '    --worker-class gthread \' >> /app/startup.sh && \
    echo '    --preload \' >> /app/startup.sh && \
    echo '    --log-level info \' >> /app/startup.sh && \
    echo '    --access-logfile - \' >> /app/startup.sh && \
    echo '    --error-logfile - \' >> /app/startup.sh && \
    echo '    --enable-stdio-inheritance \' >> /app/startup.sh && \
    echo '    app:app' >> /app/startup.sh

# Make startup script executable
RUN chmod +x /app/startup.sh

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

# Set working directory (comment without the word SET)
WORKDIR /app

# Use startup script as entrypoint
ENTRYPOINT ["/app/startup.sh"]
