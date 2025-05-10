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
    PORT=8080 \
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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first (for better caching)
COPY requirements.txt .

# Install Python dependencies with error handling
RUN pip install --no-cache-dir --upgrade pip==23.1.2 && \
    pip install --no-cache-dir --upgrade wheel setuptools && \
    pip install --no-cache-dir numpy==1.24.3 && \
    pip install --no-cache-dir pandas==1.5.3 && \
    pip install --no-cache-dir -r requirements.txt

# Create necessary directories with proper permissions
RUN mkdir -p /app/static/src \
    /app/static/dist \
    /app/templates \
    /app/data \
    /app/logs \
    /app/tmp \
    /app/cache && \
    chmod -R 755 /app

# Copy application code (order matters for caching)
COPY *.py /app/
COPY requirements.txt /app/
COPY templates /app/templates/

# Verify templates are copied
RUN ls -la /app/templates/ && \
    test -f /app/templates/base.html && \
    test -f /app/templates/500.html && \
    test -f /app/templates/dashboard.html && \
    test -f /app/templates/detail.html && \
    test -f /app/templates/content.html

# Create initialization script
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
    echo '# Function to check if port is available' >> /app/init-app.sh && \
    echo 'check_port() {' >> /app/init-app.sh && \
    echo '    local port=$1' >> /app/init-app.sh && \
    echo '    if nc -z localhost $port; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: Port $port is already in use"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    echo "Port $port is available"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Function to verify environment' >> /app/init-app.sh && \
    echo 'verify_environment() {' >> /app/init-app.sh && \
    echo '    echo "Verifying environment..."' >> /app/init-app.sh && \
    echo '    if [ ! -f /app/app.py ]; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: app.py not found"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    if [ ! -d /app/templates ]; then' >> /app/init-app.sh && \
    echo '        echo "ERROR: templates directory not found"' >> /app/init-app.sh && \
    echo '        exit 1' >> /app/init-app.sh && \
    echo '    fi' >> /app/init-app.sh && \
    echo '    echo "Environment verified successfully"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Function to initialize config' >> /app/init-app.sh && \
    echo 'init_config() {' >> /app/init-app.sh && \
    echo '    echo "Initializing application configuration..."' >> /app/init-app.sh && \
    echo '    python3 -c "' >> /app/init-app.sh && \
    echo 'import os' >> /app/init-app.sh && \
    echo 'import sys' >> /app/init-app.sh && \
    echo 'try:' >> /app/init-app.sh && \
    echo '    from config import Config' >> /app/init-app.sh && \
    echo '    Config.init_app()' >> /app/init-app.sh && \
    echo '    print(f\"Configuration initialized successfully\")' >> /app/init-app.sh && \
    echo '    print(f\"GCP_PROJECT: {Config.GCP_PROJECT}\")' >> /app/init-app.sh && \
    echo 'except Exception as e:' >> /app/init-app.sh && \
    echo '    print(f\"ERROR: Configuration initialization failed: {str(e)}\")' >> /app/init-app.sh && \
    echo '    import traceback' >> /app/init-app.sh && \
    echo '    traceback.print_exc()' >> /app/init-app.sh && \
    echo '    sys.exit(1)' >> /app/init-app.sh && \
    echo '"' >> /app/init-app.sh && \
    echo '}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Main initialization' >> /app/init-app.sh && \
    echo 'echo "Starting initialization sequence..."' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Verify environment first' >> /app/init-app.sh && \
    echo 'verify_environment' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Check port availability' >> /app/init-app.sh && \
    echo 'check_port ${PORT:-8080}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Initialize configuration' >> /app/init-app.sh && \
    echo 'init_config' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Create a health check file to indicate readiness' >> /app/init-app.sh && \
    echo 'touch /app/.ready' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo 'echo "Initialization complete, starting application..."' >> /app/init-app.sh && \
    echo 'echo "======================================"' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Start the application' >> /app/init-app.sh && \
    echo 'exec "$@"' >> /app/init-app.sh

# Make script executable
RUN chmod +x /app/init-app.sh

# Create health check script
RUN echo '#!/bin/bash' > /app/healthcheck.sh && \
    echo 'curl -f http://localhost:${PORT:-8080}/health || exit 1' >> /app/healthcheck.sh

# Make health check script executable
RUN chmod +x /app/healthcheck.sh

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Expose port
EXPOSE 8080

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/app/healthcheck.sh"]

# Switch to non-root user
USER appuser

# Set the working directory
WORKDIR /app

# Use the initialization script as entrypoint
ENTRYPOINT ["/app/init-app.sh"]

# Default command with optimized Gunicorn settings
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "120", "--worker-class", "gthread", "--preload", "--log-level", "info", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
