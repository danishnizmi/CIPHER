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
    # Default PORT for Cloud Run
    PORT=8080 \
    # BigQuery cost controls
    BIGQUERY_MAX_BYTES_BILLED=104857600 \
    # Timeout configurations
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
    # Install numpy first to avoid compatibility issues
    pip install --no-cache-dir numpy==1.24.3 && \
    # Install pandas next (depends on numpy)
    pip install --no-cache-dir pandas==1.5.3 && \
    # Then install all remaining requirements
    pip install --no-cache-dir -r requirements.txt

# Create necessary directories with proper permissions
RUN mkdir -p /app/static/src /app/static/dist /app/templates /app/data /app/logs /app/tmp /app/cache && \
    chmod -R 755 /app

# Copy all application code
COPY . .

# Create initialization script with robust error handling
RUN cat > /app/init-app.sh << 'EOF'
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
    local port=$1
    if nc -z localhost $port; then
        echo "ERROR: Port $port is already in use"
        exit 1
    fi
    echo "Port $port is available"
}

# Function to initialize config with timeout
init_config() {
    echo "Initializing application configuration..."
    timeout ${STARTUP_TIMEOUT}s python3 -c "
import os
import sys
import time
import traceback

start_time = time.time()

try:
    # Import and initialize configuration
    from config import Config
    Config.init_app()
    
    # Verify critical components
    if not hasattr(Config, 'GCP_PROJECT') or not Config.GCP_PROJECT:
        raise ValueError('GCP_PROJECT not configured')
    
    print(f'Configuration initialized successfully in {time.time() - start_time:.2f} seconds')
    print(f'GCP_PROJECT: {Config.GCP_PROJECT}')
    print(f'API_KEY configured: {\"API_KEY\" in os.environ or hasattr(Config, \"API_KEY\")}')
    
except Exception as e:
    print(f'ERROR: Configuration initialization failed: {str(e)}')
    traceback.print_exc()
    sys.exit(1)
" || {
    echo "Configuration initialization failed or timed out"
    exit 1
}
}

# Function to verify GCP connectivity
verify_gcp() {
    echo "Verifying GCP connectivity..."
    python3 -c "
import sys
try:
    from google.cloud import storage
    client = storage.Client()
    print('GCP connectivity verified')
except Exception as e:
    print(f'WARNING: GCP connectivity issue: {str(e)}')
    # Don't exit - app might still work with limited functionality
"
}

# Main initialization
echo "Starting initialization sequence..."

# Check port availability
check_port ${PORT:-8080}

# Initialize configuration
init_config

# Verify GCP connectivity (non-blocking)
verify_gcp

# Create a health check file to indicate readiness
touch /app/.ready

echo "======================================"
echo "Initialization complete, starting application..."
echo "======================================"

# Start the application
exec "$@"
EOF

# Make script executable
RUN chmod +x /app/init-app.sh

# Create health check script
RUN cat > /app/healthcheck.sh << 'EOF'
#!/bin/bash
# Simple health check that verifies the app is responding
curl -f http://localhost:${PORT:-8080}/health || exit 1
EOF
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
