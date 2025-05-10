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

# Create startup script
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
    echo '# Start the application' >> /app/startup.sh && \
    echo 'exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 120 --worker-class gthread --preload --log-level info --access-logfile - --error-logfile - app:app' >> /app/startup.sh

# Make script executable
RUN chmod +x /app/startup.sh

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

# Use the startup script
ENTRYPOINT ["/app/startup.sh"]
