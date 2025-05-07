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
    # Secret management optimization
    USE_ENV_VARS_FOR_SECRETS=true \
    SECRET_TTL=86400 \
    # BigQuery cost controls
    BIGQUERY_MAX_BYTES_BILLED=104857600 \
    # Container configuration
    PORT=8080

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies in layers for better caching
RUN pip install --no-cache-dir --upgrade pip==23.1.2 && \
    pip install --no-cache-dir --upgrade wheel setuptools && \
    # Install numpy first to avoid compatibility issues
    pip install --no-cache-dir numpy==1.24.3 && \
    # Install pandas next (depends on numpy)
    pip install --no-cache-dir pandas==1.5.3 && \
    # Then install all remaining requirements
    pip install --no-cache-dir -r requirements.txt

# Create necessary directories with proper permissions
RUN mkdir -p /app/static/src /app/static/dist /app/templates /app/data /app/logs /app/tmp /app/secrets && \
    # Create directory for offline secret backups
    mkdir -p /app/data/secrets && \
    chmod -R 755 /app

# Set Secret Manager backup path for offline fallbacks
ENV SECRET_BACKUP_PATH=/app/data/secrets/secret_backups.json

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Create Tailwind CSS file for frontend
RUN echo '@tailwind base; @tailwind components; @tailwind utilities;' > /app/static/src/input.css

# Expose port 8080
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Initialize application at startup
RUN echo '#!/bin/bash \n\
# Initialize environment \n\
python -c "import config; config.Config.init_app()" \n\
\n\
# Start the application \n\
exec gunicorn \
    --bind "0.0.0.0:${PORT:-8080}" \
    --workers ${GUNICORN_WORKERS:-2} \
    --threads ${GUNICORN_THREADS:-4} \
    --timeout ${GUNICORN_TIMEOUT:-120} \
    --worker-class ${GUNICORN_WORKER_CLASS:-gthread} \
    --preload \
    --access-logfile - \
    --error-logfile - \
    --log-level ${LOG_LEVEL:-info} \
    --worker-tmp-dir /dev/shm \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    "app:app"' > /app/startup.sh && chmod +x /app/startup.sh

# Switch to non-root user
USER appuser

# Start the application with initialization
CMD ["/app/startup.sh"]
