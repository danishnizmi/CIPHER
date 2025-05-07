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
    # Default credentials
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=admin \
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
    chmod -R 755 /app

# Initialize script to ensure consistent secret setup at container start
RUN echo '#!/bin/bash\n\
# Delete existing Secret Manager secrets to avoid duplicates\n\
if [ "$CLEAN_SECRETS" = "true" ]; then\n\
  echo "Cleaning up existing secrets..."\n\
  for SECRET_ID in "api-keys" "auth-config" "feed-config" "admin-initial-password"; do\n\
    gcloud secrets delete "$SECRET_ID" --quiet || echo "Secret $SECRET_ID not found or already deleted"\n\
  done\n\
  echo "Secrets cleaned up"\n\
fi\n\
\n\
# Initialize admin password environment variable\n\
echo "Setting up admin password environment variable"\n\
export SECRET_ADMIN_INITIAL_PASSWORD="admin"\n\
\n\
# Initialize auth config with proper admin credentials\n\
AUTH_CONFIG=\'{"session_secret":"dev-secret-key","enabled":true,"users":{"admin":{"password":"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918","role":"admin","created_at":"'"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"'"}}}\'\n\
export SECRET_AUTH_CONFIG="$AUTH_CONFIG"\n\
\n\
# Initialize API keys\n\
export SECRET_API_KEYS=\'{"platform_api_key":"dev-api-key"}\'\n\
\n\
# Initialize feed config\n\
export SECRET_FEED_CONFIG=\'{"feeds":[],"update_interval_hours":6}\'\n\
\n\
# Start the application\n\
exec "$@"\n\
' > /app/init-secrets.sh && chmod +x /app/init-secrets.sh

# Create Tailwind CSS file for frontend
RUN echo '@tailwind base; @tailwind components; @tailwind utilities;' > /app/static/src/input.css

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    chown -R appuser:appuser /app

# Expose port 8080
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Switch to non-root user
USER appuser

# Start with the entrypoint script to initialize secrets, then start the application
ENTRYPOINT ["/app/init-secrets.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "120", "--worker-class", "gthread", "--preload", "--log-level", "info", "app:app"]
