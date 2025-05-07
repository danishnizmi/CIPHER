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

# Create initialization script (using RUN with echo instead of heredoc to avoid syntax issues)
RUN echo '#!/bin/bash' > /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Check if secrets need to be cleaned' >> /app/init-secrets.sh && \
    echo 'if [ "$CLEAN_SECRETS" = "true" ]; then' >> /app/init-secrets.sh && \
    echo '  echo "Cleaning up existing secrets..."' >> /app/init-secrets.sh && \
    echo '  for SECRET_ID in "api-keys" "auth-config" "feed-config" "admin-initial-password"; do' >> /app/init-secrets.sh && \
    echo '    if [ -n "$GCP_PROJECT" ]; then' >> /app/init-secrets.sh && \
    echo '      gcloud secrets delete "$SECRET_ID" --quiet --project="$GCP_PROJECT" || echo "Secret $SECRET_ID not found or already deleted"' >> /app/init-secrets.sh && \
    echo '    fi' >> /app/init-secrets.sh && \
    echo '  done' >> /app/init-secrets.sh && \
    echo '  echo "Secrets cleaned up"' >> /app/init-secrets.sh && \
    echo 'fi' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Use environment variables for secrets if provided, otherwise use defaults' >> /app/init-secrets.sh && \
    echo 'if [ -z "$SECRET_ADMIN_INITIAL_PASSWORD" ]; then' >> /app/init-secrets.sh && \
    echo '  echo "Using default admin password because none was provided"' >> /app/init-secrets.sh && \
    echo '  export SECRET_ADMIN_INITIAL_PASSWORD="${ADMIN_PASSWORD:-admin}"' >> /app/init-secrets.sh && \
    echo 'fi' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Initialize auth config with proper admin credentials if not already set' >> /app/init-secrets.sh && \
    echo 'if [ -z "$SECRET_AUTH_CONFIG" ]; then' >> /app/init-secrets.sh && \
    echo '  # Hash the admin password (SHA-256)' >> /app/init-secrets.sh && \
    echo '  ADMIN_PASSWORD_HASH=$(echo -n "${SECRET_ADMIN_INITIAL_PASSWORD}" | sha256sum | cut -d " " -f1)' >> /app/init-secrets.sh && \
    echo '  CURRENT_TIME=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)' >> /app/init-secrets.sh && \
    echo '  # Create auth config with secure session key' >> /app/init-secrets.sh && \
    echo '  SESSION_SECRET="${SECRET_KEY:-$(head -c 32 /dev/urandom | base64)}"' >> /app/init-secrets.sh && \
    echo '  AUTH_CONFIG="{\"session_secret\":\"$SESSION_SECRET\",\"enabled\":true,\"users\":{\"${ADMIN_USERNAME:-admin}\":{\"password\":\"$ADMIN_PASSWORD_HASH\",\"role\":\"admin\",\"created_at\":\"$CURRENT_TIME\"}}}"' >> /app/init-secrets.sh && \
    echo '  export SECRET_AUTH_CONFIG="$AUTH_CONFIG"' >> /app/init-secrets.sh && \
    echo 'fi' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Initialize API keys if not already set' >> /app/init-secrets.sh && \
    echo 'if [ -z "$SECRET_API_KEYS" ]; then' >> /app/init-secrets.sh && \
    echo '  # Generate random API key if not provided' >> /app/init-secrets.sh && \
    echo '  API_KEY="${API_KEY:-$(head -c 24 /dev/urandom | base64)}"' >> /app/init-secrets.sh && \
    echo '  export SECRET_API_KEYS="{\"platform_api_key\":\"$API_KEY\"}"' >> /app/init-secrets.sh && \
    echo 'fi' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Initialize feed config if not already set' >> /app/init-secrets.sh && \
    echo 'if [ -z "$SECRET_FEED_CONFIG" ]; then' >> /app/init-secrets.sh && \
    echo '  export SECRET_FEED_CONFIG="{\"feeds\":[],\"update_interval_hours\":${FEED_UPDATE_INTERVAL:-6}}"' >> /app/init-secrets.sh && \
    echo 'fi' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Print startup info' >> /app/init-secrets.sh && \
    echo 'echo "Starting threat intelligence platform with environment: $ENVIRONMENT"' >> /app/init-secrets.sh && \
    echo 'echo "GCP Project: $GCP_PROJECT Region: $GCP_REGION"' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Handle error in case we cannot start properly' >> /app/init-secrets.sh && \
    echo 'function handle_error() {' >> /app/init-secrets.sh && \
    echo '  echo "ERROR: Failed to start application properly"' >> /app/init-secrets.sh && \
    echo '  exit 1' >> /app/init-secrets.sh && \
    echo '}' >> /app/init-secrets.sh && \
    echo 'trap handle_error ERR' >> /app/init-secrets.sh && \
    echo '' >> /app/init-secrets.sh && \
    echo '# Start the application' >> /app/init-secrets.sh && \
    echo 'exec "$@"' >> /app/init-secrets.sh && \
    chmod +x /app/init-secrets.sh

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
