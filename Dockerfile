FROM python:3.10-slim

WORKDIR /app

# Set environment variables - removed PORT (Cloud Run sets this)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ENVIRONMENT=production \
    LOAD_SECRETS=true \
    ENSURE_GCP_RESOURCES=true \
    IGNORE_PERMISSION_ERRORS=false

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    curl \
    gnupg \
    apt-transport-https \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install gcloud CLI for better GCP integration
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p static/dist templates data logs /app/secrets /tmp/keys

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir numpy==1.24.3 pandas==1.5.3 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Generate a minimal CSS file for the frontend if not exists
RUN if [ ! -f static/dist/output.css ]; then \
    echo "@tailwind base; @tailwind components; @tailwind utilities;" > static/src/input.css && \
    mkdir -p static/dist && \
    echo "/* Placeholder CSS - will be replaced by Tailwind in production */" > static/dist/output.css; \
    fi

# Create startup script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'cd /app' >> /app/start.sh && \
    echo 'echo "Starting application on port $PORT"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Check GCP authentication' >> /app/start.sh && \
    echo 'if [ "$ENVIRONMENT" = "production" ]; then' >> /app/start.sh && \
    echo '  echo "Checking GCP authentication..."' >> /app/start.sh && \
    echo '  if ! curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/ > /dev/null; then' >> /app/start.sh && \
    echo '    echo "Warning: Not running on GCP or metadata server not available"' >> /app/start.sh && \
    echo '  else' >> /app/start.sh && \
    echo '    echo "Running on GCP with metadata server available"' >> /app/start.sh && \
    echo '    # Get service account from metadata' >> /app/start.sh && \
    echo '    export DETECTED_SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email)' >> /app/start.sh && \
    echo '    echo "Using service account: $DETECTED_SA_EMAIL"' >> /app/start.sh && \
    echo '  fi' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Copy secrets from mounted volumes to appropriate locations' >> /app/start.sh && \
    echo 'if [ -d "/app/secrets" ]; then' >> /app/start.sh && \
    echo '  echo "Processing mounted secrets..."' >> /app/start.sh && \
    echo '  mkdir -p ./data' >> /app/start.sh && \
    echo '  # Copy feed configuration if available' >> /app/start.sh && \
    echo '  if [ -f "/app/secrets/feed-config/feed-config.json" ]; then' >> /app/start.sh && \
    echo '    echo "Found feed configuration, copying to data directory"' >> /app/start.sh && \
    echo '    cp /app/secrets/feed-config/feed-config.json ./data/feeds.json' >> /app/start.sh && \
    echo '  else' >> /app/start.sh && \
    echo '    echo "No feed configuration found in mounted secrets"' >> /app/start.sh && \
    echo '  fi' >> /app/start.sh && \
    echo 'else' >> /app/start.sh && \
    echo '  echo "No secrets directory found, using default configurations"' >> /app/start.sh && \
    echo '  mkdir -p ./data' >> /app/start.sh && \
    echo '  if [ ! -f ./data/feeds.json ]; then' >> /app/start.sh && \
    echo '    echo "{\"feeds\": [{\"id\": \"test-feed\", \"name\": \"Test Feed\", \"url\": \"https://example.com/feed.txt\", \"format\": \"text\", \"enabled\": true}]}" > ./data/feeds.json' >> /app/start.sh && \
    echo '  fi' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Ensure GCP resources are set up correctly' >> /app/start.sh && \
    echo 'if [ "$ENSURE_GCP_RESOURCES" = "true" ]; then' >> /app/start.sh && \
    echo '  echo "Ensuring GCP resources are properly set up..."' >> /app/start.sh && \
    echo '  python -c "import config; config.Config.ensure_gcp_resources()"' >> /app/start.sh && \
    echo 'else' >> /app/start.sh && \
    echo '  echo "Skipping GCP resource validation"' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Log information about environment' >> /app/start.sh && \
    echo 'echo "Environment: $ENVIRONMENT"' >> /app/start.sh && \
    echo 'echo "GCP Project: $GCP_PROJECT"' >> /app/start.sh && \
    echo 'echo "GCP Region: $GCP_REGION"' >> /app/start.sh && \
    echo 'echo "BigQuery Dataset: $BIGQUERY_DATASET"' >> /app/start.sh && \
    echo 'echo "GCS Bucket: $GCS_BUCKET"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Test connections to required services' >> /app/start.sh && \
    echo 'python -c "from config import check_gcp_permissions; print(\"\\nGCP Permissions Check:\", check_gcp_permissions())"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Ensure all directories have proper permissions' >> /app/start.sh && \
    echo 'mkdir -p data logs static/dist' >> /app/start.sh && \
    echo 'chmod -R 755 data logs static/dist' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Start the application with gunicorn' >> /app/start.sh && \
    echo 'exec gunicorn --workers=2 --threads=8 --timeout=120 --bind=:$PORT app:app' >> /app/start.sh && \
    chmod +x /app/start.sh

# Set proper permissions
RUN chmod -R 755 /app

# Expose port 8080 (documentation only - doesn't set the PORT env var)
EXPOSE 8080

# Set healthcheck 
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Run the application
CMD ["/app/start.sh"]
