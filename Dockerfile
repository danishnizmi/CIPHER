FROM python:3.10-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8080 \
    ENVIRONMENT=production \
    LOAD_SECRETS=true \
    ENSURE_GCP_RESOURCES=true

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    curl \
    gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install gcloud CLI for better GCP integration
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p static/dist templates data logs

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

# Wait for GCP services to be available before starting the app
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'cd /app' >> /app/start.sh && \
    echo 'echo "Starting application on port $PORT"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Check GCP authentication' >> /app/start.sh && \
    echo 'if [ "$ENVIRONMENT" = "production" ]; then' >> /app/start.sh && \
    echo '  echo "Checking GCP authentication..."' >> /app/start.sh && \
    echo '  if ! curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/ > /dev/null; then' >> /app/start.sh && \
    echo '    echo "Warning: Not running on GCP or metadata server not available."' >> /app/start.sh && \
    echo '  else' >> /app/start.sh && \
    echo '    echo "Running on GCP with metadata server available."' >> /app/start.sh && \
    echo '  fi' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Initialize default feed configuration if not exists' >> /app/start.sh && \
    echo 'if [ "$ENVIRONMENT" = "development" ]; then' >> /app/start.sh && \
    echo '  echo "Setting up default development feed configuration..."' >> /app/start.sh && \
    echo '  mkdir -p ./data' >> /app/start.sh && \
    echo '  if [ ! -f ./data/feeds.json ]; then' >> /app/start.sh && \
    echo '    echo "{\"feeds\": [{\"id\": \"test-feed\", \"name\": \"Test Feed\", \"url\": \"https://example.com/feed.txt\", \"format\": \"text\", \"enabled\": true}]}" > ./data/feeds.json' >> /app/start.sh && \
    echo '  fi' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Run database migrations if needed' >> /app/start.sh && \
    echo 'python -c "import config; config.Config.ensure_gcp_resources()" || echo "Warning: Could not ensure GCP resources"' >> /app/start.sh && \
    echo '' >> /app/start.sh && \
    echo '# Start the application with gunicorn' >> /app/start.sh && \
    echo 'exec gunicorn --workers=2 --threads=8 --timeout=120 --bind=:$PORT app:app' >> /app/start.sh && \
    chmod +x /app/start.sh

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["/app/start.sh"]
