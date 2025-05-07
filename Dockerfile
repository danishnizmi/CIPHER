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
    # Default credentials (will be overridden by Secret Manager in production)
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

# Copy requirements file first (for better caching)
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

# Create Tailwind CSS file for frontend
RUN echo '@tailwind base; @tailwind components; @tailwind utilities;' > /app/static/src/input.css

# Create initialization script
RUN echo '#!/bin/bash' > /app/init-app.sh && \
    echo 'set -e' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo 'echo "Starting Threat Intelligence Platform initialization..."' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Set up environment for secret management' >> /app/init-app.sh && \
    echo 'export USE_ENV_VARS_FOR_SECRETS=${USE_ENV_VARS_FOR_SECRETS:-true}' >> /app/init-app.sh && \
    echo 'export LOAD_SECRETS=${LOAD_SECRETS:-true}' >> /app/init-app.sh && \
    echo 'export ENSURE_GCP_RESOURCES=${ENSURE_GCP_RESOURCES:-true}' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Initialize application configuration with a Python helper that uses our modules' >> /app/init-app.sh && \
    echo 'if [ "$LOAD_SECRETS" = "true" ]; then' >> /app/init-app.sh && \
    echo '    echo "Initializing secrets and configuration..."' >> /app/init-app.sh && \
    echo '    python -c "' >> /app/init-app.sh && \
    echo 'import os' >> /app/init-app.sh && \
    echo 'import sys' >> /app/init-app.sh && \
    echo 'try:' >> /app/init-app.sh && \
    echo '    import config' >> /app/init-app.sh && \
    echo '    from config import Config, SecretManager' >> /app/init-app.sh && \
    echo '    print(\"Initializing application configuration...\")' >> /app/init-app.sh && \
    echo '    # Initialize secret manager first' >> /app/init-app.sh && \
    echo '    SecretManager.init()' >> /app/init-app.sh && \
    echo '    # Then initialize app config' >> /app/init-app.sh && \
    echo '    Config.init_app()' >> /app/init-app.sh && \
    echo '    print(\"Configuration initialized successfully\")' >> /app/init-app.sh && \
    echo 'except Exception as e:' >> /app/init-app.sh && \
    echo '    print(f\"Error initializing configuration: {str(e)}\", file=sys.stderr)' >> /app/init-app.sh && \
    echo '    # Do not exit - we can still try to start with environment variables' >> /app/init-app.sh && \
    echo '    pass' >> /app/init-app.sh && \
    echo '"' >> /app/init-app.sh && \
    echo 'fi' >> /app/init-app.sh && \
    echo '' >> /app/init-app.sh && \
    echo '# Start the application with the command passed to the script' >> /app/init-app.sh && \
    echo 'echo "Starting application..."' >> /app/init-app.sh && \
    echo 'exec "$@"' >> /app/init-app.sh

# Make script executable
RUN chmod +x /app/init-app.sh

# Copy all application code
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

# Start with the initialization script
ENTRYPOINT ["/app/init-app.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "120", "--worker-class", "gthread", "--preload", "--log-level", "info", "app:app"]
