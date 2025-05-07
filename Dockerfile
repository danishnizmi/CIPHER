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

# Copy all application code
COPY . .

# Create initialization script that leverages config module functionality
RUN bash -c 'cat > /app/init-app.sh << "EOF"
#!/bin/bash
set -e

echo "Starting Threat Intelligence Platform initialization..."

# Set up environment for secret management
export USE_ENV_VARS_FOR_SECRETS=${USE_ENV_VARS_FOR_SECRETS:-true}
export LOAD_SECRETS=${LOAD_SECRETS:-true}
export ENSURE_GCP_RESOURCES=${ENSURE_GCP_RESOURCES:-true}

# Initialize application configuration with a Python helper that uses our modules
if [ "$LOAD_SECRETS" = "true" ]; then
    echo "Initializing secrets and configuration..."
    python -c "
import os
import sys
try:
    import config
    from config import Config, SecretManager
    print(\"Initializing application configuration...\")
    # Initialize secret manager first
    SecretManager.init()
    # Then initialize app config
    Config.init_app()
    print(\"Configuration initialized successfully\")
except Exception as e:
    print(f\"Error initializing configuration: {str(e)}\", file=sys.stderr)
    # Do not exit - we can still try to start with environment variables
    pass
"
fi

# Start the application with the command passed to the script
echo "Starting application..."
exec \$@
EOF'

RUN chmod +x /app/init-app.sh

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
