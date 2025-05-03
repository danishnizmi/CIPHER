FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CONTAINER_BUILD=true \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies with cleanup in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    python3-dev \
    libffi-dev \
    git \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis

# Copy requirements.txt first to leverage Docker caching
COPY requirements.txt .

# Install dependencies in single layer with optimized flags
# Pin numpy version to avoid compatibility issues with pandas
RUN pip install --upgrade pip && \
    pip install numpy==1.24.3 && \
    pip install --no-cache-dir -r requirements.txt

# Create Python package structure
RUN touch __init__.py \
    functions/__init__.py \
    functions/ingestion/__init__.py \
    functions/analysis/__init__.py

# Copy application code
COPY . .

# Ensure template directory exists and create it if needed
RUN mkdir -p /app/templates

# Ensure all required template files exist - ONLY check for the templates we have
RUN for template in auth.html base.html content.html dashboard.html; do \
    if [ ! -f "/app/templates/$template" ]; then \
        echo "<!DOCTYPE html><html><head><title>Placeholder for $template</title></head><body><h1>Placeholder for $template</h1></body></html>" > "/app/templates/$template"; \
    fi; \
done

# Ensure static directory has CSS file
RUN if [ ! -f /app/static/dist/output.css ]; then \
    echo "/* Default CSS */" > /app/static/dist/output.css; \
fi

# Create secrets directory
RUN mkdir -p /secrets && chmod 755 /secrets

# Create startup script using HEREDOC syntax instead of echo to avoid Dockerfile parse errors
RUN cat > /app/docker-entrypoint.sh << 'EOFSCRIPT'
#!/bin/bash
set -e

# Initialize
echo "Starting Threat Intelligence Platform..."
python --version

# Verify critical files
if [ ! -f app.py ]; then
  echo "ERROR: app.py not found!"
  exit 1
fi

# Ensure Python module structure
touch __init__.py
touch functions/__init__.py
touch functions/ingestion/__init__.py
touch functions/analysis/__init__.py

# Set PYTHONPATH
export PYTHONPATH=/app:$PYTHONPATH

# Ensure static files exist
mkdir -p static/dist
[ ! -f "static/dist/output.css" ] && echo "/* Default CSS */" > static/dist/output.css

# Ensure templates exist - ONLY check for the templates we have
mkdir -p templates
for template in auth.html base.html content.html dashboard.html; do
  if [ ! -f "templates/$template" ]; then
    echo "WARNING: Creating placeholder for $template"
    echo "<!DOCTYPE html><html><head><title>$template</title></head><body><h1>$template</h1></body></html>" > "templates/$template"
  fi
done

# Verify imports
python -c "import flask; print(\"flask module found\")" || echo "WARNING: flask module not found"
python -c "import config; print(\"config module found\")" || echo "WARNING: config module not found"

# Start gunicorn with correct port reference
echo "Starting gunicorn..."
cd /app && exec gunicorn \
  --bind :${PORT} \
  --workers 2 \
  --threads 8 \
  --timeout 300 \
  --log-level info \
  app:app
EOFSCRIPT
RUN chmod +x /app/docker-entrypoint.sh

# Setup non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
