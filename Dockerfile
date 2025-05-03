FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CONTAINER_BUILD=true \
    PYTHONPATH=/app

# Install system dependencies
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

# Copy requirements first for better caching
COPY requirements.txt .

# Install numpy first, then the rest of requirements
RUN pip install --upgrade pip && \
    pip install numpy==1.24.3 && \
    pip install --no-cache-dir -r requirements.txt

# Create package structure
RUN touch __init__.py \
    functions/__init__.py \
    functions/ingestion/__init__.py \
    functions/analysis/__init__.py

# Copy application code
COPY . .

# Ensure template directory exists
RUN mkdir -p templates

# Create placeholder templates if missing
RUN for template in auth.html base.html content.html dashboard.html; do \
    if [ ! -f "/app/templates/$template" ]; then \
        echo "<!DOCTYPE html><html><head><title>Placeholder</title></head><body><h1>Placeholder for $template</h1></body></html>" > "/app/templates/$template"; \
    fi; \
done

# Ensure static CSS file exists
RUN mkdir -p static/dist && \
    if [ ! -f /app/static/dist/output.css ]; then \
        echo "/* Default CSS */" > /app/static/dist/output.css; \
    fi

# Create secrets directory
RUN mkdir -p /secrets && chmod 755 /secrets

# Write startup script - no HEREDOC, just direct file write
RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    echo 'set -e' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Initialize' >> /app/entrypoint.sh && \
    echo 'echo "Starting Threat Intelligence Platform..."' >> /app/entrypoint.sh && \
    echo 'python --version' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Verify files' >> /app/entrypoint.sh && \
    echo 'if [ ! -f app.py ]; then' >> /app/entrypoint.sh && \
    echo '  echo "ERROR: app.py not found!"' >> /app/entrypoint.sh && \
    echo '  exit 1' >> /app/entrypoint.sh && \
    echo 'fi' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Verify imports' >> /app/entrypoint.sh && \
    echo 'python -c "import flask; print(\"flask module found\")" || echo "WARNING: flask module not found"' >> /app/entrypoint.sh && \
    echo 'python -c "import config; print(\"config module found\")" || echo "WARNING: config module not found"' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Start gunicorn' >> /app/entrypoint.sh && \
    echo 'echo "Starting gunicorn..."' >> /app/entrypoint.sh && \
    echo 'cd /app && exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 300 --log-level info app:app' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Setup non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
