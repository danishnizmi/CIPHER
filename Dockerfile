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

# Install numpy and pandas first to ensure compatibility
# This is the key fix for the binary incompatibility error
RUN pip install --upgrade pip && \
    pip install numpy==1.23.5 && \
    pip install pandas==2.1.0

# Copy requirements.txt and install remaining dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create Python package structure
RUN touch __init__.py \
    functions/__init__.py \
    functions/ingestion/__init__.py \
    functions/analysis/__init__.py

# Copy application code
COPY . .

# Ensure template directory exists and create it if needed
RUN mkdir -p /app/templates

# Ensure all required template files exist
RUN for template in auth.html base.html content.html dashboard.html 404.html 500.html login.html detail.html; do \
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

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Initialize\n\
echo "Starting Threat Intelligence Platform..."\n\
python --version\n\
\n\
# Verify critical files\n\
if [ ! -f app.py ]; then\n\
  echo "ERROR: app.py not found!"\n\
  exit 1\n\
fi\n\
\n\
# Ensure Python module structure\n\
touch __init__.py\n\
touch functions/__init__.py\n\
touch functions/ingestion/__init__.py\n\
touch functions/analysis/__init__.py\n\
\n\
# Set PYTHONPATH\n\
export PYTHONPATH=/app:$PYTHONPATH\n\
\n\
# Ensure static files exist\n\
mkdir -p static/dist\n\
[ ! -f "static/dist/output.css" ] && echo "/* Default CSS */" > static/dist/output.css\n\
\n\
# Ensure templates exist\n\
mkdir -p templates\n\
for template in auth.html base.html content.html dashboard.html 404.html 500.html login.html detail.html; do\n\
  if [ ! -f "templates/$template" ]; then\n\
    echo "WARNING: Creating placeholder for $template"\n\
    echo "<!DOCTYPE html><html><head><title>$template</title></head><body><h1>$template</h1></body></html>" > "templates/$template"\n\
  fi\n\
done\n\
\n\
# Verify numpy and pandas compatibility before starting\n\
python -c "import numpy; import pandas; print(f\"NumPy version: {numpy.__version__}, Pandas version: {pandas.__version__}\")"\n\
\n\
# Verify imports\n\
python -c "import flask; print(\"flask module found\")" || echo "WARNING: flask module not found"\n\
python -c "import config; print(\"config module found\")" || echo "WARNING: config module not found"\n\
\n\
# Start gunicorn\n\
echo "Starting gunicorn..."\n\
cd /app && exec gunicorn \\\n\
  --bind :$PORT \\\n\
  --workers 2 \\\n\
  --threads 8 \\\n\
  --timeout 300 \\\n\
  --log-level info \\\n\
  app:app\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Setup non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets
USER appuser

# Expose port
EXPOSE $PORT

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
