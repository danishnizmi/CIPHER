FROM python:3.10.12-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CONTAINER_BUILD=true \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies with cleanup in single layer to reduce image size
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

# Copy requirements file first for better layer caching
COPY requirements.txt .

# Install Python dependencies with pip constraints to prevent dependency resolution issues
RUN pip install --upgrade pip==25.1 && \
    pip install --no-cache-dir -r requirements.txt && \
    # Install specific versions of GCP libraries to prevent dependency conflicts
    pip install --no-cache-dir \
    google-cloud-secret-manager==2.16.1 \
    google-cloud-bigquery==3.11.4 \
    google-cloud-storage==2.12.0 \
    google-cloud-pubsub==2.13.11 \
    google-cloud-logging==3.5.0 \
    google-cloud-error-reporting==1.7.0 \
    google-auth==2.22.0 \
    google-cloud-language==2.11.0 \
    vertexai==1.36.0 \
    flask-wtf==1.1.1 \
    flask-cors==4.0.0 \
    gunicorn==21.2.0 \
    # Install additional packages to support functionality
    psutil==5.9.5 \
    requests==2.31.0

# Create __init__.py files for Python modules
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Copy the application code
COPY . .

# Ensure templates directory has the necessary files
RUN for template in base.html login.html dashboard.html 404.html 500.html content.html detail.html auth.html; do \
    if [ ! -f "/app/templates/$template" ]; then \
        echo "<!DOCTYPE html><html><head><title>Placeholder for $template</title></head><body><h1>Placeholder for $template</h1></body></html>" > "/app/templates/$template"; \
    fi \
done

# Ensure static directory has necessary CSS file
RUN if [ ! -f /app/static/dist/output.css ]; then \
    echo "/* Default CSS */" > /app/static/dist/output.css; \
    fi

# Create secrets directory for mounting at runtime
RUN mkdir -p /secrets && chmod 755 /secrets

# Create improved startup script with robust error handling
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Initialize logging\n\
echo "Starting Threat Intelligence Platform..."\n\
echo "Python version:"\n\
python --version\n\
\n\
# Check for critical files\n\
if [ ! -f app.py ]; then\n\
  echo "ERROR: app.py not found!"\n\
  exit 1\n\
fi\n\
\n\
# Create required __init__.py files\n\
touch __init__.py\n\
touch functions/__init__.py\n\
touch functions/ingestion/__init__.py\n\
touch functions/analysis/__init__.py\n\
\n\
# Set Python path\n\
export PYTHONPATH=/app:$PYTHONPATH\n\
echo "PYTHONPATH: $PYTHONPATH"\n\
\n\
# Verify static files and templates\n\
if [ ! -d "static/dist" ]; then\n\
  mkdir -p static/dist\n\
fi\n\
\n\
if [ ! -f "static/dist/output.css" ]; then\n\
  echo "/* Default CSS */" > static/dist/output.css\n\
fi\n\
\n\
if [ ! -d "templates" ]; then\n\
  echo "WARNING: templates directory not found, creating it..."\n\
  mkdir -p templates\n\
fi\n\
\n\
# Verify required template files exist\n\
required_templates=("login.html" "dashboard.html" "404.html" "500.html" "base.html" "content.html" "detail.html" "auth.html")\n\
for template in "${required_templates[@]}"; do\n\
  if [ ! -f "templates/$template" ]; then\n\
    echo "WARNING: $template not found in templates directory, creating placeholder..."\n\
    echo "<!DOCTYPE html><html><head><title>$template</title></head><body><h1>$template</h1></body></html>" > "templates/$template"\n\
  fi\n\
done\n\
\n\
# Check configuration\n\
python -c "import config; print(\"Configuration module loaded successfully\")" || echo "WARNING: Failed to load config module"\n\
\n\
# Print Python package versions for debugging\n\
echo "Python package versions:"\n\
pip freeze | grep -E "flask|google-cloud|werkzeug|gunicorn"\n\
\n\
# Start gunicorn with optimized settings\n\
cd /app && exec gunicorn \\\n\
  --bind :$PORT \\\n\
  --workers 2 \\\n\
  --threads 8 \\\n\
  --timeout 300 \\\n\
  --log-level info \\\n\
  --access-logfile - \\\n\
  --error-logfile - \\\n\
  --capture-output \\\n\
  app:app\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Run as non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets /app/templates
USER appuser

# Expose port
EXPOSE $PORT

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
