FROM python:3.10-slim

# Update pip to latest version first
RUN pip install --upgrade pip

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

# Copy requirements file first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    # Explicitly install GCP libraries to ensure they're available
    pip install --no-cache-dir \
    google-cloud-secret-manager>=2.12.0 \
    google-cloud-bigquery>=3.3.5 \
    google-cloud-storage>=2.7.0 \
    google-cloud-pubsub>=2.13.11 \
    google-cloud-logging>=3.2.5 \
    google-cloud-error-reporting>=1.6.0 \
    google-auth>=2.15.0 \
    # Install other important dependencies
    google-cloud-language>=2.6.1 \
    vertexai>=1.0.0 \
    flask-wtf>=1.0.1 \
    flask-cors>=3.0.10 \
    gunicorn>=20.1.0

# Create __init__.py files for Python modules
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Copy the application code
COPY . .

# Ensure templates directory has the necessary files
RUN mkdir -p /app/templates
# Check if required template files exist and create placeholders if missing
RUN for template in base.html login.html dashboard.html 404.html 500.html content.html detail.html auth.html; do \
    if [ ! -f "/app/templates/$template" ]; then \
        echo "<!DOCTYPE html><html><head><title>Placeholder for $template</title></head><body><h1>Placeholder for $template</h1></body></html>" > "/app/templates/$template"; \
    fi \
done

# Ensure static directory structure is correct
RUN mkdir -p /app/static/dist

# Create placeholder CSS file if it doesn't exist
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
echo "Application directory:"\n\
ls -la\n\
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
# Make sure PYTHONPATH is correctly set\n\
export PYTHONPATH=/app:$PYTHONPATH\n\
echo "PYTHONPATH: $PYTHONPATH"\n\
\n\
# Create empty config files if they dont exist to prevent errors\n\
if [ ! -d "static/dist" ]; then\n\
  mkdir -p static/dist\n\
fi\n\
\n\
if [ ! -f "static/dist/output.css" ]; then\n\
  echo "/* Default CSS */" > static/dist/output.css\n\
fi\n\
\n\
# Check for templates directory and its contents\n\
if [ ! -d "templates" ]; then\n\
  echo "WARNING: templates directory not found, creating it..."\n\
  mkdir -p templates\n\
fi\n\
\n\
echo "Templates directory contents:"\n\
ls -la templates/\n\
\n\
# Verify required template files exist\n\
required_templates=("login.html" "dashboard.html" "404.html" "500.html" "base.html" "content.html" "detail.html" "auth.html")\n\
for template in "${required_templates[@]}"; do\n\
  if [ ! -f "templates/$template" ]; then\n\
    echo "WARNING: $template not found in templates directory, creating placeholder..."\n\
    echo "<!DOCTYPE html><html><head><title>$template</title></head><body><h1>$template</h1></body></html>" > "templates/$template"\n\
  else\n\
    echo "Template $template found."\n\
  fi\n\
done\n\
\n\
# Check for static directory and its contents\n\
if [ ! -d "static" ]; then\n\
  echo "WARNING: static directory not found, creating it..."\n\
  mkdir -p static/dist static/src\n\
fi\n\
\n\
echo "Static directory contents:"\n\
ls -la static/\n\
\n\
# Verify module imports\n\
echo "Checking if key modules are importable:"\n\
python -c "import sys; print(sys.path)" || echo "WARNING: Failed to print sys.path"\n\
python -c "import flask; print(\"flask module found\")" || echo "WARNING: flask module not found"\n\
python -c "import config; print(\"config module found\")" || echo "WARNING: config module not found"\n\
python -c "import google.cloud.secretmanager; print(\"secretmanager module found\")" || echo "WARNING: secretmanager module not found"\n\
\n\
# Print Python environment information\n\
echo "Python environment:"\n\
pip list\n\
\n\
# Start with gunicorn with more robust settings\n\
echo "Starting gunicorn with app:app..."\n\
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
