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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis

# Create __init__.py files for Python modules
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Copy the application code
COPY . .

# Ensure templates directory has the necessary files
RUN mkdir -p /app/templates
COPY templates/*.html /app/templates/

# Ensure static directory structure is correct
RUN mkdir -p /app/static/dist

# Create placeholder CSS file if it doesn't exist
RUN if [ ! -f /app/static/dist/output.css ]; then \
    echo "/* Default CSS */" > /app/static/dist/output.css; \
    fi

# Ensure all __init__.py files exist after copying code
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Create secrets directory for mounting at runtime
RUN mkdir -p /secrets && chmod 755 /secrets

# Run as non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets /app/templates
USER appuser

# Expose port
EXPOSE $PORT

# Create improved startup script with robust error handling
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Enable more verbose debugging\n\
export PS4="\${BASH_SOURCE}:\${LINENO}: "\n\
\n\
# Switch to runtime mode\n\
export CONTAINER_BUILD=false\n\
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
# Create empty config files if they don\'t exist to prevent errors\n\
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
required_templates=("login.html" "dashboard.html" "404.html" "500.html" "base.html" "content.html")\n\
for template in "${required_templates[@]}"; do\n\
  if [ ! -f "templates/$template" ]; then\n\
    echo "WARNING: $template not found in templates directory!"\n\
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
python -c "import sys; print(sys.path)"\n\
python -c "import app; print(\"app module found\")" || echo "app module not found, this will cause the application to fail"\n\
python -c "import config; print(\"config module found\")" || echo "config module not found"\n\
python -c "import flask; print(\"flask module found\")" || echo "flask module not found"\n\
python -c "import frontend; print(\"frontend module found\")" || echo "frontend module not found"\n\
python -c "import api; print(\"api module found\")" || echo "api module not found"\n\
python -c "from google.cloud import bigquery; print(\"bigquery module found\")" || echo "bigquery module not found"\n\
python -c "from google.cloud import secretmanager; print(\"secretmanager module found\")" || echo "secretmanager module not found"\n\
\n\
# Validate app initialization\n\
echo "Pre-initializing the application to test startup..."\n\
python -c "import app; print(\"App module loaded successfully\")" || echo "WARNING: Failed to import app module"\n\
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
  --timeout 0 \\\n\
  --log-level debug \\\n\
  --access-logfile - \\\n\
  --error-logfile - \\\n\
  --capture-output \\\n\
  --preload \\\n\
  app:app\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
