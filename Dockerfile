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

# Ensure all __init__.py files exist after copying code
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Create secrets directory for mounting at runtime
RUN mkdir -p /secrets && chmod 755 /secrets

# Run as non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets
USER appuser

# Expose port
EXPOSE $PORT

# Create comprehensive startup script with robust error handling
RUN echo '#!/bin/bash\n\
set -e\n\
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
# Check for templates directory\n\
if [ ! -d "templates" ]; then\n\
  mkdir -p templates\n\
  echo "<!DOCTYPE html><html><body><h1>Threat Intelligence Platform</h1></body></html>" > templates/dashboard.html\n\
  echo "<!DOCTYPE html><html><body><h1>Login</h1></body></html>" > templates/login.html\n\
  echo "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>" > templates/404.html\n\
  echo "<!DOCTYPE html><html><body><h1>500 Server Error</h1></body></html>" > templates/500.html\n\
fi\n\
\n\
# Display available modules\n\
echo "Checking if key modules are importable:"\n\
python -c "import sys; print(sys.path)"\n\
python -c "import app; print(\"app module found\")" || echo "app module not found, this will cause the application to fail"\n\
python -c "import config; print(\"config module found\")" || echo "config module not found"\n\
python -c "import flask; print(\"flask module found\")" || echo "flask module not found"\n\
python -c "from google.cloud import bigquery; print(\"bigquery module found\")" || echo "bigquery module not found"\n\
\n\
echo "Starting gunicorn with app:app..."\n\
cd /app && exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 0 --log-level debug --access-logfile - app:app\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
