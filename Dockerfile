FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CONTAINER_BUILD=true

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

# Create necessary directories and __init__.py files
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis && \
    touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Create placeholder files for BigQuery setup
RUN echo 'print("BigQuery setup script placeholder")' > scripts/setup_bigquery_tables.py

# Create placeholder Cloud Functions files
RUN echo 'def ingest_threat_data(request):\n    return {"status": "ok"}' > functions/ingestion/main.py && \
    echo 'def analyze_threat_data(event, context):\n    return {"status": "ok"}' > functions/analysis/main.py

# Copy the application code (will overwrite placeholders)
COPY . .

# Ensure all __init__.py files exist after copying code
RUN touch __init__.py && \
    touch functions/__init__.py && \
    touch functions/ingestion/__init__.py && \
    touch functions/analysis/__init__.py

# Initialize and apply configurations in build mode
RUN python -c "from config import init_app_config; init_app_config()"

# Create secrets directory for mounting at runtime (if needed)
RUN mkdir -p /secrets && chmod 755 /secrets

# Run as non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app /secrets
USER appuser

# Expose port
EXPOSE $PORT

# Create startup script to handle initialization at runtime
RUN echo '#!/bin/bash\n\
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
# Create required __init__.py files again to be safe\n\
touch __init__.py\n\
touch functions/__init__.py\n\
touch functions/ingestion/__init__.py\n\
touch functions/analysis/__init__.py\n\
\n\
# Check PYTHONPATH\n\
echo "PYTHONPATH: $PYTHONPATH"\n\
\n\
# Add current directory to PYTHONPATH\n\
export PYTHONPATH=$PYTHONPATH:/app\n\
\n\
# Display available modules\n\
echo "Checking if key modules are importable:"\n\
python -c "import sys; print(sys.path)"\n\
python -c "import app; print(\"app module found\")" || echo "app module not found"\n\
python -c "import config; print(\"config module found\")" || echo "config module not found"\n\
python -c "import frontend; print(\"frontend module found\")" || echo "frontend module not found"\n\
python -c "import api; print(\"api module found\")" || echo "api module not found"\n\
\n\
# Run the application\n\
echo "Starting gunicorn with app:create_app()..."\n\
exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 0 --log-level info "app:create_app()"\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
