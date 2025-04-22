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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis

# Create placeholder files for BigQuery setup
RUN echo 'print("BigQuery setup script placeholder")' > scripts/setup_bigquery_tables.py

# Create placeholder Cloud Functions files
RUN echo 'def ingest_threat_data(request):\n    return {"status": "ok"}' > functions/ingestion/main.py && \
    echo 'def analyze_threat_data(event, context):\n    return {"status": "ok"}' > functions/analysis/main.py

# Copy the application code
COPY . .

# Make sure our app.py exists and is executable
RUN chmod +x app.py

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
\n\
# Add debug info\n\
echo "Python version:"\n\
python --version\n\
echo "Application directory:"\n\
ls -la\n\
\n\
# Run the application\n\
exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 0 --log-level info app:create_app\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
