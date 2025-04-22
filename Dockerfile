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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Add BigQuery setup script - creating empty file if it doesn't exist
RUN mkdir -p scripts && \
    touch scripts/setup_bigquery_tables.py && \
    echo 'print("BigQuery setup script placeholder")' > scripts/setup_bigquery_tables.py

# Copy the application code
COPY . .

# Initialize and apply configurations in build mode
# The CONTAINER_BUILD=true environment variable will prevent
# Secret Manager authentication attempts during build
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
# Run the application\n\
exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 0 "app:create_app()"\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Use the startup script as entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
