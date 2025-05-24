# Use Python 3.11 slim image for optimal performance
FROM python:3.11-slim as base

# Set environment variables for Cloud Run
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080 \
    PYTHONPATH=/app

# Install system dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user early
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with optimization
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/templates /app/static /app/logs /tmp/sessions && \
    chown -R appuser:appuser /app /tmp/sessions && \
    chmod -R 755 /app && \
    chmod -R 777 /tmp/sessions

# Switch to non-root user
USER appuser

# Expose port
EXPOSE ${PORT}

# Health check optimized for Cloud Run
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health/live || exit 1

# Production-ready startup command optimized for Cloud Run
CMD exec uvicorn main:app \
    --host 0.0.0.0 \
    --port ${PORT} \
    --workers 1 \
    --loop uvloop \
    --http httptools \
    --access-log \
    --log-level info \
    --timeout-keep-alive 65 \
    --timeout-graceful-shutdown 30 \
    --max-requests 1000 \
    --max-requests-jitter 100
