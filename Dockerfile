# Multi-stage build for production optimization
FROM python:3.11-slim as base

# Production environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080 \
    PYTHONPATH=/app

# Install system dependencies efficiently
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    make \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy requirements and install dependencies first (better caching)
COPY requirements.txt .

# Install Python dependencies optimized for production
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/templates /app/static /app/logs /tmp && \
    chown -R appuser:appuser /app /tmp

# Switch to non-root user
USER appuser

# Health check - CRITICAL for Cloud Run
HEALTHCHECK --interval=15s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health/live || exit 1

# Expose port
EXPOSE ${PORT}

# Production command - starts web server immediately
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--access-log", \
     "--log-level", "info", \
     "--timeout-keep-alive", "30"]
