# Multi-stage build for Threat Intelligence Platform
# Stage 1: Build Go ingestion service
FROM golang:1.19-alpine AS go-builder

# Install required build tools
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /go/src/app

# Copy Go module files
COPY go.mod ./
# Copy the Go source code
COPY threat_ingestion.go ./

# Fix the unused variable issue in the Go code
RUN sed -i '916s/v :=/_ :=/' threat_ingestion.go

# Download dependencies
RUN go mod download

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o threat_ingestion .

# Stage 2: Build Python application
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
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GO_INGESTION_PORT=8081

# Install system dependencies with cleanup in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    python3-dev \
    libffi-dev \
    git \
    procps \
    netcat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis bin logs

# Install numpy and pandas first to ensure compatibility
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

# Copy Go binary from the go-builder stage
COPY --from=go-builder /go/src/app/threat_ingestion /app/bin/threat_ingestion
RUN chmod +x /app/bin/threat_ingestion

# Copy application code
COPY . .

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
# Set PYTHONPATH\n\
export PYTHONPATH=/app:$PYTHONPATH\n\
\n\
# Verify numpy and pandas compatibility before starting\n\
python -c "import numpy; import pandas; print(f\"NumPy version: {numpy.__version__}, Pandas version: {pandas.__version__}\")"\n\
\n\
# Verify imports\n\
python -c "import flask; print(\"flask module found\")" || echo "WARNING: flask module not found"\n\
python -c "import config; print(\"config module found\")" || echo "WARNING: config module not found"\n\
\n\
# Start the Go ingestion service in the background\n\
echo "Starting Go Threat Ingestion service..."\n\
/app/bin/threat_ingestion > /app/logs/go_ingestion.log 2>&1 &\n\
INGESTION_PID=$!\n\
echo "Go ingestion service started with PID: $INGESTION_PID"\n\
\n\
# Wait for Go service to be ready\n\
echo "Waiting for Go service to be ready..."\n\
for i in {1..10}; do\n\
  if nc -z localhost $GO_INGESTION_PORT; then\n\
    echo "Go service is ready!"\n\
    break\n\
  fi\n\
  echo "Waiting for Go service..."\n\
  sleep 1\n\
  if [ $i -eq 10 ]; then\n\
    echo "WARNING: Go service did not start in time."\n\
    exit 1\n\
  fi\n\
done\n\
\n\
# Setup cleanup on exit\n\
cleanup() {\n\
  echo "Shutting down services..."\n\
  if [ -n "$INGESTION_PID" ]; then\n\
    kill -TERM $INGESTION_PID 2>/dev/null || true\n\
    wait $INGESTION_PID 2>/dev/null || true\n\
  fi\n\
  echo "Cleanup complete"\n\
  exit 0\n\
}\n\
trap cleanup SIGTERM SIGINT\n\
\n\
# Start gunicorn in the foreground\n\
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

# Expose ports
EXPOSE $PORT
EXPOSE $GO_INGESTION_PORT

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
