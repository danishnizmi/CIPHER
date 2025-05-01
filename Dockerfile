FROM python:3.10-slim

WORKDIR /app

# Set environment variables without substitution
ENV PORT=8080
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GO_INGESTION_PORT=8081

# Install dependencies - Including Go compiler
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    python3-dev \
    libffi-dev \
    git \
    procps \
    netcat-openbsd \
    golang \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p scripts static/src static/dist templates functions/ingestion functions/analysis bin logs

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Build Go ingestion service
RUN go build -o bin/threat_ingestion threat_ingestion.go

# Setup supervisor config to run both services
RUN echo '[supervisord]\nnodaemon=true\n\n[program:flask]\ncommand=gunicorn --bind :${PORT:-8080} --workers 2 --threads 8 --timeout 120 app:app\ndirectory=/app\nautostart=true\nautorestart=true\nstdout_logfile=/dev/stdout\nstdout_logfile_maxbytes=0\nstderr_logfile=/dev/stderr\nstderr_logfile_maxbytes=0\n\n[program:ingestion]\ncommand=/app/bin/threat_ingestion\ndirectory=/app\nautostart=true\nautorestart=true\nstdout_logfile=/dev/stdout\nstdout_logfile_maxbytes=0\nstderr_logfile=/dev/stderr\nstderr_logfile_maxbytes=0' > /etc/supervisor/conf.d/supervisord.conf

# Create a simple startup script as backup
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo '# Start supervisor to manage both services' >> /app/start.sh && \
    echo '/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf' >> /app/start.sh && \
    chmod +x /app/start.sh

EXPOSE 8080
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
