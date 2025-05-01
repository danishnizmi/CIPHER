FROM python:3.10-slim

WORKDIR /app

# Set environment variables without substitution
ENV PORT=8080
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GO_INGESTION_PORT=8081

# Install dependencies
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

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a simple startup script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'cd /app && gunicorn --bind :8080 --workers 2 --threads 8 app:app' >> /app/start.sh && \
    chmod +x /app/start.sh

EXPOSE 8080
EXPOSE 8081

CMD ["/app/start.sh"]
