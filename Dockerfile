FROM python:3.10-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p static/dist templates

# Copy requirements first
COPY requirements.txt .

# Install dependencies with strict version pinning to ensure compatibility
RUN pip install --upgrade pip && \
    pip install numpy==1.24.3 && \
    pip install pandas==1.5.3 && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create a very simple startup script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'cd /app' >> /app/start.sh && \
    echo 'echo "Starting application on port $PORT"' >> /app/start.sh && \
    echo 'exec gunicorn --bind :$PORT --workers 2 --threads 8 app:app' >> /app/start.sh && \
    chmod +x /app/start.sh

EXPOSE 8080

CMD ["/app/start.sh"]
