FROM python:3.10-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p static/dist templates data logs

# Create startup script
RUN echo '#!/bin/bash\nset -e\n\necho "Starting Threat Intelligence Platform..."\necho "Environment: $ENVIRONMENT"\necho "Port: $PORT"\n\n# Ensure directories exist\nmkdir -p data logs static/dist\n\n# Start the application\nexec gunicorn \\\n    --bind 0.0.0.0:$PORT \\\n    --workers 2 \\\n    --threads 4 \\\n    --timeout 120 \\\n    --preload \\\n    --access-logfile - \\\n    --error-logfile - \\\n    app:app' > /app/start.sh && \
    chmod +x /app/start.sh

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["/app/start.sh"]
