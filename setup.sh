#!/bin/bash

# CIPHER Platform - Initial Setup Script
# Run this script once to set up your development/production environment

set -e

PROJECT_ID="primal-chariot-382610"
SERVICE_ACCOUNT="cipher-service@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🛡️ CIPHER Platform - Initial Setup"
echo "=================================="
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI is not installed. Please install it first:"
    echo "https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo "❌ Not authenticated with gcloud. Please run:"
    echo "gcloud auth login"
    exit 1
fi

# Check if bq is available
if ! command -v bq &> /dev/null; then
    echo "❌ BigQuery CLI (bq) is not available. Please install gcloud SDK with bq component."
    exit 1
fi

echo "✅ Prerequisites met"

# Set project
echo "📋 Setting project to $PROJECT_ID..."
gcloud config set project $PROJECT_ID

# Create .env file
echo "📝 Creating environment configuration..."
cat > .env << EOF
# CIPHER Platform Environment Configuration
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
LOG_LEVEL=INFO
DATASET_ID=telegram_data
TABLE_ID=processed_messages
PORT=8080
PYTHONUNBUFFERED=1

# Development settings
DEBUG=False
TESTING=False
EOF

echo "✅ Environment file created (.env)"

# Create service account key for local development (optional)
read -p "🔑 Create service account key for local development? (y/N): " create_key
if [[ $create_key =~ ^[Yy]$ ]]; then
    echo "Creating service account key..."
    
    # Create service account if it doesn't exist
    gcloud iam service-accounts describe $SERVICE_ACCOUNT >/dev/null 2>&1 || {
        echo "Creating service account..."
        gcloud iam service-accounts create cipher-service \
            --display-name="CIPHER Service Account" \
            --description="Service account for CIPHER platform"
    }
    
    # Create and download key
    gcloud iam service-accounts keys create cipher-service-key.json \
        --iam-account=$SERVICE_ACCOUNT
    
    echo "✅ Service account key created: cipher-service-key.json"
    echo "💡 Set GOOGLE_APPLICATION_CREDENTIALS=./cipher-service-key.json for local development"
    
    # Add to .env
    echo "GOOGLE_APPLICATION_CREDENTIALS=./cipher-service-key.json" >> .env
fi

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x deploy.sh
chmod +x setup.sh

# Create basic directory structure
echo "📁 Creating directory structure..."
mkdir -p templates static logs

# Create basic templates if they don't exist
if [ ! -f templates/base.html ]; then
    cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}CIPHER Platform{% endblock %}</title>
</head>
<body>
    {% block content %}{% endblock %}
</body>
</html>
EOF
fi

# Create .dockerignore if it doesn't exist
if [ ! -f .dockerignore ]; then
    cat > .dockerignore << 'EOF'
.git
.gitignore
README.md
Dockerfile
.dockerignore
.env
cipher-service-key.json
logs/
__pycache__/
*.pyc
.pytest_cache/
.coverage
EOF
fi

# Create .gitignore if it doesn't exist
if [ ! -f .gitignore ]; then
    cat > .gitignore << 'EOF'
# Environment files
.env
.env.local
.env.production

# Service account keys
*.json
!package*.json

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Testing
.pytest_cache/
.coverage
htmlcov/

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF
fi

echo "✅ Project structure created"

# Instructions
echo ""
echo "🎉 CIPHER Platform Setup Complete!"
echo "================================"
echo ""
echo "📋 Next Steps:"
echo "1. Review the generated .env file"
echo "2. Run './deploy.sh' to deploy to Google Cloud Run"
echo "3. For local development:"
echo "   - pip install -r requirements.txt"
echo "   - uvicorn main:app --reload --port 8080"
echo ""
echo "📁 Generated Files:"
echo "- .env (environment configuration)"
echo "- .gitignore (git ignore rules)"
echo "- .dockerignore (docker ignore rules)"
echo "- templates/base.html (base template)"
if [[ $create_key =~ ^[Yy]$ ]]; then
    echo "- cipher-service-key.json (service account key)"
fi
echo ""
echo "🔗 Useful Commands:"
echo "- Deploy: ./deploy.sh"
echo "- Local run: uvicorn main:app --reload"
echo "- View logs: gcloud logs read 'resource.type=cloud_run_revision' --limit=50"
echo ""
echo "🛡️ Your CIPHER platform is ready for deployment!"
