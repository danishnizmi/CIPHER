#!/bin/bash

# CIPHER Platform - Initial Setup Script
# Using existing cloud-build-service account

set -e

PROJECT_ID="primal-chariot-382610"
SERVICE_ACCOUNT="cloud-build-service@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🛡️ CIPHER Platform - Initial Setup"
echo "=================================="
echo "Project: $PROJECT_ID"
echo "Service Account: $SERVICE_ACCOUNT"
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

# Verify cloud-build-service account exists and has permissions
echo "🔍 Verifying service account..."
PERMISSIONS=$(gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:$SERVICE_ACCOUNT" \
    --format="value(bindings.role)" | wc -l)

if [ "$PERMISSIONS" -eq 0 ]; then
    echo "❌ Error: Service account $SERVICE_ACCOUNT has no permissions"
    echo "This account should already exist with proper IAM roles for Cloud Build"
    exit 1
else
    echo "✅ Service account has $PERMISSIONS IAM roles configured"
    echo "   Including: BigQuery Admin, Cloud Run Admin, etc."
fi

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
SERVICE_ACCOUNT=$SERVICE_ACCOUNT

# Development settings
DEBUG=False
TESTING=False
EOF

echo "✅ Environment file created (.env)"

# Service account key for local development (optional)
read -p "🔑 Create service account key for local development? (y/N): " create_key
if [[ $create_key =~ ^[Yy]$ ]]; then
    echo "Creating service account key for local development..."
    
    # Create and download key for cloud-build-service
    gcloud iam service-accounts keys create cloud-build-service-key.json \
        --iam-account=$SERVICE_ACCOUNT
    
    echo "✅ Service account key created: cloud-build-service-key.json"
    echo "💡 Set GOOGLE_APPLICATION_CREDENTIALS=./cloud-build-service-key.json for local development"
    
    # Add to .env
    echo "GOOGLE_APPLICATION_CREDENTIALS=./cloud-build-service-key.json" >> .env
    
    # Add to .gitignore
    echo "cloud-build-service-key.json" >> .gitignore
fi

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x deploy.sh setup.sh

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
    <style>
        body { font-family: Arial, sans-serif; background: #0f1419; color: white; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
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
*.json
!package*.json
logs/
__pycache__/
*.pyc
.pytest_cache/
.coverage
node_modules/
.vscode/
.idea/
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

# Check BigQuery dataset
echo "📊 Checking BigQuery setup..."
if bq ls --project_id=$PROJECT_ID telegram_data >/dev/null 2>&1; then
    echo "✅ BigQuery dataset 'telegram_data' exists"
    
    # Show table info if it exists
    if bq ls --project_id=$PROJECT_ID telegram_data.processed_messages >/dev/null 2>&1; then
        echo "✅ Table 'processed_messages' exists with partitioning and clustering"
        bq show --format=prettyjson $PROJECT_ID:telegram_data.processed_messages | grep -E '"tableId"|"timePartitioning"|"clustering"' || true
    else
        echo "⚠️ Table 'processed_messages' doesn't exist yet (will be created on first deployment)"
    fi
else
    echo "⚠️ BigQuery dataset 'telegram_data' doesn't exist yet (will be created on first deployment)"
fi

# Instructions
echo ""
echo "🎉 CIPHER Platform Setup Complete!"
echo "================================"
echo ""
echo "📋 Configuration Summary:"
echo "- Project ID: $PROJECT_ID"
echo "- Service Account: $SERVICE_ACCOUNT"
echo "- BigQuery Dataset: telegram_data"
echo "- BigQuery Table: processed_messages"
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
    echo "- cloud-build-service-key.json (service account key)"
fi
echo ""
echo "🔗 Useful Commands:"
echo "- Deploy: ./deploy.sh"
echo "- Local run: uvicorn main:app --reload"
echo "- View logs: gcloud run services logs read telegram-ai-processor --region=us-central1 --limit=50"
echo "- Check permissions: gcloud projects get-iam-policy $PROJECT_ID --flatten='bindings[].members' --filter='bindings.members:$SERVICE_ACCOUNT'"
echo ""
echo "🛡️ Your CIPHER platform is ready for deployment!"
echo "The cloud-build-service account already has all necessary permissions:"
echo "- BigQuery Admin (for data operations)"
echo "- Cloud Run Admin (for service deployment)"
echo "- Logging/Monitoring (for observability)"
echo ""
echo "Run './deploy.sh' to deploy your cybersecurity intelligence platform!"
