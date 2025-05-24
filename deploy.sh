#!/bin/bash

# Quick deployment script for Telegram AI Processor with existing secrets
# Usage: ./deploy.sh

set -e

PROJECT_ID="primal-chariot-382610"
REGION="us-central1"
SERVICE_NAME="telegram-ai-processor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists gcloud; then
        print_error "gcloud CLI not found. Please install Google Cloud SDK."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        print_error "Please authenticate with gcloud first: gcloud auth login"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Check existing secrets
check_secrets() {
    print_status "Checking existing secrets..."
    
    gcloud config set project $PROJECT_ID
    
    SECRETS_OK=true
    SECRETS=("telegram-api-id" "telegram-api-hash" "telegram-phone-number" "gemini-api-key")
    
    for secret in "${SECRETS[@]}"; do
        if gcloud secrets describe $secret >/dev/null 2>&1; then
            print_success "Secret $secret exists"
        else
            print_error "Secret $secret is missing"
            SECRETS_OK=false
        fi
    done
    
    if [ "$SECRETS_OK" = false ]; then
        print_error "Some required secrets are missing. Please create them first."
        exit 1
    fi
    
    print_success "All required secrets exist"
}

# Deploy application
deploy_app() {
    print_status "Deploying application with Cloud Build..."
    
    # Submit build
    gcloud builds submit --config cloudbuild.yaml .
    
    print_success "Application deployed successfully"
}

# Get service info
get_service_info() {
    print_status "Getting service information..."
    
    SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
        --region=$REGION \
        --format='value(status.url)' 2>/dev/null || echo "Not deployed")
    
    echo ""
    echo "=================================="
    echo "🎉 DEPLOYMENT COMPLETE"
    echo "=================================="
    echo "📍 Service URL: $SERVICE_URL"
    echo "🔗 Dashboard: $SERVICE_URL"
    echo "📊 Monitoring: $SERVICE_URL/monitoring/status"
    echo "🏥 Health: $SERVICE_URL/health"
    echo "=================================="
    echo ""
    
    if [ "$SERVICE_URL" != "Not deployed" ]; then
        echo "📝 Next steps:"
        echo "1. Visit $SERVICE_URL to check the dashboard"
        echo "2. Monitor the logs: gcloud logs read \"resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE_NAME\" --limit 20"
        echo "3. Check monitoring status: curl $SERVICE_URL/monitoring/status"
        echo ""
        echo "🔧 Useful commands:"
        echo "   View logs: gcloud logs read \"resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE_NAME\" --limit 20"
        echo "   Service status: gcloud run services describe $SERVICE_NAME --region=$REGION"
        echo "   Check BigQuery: bq query --use_legacy_sql=false 'SELECT COUNT(*) FROM \`$PROJECT_ID.telegram_data.processed_messages\`'"
    fi
}

# Test deployment
test_deployment() {
    print_status "Testing deployment..."
    
    SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
        --region=$REGION \
        --format='value(status.url)' 2>/dev/null || echo "")
    
    if [ -n "$SERVICE_URL" ]; then
        print_status "Waiting for service to be ready..."
        sleep 10
        
        if curl -s -f "$SERVICE_URL/health" >/dev/null; then
            print_success "Service health check passed"
        else
            print_warning "Service health check failed - may still be starting"
        fi
    else
        print_error "Could not get service URL"
    fi
}

# Main deployment logic
main() {
    echo "🚀 Telegram AI Processor Deployment (Using Existing Secrets)"
    echo "============================================================="
    
    check_prerequisites
    check_secrets
    deploy_app
    test_deployment
    get_service_info
    
    echo ""
    print_success "Deployment completed! Your Telegram AI Processor should now be running."
    print_status "The service will use your existing secrets for Telegram and Gemini APIs."
}

# Run main function
main "$@"
