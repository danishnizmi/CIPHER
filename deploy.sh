#!/bin/bash

# Quick deployment script for Telegram AI Processor
# Usage: ./deploy.sh [--setup] [--update-secrets]

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
    
    if ! command_exists docker; then
        print_warning "Docker not found. Cloud Build will handle container building."
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        print_error "Please authenticate with gcloud first: gcloud auth login"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Setup initial resources
setup_resources() {
    print_status "Setting up initial resources..."
    
    gcloud config set project $PROJECT_ID
    
    # Enable APIs
    print_status "Enabling required APIs..."
    gcloud services enable \
        cloudbuild.googleapis.com \
        run.googleapis.com \
        bigquery.googleapis.com \
        secretmanager.googleapis.com \
        aiplatform.googleapis.com \
        logging.googleapis.com
    
    print_success "APIs enabled"
}

# Update secrets
update_secrets() {
    print_status "Updating secrets..."
    
    echo -n "Enter your Telegram bot token: "
    read -s BOT_TOKEN
    echo
    
    if [ -n "$BOT_TOKEN" ]; then
        echo -n "$BOT_TOKEN" | gcloud secrets create telegram-bot-token --data-file=- 2>/dev/null || \
        echo -n "$BOT_TOKEN" | gcloud secrets versions add telegram-bot-token --data-file=-
        print_success "Bot token updated"
    else
        print_warning "No bot token provided, skipping update"
    fi
    
    # Generate webhook secret
    WEBHOOK_SECRET=$(openssl rand -base64 32)
    echo -n "$WEBHOOK_SECRET" | gcloud secrets create telegram-webhook-secret --data-file=- 2>/dev/null || \
    echo -n "$WEBHOOK_SECRET" | gcloud secrets versions add telegram-webhook-secret --data-file=-
    
    print_success "Webhook secret generated and stored"
}

# Deploy application
deploy_app() {
    print_status "Deploying application..."
    
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
    echo "🤖 Webhook URL: $SERVICE_URL/webhook/telegram"
    echo "=================================="
    echo ""
    
    if [ "$SERVICE_URL" != "Not deployed" ]; then
        echo "📝 Next steps:"
        echo "1. Set your Telegram bot webhook:"
        echo "   curl -X POST \"https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook\" \\"
        echo "        -H \"Content-Type: application/json\" \\"
        echo "        -d \"{\\\"url\\\": \\\"$SERVICE_URL/webhook/telegram\\\"}\""
        echo ""
        echo "2. Send a message to your bot to test the integration"
        echo ""
        echo "🔧 Useful commands:"
        echo "   View logs: gcloud logs read \"resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE_NAME\" --limit 20"
        echo "   Service status: gcloud run services describe $SERVICE_NAME --region=$REGION"
    fi
}

# Main deployment logic
main() {
    echo "🚀 Telegram AI Processor Deployment"
    echo "===================================="
    
    check_prerequisites
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --setup)
                setup_resources
                shift
                ;;
            --update-secrets)
                update_secrets
                shift
                ;;
            *)
                print_warning "Unknown option: $1"
                shift
                ;;
        esac
    done
    
    # If no specific flags, do full deployment
    if [ $# -eq 0 ]; then
        setup_resources
        update_secrets
    fi
    
    deploy_app
    get_service_info
}

# Run main function with all arguments
main "$@"
