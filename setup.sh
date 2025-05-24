#!/bin/bash

# Telegram AI Processor Setup Script
# This script sets up the necessary GCP resources and secrets

set -e

PROJECT_ID="primal-chariot-382610"
SERVICE_ACCOUNT="cloud-build-service@primal-chariot-382610.iam.gserviceaccount.com"
REGION="us-central1"
SERVICE_NAME="telegram-ai-processor"

echo "🚀 Setting up Telegram AI Processor on GCP..."

# Check if gcloud is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo "❌ Please authenticate with gcloud first:"
    echo "   gcloud auth login"
    exit 1
fi

# Set the project
echo "📋 Setting GCP project..."
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "🔧 Enabling required APIs..."
gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    bigquery.googleapis.com \
    secretmanager.googleapis.com \
    aiplatform.googleapis.com \
    artifactregistry.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com

# Create secrets (you'll need to update these with actual values)
echo "🔐 Creating secrets in Secret Manager..."

# Telegram Bot Token (replace with your actual token)
echo -n "REPLACE_WITH_YOUR_TELEGRAM_BOT_TOKEN" | gcloud secrets create telegram-bot-token --data-file=-

# Telegram Webhook Secret (generate a random secret)
WEBHOOK_SECRET=$(openssl rand -base64 32)
echo -n "$WEBHOOK_SECRET" | gcloud secrets create telegram-webhook-secret --data-file=-

echo "✅ Secrets created. Please update them with actual values:"
echo "   gcloud secrets versions add telegram-bot-token --data-file=<(echo -n 'YOUR_ACTUAL_BOT_TOKEN')"

# Grant service account access to secrets
echo "🔑 Granting service account access to secrets..."
gcloud secrets add-iam-policy-binding telegram-bot-token \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding telegram-webhook-secret \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"

# Create BigQuery dataset
echo "📊 Creating BigQuery dataset..."
bq mk --location=US --description="Telegram AI Processor data" telegram_data || echo "Dataset already exists"

# Build and deploy using Cloud Build
echo "🏗️ Building and deploying with Cloud Build..."
gcloud builds submit --config cloudbuild.yaml .

# Get the service URL
echo "🌐 Getting service URL..."
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --format='value(status.url)')

echo ""
echo "✅ Deployment complete!"
echo "📍 Service URL: $SERVICE_URL"
echo "🔗 Dashboard: $SERVICE_URL"
echo "🤖 Webhook URL: $SERVICE_URL/webhook/telegram"
echo ""
echo "📝 Next steps:"
echo "1. Update your Telegram bot webhook URL to: $SERVICE_URL/webhook/telegram"
echo "2. Update the telegram-bot-token secret with your actual bot token"
echo "3. Send a message to your bot to test the integration"
echo ""
echo "🔧 To update bot token:"
echo "   echo -n 'YOUR_BOT_TOKEN' | gcloud secrets versions add telegram-bot-token --data-file=-"
echo ""
echo "🎉 Your Telegram AI Processor is ready!"
