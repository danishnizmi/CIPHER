#!/bin/bash

# CIPHER Platform - Production Deployment Script
# This script handles complete deployment with permission fixes

set -e

# Configuration
PROJECT_ID="primal-chariot-382610"
SERVICE_NAME="telegram-ai-processor"
REGION="us-central1"
SERVICE_ACCOUNT="cipher-service@${PROJECT_ID}.iam.gserviceaccount.com"
CLOUD_BUILD_SA="cloud-build-service@${PROJECT_ID}.iam.gserviceaccount.com"
DATASET_ID="telegram_data"
TABLE_ID="processed_messages"

echo "🛡️ CIPHER Platform - Production Deployment"
echo "============================================"
echo "Project: $PROJECT_ID"
echo "Service: $SERVICE_NAME"
echo "Region: $REGION"
echo ""

# Check if gcloud is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo "❌ Error: No active gcloud authentication found"
    echo "Please run: gcloud auth login"
    exit 1
fi

# Set the project
echo "📋 Setting up project..."
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "🔧 Enabling required Google Cloud APIs..."
gcloud services enable \
    bigquery.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    container.googleapis.com \
    artifactregistry.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    --project=$PROJECT_ID

echo "✅ APIs enabled successfully"

# Fix BigQuery permissions
echo "🗄️ Setting up BigQuery permissions..."

# Create service account if it doesn't exist
gcloud iam service-accounts describe $SERVICE_ACCOUNT --project=$PROJECT_ID >/dev/null 2>&1 || {
    echo "Creating service account: $SERVICE_ACCOUNT"
    gcloud iam service-accounts create cipher-service \
        --display-name="CIPHER Service Account" \
        --description="Service account for CIPHER cybersecurity platform" \
        --project=$PROJECT_ID
}

# Grant BigQuery permissions to service account
echo "Setting BigQuery permissions for cipher-service..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/bigquery.admin" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/bigquery.jobUser" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/bigquery.dataEditor" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/logging.logWriter" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/monitoring.metricWriter" \
    --quiet

# Grant Cloud Build permissions
echo "Setting Cloud Build permissions..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$CLOUD_BUILD_SA" \
    --role="roles/bigquery.admin" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$CLOUD_BUILD_SA" \
    --role="roles/run.admin" \
    --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$CLOUD_BUILD_SA" \
    --role="roles/iam.serviceAccountUser" \
    --quiet

echo "✅ Permissions configured successfully"

# Setup BigQuery dataset and table
echo "📊 Setting up BigQuery dataset and table..."

# Create dataset if it doesn't exist
bq ls --project_id=$PROJECT_ID $DATASET_ID >/dev/null 2>&1 || {
    echo "Creating BigQuery dataset: $DATASET_ID"
    bq mk --dataset \
        --location=US \
        --description="CIPHER Telegram Intelligence Data" \
        $PROJECT_ID:$DATASET_ID
}

# Create table schema
cat > /tmp/cipher_table_schema.json << 'EOF'
[
  {
    "name": "message_id",
    "type": "STRING",
    "mode": "REQUIRED",
    "description": "Unique identifier for the message"
  },
  {
    "name": "channel",
    "type": "STRING",
    "mode": "REQUIRED",
    "description": "Source channel name"
  },
  {
    "name": "timestamp",
    "type": "TIMESTAMP",
    "mode": "REQUIRED",
    "description": "When the message was processed"
  },
  {
    "name": "content",
    "type": "STRING",
    "mode": "REQUIRED",
    "description": "Original message content"
  },
  {
    "name": "threat_level",
    "type": "STRING",
    "mode": "NULLABLE",
    "description": "AI-assessed threat level"
  },
  {
    "name": "threat_type",
    "type": "STRING",
    "mode": "NULLABLE",
    "description": "Type of threat detected"
  },
  {
    "name": "processed_at",
    "type": "TIMESTAMP",
    "mode": "REQUIRED",
    "description": "When this record was created"
  }
]
EOF

# Create table if it doesn't exist
bq ls --project_id=$PROJECT_ID $DATASET_ID.$TABLE_ID >/dev/null 2>&1 || {
    echo "Creating BigQuery table: $TABLE_ID"
    bq mk --table \
        --description="CIPHER processed messages" \
        $PROJECT_ID:$DATASET_ID.$TABLE_ID \
        /tmp/cipher_table_schema.json
}

echo "✅ BigQuery setup completed"

# Build and deploy the service
echo "🚀 Building and deploying CIPHER service..."

# Deploy using gcloud run deploy
gcloud run deploy $SERVICE_NAME \
    --source . \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --service-account $SERVICE_ACCOUNT \
    --memory 4Gi \
    --cpu 2 \
    --timeout 3600 \
    --max-instances 10 \
    --min-instances 0 \
    --port 8080 \
    --concurrency 80 \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID,LOG_LEVEL=INFO,DATASET_ID=$DATASET_ID,TABLE_ID=$TABLE_ID,PORT=8080,PYTHONUNBUFFERED=1" \
    --project $PROJECT_ID \
    --quiet

echo "✅ Service deployed successfully"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format='value(status.url)')

echo ""
echo "🎉 CIPHER Platform Deployment Complete!"
echo "======================================"
echo "Service URL: $SERVICE_URL"
echo "Dashboard: $SERVICE_URL/dashboard"
echo "Health Check: $SERVICE_URL/health"
echo "Stats API: $SERVICE_URL/api/stats"
echo ""

# Test the deployment
echo "🧪 Testing deployment..."

# Test health endpoints
echo "Testing /health/live endpoint..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health/live" || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ Liveness check: PASSED"
else
    echo "❌ Liveness check: FAILED (HTTP $HTTP_STATUS)"
fi

echo "Testing /health endpoint..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ Readiness check: PASSED"
else
    echo "❌ Readiness check: FAILED (HTTP $HTTP_STATUS)"
fi

echo "Testing /api/stats endpoint..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/api/stats" || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ Stats API: PASSED"
else
    echo "❌ Stats API: FAILED (HTTP $HTTP_STATUS)"
fi

echo ""
echo "🔍 Deployment Status:"
gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format='table(status.conditions[].type,status.conditions[].status,status.conditions[].reason)'

echo ""
echo "📝 Quick Access Commands:"
echo "View logs: gcloud logs read 'resource.type=cloud_run_revision' --project=$PROJECT_ID --limit=50"
echo "Update service: ./deploy.sh"
echo "View service: gcloud run services describe $SERVICE_NAME --region=$REGION --project=$PROJECT_ID"

# Cleanup temporary files
rm -f /tmp/cipher_table_schema.json

echo ""
echo "🛡️ CIPHER Platform is now operational!"
echo "Monitor the dashboard at: $SERVICE_URL/dashboard"
