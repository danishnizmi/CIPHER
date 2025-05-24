#!/bin/bash

# CIPHER Platform - Production Deployment Script
# Using existing cloud-build-service account with all permissions

set -e

# Configuration
PROJECT_ID="primal-chariot-382610"
SERVICE_NAME="telegram-ai-processor"
REGION="us-central1"
SERVICE_ACCOUNT="cloud-build-service@${PROJECT_ID}.iam.gserviceaccount.com"
DATASET_ID="telegram_data"
TABLE_ID="processed_messages"

echo "🛡️ CIPHER Platform - Production Deployment"
echo "============================================"
echo "Project: $PROJECT_ID"
echo "Service: $SERVICE_NAME"
echo "Region: $REGION"
echo "Service Account: $SERVICE_ACCOUNT"
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

# Verify cloud-build-service account exists and has permissions
echo "🔍 Verifying service account permissions..."
PERMISSIONS=$(gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:$SERVICE_ACCOUNT" \
    --format="value(bindings.role)" | wc -l)

if [ "$PERMISSIONS" -eq 0 ]; then
    echo "❌ Error: Service account $SERVICE_ACCOUNT has no permissions"
    echo "Please check the service account exists and has proper IAM roles"
    exit 1
else
    echo "✅ Service account has $PERMISSIONS IAM roles configured"
fi

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
    --project=$PROJECT_ID \
    --quiet

echo "✅ APIs enabled successfully"

# Setup BigQuery dataset and table
echo "📊 Setting up BigQuery dataset and table..."

# Check if dataset exists
if bq ls --project_id=$PROJECT_ID $DATASET_ID >/dev/null 2>&1; then
    echo "✅ BigQuery dataset '$DATASET_ID' already exists"
else
    echo "Creating BigQuery dataset: $DATASET_ID"
    bq mk --dataset \
        --location=US \
        --description="CIPHER Telegram Intelligence Data" \
        $PROJECT_ID:$DATASET_ID
fi

# Check if table exists  
if bq ls --project_id=$PROJECT_ID $DATASET_ID.$TABLE_ID >/dev/null 2>&1; then
    echo "✅ BigQuery table '$TABLE_ID' already exists"
else
    echo "Creating BigQuery table: $TABLE_ID"
    
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
  },
  {
    "name": "processed_date",
    "type": "DATE",
    "mode": "REQUIRED",
    "description": "Date partition field"
  },
  {
    "name": "channel_type",
    "type": "STRING",
    "mode": "NULLABLE",
    "description": "Channel type for clustering"
  },
  {
    "name": "category",
    "type": "STRING",
    "mode": "NULLABLE",
    "description": "Message category for clustering"
  }
]
EOF

    bq mk --table \
        --description="CIPHER processed messages with partitioning and clustering" \
        --time_partitioning_field=processed_date \
        --time_partitioning_type=DAY \
        --clustering_fields=threat_level,channel_type,category \
        $PROJECT_ID:$DATASET_ID.$TABLE_ID \
        /tmp/cipher_table_schema.json
        
    # Cleanup temp file
    rm -f /tmp/cipher_table_schema.json
fi

echo "✅ BigQuery setup completed"

# Build and deploy the service
echo "🚀 Building and deploying CIPHER service..."

# Deploy using gcloud run deploy with cloud-build-service account
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
    --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID,LOG_LEVEL=INFO,DATASET_ID=$DATASET_ID,TABLE_ID=$TABLE_ID,PORT=8080,PYTHONUNBUFFERED=1,SERVICE_ACCOUNT=$SERVICE_ACCOUNT" \
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
echo "Service Account: $SERVICE_ACCOUNT"
echo ""

# Test the deployment
echo "🧪 Testing deployment..."

# Wait for service to be ready
echo "Waiting for service to stabilize..."
sleep 30

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

echo "Testing /api/monitoring/status endpoint..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/api/monitoring/status" || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ Monitoring API: PASSED"
else
    echo "❌ Monitoring API: FAILED (HTTP $HTTP_STATUS)"
fi

echo ""
echo "🔍 Deployment Status:"
gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format='table(status.conditions[].type,status.conditions[].status,status.conditions[].reason)'

echo ""
echo "📊 Service Account Permissions:"
gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:$SERVICE_ACCOUNT" \
    --format="table(bindings.role)"

echo ""
echo "📝 Quick Access Commands:"
echo "View logs: gcloud run services logs read $SERVICE_NAME --region=$REGION --project=$PROJECT_ID --limit=50"
echo "Update service: ./deploy.sh"
echo "View service: gcloud run services describe $SERVICE_NAME --region=$REGION --project=$PROJECT_ID"
echo "Scale service: gcloud run services update $SERVICE_NAME --region=$REGION --max-instances=20"

echo ""
echo "🛡️ CIPHER Platform is now operational!"
echo "Monitor the dashboard at: $SERVICE_URL/dashboard"
echo "Real-time cybersecurity intelligence monitoring active!"
echo ""
echo "📡 Monitoring Channels:"
echo "🔴 @DarkfeedNews - Threat Intelligence"
echo "🟠 @breachdetector - Data Breach Monitor" 
echo "🔵 @secharvester - Security News"
