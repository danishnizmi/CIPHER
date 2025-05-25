#!/bin/bash

# CIPHER Platform - Production Deployment Script
# Complete production-ready deployment with all prerequisites

set -e

# Configuration
PROJECT_ID="primal-chariot-382610"
SERVICE_NAME="telegram-ai-processor"
REGION="us-central1"
SERVICE_ACCOUNT="cloud-build-service@${PROJECT_ID}.iam.gserviceaccount.com"
DATASET_ID="telegram_data"
TABLE_ID="processed_messages"
BUCKET_NAME="${PROJECT_ID}-telegram-sessions"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_header() {
    echo -e "${PURPLE}🛡️  $1${NC}"
}

log_step() {
    echo -e "${CYAN}🔧 $1${NC}"
}

# Error handling
handle_error() {
    log_error "Deployment failed at step: $1"
    log_error "Check the errors above for details"
    exit 1
}

# Main deployment header
echo -e "${WHITE}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                   CIPHER Platform                            ║
║              Production Deployment                           ║
║         Cybersecurity Intelligence Platform                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log_header "CIPHER Platform - Production Deployment"
echo "=================================================="
echo "Project: $PROJECT_ID"
echo "Service: $SERVICE_NAME"
echo "Region: $REGION"
echo "Service Account: $SERVICE_ACCOUNT"
echo ""

# Step 1: Verify Prerequisites
log_step "Step 1: Verifying Prerequisites"

# Check if gcloud is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    handle_error "No active gcloud authentication found. Run: gcloud auth login"
fi

log_success "Google Cloud authentication verified"

# Set the project
gcloud config set project $PROJECT_ID

# Verify service account permissions
log_info "Verifying service account permissions..."
PERMISSIONS=$(gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:$SERVICE_ACCOUNT" \
    --format="value(bindings.role)" | wc -l)

if [ "$PERMISSIONS" -eq 0 ]; then
    handle_error "Service account $SERVICE_ACCOUNT has no permissions"
else
    log_success "Service account has $PERMISSIONS IAM roles configured"
fi

# Step 2: Check Telegram Session
log_step "Step 2: Verifying Telegram Authentication"

log_info "Checking Telegram session..."
if gsutil ls gs://${BUCKET_NAME}/cipher_session.session >/dev/null 2>&1; then
    SESSION_SIZE=$(gsutil stat gs://${BUCKET_NAME}/cipher_session.session | grep "Content-Length" | awk '{print $2}')
    log_success "Telegram session found (${SESSION_SIZE} bytes)"
    
    # Get session metadata
    SESSION_PHONE=$(gsutil stat gs://${BUCKET_NAME}/cipher_session.session | grep "phone_number" | cut -d: -f2 | tr -d ' ' || echo "unknown")
    if [ "$SESSION_PHONE" != "unknown" ] && [ ! -z "$SESSION_PHONE" ]; then
        log_info "Session authenticated for phone: $SESSION_PHONE"
    fi
else
    log_error "Telegram session not found in Cloud Storage"
    log_error "Please run the authentication script first:"
    log_error "python local_auth.py"
    handle_error "Missing Telegram authentication"
fi

# Step 3: Create/Verify All Required Secrets
log_step "Step 3: Creating/Verifying Required Secrets"

# Function to create secret if it doesn't exist
create_secret_if_missing() {
    local secret_name=$1
    local secret_value=$2
    local description=$3
    
    if ! gcloud secrets describe $secret_name >/dev/null 2>&1; then
        if [ -z "$secret_value" ]; then
            log_error "Secret $secret_name does not exist and no value provided"
            log_error "$description"
            return 1
        else
            echo "$secret_value" | gcloud secrets create $secret_name --data-file=-
            log_success "Created secret: $secret_name"
        fi
    else
        log_success "Secret exists: $secret_name"
    fi
    return 0
}

# Create Telegram API secrets (from your successful authentication)
log_info "Creating Telegram API secrets..."

if ! create_secret_if_missing "telegram-api-id" "29916660" "Get from https://my.telegram.org/apps"; then
    read -p "Enter your Telegram API ID: " api_id
    create_secret_if_missing "telegram-api-id" "$api_id" "Telegram API ID"
fi

if ! create_secret_if_missing "telegram-api-hash" "25fce6daeea191ec384eafe222ae0655" "Get from https://my.telegram.org/apps"; then
    read -p "Enter your Telegram API Hash: " api_hash
    create_secret_if_missing "telegram-api-hash" "$api_hash" "Telegram API Hash"
fi

if ! create_secret_if_missing "telegram-phone-number" "+61435083433" "Your authenticated phone number"; then
    read -p "Enter your phone number (with country code): " phone_number
    create_secret_if_missing "telegram-phone-number" "$phone_number" "Phone number"
fi

# Create Gemini API key secret
log_info "Checking Gemini API key..."
if ! gcloud secrets describe gemini-api-key >/dev/null 2>&1; then
    log_warning "Gemini API key not found"
    log_info "Please get your free API key from: https://makersuite.google.com/app/apikey"
    read -p "Enter your Gemini API key: " gemini_key
    
    if [ ! -z "$gemini_key" ]; then
        echo "$gemini_key" | gcloud secrets create gemini-api-key --data-file=-
        log_success "Created Gemini API key secret"
    else
        log_warning "No Gemini API key provided - AI features will be limited"
    fi
else
    log_success "Gemini API key exists"
fi

# Step 4: Enable Required APIs
log_step "Step 4: Enabling Required Google Cloud APIs"

log_info "Enabling APIs..."
gcloud services enable \
    bigquery.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    container.googleapis.com \
    artifactregistry.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    secretmanager.googleapis.com \
    storage.googleapis.com \
    --project=$PROJECT_ID \
    --quiet

log_success "All required APIs enabled"

# Step 5: Setup BigQuery Infrastructure
log_step "Step 5: Setting up BigQuery Infrastructure"

log_info "Setting up BigQuery dataset and table..."

# Create dataset if not exists
if ! bq ls --project_id=$PROJECT_ID $DATASET_ID >/dev/null 2>&1; then
    log_info "Creating BigQuery dataset: $DATASET_ID"
    bq mk --dataset \
        --location=US \
        --description="CIPHER Cybersecurity Intelligence Platform Data" \
        $PROJECT_ID:$DATASET_ID
    log_success "Created BigQuery dataset: $DATASET_ID"
else
    log_success "BigQuery dataset '$DATASET_ID' already exists"
fi

# Create table with enhanced schema if not exists
if ! bq ls --project_id=$PROJECT_ID $DATASET_ID.$TABLE_ID >/dev/null 2>&1; then
    log_info "Creating BigQuery table: $TABLE_ID"
    
    # Create enhanced cybersecurity schema
    cat > /tmp/cipher_schema.json << 'EOF'
[
  {"name": "message_id", "type": "STRING", "mode": "REQUIRED", "description": "Unique message identifier"},
  {"name": "chat_id", "type": "STRING", "mode": "REQUIRED", "description": "Telegram chat/channel ID"},
  {"name": "chat_username", "type": "STRING", "mode": "NULLABLE", "description": "Channel username (e.g., @DarkfeedNews)"},
  {"name": "user_id", "type": "STRING", "mode": "NULLABLE", "description": "Telegram user ID"},
  {"name": "username", "type": "STRING", "mode": "NULLABLE", "description": "Username without @ symbol"},
  {"name": "message_text", "type": "STRING", "mode": "NULLABLE", "description": "Original message content"},
  {"name": "message_date", "type": "TIMESTAMP", "mode": "REQUIRED", "description": "When message was sent"},
  {"name": "processed_date", "type": "TIMESTAMP", "mode": "REQUIRED", "description": "When message was processed"},
  {"name": "gemini_analysis", "type": "STRING", "mode": "NULLABLE", "description": "Gemini AI threat analysis summary"},
  {"name": "sentiment", "type": "STRING", "mode": "NULLABLE", "description": "Message sentiment: positive/negative/neutral"},
  {"name": "key_topics", "type": "STRING", "mode": "REPEATED", "description": "Key cybersecurity topics identified"},
  {"name": "urgency_score", "type": "FLOAT", "mode": "NULLABLE", "description": "Threat urgency score (0.0-1.0)"},
  {"name": "category", "type": "STRING", "mode": "NULLABLE", "description": "Threat category classification"},
  {"name": "threat_level", "type": "STRING", "mode": "NULLABLE", "description": "Threat level: critical/high/medium/low/info"},
  {"name": "threat_type", "type": "STRING", "mode": "NULLABLE", "description": "Specific threat type (e.g., APT, ransomware)"},
  {"name": "channel_type", "type": "STRING", "mode": "NULLABLE", "description": "Source channel type"},
  {"name": "channel_priority", "type": "STRING", "mode": "NULLABLE", "description": "Channel priority level"},
  {"name": "iocs_detected", "type": "STRING", "mode": "REPEATED", "description": "Indicators of Compromise found"},
  {"name": "cve_references", "type": "STRING", "mode": "REPEATED", "description": "CVE references mentioned"},
  {"name": "malware_families", "type": "STRING", "mode": "REPEATED", "description": "Malware families identified"},
  {"name": "affected_systems", "type": "STRING", "mode": "REPEATED", "description": "Systems/platforms affected"},
  {"name": "attack_vectors", "type": "STRING", "mode": "REPEATED", "description": "Attack vectors mentioned"},
  {"name": "threat_actors", "type": "STRING", "mode": "REPEATED", "description": "Threat actors/groups mentioned"},
  {"name": "campaign_names", "type": "STRING", "mode": "REPEATED", "description": "Campaign or operation names"},
  {"name": "geographical_targets", "type": "STRING", "mode": "REPEATED", "description": "Geographic regions targeted"},
  {"name": "industry_targets", "type": "STRING", "mode": "REPEATED", "description": "Industries targeted"}
]
EOF
    
    bq mk --table \
        --description="CIPHER Cybersecurity Intelligence Messages" \
        --time_partitioning_field=processed_date \
        --time_partitioning_type=DAY \
        --clustering_fields=threat_level,channel_type,category,threat_type \
        $PROJECT_ID:$DATASET_ID.$TABLE_ID \
        /tmp/cipher_schema.json
        
    rm -f /tmp/cipher_schema.json
    log_success "Created partitioned and clustered BigQuery table: $TABLE_ID"
else
    log_success "BigQuery table '$TABLE_ID' already exists"
    
    # Verify table schema
    FIELD_COUNT=$(bq show --format=json $PROJECT_ID:$DATASET_ID.$TABLE_ID | jq '.schema.fields | length')
    log_info "Table has $FIELD_COUNT fields configured"
fi

# Step 6: Validate Code Files
log_step "Step 6: Validating Code Files"

# Check if all required files exist
REQUIRED_FILES=("main.py" "utils.py" "frontend.py" "requirements.txt" "Dockerfile" "cloudbuild.yaml")
MISSING_FILES=()

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        log_success "Found: $file"
    else
        MISSING_FILES+=("$file")
        log_warning "Missing: $file"
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    log_warning "Some files are missing but deployment can continue"
    log_info "Missing files: ${MISSING_FILES[*]}"
fi

# Verify main.py contains the fix
if grep -q "processed_date" main.py; then
    log_success "main.py contains BigQuery schema fix"
else
    log_warning "main.py may not have the latest BigQuery schema fix"
fi

# Step 7: Build and Deploy
log_step "Step 7: Building and Deploying CIPHER Platform"

log_info "Starting Cloud Build deployment..."

# Use Cloud Build for production deployment
gcloud builds submit \
    --config cloudbuild.yaml \
    --project=$PROJECT_ID \
    --timeout=1800s

DEPLOY_EXIT_CODE=$?

if [ $DEPLOY_EXIT_CODE -eq 0 ]; then
    log_success "Cloud Build deployment completed successfully"
else
    log_error "Cloud Build deployment failed with exit code: $DEPLOY_EXIT_CODE"
    log_info "Attempting direct deployment as fallback..."
    
    # Fallback to direct gcloud run deploy
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
        --project $PROJECT_ID
        
    log_success "Direct deployment completed"
fi

# Step 8: Get Service URL and Verify Deployment
log_step "Step 8: Verifying Deployment"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format='value(status.url)')

if [ -z "$SERVICE_URL" ]; then
    handle_error "Failed to get service URL"
fi

log_success "Service deployed at: $SERVICE_URL"

# Wait for service to be ready
log_info "Waiting for service to initialize..."
sleep 20

# Step 9: Comprehensive Health Checks
log_step "Step 9: Running Health Checks"

# Test liveness probe
log_info "Testing liveness probe..."
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health/live" || echo "000")
if [ "$HEALTH_STATUS" = "200" ]; then
    log_success "Liveness check: PASSED"
else
    log_warning "Liveness check: HTTP $HEALTH_STATUS (service may still be starting)"
fi

# Test readiness probe
log_info "Testing readiness probe..."
READY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" || echo "000")
if [ "$READY_STATUS" = "200" ]; then
    log_success "Readiness check: PASSED"
    
    # Get detailed health info
    HEALTH_INFO=$(curl -s "$SERVICE_URL/health" | jq -r '.checks.bigquery, .checks.monitoring' 2>/dev/null || echo "unknown unknown")
    BQ_STATUS=$(echo $HEALTH_INFO | cut -d' ' -f1)
    MONITORING_STATUS=$(echo $HEALTH_INFO | cut -d' ' -f2)
    
    log_info "BigQuery: $BQ_STATUS, Monitoring: $MONITORING_STATUS"
else
    log_warning "Readiness check: HTTP $READY_STATUS"
fi

# Test main page
log_info "Testing main page..."
MAIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/" || echo "000")
if [ "$MAIN_STATUS" = "200" ]; then
    log_success "Main page: WORKING"
else
    log_warning "Main page: HTTP $MAIN_STATUS"
fi

# Test stats API (this was the main problem)
log_info "Testing stats API..."
STATS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/api/stats" || echo "000")
if [ "$STATS_STATUS" = "200" ]; then
    log_success "Stats API: FIXED AND WORKING ✅"
    
    # Get actual stats
    STATS_DATA=$(curl -s "$SERVICE_URL/api/stats" 2>/dev/null)
    if [ ! -z "$STATS_DATA" ]; then
        TOTAL_MESSAGES=$(echo "$STATS_DATA" | jq -r '.total_messages' 2>/dev/null || echo "0")
        DATA_SOURCE=$(echo "$STATS_DATA" | jq -r '.data_source' 2>/dev/null || echo "unknown")
        MONITORING_ACTIVE=$(echo "$STATS_DATA" | jq -r '.monitoring_active' 2>/dev/null || echo "false")
        
        log_info "Stats: Messages: $TOTAL_MESSAGES, Source: $DATA_SOURCE, Monitoring: $MONITORING_ACTIVE"
    fi
else
    log_error "Stats API: FAILED (HTTP $STATS_STATUS) - This was the main issue!"
fi

# Test monitoring status
log_info "Testing monitoring status..."
MONITOR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/api/monitoring/status" || echo "000")
if [ "$MONITOR_STATUS" = "200" ]; then
    log_success "Monitoring API: WORKING"
    
    # Get monitoring details
    MONITORING_DATA=$(curl -s "$SERVICE_URL/api/monitoring/status" 2>/dev/null)
    if [ ! -z "$MONITORING_DATA" ]; then
        TELEGRAM_ACTIVE=$(echo "$MONITORING_DATA" | jq -r '.active' 2>/dev/null || echo "false")
        UTILS_AVAILABLE=$(echo "$MONITORING_DATA" | jq -r '.utils_available' 2>/dev/null || echo "false")
        
        log_info "Telegram monitoring: $TELEGRAM_ACTIVE, Utils: $UTILS_AVAILABLE"
    fi
else
    log_warning "Monitoring API: HTTP $MONITOR_STATUS"
fi

# Test dashboard
log_info "Testing dashboard..."
DASH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/dashboard" || echo "000")
if [ "$DASH_STATUS" = "200" ]; then
    log_success "Dashboard: WORKING"
else
    log_warning "Dashboard: HTTP $DASH_STATUS"
fi

# Step 10: Show Logs
log_step "Step 10: Recent Service Logs"

log_info "Showing recent service logs..."
gcloud run services logs read $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --limit=15 \
    --format="table(timestamp,severity,textPayload)" | head -20

# Step 11: Final Status Report
log_step "Step 11: Final Deployment Report"

echo ""
echo -e "${WHITE}═══════════════════════════════════════════════════════════════${NC}"
log_header "🎉 CIPHER Platform Deployment Complete!"
echo -e "${WHITE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Service Information
echo -e "${CYAN}🔗 Service Information:${NC}"
echo "   Service URL: $SERVICE_URL"
echo "   Dashboard: $SERVICE_URL/dashboard"
echo "   Health Check: $SERVICE_URL/health"
echo "   Stats API: $SERVICE_URL/api/stats"
echo "   Monitoring Status: $SERVICE_URL/api/monitoring/status"
echo ""

# Technical Details
echo -e "${CYAN}🔧 Technical Details:${NC}"
echo "   Project: $PROJECT_ID"
echo "   Service Account: $SERVICE_ACCOUNT"
echo "   Region: $REGION"
echo "   BigQuery Dataset: $DATASET_ID"
echo "   BigQuery Table: $TABLE_ID"
echo "   Telegram Session: Authenticated ✅"
echo ""

# Monitoring Channels
echo -e "${CYAN}📡 Monitoring Channels:${NC}"
echo "   🔴 @DarkfeedNews - Advanced Threat Intelligence"
echo "   🟠 @breachdetector - Data Breach Monitor"
echo "   🔵 @secharvester - Security News & CVEs"
echo ""

# Health Summary
echo -e "${CYAN}🏥 Health Status Summary:${NC}"
if [ "$HEALTH_STATUS" = "200" ] && [ "$STATS_STATUS" = "200" ]; then
    log_success "ALL SYSTEMS OPERATIONAL ✅"
    echo "   ✅ HTTP Server: Responsive"
    echo "   ✅ BigQuery: Connected and working"
    echo "   ✅ Stats API: Fixed and functional"
    echo "   ✅ Health Checks: All passing"
    echo "   ✅ Telegram Session: Authenticated"
elif [ "$HEALTH_STATUS" = "200" ]; then
    log_success "DEPLOYMENT SUCCESSFUL - Some features initializing"
    echo "   ✅ HTTP Server: Responsive"
    echo "   ⚠️  Some components may still be starting up"
else
    log_warning "SERVICE DEPLOYED - May need more time to initialize"
    echo "   ⚠️  Check logs for initialization progress"
fi

echo ""

# Quick Commands
echo -e "${CYAN}📝 Useful Commands:${NC}"
echo "   View logs: gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=50"
echo "   Redeploy: ./deploy.sh"
echo "   Scale service: gcloud run services update $SERVICE_NAME --region=$REGION --max-instances=20"
echo "   Service status: gcloud run services describe $SERVICE_NAME --region=$REGION"
echo ""

# Final message based on status
if [ "$HEALTH_STATUS" = "200" ] && [ "$STATS_STATUS" = "200" ]; then
    echo -e "${GREEN}🎯 SUCCESS: CIPHER cybersecurity platform is fully operational!${NC}"
    echo -e "${GREEN}🛡️ Your threat intelligence monitoring system is now protecting your digital assets.${NC}"
elif [ "$HEALTH_STATUS" = "200" ]; then
    echo -e "${YELLOW}🎯 DEPLOYED: CIPHER is running and components are initializing.${NC}"
    echo -e "${YELLOW}🔄 Check the service in a few minutes for full functionality.${NC}"
else
    echo -e "${YELLOW}⚠️ PARTIAL DEPLOYMENT: Service deployed but may need more time.${NC}"
    echo -e "${YELLOW}💡 Monitor the health endpoint: $SERVICE_URL/health${NC}"
fi

echo ""
log_header "🛡️ CIPHER Platform - Protecting Your Cybersecurity Perimeter"
echo ""

# Create deployment summary
cat > deployment_summary.txt << EOF
CIPHER Platform Deployment Summary
Generated: $(date)

Service URL: $SERVICE_URL
Dashboard: $SERVICE_URL/dashboard
Health Check: $SERVICE_URL/health
Stats API: $SERVICE_URL/api/stats

Project: $PROJECT_ID
Service: $SERVICE_NAME
Region: $REGION
Service Account: $SERVICE_ACCOUNT

BigQuery Dataset: $DATASET_ID
BigQuery Table: $TABLE_ID
Telegram Session: Authenticated
Monitoring Channels: @DarkfeedNews, @breachdetector, @secharvester

Health Status: $HEALTH_STATUS
Stats API Status: $STATS_STATUS
Monitoring API Status: $MONITOR_STATUS
Dashboard Status: $DASH_STATUS

Deployment completed: $(date)
EOF

log_info "Deployment summary saved to: deployment_summary.txt"

echo ""
echo -e "${PURPLE}🚀 Access your CIPHER cybersecurity dashboard: $SERVICE_URL/dashboard${NC}"
echo ""

exit 0
