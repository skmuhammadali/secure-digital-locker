#!/bin/bash

# Secure Digital Locker Deployment Script
# This script sets up the complete infrastructure for the document management system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${1:-your-gcp-project-id}"
REGION="${2:-us-central1}"
BUCKET_LOCATION="${3:-US}"

echo -e "${BLUE}🚀 Starting Secure Digital Locker Deployment${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Project ID: ${PROJECT_ID}"
echo -e "Region: ${REGION}"
echo -e "Bucket Location: ${BUCKET_LOCATION}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if user is logged in
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo -e "${YELLOW}⚠️  Please login to gcloud first${NC}"
    gcloud auth login
fi

# Set the project
echo -e "${BLUE}📋 Setting up project configuration...${NC}"
gcloud config set project $PROJECT_ID

# Enable required APIs
echo -e "${BLUE}🔌 Enabling required APIs...${NC}"
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable cloudkms.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable firebase.googleapis.com
gcloud services enable identitytoolkit.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com

echo -e "${GREEN}✅ APIs enabled successfully${NC}"

# Create KMS key ring and key
echo -e "${BLUE}🔐 Setting up Cloud KMS encryption...${NC}"
KMS_KEY_RING="document-encryption-ring"
KMS_KEY_NAME="document-encryption-key"
KMS_LOCATION="global"

# Create key ring (ignore error if it already exists)
gcloud kms keyrings create $KMS_KEY_RING --location=$KMS_LOCATION 2>/dev/null || true

# Create key (ignore error if it already exists)
gcloud kms keys create $KMS_KEY_NAME \
    --location=$KMS_LOCATION \
    --keyring=$KMS_KEY_RING \
    --purpose=encryption 2>/dev/null || true

echo -e "${GREEN}✅ KMS encryption key created${NC}"

# Create storage buckets
echo -e "${BLUE}📦 Setting up Cloud Storage buckets...${NC}"
DOCUMENTS_BUCKET="secure-documents-${PROJECT_ID}"
STATIC_BUCKET="secure-documents-static-${PROJECT_ID}"

# Create documents bucket
gsutil ls gs://$DOCUMENTS_BUCKET 2>/dev/null || {
    gsutil mb -l $BUCKET_LOCATION gs://$DOCUMENTS_BUCKET
    echo -e "${GREEN}✅ Documents bucket created${NC}"
}

# Create static bucket for frontend
gsutil ls gs://$STATIC_BUCKET 2>/dev/null || {
    gsutil mb -l $BUCKET_LOCATION gs://$STATIC_BUCKET
    echo -e "${GREEN}✅ Static bucket created${NC}"
}

# Set bucket versioning and lifecycle
gsutil versioning set on gs://$DOCUMENTS_BUCKET
gsutil lifecycle set bucket-lifecycle.json gs://$DOCUMENTS_BUCKET

# Set uniform bucket-level access
gsutil uniformbucketlevelaccess set on gs://$DOCUMENTS_BUCKET
gsutil uniformbucketlevelaccess set on gs://$STATIC_BUCKET

# Make static bucket public for web hosting
gsutil iam ch allUsers:objectViewer gs://$STATIC_BUCKET

echo -e "${GREEN}✅ Storage buckets configured${NC}"

# Set up Firestore
echo -e "${BLUE}🗃️  Setting up Firestore database...${NC}"
# Create Firestore database if it doesn't exist
gcloud firestore databases create --region=$REGION --quiet 2>/dev/null || true

# Create indexes
gcloud firestore indexes create --quiet 2>/dev/null || {
    echo -e "${YELLOW}⚠️  Firestore indexes creation skipped (may already exist)${NC}"
}

echo -e "${GREEN}✅ Firestore database configured${NC}"

# Set up IAM permissions
echo -e "${BLUE}🔑 Configuring IAM permissions...${NC}"

# Get the default service account
SERVICE_ACCOUNT="${PROJECT_ID}@appspot.gserviceaccount.com"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/storage.objectAdmin" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/datastore.user" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/firebase.admin" --quiet

echo -e "${GREEN}✅ IAM permissions configured${NC}"

# Create environment file
echo -e "${BLUE}⚙️  Creating environment configuration...${NC}"
cat > .env << EOF
# Google Cloud Project Configuration
GCP_PROJECT_ID=$PROJECT_ID
GCP_REGION=$REGION

# Cloud Storage Configuration
BUCKET_NAME=$DOCUMENTS_BUCKET
BUCKET_LOCATION=$BUCKET_LOCATION

# Cloud KMS Configuration
KMS_KEY_RING=$KMS_KEY_RING
KMS_KEY_NAME=$KMS_KEY_NAME
KMS_LOCATION=$KMS_LOCATION

# Firestore Configuration
FIRESTORE_COLLECTION_AUDIT=audit_logs
FIRESTORE_COLLECTION_USERS=users
FIRESTORE_COLLECTION_DOCUMENTS=document_metadata

# Firebase Configuration
FIREBASE_PROJECT_ID=$PROJECT_ID

# Application Configuration
NODE_ENV=production
PORT=8080

# Security Configuration
JWT_SECRET=$(openssl rand -hex 32)
CORS_ORIGIN=https://$STATIC_BUCKET.storage.googleapis.com
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=pdf,doc,docx,jpg,jpeg,png

# Session Configuration
SESSION_TIMEOUT=3600
REFRESH_TOKEN_TIMEOUT=2592000
EOF

echo -e "${GREEN}✅ Environment configuration created${NC}"

# Install dependencies
echo -e "${BLUE}📦 Installing dependencies...${NC}"
npm install

echo -e "${GREEN}✅ Dependencies installed${NC}"

# Deploy Cloud Function
echo -e "${BLUE}☁️  Deploying Cloud Function...${NC}"
gcloud functions deploy secure-document-api \
    --source=. \
    --entry-point=app \
    --runtime=nodejs18 \
    --trigger=http \
    --allow-unauthenticated \
    --memory=512MB \
    --timeout=540s \
    --max-instances=100 \
    --set-env-vars="NODE_ENV=production,GCP_PROJECT_ID=$PROJECT_ID,BUCKET_NAME=$DOCUMENTS_BUCKET,KMS_KEY_RING=$KMS_KEY_RING,KMS_KEY_NAME=$KMS_KEY_NAME" \
    --region=$REGION

FUNCTION_URL=$(gcloud functions describe secure-document-api --region=$REGION --format="value(httpsTrigger.url)")

echo -e "${GREEN}✅ Cloud Function deployed${NC}"
echo -e "Function URL: ${FUNCTION_URL}"

# Deploy static frontend
echo -e "${BLUE}🌐 Deploying frontend...${NC}"
if [ -d "public" ]; then
    # Update the API URL in the frontend
    sed -i.bak "s|API_BASE_URL = '.*'|API_BASE_URL = '$FUNCTION_URL'|g" public/app.js 2>/dev/null || true
    
    gsutil -m rsync -r -c -d ./public gs://$STATIC_BUCKET
    echo -e "${GREEN}✅ Frontend deployed${NC}"
    echo -e "Frontend URL: https://storage.googleapis.com/$STATIC_BUCKET/index.html"
else
    echo -e "${YELLOW}⚠️  No public directory found, skipping frontend deployment${NC}"
fi

# Create Firebase project configuration
echo -e "${BLUE}🔥 Setting up Firebase configuration...${NC}"
cat > firebase-config.json << EOF
{
  "apiKey": "YOUR_FIREBASE_API_KEY",
  "authDomain": "$PROJECT_ID.firebaseapp.com",
  "projectId": "$PROJECT_ID",
  "storageBucket": "$PROJECT_ID.appspot.com",
  "messagingSenderId": "YOUR_MESSAGING_SENDER_ID",
  "appId": "YOUR_FIREBASE_APP_ID"
}
EOF

echo -e "${YELLOW}⚠️  Please update firebase-config.json with your actual Firebase configuration${NC}"

# Summary
echo ""
echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📋 Deployment Summary:${NC}"
echo ""
echo -e "🔐 KMS Key: projects/$PROJECT_ID/locations/$KMS_LOCATION/keyRings/$KMS_KEY_RING/cryptoKeys/$KMS_KEY_NAME"
echo -e "📦 Documents Bucket: gs://$DOCUMENTS_BUCKET"
echo -e "🌐 Static Bucket: gs://$STATIC_BUCKET"
echo -e "☁️  API Function: $FUNCTION_URL"
echo -e "🗃️  Firestore: $PROJECT_ID (default database)"
echo ""
echo -e "${BLUE}🔧 Next Steps:${NC}"
echo -e "1. Set up Firebase Authentication in the Firebase Console"
echo -e "2. Update firebase-config.json with your Firebase config"
echo -e "3. Create initial admin user through Firebase Console"
echo -e "4. Test the application endpoints"
echo ""
echo -e "${BLUE}📖 API Endpoints:${NC}"
echo -e "• Health Check: $FUNCTION_URL/health"
echo -e "• Authentication: $FUNCTION_URL/api/auth"
echo -e "• Documents: $FUNCTION_URL/api/documents"
echo -e "• Admin: $FUNCTION_URL/api/admin"
echo ""
echo -e "${GREEN}✨ Your Secure Digital Locker is now ready!${NC}"