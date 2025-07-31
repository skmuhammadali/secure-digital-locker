const path = require('path');
require('dotenv').config();

const config = {
  // Google Cloud Configuration
  gcp: {
    projectId: process.env.GCP_PROJECT_ID,
    region: process.env.GCP_REGION || 'us-central1',
    keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  },

  // Cloud Storage Configuration
  storage: {
    bucketName: process.env.BUCKET_NAME,
    bucketLocation: process.env.BUCKET_LOCATION || 'US',
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
    allowedFileTypes: (process.env.ALLOWED_FILE_TYPES || 'pdf,doc,docx,jpg,jpeg,png').split(','),
  },

  // Cloud KMS Configuration
  kms: {
    keyRing: process.env.KMS_KEY_RING,
    keyName: process.env.KMS_KEY_NAME,
    location: process.env.KMS_LOCATION || 'global',
    keyId: `projects/${process.env.GCP_PROJECT_ID}/locations/${process.env.KMS_LOCATION || 'global'}/keyRings/${process.env.KMS_KEY_RING}/cryptoKeys/${process.env.KMS_KEY_NAME}`,
  },

  // Firestore Configuration
  firestore: {
    collections: {
      auditLogs: process.env.FIRESTORE_COLLECTION_AUDIT || 'audit_logs',
      users: process.env.FIRESTORE_COLLECTION_USERS || 'users',
      documents: process.env.FIRESTORE_COLLECTION_DOCUMENTS || 'document_metadata',
    },
  },

  // Firebase Configuration
  firebase: {
    projectId: process.env.FIREBASE_PROJECT_ID || process.env.GCP_PROJECT_ID,
    webApiKey: process.env.FIREBASE_WEB_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    serviceAccountPath: process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
  },

  // Application Configuration
  app: {
    nodeEnv: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT) || 8080,
    corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  },

  // Security Configuration
  security: {
    jwtSecret: process.env.JWT_SECRET,
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 3600, // 1 hour
    refreshTokenTimeout: parseInt(process.env.REFRESH_TOKEN_TIMEOUT) || 2592000, // 30 days
    bcryptRounds: 12,
  },

  // User Roles
  roles: {
    ADMIN: 'admin',
    HR: 'hr',
    EMPLOYEE: 'employee',
  },

  // Document Types
  documentTypes: {
    OFFER_LETTER: 'offer_letter',
    ID_PROOF: 'id_proof',
    SALARY_SLIP: 'salary_slip',
    CERTIFICATION: 'certification',
    CONTRACT: 'contract',
    PERFORMANCE_REVIEW: 'performance_review',
    OTHER: 'other',
  },

  // Audit Event Types
  auditEvents: {
    DOCUMENT_UPLOAD: 'document_upload',
    DOCUMENT_DOWNLOAD: 'document_download',
    DOCUMENT_DELETE: 'document_delete',
    DOCUMENT_VIEW: 'document_view',
    USER_LOGIN: 'user_login',
    USER_LOGOUT: 'user_logout',
    ROLE_CHANGE: 'role_change',
    ACCESS_DENIED: 'access_denied',
  },
};

// Validation
const requiredEnvVars = [
  'GCP_PROJECT_ID',
  'BUCKET_NAME',
  'KMS_KEY_RING',
  'KMS_KEY_NAME',
  'JWT_SECRET',
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
}

module.exports = config;