# Secure Digital Locker for Employee Documents

A comprehensive secure document management system built on Google Cloud Platform (GCP) for storing, encrypting, and controlling access to sensitive employee documents with full audit trails.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Client    │───▶│  Cloud Functions │───▶│  Cloud Storage  │
│  (React/HTML)   │    │   (Auth & Logic) │    │   (Encrypted)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                         │
                                ▼                         ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │    Firestore     │    │   Cloud KMS     │
                       │  (Audit Logs)    │    │ (Encryption)    │
                       └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Firebase Auth /  │
                       │ Identity Platform│
                       └──────────────────┘
```

## Features

### 🔐 Security
- **End-to-end encryption** using Cloud KMS
- **Role-based access control** (Admin, HR, Employee)
- **Signed URLs** for temporary secure access
- **Document integrity verification**

### 👥 User Management
- **Firebase Authentication** with custom claims
- **Multi-factor authentication** support
- **Session management** with automatic expiry

### 📊 Audit & Compliance
- **Complete audit trails** for all document operations
- **Access logging** with timestamps and user details
- **Compliance reporting** for regulatory requirements

### 🚀 Performance & Availability
- **Serverless architecture** with Cloud Functions
- **Auto-scaling** based on demand
- **Global CDN** for fast document access

## User Roles

1. **Admin**: Full system access, user management, all documents
2. **HR**: Access to all employee documents, upload permissions
3. **Employee**: Access only to their own documents

## Setup Instructions

### Prerequisites
- Google Cloud Project with billing enabled
- Node.js 18+ installed
- Google Cloud SDK installed and configured

### 1. Enable Required APIs
```bash
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable cloudkms.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable identitytoolkit.googleapis.com
```

### 2. Set up Environment Variables
```bash
cp .env.example .env
# Edit .env with your project details
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Deploy Infrastructure
```bash
npm run deploy
```

## Environment Variables

```
GCP_PROJECT_ID=your-project-id
BUCKET_NAME=secure-documents-bucket
KMS_KEY_RING=document-encryption
KMS_KEY_NAME=document-key
FIRESTORE_COLLECTION=audit_logs
FIREBASE_CONFIG=path/to/firebase-config.json
```

## API Endpoints

### Authentication
- `POST /auth/login` - User authentication
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Get user profile

### Document Management
- `POST /documents/upload` - Upload document
- `GET /documents/:id` - Download document
- `DELETE /documents/:id` - Delete document
- `GET /documents/list` - List user's documents

### Admin Operations
- `GET /admin/users` - List all users
- `POST /admin/users/:id/role` - Update user role
- `GET /admin/audit` - Get audit logs

## Security Considerations

1. **Encryption at Rest**: All documents encrypted using Cloud KMS
2. **Encryption in Transit**: HTTPS/TLS for all communications
3. **Access Control**: IAM policies and custom authentication
4. **Audit Logging**: All operations logged to Firestore
5. **Input Validation**: Joi schemas for all inputs
6. **Rate Limiting**: Implemented at Cloud Functions level

## Compliance Features

- **GDPR Compliance**: Right to be forgotten, data portability
- **SOX Compliance**: Immutable audit trails
- **HIPAA Ready**: Encryption and access controls
- **ISO 27001**: Security management framework

## Monitoring & Alerting

- Cloud Monitoring for function performance
- Cloud Logging for centralized logs
- Custom alerts for security events
- Dashboard for real-time metrics

## Development

```bash
# Start development server
npm run dev

# Run tests
npm test

# Deploy functions
npm run deploy
```

## License

MIT License - see LICENSE file for details