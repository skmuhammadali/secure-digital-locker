const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const config = require('./src/config/config');
const { manageSession } = require('./src/middleware/auth');

// Import routes
const documentRoutes = require('./src/routes/documents');
const authRoutes = require('./src/routes/auth');
const adminRoutes = require('./src/routes/admin');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: config.app.corsOrigin,
  credentials: true,
  optionsSuccessStatus: 200,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  exposedHeaders: ['X-Session-Expires', 'X-User-Role'],
}));

// Body parsing middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || require('uuid').v4();
  req.requestId = requestId;
  res.set('X-Request-ID', requestId);
  
  console.log(`${new Date().toISOString()} [${requestId}] ${req.method} ${req.path}`);
  next();
});

// Session management
app.use(manageSession);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: config.app.nodeEnv,
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/admin', adminRoutes);

// Serve static files in production
if (config.app.nodeEnv === 'production') {
  app.use(express.static(path.join(__dirname, 'public')));
  
  // Catch-all handler for SPA
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    code: 'NOT_FOUND',
    path: req.path,
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error(`Error in ${req.method} ${req.path}:`, error);
  
  // Don't leak error details in production
  const isDevelopment = config.app.nodeEnv === 'development';
  
  res.status(error.status || 500).json({
    error: error.message || 'Internal Server Error',
    code: error.code || 'INTERNAL_ERROR',
    ...(isDevelopment && { stack: error.stack }),
    requestId: req.requestId,
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't crash the process in production
  if (config.app.nodeEnv !== 'production') {
    process.exit(1);
  }
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

const PORT = config.app.port;
const server = app.listen(PORT, () => {
  console.log(`
🚀 Secure Digital Locker Server Started
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Environment: ${config.app.nodeEnv}
Port: ${PORT}
Project: ${config.gcp.projectId}
Bucket: ${config.storage.bucketName}

📊 Endpoints:
• Health: http://localhost:${PORT}/health
• Auth: http://localhost:${PORT}/api/auth
• Documents: http://localhost:${PORT}/api/documents
• Admin: http://localhost:${PORT}/api/admin

🔒 Security Features:
• Firebase Authentication
• Role-based Access Control
• Cloud KMS Encryption
• Audit Logging
• Rate Limiting

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
});

module.exports = app;