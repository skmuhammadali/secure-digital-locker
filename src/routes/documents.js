const express = require('express');
const multer = require('multer');
const documentService = require('../services/documentService');
const auditService = require('../services/auditService');
const config = require('../config/config');
const { 
  authenticate, 
  requireHROrAdmin, 
  requireEmployeeAccess,
  rateLimit,
  validateRequest,
} = require('../middleware/auth');
const {
  upload: uploadValidator,
  list: listValidator,
  documentId: documentIdValidator,
  share: shareValidator,
  signedUrl: signedUrlValidator,
  delete: deleteValidator,
  statistics: statisticsValidator,
  fileMetadata: fileMetadataValidator,
  validateFileType,
  validateMimeType,
} = require('../validators/documentValidators');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.storage.maxFileSize,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    // Basic file validation
    const { error } = fileMetadataValidator.validate(file);
    if (error) {
      return cb(new Error(`File validation failed: ${error.details[0].message}`), false);
    }

    // MIME type validation
    if (!validateMimeType(file)) {
      return cb(new Error('File extension does not match MIME type'), false);
    }

    cb(null, true);
  },
});

// Apply authentication to all routes
router.use(authenticate);

/**
 * POST /api/documents/upload
 * Upload a new document
 * Requires: HR or Admin role
 */
router.post('/upload',
  requireHROrAdmin,
  rateLimit({ maxRequests: 20, windowMs: 60 * 1000 }), // 20 uploads per minute
  upload.single('document'),
  validateRequest(uploadValidator, 'body'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'No file uploaded',
          code: 'NO_FILE',
        });
      }

      // Additional file type validation based on document type
      if (!validateFileType(req.file, req.body.documentType)) {
        return res.status(400).json({
          error: 'File type not allowed for this document type',
          code: 'INVALID_FILE_TYPE',
        });
      }

      const metadata = {
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        documentType: req.body.documentType,
        employeeId: req.body.employeeId,
        description: req.body.description,
        tags: req.body.tags,
        viewers: req.body.viewers,
        editors: req.body.editors,
      };

      const result = await documentService.uploadDocument(
        req.file.buffer,
        metadata,
        req.user,
        req.requestContext
      );

      res.status(201).json({
        success: true,
        message: 'Document uploaded successfully',
        data: result,
      });

    } catch (error) {
      console.error('Document upload error:', error);
      res.status(500).json({
        error: 'Failed to upload document',
        code: 'UPLOAD_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/documents
 * List documents based on user role and filters
 */
router.get('/',
  validateRequest(listValidator, 'query'),
  async (req, res) => {
    try {
      const filters = {
        documentType: req.query.documentType,
        employeeId: req.query.employeeId,
        uploadedAfter: req.query.uploadedAfter ? new Date(req.query.uploadedAfter) : null,
        uploadedBefore: req.query.uploadedBefore ? new Date(req.query.uploadedBefore) : null,
      };

      const pagination = {
        limit: req.query.limit,
        startAfter: req.query.startAfter,
      };

      const result = await documentService.listDocuments(req.user, filters, pagination);

      res.json({
        success: true,
        data: result,
      });

    } catch (error) {
      console.error('Document listing error:', error);
      res.status(500).json({
        error: 'Failed to list documents',
        code: 'LIST_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/documents/:documentId
 * Download a specific document
 * Requires: Access permissions based on role and document ownership
 */
router.get('/:documentId',
  validateRequest(documentIdValidator, 'params'),
  rateLimit({ maxRequests: 50, windowMs: 60 * 1000 }), // 50 downloads per minute
  async (req, res) => {
    try {
      const result = await documentService.downloadDocument(
        req.params.documentId,
        req.user,
        req.requestContext
      );

      // Set appropriate headers for file download
      res.set({
        'Content-Type': result.metadata.mimeType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${result.metadata.originalName}"`,
        'Content-Length': result.data.length,
        'X-Document-Type': result.metadata.documentType,
        'X-Upload-Date': result.metadata.uploadedAt,
      });

      res.send(result.data);

    } catch (error) {
      console.error('Document download error:', error);
      
      if (error.message === 'Document not found') {
        return res.status(404).json({
          error: 'Document not found',
          code: 'NOT_FOUND',
        });
      }

      if (error.message === 'Access denied') {
        return res.status(403).json({
          error: 'Access denied',
          code: 'FORBIDDEN',
        });
      }

      res.status(500).json({
        error: 'Failed to download document',
        code: 'DOWNLOAD_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * DELETE /api/documents/:documentId
 * Delete a document
 * Requires: HR or Admin role
 */
router.delete('/:documentId',
  validateRequest(documentIdValidator, 'params'),
  validateRequest(deleteValidator, 'body'),
  requireHROrAdmin,
  rateLimit({ maxRequests: 10, windowMs: 60 * 1000 }), // 10 deletions per minute
  async (req, res) => {
    try {
      const requestInfo = {
        ...req.requestContext,
        reason: req.body.reason,
        permanentDelete: req.body.permanentDelete,
      };

      const result = await documentService.deleteDocument(
        req.params.documentId,
        req.user,
        requestInfo
      );

      res.json({
        success: true,
        message: 'Document deleted successfully',
        data: result,
      });

    } catch (error) {
      console.error('Document deletion error:', error);
      
      if (error.message === 'Document not found') {
        return res.status(404).json({
          error: 'Document not found',
          code: 'NOT_FOUND',
        });
      }

      if (error.message.includes('Insufficient permissions')) {
        return res.status(403).json({
          error: 'Insufficient permissions to delete document',
          code: 'FORBIDDEN',
        });
      }

      res.status(500).json({
        error: 'Failed to delete document',
        code: 'DELETE_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/documents/:documentId/share
 * Share a document with other users
 * Requires: Document owner, HR, or Admin
 */
router.post('/:documentId/share',
  validateRequest(documentIdValidator, 'params'),
  validateRequest(shareValidator, 'body'),
  async (req, res) => {
    try {
      const result = await documentService.shareDocument(
        req.params.documentId,
        req.body.shareWith,
        req.user
      );

      res.json({
        success: true,
        message: 'Document shared successfully',
        data: result,
      });

    } catch (error) {
      console.error('Document sharing error:', error);
      
      if (error.message === 'Document not found') {
        return res.status(404).json({
          error: 'Document not found',
          code: 'NOT_FOUND',
        });
      }

      if (error.message.includes('Insufficient permissions')) {
        return res.status(403).json({
          error: 'Insufficient permissions to share document',
          code: 'FORBIDDEN',
        });
      }

      res.status(500).json({
        error: 'Failed to share document',
        code: 'SHARE_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/documents/:documentId/signed-url
 * Generate signed URL for temporary access
 * Requires: Document access permissions
 */
router.post('/:documentId/signed-url',
  validateRequest(documentIdValidator, 'params'),
  validateRequest(signedUrlValidator, 'body'),
  rateLimit({ maxRequests: 30, windowMs: 60 * 1000 }), // 30 URL generations per minute
  async (req, res) => {
    try {
      const options = {
        action: req.body.action,
        expirationMinutes: req.body.expirationMinutes,
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
      };

      const result = await documentService.generateSignedUrl(
        req.params.documentId,
        req.user,
        options
      );

      res.json({
        success: true,
        message: 'Signed URL generated successfully',
        data: result,
      });

    } catch (error) {
      console.error('Signed URL generation error:', error);
      
      if (error.message === 'Document not found') {
        return res.status(404).json({
          error: 'Document not found',
          code: 'NOT_FOUND',
        });
      }

      if (error.message === 'Access denied') {
        return res.status(403).json({
          error: 'Access denied',
          code: 'FORBIDDEN',
        });
      }

      res.status(500).json({
        error: 'Failed to generate signed URL',
        code: 'SIGNED_URL_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/documents/statistics
 * Get document statistics
 * Requires: HR or Admin for all stats, Employee for own stats
 */
router.get('/statistics',
  validateRequest(statisticsValidator, 'query'),
  requireEmployeeAccess,
  async (req, res) => {
    try {
      const filters = {
        startDate: req.query.startDate ? new Date(req.query.startDate) : null,
        endDate: req.query.endDate ? new Date(req.query.endDate) : null,
        employeeId: req.query.employeeId,
        documentType: req.query.documentType,
        groupBy: req.query.groupBy,
      };

      const result = await documentService.getDocumentStatistics(req.user, filters);

      res.json({
        success: true,
        data: result,
      });

    } catch (error) {
      console.error('Document statistics error:', error);
      res.status(500).json({
        error: 'Failed to get document statistics',
        code: 'STATISTICS_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/documents/:documentId/metadata
 * Get document metadata without downloading the file
 */
router.get('/:documentId/metadata',
  validateRequest(documentIdValidator, 'params'),
  async (req, res) => {
    try {
      // This would need to be implemented in documentService
      // For now, we'll return a placeholder response
      res.json({
        success: true,
        message: 'Document metadata retrieved successfully',
        data: {
          id: req.params.documentId,
          message: 'Metadata endpoint to be implemented',
        },
      });

    } catch (error) {
      console.error('Document metadata error:', error);
      res.status(500).json({
        error: 'Failed to get document metadata',
        code: 'METADATA_FAILED',
        message: error.message,
      });
    }
  }
);

// Error handling middleware for multer
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        return res.status(400).json({
          error: 'File too large',
          code: 'FILE_TOO_LARGE',
          maxSize: config.storage.maxFileSize,
        });
      case 'LIMIT_FILE_COUNT':
        return res.status(400).json({
          error: 'Too many files',
          code: 'TOO_MANY_FILES',
        });
      case 'LIMIT_UNEXPECTED_FILE':
        return res.status(400).json({
          error: 'Unexpected file field',
          code: 'UNEXPECTED_FILE',
        });
      default:
        return res.status(400).json({
          error: 'File upload error',
          code: 'UPLOAD_ERROR',
          message: error.message,
        });
    }
  }

  if (error.message && error.message.includes('File validation failed')) {
    return res.status(400).json({
      error: 'File validation failed',
      code: 'FILE_VALIDATION_ERROR',
      message: error.message,
    });
  }

  next(error);
});

module.exports = router;