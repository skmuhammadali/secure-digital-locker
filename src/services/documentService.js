const admin = require('firebase-admin');
const config = require('../config/config');
const storageService = require('./storageService');
const auditService = require('./auditService');
const firebaseService = require('./firebaseService');
const { v4: uuidv4 } = require('uuid');

class DocumentService {
  constructor() {
    this.firestore = admin.firestore();
    this.documentsCollection = this.firestore.collection(config.firestore.collections.documents);
  }

  /**
   * Upload a new document
   * @param {Buffer} fileBuffer - File data
   * @param {Object} metadata - Document metadata
   * @param {Object} userInfo - User information
   * @param {Object} requestInfo - Request context (IP, user agent, etc.)
   * @returns {Promise<Object>} Upload result
   */
  async uploadDocument(fileBuffer, metadata, userInfo, requestInfo = {}) {
    const startTime = Date.now();
    
    try {
      // Validate user permissions
      if (!this.canUploadDocument(userInfo, metadata)) {
        await auditService.logAccessDenied({
          userId: userInfo.uid,
          userEmail: userInfo.email,
          userRole: userInfo.role,
          employeeId: userInfo.employeeId,
          resource: {
            type: 'document',
            action: 'upload',
          },
          attemptedAction: 'upload_document',
          reason: 'insufficient_permissions',
          requiredRole: [config.roles.HR, config.roles.ADMIN],
          ipAddress: requestInfo.ipAddress,
          userAgent: requestInfo.userAgent,
        });
        throw new Error('Insufficient permissions to upload document');
      }

      // Upload to storage
      const uploadResult = await storageService.uploadDocument(fileBuffer, metadata, userInfo);
      
      // Store document metadata in Firestore
      const documentMetadata = {
        ...uploadResult.metadata,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        accessCount: 0,
        lastAccessed: null,
        sharedWith: [],
        permissions: {
          owner: userInfo.uid,
          viewers: metadata.viewers || [],
          editors: metadata.editors || [],
        },
      };

      await this.documentsCollection.doc(uploadResult.documentId).set(documentMetadata);

      // Log audit event
      await auditService.logDocumentUpload({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: uploadResult.documentId,
        documentName: metadata.originalName,
        documentType: metadata.documentType,
        documentEmployeeId: metadata.employeeId || userInfo.employeeId,
        fileName: uploadResult.fileName,
        fileSize: fileBuffer.length,
        mimeType: metadata.mimeType,
        encryptionAlgorithm: 'aes-256-gcm',
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: true,
        duration: Date.now() - startTime,
      });

      return {
        success: true,
        documentId: uploadResult.documentId,
        message: 'Document uploaded successfully',
        metadata: {
          id: uploadResult.documentId,
          name: metadata.originalName,
          type: metadata.documentType,
          size: fileBuffer.length,
          uploadedAt: new Date().toISOString(),
        },
      };

    } catch (error) {
      // Log failed upload
      await auditService.logDocumentUpload({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentName: metadata.originalName,
        documentType: metadata.documentType,
        fileName: metadata.originalName,
        fileSize: fileBuffer.length,
        mimeType: metadata.mimeType,
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: false,
        errorMessage: error.message,
        duration: Date.now() - startTime,
      });

      throw error;
    }
  }

  /**
   * Download a document
   * @param {string} documentId - Document ID
   * @param {Object} userInfo - User information
   * @param {Object} requestInfo - Request context
   * @returns {Promise<Object>} Document data and metadata
   */
  async downloadDocument(documentId, userInfo, requestInfo = {}) {
    const startTime = Date.now();
    
    try {
      // Get document metadata from Firestore
      const docRef = this.documentsCollection.doc(documentId);
      const docSnapshot = await docRef.get();

      if (!docSnapshot.exists) {
        throw new Error('Document not found');
      }

      const documentMetadata = docSnapshot.data();

      // Check access permissions
      if (!this.canAccessDocument(userInfo, documentMetadata)) {
        await auditService.logAccessDenied({
          userId: userInfo.uid,
          userEmail: userInfo.email,
          userRole: userInfo.role,
          employeeId: userInfo.employeeId,
          resource: {
            type: 'document',
            id: documentId,
            name: documentMetadata.originalName,
            employeeId: documentMetadata.employeeId,
          },
          attemptedAction: 'download_document',
          reason: 'access_denied',
          ipAddress: requestInfo.ipAddress,
          userAgent: requestInfo.userAgent,
        });
        throw new Error('Access denied');
      }

      // Download from storage
      const downloadResult = await storageService.downloadDocument(documentMetadata.fileName, userInfo);

      // Update access statistics
      await docRef.update({
        accessCount: admin.firestore.FieldValue.increment(1),
        lastAccessed: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // Log audit event
      await auditService.logDocumentDownload({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: documentId,
        documentName: documentMetadata.originalName,
        documentEmployeeId: documentMetadata.employeeId,
        downloadSize: downloadResult.data.length,
        accessMethod: 'direct',
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: true,
        duration: Date.now() - startTime,
      });

      return {
        data: downloadResult.data,
        metadata: {
          id: documentId,
          originalName: documentMetadata.originalName,
          mimeType: documentMetadata.mimeType,
          size: downloadResult.data.length,
          documentType: documentMetadata.documentType,
          uploadedAt: documentMetadata.uploadedAt,
          lastModified: documentMetadata.updatedAt,
        },
      };

    } catch (error) {
      // Log failed download
      await auditService.logDocumentDownload({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: documentId,
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: false,
        errorMessage: error.message,
        duration: Date.now() - startTime,
      });

      throw error;
    }
  }

  /**
   * Delete a document
   * @param {string} documentId - Document ID
   * @param {Object} userInfo - User information
   * @param {Object} requestInfo - Request context
   * @returns {Promise<Object>} Deletion result
   */
  async deleteDocument(documentId, userInfo, requestInfo = {}) {
    const startTime = Date.now();
    
    try {
      // Get document metadata
      const docRef = this.documentsCollection.doc(documentId);
      const docSnapshot = await docRef.get();

      if (!docSnapshot.exists) {
        throw new Error('Document not found');
      }

      const documentMetadata = docSnapshot.data();

      // Check delete permissions
      if (!this.canDeleteDocument(userInfo, documentMetadata)) {
        await auditService.logAccessDenied({
          userId: userInfo.uid,
          userEmail: userInfo.email,
          userRole: userInfo.role,
          employeeId: userInfo.employeeId,
          resource: {
            type: 'document',
            id: documentId,
            name: documentMetadata.originalName,
            employeeId: documentMetadata.employeeId,
          },
          attemptedAction: 'delete_document',
          reason: 'insufficient_permissions',
          requiredRole: [config.roles.ADMIN, config.roles.HR],
          ipAddress: requestInfo.ipAddress,
          userAgent: requestInfo.userAgent,
        });
        throw new Error('Insufficient permissions to delete document');
      }

      // Delete from storage
      await storageService.deleteDocument(documentMetadata.fileName, userInfo);

      // Mark as deleted in Firestore (soft delete for audit trail)
      await docRef.update({
        isActive: false,
        deletedAt: admin.firestore.FieldValue.serverTimestamp(),
        deletedBy: userInfo.uid,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // Log audit event
      await auditService.logDocumentDelete({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: documentId,
        documentName: documentMetadata.originalName,
        documentEmployeeId: documentMetadata.employeeId,
        reason: requestInfo.reason || 'user_request',
        permanentDeletion: true,
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: true,
        duration: Date.now() - startTime,
      });

      return {
        success: true,
        message: 'Document deleted successfully',
        documentId: documentId,
      };

    } catch (error) {
      // Log failed deletion
      await auditService.logDocumentDelete({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: documentId,
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        success: false,
        errorMessage: error.message,
        duration: Date.now() - startTime,
      });

      throw error;
    }
  }

  /**
   * List documents for a user
   * @param {Object} userInfo - User information
   * @param {Object} filters - Filter options
   * @param {Object} pagination - Pagination options
   * @returns {Promise<Object>} Document list and pagination info
   */
  async listDocuments(userInfo, filters = {}, pagination = {}) {
    try {
      let query = this.documentsCollection.where('isActive', '==', true);

      // Apply role-based filtering
      if (userInfo.role === config.roles.EMPLOYEE) {
        // Employees can only see their own documents
        query = query.where('employeeId', '==', userInfo.employeeId);
      } else if (userInfo.role === config.roles.HR) {
        // HR can see all employee documents (no additional filter needed)
      } else if (userInfo.role === config.roles.ADMIN) {
        // Admin can see all documents (no additional filter needed)
      }

      // Apply additional filters
      if (filters.documentType) {
        query = query.where('documentType', '==', filters.documentType);
      }

      if (filters.employeeId && userInfo.role !== config.roles.EMPLOYEE) {
        query = query.where('employeeId', '==', filters.employeeId);
      }

      if (filters.uploadedAfter) {
        query = query.where('uploadedAt', '>=', filters.uploadedAfter);
      }

      // Apply ordering
      query = query.orderBy('uploadedAt', 'desc');

      // Apply pagination
      const limit = Math.min(pagination.limit || 20, 100); // Max 100 items
      query = query.limit(limit);

      if (pagination.startAfter) {
        const startAfterDoc = await this.documentsCollection.doc(pagination.startAfter).get();
        query = query.startAfter(startAfterDoc);
      }

      const snapshot = await query.get();
      const documents = [];

      snapshot.forEach(doc => {
        const data = doc.data();
        documents.push({
          id: doc.id,
          name: data.originalName,
          type: data.documentType,
          size: data.size,
          mimeType: data.mimeType,
          employeeId: data.employeeId,
          uploadedAt: data.uploadedAt?.toDate(),
          lastAccessed: data.lastAccessed?.toDate(),
          accessCount: data.accessCount || 0,
          tags: data.tags || [],
          description: data.description || '',
        });
      });

      return {
        documents,
        pagination: {
          hasMore: documents.length === limit,
          lastDocId: documents.length > 0 ? documents[documents.length - 1].id : null,
        },
        total: documents.length,
      };

    } catch (error) {
      console.error('Error listing documents:', error);
      throw error;
    }
  }

  /**
   * Generate signed URL for document access
   * @param {string} documentId - Document ID
   * @param {Object} userInfo - User information
   * @param {Object} options - URL options
   * @returns {Promise<Object>} Signed URL and metadata
   */
  async generateSignedUrl(documentId, userInfo, options = {}) {
    try {
      // Get document metadata
      const docSnapshot = await this.documentsCollection.doc(documentId).get();
      
      if (!docSnapshot.exists) {
        throw new Error('Document not found');
      }

      const documentMetadata = docSnapshot.data();

      // Check access permissions
      if (!this.canAccessDocument(userInfo, documentMetadata)) {
        throw new Error('Access denied');
      }

      // Generate signed URL
      const signedUrl = await storageService.generateSignedUrl(documentMetadata.fileName, {
        action: options.action || 'read',
        expirationMinutes: options.expirationMinutes || 15,
      });

      // Log access (for signed URL generation)
      await auditService.logDocumentDownload({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        documentId: documentId,
        documentName: documentMetadata.originalName,
        documentEmployeeId: documentMetadata.employeeId,
        accessMethod: 'signed-url',
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        success: true,
      });

      return {
        signedUrl,
        expiresAt: new Date(Date.now() + (options.expirationMinutes || 15) * 60 * 1000),
        documentName: documentMetadata.originalName,
        documentType: documentMetadata.documentType,
      };

    } catch (error) {
      console.error('Error generating signed URL:', error);
      throw error;
    }
  }

  /**
   * Share document with other users
   * @param {string} documentId - Document ID
   * @param {Array} shareWith - List of user IDs to share with
   * @param {Object} userInfo - User information
   * @returns {Promise<Object>} Share result
   */
  async shareDocument(documentId, shareWith, userInfo) {
    try {
      const docRef = this.documentsCollection.doc(documentId);
      const docSnapshot = await docRef.get();

      if (!docSnapshot.exists) {
        throw new Error('Document not found');
      }

      const documentMetadata = docSnapshot.data();

      // Check if user can share (owner, HR, or admin)
      if (!this.canShareDocument(userInfo, documentMetadata)) {
        throw new Error('Insufficient permissions to share document');
      }

      // Update shared users list
      await docRef.update({
        sharedWith: admin.firestore.FieldValue.arrayUnion(...shareWith),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return {
        success: true,
        message: 'Document shared successfully',
        sharedWith: shareWith,
      };

    } catch (error) {
      console.error('Error sharing document:', error);
      throw error;
    }
  }

  /**
   * Get document statistics
   * @param {Object} userInfo - User information
   * @param {Object} filters - Filter options
   * @returns {Promise<Object>} Document statistics
   */
  async getDocumentStatistics(userInfo, filters = {}) {
    try {
      let query = this.documentsCollection.where('isActive', '==', true);

      // Apply role-based filtering
      if (userInfo.role === config.roles.EMPLOYEE) {
        query = query.where('employeeId', '==', userInfo.employeeId);
      }

      const snapshot = await query.get();
      const stats = {
        totalDocuments: 0,
        documentTypes: {},
        totalSize: 0,
        recentUploads: 0,
        accessCounts: 0,
      };

      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      snapshot.forEach(doc => {
        const data = doc.data();
        stats.totalDocuments++;
        stats.totalSize += data.size || 0;
        stats.accessCounts += data.accessCount || 0;

        // Count by document type
        stats.documentTypes[data.documentType] = (stats.documentTypes[data.documentType] || 0) + 1;

        // Count recent uploads
        if (data.uploadedAt && data.uploadedAt.toDate() > thirtyDaysAgo) {
          stats.recentUploads++;
        }
      });

      return stats;
    } catch (error) {
      console.error('Error getting document statistics:', error);
      throw error;
    }
  }

  /**
   * Check if user can upload documents
   * @param {Object} userInfo - User information
   * @param {Object} metadata - Document metadata
   * @returns {boolean} True if user can upload
   */
  canUploadDocument(userInfo, metadata) {
    // Only HR and Admin can upload documents
    // Employees cannot upload their own documents (HR uploads for them)
    return firebaseService.hasRole(userInfo, [config.roles.HR, config.roles.ADMIN]);
  }

  /**
   * Check if user can access document
   * @param {Object} userInfo - User information
   * @param {Object} documentMetadata - Document metadata
   * @returns {boolean} True if user can access
   */
  canAccessDocument(userInfo, documentMetadata) {
    return firebaseService.canAccessDocument(userInfo, documentMetadata) || 
           documentMetadata.sharedWith?.includes(userInfo.uid);
  }

  /**
   * Check if user can delete document
   * @param {Object} userInfo - User information
   * @param {Object} documentMetadata - Document metadata
   * @returns {boolean} True if user can delete
   */
  canDeleteDocument(userInfo, documentMetadata) {
    // Only Admin and HR can delete documents
    return firebaseService.hasRole(userInfo, [config.roles.ADMIN, config.roles.HR]);
  }

  /**
   * Check if user can share document
   * @param {Object} userInfo - User information
   * @param {Object} documentMetadata - Document metadata
   * @returns {boolean} True if user can share
   */
  canShareDocument(userInfo, documentMetadata) {
    return documentMetadata.ownerId === userInfo.uid || 
           firebaseService.hasRole(userInfo, [config.roles.ADMIN, config.roles.HR]);
  }
}

module.exports = new DocumentService();