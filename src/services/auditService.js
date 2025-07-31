const admin = require('firebase-admin');
const config = require('../config/config');
const { v4: uuidv4 } = require('uuid');

class AuditService {
  constructor() {
    this.firestore = admin.firestore();
    this.auditCollection = this.firestore.collection(config.firestore.collections.auditLogs);
  }

  /**
   * Log audit event
   * @param {Object} eventData - Audit event data
   * @param {string} eventData.eventType - Type of event (from config.auditEvents)
   * @param {string} eventData.userId - User ID performing the action
   * @param {string} eventData.userEmail - User email
   * @param {string} eventData.userRole - User role
   * @param {Object} eventData.resource - Resource being accessed/modified
   * @param {Object} eventData.metadata - Additional metadata
   * @param {string} eventData.ipAddress - Client IP address
   * @param {string} eventData.userAgent - Client user agent
   * @param {boolean} eventData.success - Whether the action was successful
   * @param {string} eventData.errorMessage - Error message if action failed
   * @returns {Promise<string>} Audit log ID
   */
  async logEvent(eventData) {
    try {
      const auditLogId = uuidv4();
      const timestamp = admin.firestore.FieldValue.serverTimestamp();

      const auditLog = {
        id: auditLogId,
        eventType: eventData.eventType,
        timestamp,
        user: {
          uid: eventData.userId,
          email: eventData.userEmail,
          role: eventData.userRole,
          employeeId: eventData.employeeId,
        },
        resource: eventData.resource || null,
        action: {
          success: eventData.success !== false, // Default to true if not specified
          errorMessage: eventData.errorMessage || null,
          duration: eventData.duration || null,
        },
        context: {
          ipAddress: eventData.ipAddress,
          userAgent: eventData.userAgent,
          sessionId: eventData.sessionId,
          requestId: eventData.requestId,
        },
        metadata: eventData.metadata || {},
        compliance: {
          dataClassification: eventData.dataClassification || 'confidential',
          retentionPeriod: eventData.retentionPeriod || 2555, // 7 years in days
          gdprApplicable: eventData.gdprApplicable !== false,
        },
        system: {
          version: process.env.npm_package_version || '1.0.0',
          environment: config.app.nodeEnv,
          service: 'secure-digital-locker',
        },
      };

      await this.auditCollection.doc(auditLogId).set(auditLog);
      
      // For critical events, also log to Cloud Logging
      if (this.isCriticalEvent(eventData.eventType)) {
        console.log(`AUDIT: ${eventData.eventType}`, {
          userId: eventData.userId,
          resource: eventData.resource,
          success: eventData.success,
          timestamp: new Date().toISOString(),
        });
      }

      return auditLogId;
    } catch (error) {
      console.error('Error logging audit event:', error);
      // Don't throw error to avoid breaking the main operation
      return null;
    }
  }

  /**
   * Log document upload event
   * @param {Object} data - Upload event data
   * @returns {Promise<string>} Audit log ID
   */
  async logDocumentUpload(data) {
    return await this.logEvent({
      eventType: config.auditEvents.DOCUMENT_UPLOAD,
      userId: data.userId,
      userEmail: data.userEmail,
      userRole: data.userRole,
      employeeId: data.employeeId,
      resource: {
        type: 'document',
        id: data.documentId,
        name: data.documentName,
        type: data.documentType,
        size: data.fileSize,
        employeeId: data.documentEmployeeId,
      },
      metadata: {
        fileName: data.fileName,
        mimeType: data.mimeType,
        encrypted: true,
        encryptionAlgorithm: data.encryptionAlgorithm,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: data.success,
      errorMessage: data.errorMessage,
    });
  }

  /**
   * Log document download event
   * @param {Object} data - Download event data
   * @returns {Promise<string>} Audit log ID
   */
  async logDocumentDownload(data) {
    return await this.logEvent({
      eventType: config.auditEvents.DOCUMENT_DOWNLOAD,
      userId: data.userId,
      userEmail: data.userEmail,
      userRole: data.userRole,
      employeeId: data.employeeId,
      resource: {
        type: 'document',
        id: data.documentId,
        name: data.documentName,
        employeeId: data.documentEmployeeId,
      },
      metadata: {
        accessMethod: data.accessMethod || 'direct', // direct, signed-url, etc.
        downloadSize: data.downloadSize,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: data.success,
      errorMessage: data.errorMessage,
    });
  }

  /**
   * Log document deletion event
   * @param {Object} data - Deletion event data
   * @returns {Promise<string>} Audit log ID
   */
  async logDocumentDelete(data) {
    return await this.logEvent({
      eventType: config.auditEvents.DOCUMENT_DELETE,
      userId: data.userId,
      userEmail: data.userEmail,
      userRole: data.userRole,
      employeeId: data.employeeId,
      resource: {
        type: 'document',
        id: data.documentId,
        name: data.documentName,
        employeeId: data.documentEmployeeId,
      },
      metadata: {
        reason: data.reason || 'user_request',
        permanentDeletion: data.permanentDeletion || false,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: data.success,
      errorMessage: data.errorMessage,
      dataClassification: 'confidential',
    });
  }

  /**
   * Log user authentication event
   * @param {Object} data - Auth event data
   * @returns {Promise<string>} Audit log ID
   */
  async logUserLogin(data) {
    return await this.logEvent({
      eventType: config.auditEvents.USER_LOGIN,
      userId: data.userId,
      userEmail: data.userEmail,
      userRole: data.userRole,
      employeeId: data.employeeId,
      metadata: {
        loginMethod: data.loginMethod || 'firebase',
        mfaUsed: data.mfaUsed || false,
        deviceInfo: data.deviceInfo,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      sessionId: data.sessionId,
      success: data.success,
      errorMessage: data.errorMessage,
    });
  }

  /**
   * Log access denied event
   * @param {Object} data - Access denial event data
   * @returns {Promise<string>} Audit log ID
   */
  async logAccessDenied(data) {
    return await this.logEvent({
      eventType: config.auditEvents.ACCESS_DENIED,
      userId: data.userId,
      userEmail: data.userEmail,
      userRole: data.userRole,
      employeeId: data.employeeId,
      resource: data.resource,
      metadata: {
        attemptedAction: data.attemptedAction,
        reason: data.reason,
        requiredRole: data.requiredRole,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: false,
      errorMessage: data.errorMessage || 'Access denied due to insufficient permissions',
    });
  }

  /**
   * Log role change event
   * @param {Object} data - Role change event data
   * @returns {Promise<string>} Audit log ID
   */
  async logRoleChange(data) {
    return await this.logEvent({
      eventType: config.auditEvents.ROLE_CHANGE,
      userId: data.performedBy,
      userEmail: data.performedByEmail,
      userRole: data.performedByRole,
      resource: {
        type: 'user',
        id: data.targetUserId,
        email: data.targetUserEmail,
      },
      metadata: {
        oldRole: data.oldRole,
        newRole: data.newRole,
        reason: data.reason,
      },
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: data.success,
      errorMessage: data.errorMessage,
    });
  }

  /**
   * Get audit logs with filtering
   * @param {Object} filters - Filter criteria
   * @param {Object} pagination - Pagination options
   * @returns {Promise<Object>} Audit logs and pagination info
   */
  async getAuditLogs(filters = {}, pagination = {}) {
    try {
      let query = this.auditCollection;

      // Apply filters
      if (filters.userId) {
        query = query.where('user.uid', '==', filters.userId);
      }

      if (filters.eventType) {
        query = query.where('eventType', '==', filters.eventType);
      }

      if (filters.startDate) {
        query = query.where('timestamp', '>=', admin.firestore.Timestamp.fromDate(new Date(filters.startDate)));
      }

      if (filters.endDate) {
        query = query.where('timestamp', '<=', admin.firestore.Timestamp.fromDate(new Date(filters.endDate)));
      }

      if (filters.resourceId) {
        query = query.where('resource.id', '==', filters.resourceId);
      }

      if (filters.success !== undefined) {
        query = query.where('action.success', '==', filters.success);
      }

      // Apply ordering
      query = query.orderBy('timestamp', 'desc');

      // Apply pagination
      const limit = pagination.limit || 50;
      query = query.limit(limit);

      if (pagination.startAfter) {
        const startAfterDoc = await this.auditCollection.doc(pagination.startAfter).get();
        query = query.startAfter(startAfterDoc);
      }

      const snapshot = await query.get();
      const logs = [];

      snapshot.forEach(doc => {
        logs.push({
          id: doc.id,
          ...doc.data(),
          timestamp: doc.data().timestamp?.toDate(),
        });
      });

      return {
        logs,
        pagination: {
          hasMore: logs.length === limit,
          lastDocId: logs.length > 0 ? logs[logs.length - 1].id : null,
        },
      };
    } catch (error) {
      console.error('Error getting audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit statistics
   * @param {Object} filters - Filter criteria
   * @returns {Promise<Object>} Audit statistics
   */
  async getAuditStatistics(filters = {}) {
    try {
      let query = this.auditCollection;

      // Apply date filter if provided
      if (filters.startDate) {
        query = query.where('timestamp', '>=', admin.firestore.Timestamp.fromDate(new Date(filters.startDate)));
      }

      if (filters.endDate) {
        query = query.where('timestamp', '<=', admin.firestore.Timestamp.fromDate(new Date(filters.endDate)));
      }

      const snapshot = await query.get();
      const stats = {
        totalEvents: 0,
        eventTypes: {},
        userActivity: {},
        failedEvents: 0,
        successfulEvents: 0,
        resourceAccess: {},
      };

      snapshot.forEach(doc => {
        const data = doc.data();
        stats.totalEvents++;

        // Count by event type
        stats.eventTypes[data.eventType] = (stats.eventTypes[data.eventType] || 0) + 1;

        // Count by user
        stats.userActivity[data.user.email] = (stats.userActivity[data.user.email] || 0) + 1;

        // Count success/failure
        if (data.action.success) {
          stats.successfulEvents++;
        } else {
          stats.failedEvents++;
        }

        // Count resource access
        if (data.resource) {
          const resourceKey = `${data.resource.type}:${data.resource.id}`;
          stats.resourceAccess[resourceKey] = (stats.resourceAccess[resourceKey] || 0) + 1;
        }
      });

      return stats;
    } catch (error) {
      console.error('Error getting audit statistics:', error);
      throw error;
    }
  }

  /**
   * Export audit logs for compliance
   * @param {Object} filters - Filter criteria
   * @param {string} format - Export format (json, csv)
   * @returns {Promise<string>} Exported data
   */
  async exportAuditLogs(filters = {}, format = 'json') {
    try {
      const { logs } = await this.getAuditLogs(filters, { limit: 10000 });

      if (format === 'csv') {
        return this.convertToCSV(logs);
      }

      return JSON.stringify(logs, null, 2);
    } catch (error) {
      console.error('Error exporting audit logs:', error);
      throw error;
    }
  }

  /**
   * Convert audit logs to CSV format
   * @param {Array} logs - Audit logs
   * @returns {string} CSV formatted data
   */
  convertToCSV(logs) {
    if (logs.length === 0) return '';

    const headers = [
      'Timestamp',
      'Event Type',
      'User Email',
      'User Role',
      'Resource Type',
      'Resource ID',
      'Success',
      'IP Address',
      'Error Message',
    ];

    const rows = logs.map(log => [
      log.timestamp?.toISOString() || '',
      log.eventType || '',
      log.user?.email || '',
      log.user?.role || '',
      log.resource?.type || '',
      log.resource?.id || '',
      log.action?.success ? 'Yes' : 'No',
      log.context?.ipAddress || '',
      log.action?.errorMessage || '',
    ]);

    return [headers, ...rows].map(row => row.map(field => `"${field}"`).join(',')).join('\n');
  }

  /**
   * Check if event type is critical
   * @param {string} eventType - Event type
   * @returns {boolean} True if critical
   */
  isCriticalEvent(eventType) {
    const criticalEvents = [
      config.auditEvents.DOCUMENT_DELETE,
      config.auditEvents.ROLE_CHANGE,
      config.auditEvents.ACCESS_DENIED,
    ];
    return criticalEvents.includes(eventType);
  }

  /**
   * Clean up old audit logs based on retention policy
   * @param {number} retentionDays - Number of days to retain logs
   * @returns {Promise<number>} Number of logs deleted
   */
  async cleanupOldLogs(retentionDays = 2555) { // Default 7 years
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const query = this.auditCollection
        .where('timestamp', '<', admin.firestore.Timestamp.fromDate(cutoffDate))
        .limit(500); // Process in batches

      const snapshot = await query.get();
      
      if (snapshot.empty) {
        return 0;
      }

      const batch = this.firestore.batch();
      snapshot.docs.forEach(doc => {
        batch.delete(doc.ref);
      });

      await batch.commit();
      
      console.log(`Deleted ${snapshot.size} old audit logs`);
      return snapshot.size;
    } catch (error) {
      console.error('Error cleaning up old logs:', error);
      throw error;
    }
  }
}

module.exports = new AuditService();