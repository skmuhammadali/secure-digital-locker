const express = require('express');
const firebaseService = require('../services/firebaseService');
const auditService = require('../services/auditService');
const config = require('../config/config');
const { 
  authenticate, 
  requireAdmin,
  requireHROrAdmin,
  rateLimit,
  validateRequest,
} = require('../middleware/auth');
const Joi = require('joi');

const router = express.Router();

// Apply authentication and admin requirement to all routes
router.use(authenticate);
router.use(requireAdmin);

// Validation schemas
const updateRoleSchema = Joi.object({
  role: Joi.string().valid(...Object.values(config.roles)).required().messages({
    'any.only': 'Role must be one of: admin, hr, employee',
    'any.required': 'Role is required',
  }),
  reason: Joi.string().max(200).optional().allow('').messages({
    'string.max': 'Reason must not exceed 200 characters',
  }),
});

const auditFiltersSchema = Joi.object({
  userId: Joi.string().guid({ version: 'uuidv4' }).optional(),
  eventType: Joi.string().valid(...Object.values(config.auditEvents)).optional(),
  startDate: Joi.date().iso().optional(),
  endDate: Joi.date().iso().greater(Joi.ref('startDate')).optional(),
  resourceId: Joi.string().optional(),
  success: Joi.boolean().optional(),
  limit: Joi.number().integer().min(1).max(100).optional().default(50),
  startAfter: Joi.string().optional(),
});

const userFiltersSchema = Joi.object({
  role: Joi.string().valid(...Object.values(config.roles)).optional(),
  isActive: Joi.boolean().optional(),
  limit: Joi.number().integer().min(1).max(100).optional().default(50),
  employeeId: Joi.string().alphanum().optional(),
});

/**
 * GET /api/admin/users
 * Get all users with filtering
 */
router.get('/users',
  validateRequest(userFiltersSchema, 'query'),
  async (req, res) => {
    try {
      const allUsers = await firebaseService.getAllUsers();
      
      // Apply filters
      let filteredUsers = allUsers;
      
      if (req.query.role) {
        filteredUsers = filteredUsers.filter(user => user.role === req.query.role);
      }
      
      if (req.query.isActive !== undefined) {
        filteredUsers = filteredUsers.filter(user => user.isActive === req.query.isActive);
      }
      
      if (req.query.employeeId) {
        filteredUsers = filteredUsers.filter(user => user.employeeId === req.query.employeeId);
      }

      // Apply pagination
      const limit = req.query.limit;
      const startIndex = req.query.startAfter ? 
        filteredUsers.findIndex(user => user.id === req.query.startAfter) + 1 : 0;
      
      const paginatedUsers = filteredUsers.slice(startIndex, startIndex + limit);

      // Remove sensitive information
      const safeUsers = paginatedUsers.map(user => ({
        id: user.uid,
        email: user.email,
        displayName: user.displayName,
        role: user.role,
        employeeId: user.employeeId,
        isActive: user.isActive,
        createdAt: user.createdAt?.toDate(),
        lastLogin: user.lastLogin?.toDate(),
        emailVerified: user.emailVerified,
      }));

      res.json({
        success: true,
        data: {
          users: safeUsers,
          pagination: {
            hasMore: startIndex + limit < filteredUsers.length,
            total: filteredUsers.length,
            returned: safeUsers.length,
          },
        },
      });

    } catch (error) {
      console.error('Users retrieval error:', error);
      res.status(500).json({
        error: 'Failed to retrieve users',
        code: 'USERS_RETRIEVAL_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * PUT /api/admin/users/:userId/role
 * Update user role
 */
router.put('/users/:userId/role',
  rateLimit({ maxRequests: 20, windowMs: 60 * 1000 }), // 20 role changes per minute
  validateRequest(updateRoleSchema, 'body'),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { role, reason } = req.body;

      // Get current user data
      const userData = await firebaseService.getUserData(userId);
      const oldRole = userData.role;

      // Update role
      await firebaseService.updateUserRole(userId, role);

      // Log role change
      await auditService.logRoleChange({
        performedBy: req.user.uid,
        performedByEmail: req.user.email,
        performedByRole: req.user.role,
        targetUserId: userId,
        targetUserEmail: userData.email,
        oldRole,
        newRole: role,
        reason: reason || 'Admin role change',
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: true,
      });

      res.json({
        success: true,
        message: 'User role updated successfully',
        data: {
          userId,
          oldRole,
          newRole: role,
          updatedBy: req.user.email,
          updatedAt: new Date().toISOString(),
        },
      });

    } catch (error) {
      console.error('Role update error:', error);
      
      // Log failed role change
      await auditService.logRoleChange({
        performedBy: req.user.uid,
        performedByEmail: req.user.email,
        performedByRole: req.user.role,
        targetUserId: req.params.userId,
        newRole: req.body.role,
        reason: req.body.reason || 'Admin role change',
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: false,
        errorMessage: error.message,
      });

      if (error.message === 'User not found') {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND',
        });
      }

      res.status(500).json({
        error: 'Failed to update user role',
        code: 'ROLE_UPDATE_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * PUT /api/admin/users/:userId/status
 * Enable/disable user account
 */
router.put('/users/:userId/status',
  rateLimit({ maxRequests: 10, windowMs: 60 * 1000 }), // 10 status changes per minute
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { isActive, reason } = req.body;

      if (typeof isActive !== 'boolean') {
        return res.status(400).json({
          error: 'isActive must be a boolean value',
          code: 'INVALID_STATUS',
        });
      }

      if (!isActive) {
        // Disable user
        await firebaseService.disableUser(userId);
      } else {
        // Enable user (update Firestore only, Firebase Auth enable would need custom logic)
        await firebaseService.firestore
          .collection(config.firestore.collections.users)
          .doc(userId)
          .update({
            isActive: true,
            enabledAt: admin.firestore.FieldValue.serverTimestamp(),
          });
      }

      // Log status change
      await auditService.logEvent({
        eventType: config.auditEvents.ROLE_CHANGE,
        userId: req.user.uid,
        userEmail: req.user.email,
        userRole: req.user.role,
        employeeId: req.user.employeeId,
        resource: {
          type: 'user',
          id: userId,
        },
        metadata: {
          action: isActive ? 'enable_user' : 'disable_user',
          reason: reason || 'Admin status change',
        },
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: true,
      });

      res.json({
        success: true,
        message: `User ${isActive ? 'enabled' : 'disabled'} successfully`,
        data: {
          userId,
          isActive,
          updatedBy: req.user.email,
          updatedAt: new Date().toISOString(),
        },
      });

    } catch (error) {
      console.error('Status update error:', error);
      res.status(500).json({
        error: 'Failed to update user status',
        code: 'STATUS_UPDATE_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/admin/audit-logs
 * Get audit logs with filtering
 */
router.get('/audit-logs',
  validateRequest(auditFiltersSchema, 'query'),
  async (req, res) => {
    try {
      const filters = {
        userId: req.query.userId,
        eventType: req.query.eventType,
        startDate: req.query.startDate,
        endDate: req.query.endDate,
        resourceId: req.query.resourceId,
        success: req.query.success,
      };

      const pagination = {
        limit: req.query.limit,
        startAfter: req.query.startAfter,
      };

      const result = await auditService.getAuditLogs(filters, pagination);

      res.json({
        success: true,
        data: result,
      });

    } catch (error) {
      console.error('Audit logs retrieval error:', error);
      res.status(500).json({
        error: 'Failed to retrieve audit logs',
        code: 'AUDIT_LOGS_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/admin/audit-statistics
 * Get audit statistics
 */
router.get('/audit-statistics',
  async (req, res) => {
    try {
      const filters = {
        startDate: req.query.startDate,
        endDate: req.query.endDate,
      };

      const statistics = await auditService.getAuditStatistics(filters);

      res.json({
        success: true,
        data: statistics,
      });

    } catch (error) {
      console.error('Audit statistics error:', error);
      res.status(500).json({
        error: 'Failed to retrieve audit statistics',
        code: 'AUDIT_STATISTICS_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/admin/audit-export
 * Export audit logs for compliance
 */
router.post('/audit-export',
  rateLimit({ maxRequests: 5, windowMs: 60 * 1000 }), // 5 exports per minute
  async (req, res) => {
    try {
      const { format = 'json', filters = {} } = req.body;

      if (!['json', 'csv'].includes(format)) {
        return res.status(400).json({
          error: 'Format must be json or csv',
          code: 'INVALID_FORMAT',
        });
      }

      const exportData = await auditService.exportAuditLogs(filters, format);

      // Set appropriate headers for download
      const timestamp = new Date().toISOString().split('T')[0];
      const filename = `audit-logs-${timestamp}.${format}`;
      
      res.set({
        'Content-Type': format === 'csv' ? 'text/csv' : 'application/json',
        'Content-Disposition': `attachment; filename="${filename}"`,
      });

      res.send(exportData);

    } catch (error) {
      console.error('Audit export error:', error);
      res.status(500).json({
        error: 'Failed to export audit logs',
        code: 'AUDIT_EXPORT_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/admin/system-info
 * Get system information and health
 */
router.get('/system-info',
  async (req, res) => {
    try {
      const systemInfo = {
        version: process.env.npm_package_version || '1.0.0',
        environment: config.app.nodeEnv,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        gcpProject: config.gcp.projectId,
        storageBucket: config.storage.bucketName,
        nodeVersion: process.version,
        timestamp: new Date().toISOString(),
      };

      res.json({
        success: true,
        data: systemInfo,
      });

    } catch (error) {
      console.error('System info error:', error);
      res.status(500).json({
        error: 'Failed to retrieve system information',
        code: 'SYSTEM_INFO_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/admin/cleanup-logs
 * Clean up old audit logs (Admin only, careful operation)
 */
router.post('/cleanup-logs',
  rateLimit({ maxRequests: 1, windowMs: 60 * 60 * 1000 }), // 1 cleanup per hour
  async (req, res) => {
    try {
      const { retentionDays = 2555 } = req.body; // Default 7 years

      if (retentionDays < 365) {
        return res.status(400).json({
          error: 'Retention period must be at least 365 days for compliance',
          code: 'INVALID_RETENTION',
        });
      }

      const deletedCount = await auditService.cleanupOldLogs(retentionDays);

      // Log the cleanup operation
      await auditService.logEvent({
        eventType: config.auditEvents.ROLE_CHANGE,
        userId: req.user.uid,
        userEmail: req.user.email,
        userRole: req.user.role,
        employeeId: req.user.employeeId,
        metadata: {
          action: 'cleanup_audit_logs',
          retentionDays,
          deletedCount,
        },
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: true,
      });

      res.json({
        success: true,
        message: 'Audit logs cleanup completed',
        data: {
          deletedCount,
          retentionDays,
          performedBy: req.user.email,
          timestamp: new Date().toISOString(),
        },
      });

    } catch (error) {
      console.error('Cleanup logs error:', error);
      res.status(500).json({
        error: 'Failed to cleanup audit logs',
        code: 'CLEANUP_FAILED',
        message: error.message,
      });
    }
  }
);

module.exports = router;