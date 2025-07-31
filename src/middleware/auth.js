const firebaseService = require('../services/firebaseService');
const auditService = require('../services/auditService');
const config = require('../config/config');

/**
 * Extract client IP address from request
 * @param {Object} req - Express request object
 * @returns {string} Client IP address
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for'] ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         '127.0.0.1';
}

/**
 * Authentication middleware
 * Verifies Firebase ID token and attaches user info to request
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authorization header missing or invalid',
        code: 'UNAUTHORIZED',
      });
    }

    const idToken = authHeader.split('Bearer ')[1];
    
    if (!idToken) {
      return res.status(401).json({
        error: 'ID token missing',
        code: 'UNAUTHORIZED',
      });
    }

    // Verify the token
    const decodedToken = await firebaseService.verifyToken(idToken);
    
    // Get additional user data from Firestore
    const userData = await firebaseService.getUserData(decodedToken.uid);
    
    // Check if user account is active
    if (!userData.isActive) {
      await auditService.logAccessDenied({
        userId: decodedToken.uid,
        userEmail: decodedToken.email,
        userRole: decodedToken.role,
        employeeId: decodedToken.employeeId,
        resource: {
          type: 'system',
          action: 'access',
        },
        attemptedAction: 'system_access',
        reason: 'account_disabled',
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent'),
      });
      
      return res.status(403).json({
        error: 'Account is disabled',
        code: 'ACCOUNT_DISABLED',
      });
    }

    // Attach user info to request
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      name: decodedToken.name,
      role: decodedToken.role,
      employeeId: decodedToken.employeeId,
      emailVerified: decodedToken.emailVerified,
      lastLogin: userData.lastLogin,
      isActive: userData.isActive,
    };

    // Attach request context
    req.requestContext = {
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent'),
      requestId: req.headers['x-request-id'] || require('uuid').v4(),
      timestamp: new Date().toISOString(),
    };

    // Update last login time (async, don't wait)
    firebaseService.updateLastLogin(decodedToken.uid).catch(err => {
      console.error('Error updating last login:', err);
    });

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    // Log failed authentication attempt
    const ipAddress = getClientIP(req);
    auditService.logUserLogin({
      userEmail: 'unknown',
      ipAddress,
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
    }).catch(err => {
      console.error('Error logging failed auth:', err);
    });

    res.status(401).json({
      error: 'Authentication failed',
      code: 'AUTHENTICATION_FAILED',
      message: error.message,
    });
  }
};

/**
 * Role-based authorization middleware
 * @param {string|Array} requiredRoles - Required role(s)
 * @returns {Function} Express middleware function
 */
const requireRole = (requiredRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'User not authenticated',
          code: 'UNAUTHORIZED',
        });
      }

      const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
      
      if (!firebaseService.hasRole(req.user, roles)) {
        await auditService.logAccessDenied({
          userId: req.user.uid,
          userEmail: req.user.email,
          userRole: req.user.role,
          employeeId: req.user.employeeId,
          resource: {
            type: 'endpoint',
            path: req.path,
            method: req.method,
          },
          attemptedAction: `${req.method} ${req.path}`,
          reason: 'insufficient_role',
          requiredRole: roles,
          ipAddress: req.requestContext.ipAddress,
          userAgent: req.requestContext.userAgent,
        });

        return res.status(403).json({
          error: 'Insufficient permissions',
          code: 'FORBIDDEN',
          requiredRoles: roles,
          userRole: req.user.role,
        });
      }

      next();
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({
        error: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR',
      });
    }
  };
};

/**
 * Admin-only middleware
 */
const requireAdmin = requireRole(config.roles.ADMIN);

/**
 * HR or Admin middleware
 */
const requireHROrAdmin = requireRole([config.roles.HR, config.roles.ADMIN]);

/**
 * Employee access middleware (for own resources)
 */
const requireEmployeeAccess = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'User not authenticated',
        code: 'UNAUTHORIZED',
      });
    }

    // Admin and HR have access to all employee resources
    if (firebaseService.hasRole(req.user, [config.roles.ADMIN, config.roles.HR])) {
      return next();
    }

    // For employees, check if they're accessing their own resources
    const targetEmployeeId = req.params.employeeId || req.query.employeeId || req.body.employeeId;
    
    if (req.user.role === config.roles.EMPLOYEE) {
      if (targetEmployeeId && targetEmployeeId !== req.user.employeeId) {
        await auditService.logAccessDenied({
          userId: req.user.uid,
          userEmail: req.user.email,
          userRole: req.user.role,
          employeeId: req.user.employeeId,
          resource: {
            type: 'employee_resource',
            id: targetEmployeeId,
          },
          attemptedAction: `access_employee_resource`,
          reason: 'not_own_resource',
          ipAddress: req.requestContext.ipAddress,
          userAgent: req.requestContext.userAgent,
        });

        return res.status(403).json({
          error: 'Can only access your own resources',
          code: 'FORBIDDEN',
        });
      }
    }

    next();
  } catch (error) {
    console.error('Employee access check error:', error);
    res.status(500).json({
      error: 'Access check failed',
      code: 'ACCESS_CHECK_ERROR',
    });
  }
};

/**
 * Rate limiting middleware
 * @param {Object} options - Rate limit options
 * @returns {Function} Express middleware function
 */
const rateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    maxRequests = 100,
    message = 'Too many requests',
  } = options;

  const requests = new Map();

  return (req, res, next) => {
    const key = `${getClientIP(req)}:${req.user?.uid || 'anonymous'}`;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Get existing requests for this key
    let userRequests = requests.get(key) || [];
    
    // Filter out old requests
    userRequests = userRequests.filter(time => time > windowStart);
    
    // Check if limit exceeded
    if (userRequests.length >= maxRequests) {
      return res.status(429).json({
        error: message,
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((userRequests[0] + windowMs - now) / 1000),
      });
    }

    // Add current request
    userRequests.push(now);
    requests.set(key, userRequests);

    // Clean up old entries periodically
    if (Math.random() < 0.01) { // 1% chance
      for (const [k, reqs] of requests.entries()) {
        const filtered = reqs.filter(time => time > windowStart);
        if (filtered.length === 0) {
          requests.delete(k);
        } else {
          requests.set(k, filtered);
        }
      }
    }

    next();
  };
};

/**
 * Request validation middleware
 * @param {Object} schema - Joi validation schema
 * @param {string} source - Source of data to validate ('body', 'params', 'query')
 * @returns {Function} Express middleware function
 */
const validateRequest = (schema, source = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[source], {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const details = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details,
      });
    }

    // Replace the source with validated and sanitized data
    req[source] = value;
    next();
  };
};

/**
 * Session management middleware
 */
const manageSession = async (req, res, next) => {
  if (req.user) {
    // Check session timeout
    const sessionTimeout = config.security.sessionTimeout * 1000; // Convert to ms
    const lastActivity = req.user.lastLogin ? new Date(req.user.lastLogin) : new Date();
    const now = new Date();

    if (now - lastActivity > sessionTimeout) {
      return res.status(401).json({
        error: 'Session expired',
        code: 'SESSION_EXPIRED',
      });
    }

    // Set session headers
    res.set({
      'X-Session-Expires': new Date(now.getTime() + sessionTimeout).toISOString(),
      'X-User-Role': req.user.role,
    });
  }

  next();
};

module.exports = {
  authenticate,
  requireRole,
  requireAdmin,
  requireHROrAdmin,
  requireEmployeeAccess,
  rateLimit,
  validateRequest,
  manageSession,
  getClientIP,
};