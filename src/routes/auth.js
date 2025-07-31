const express = require('express');
const firebaseService = require('../services/firebaseService');
const auditService = require('../services/auditService');
const config = require('../config/config');
const { 
  authenticate, 
  requireAdmin,
  rateLimit,
  validateRequest,
  getClientIP,
} = require('../middleware/auth');
const Joi = require('joi');

const router = express.Router();

// Validation schemas
const loginSchema = Joi.object({
  idToken: Joi.string().required().messages({
    'any.required': 'ID token is required',
    'string.empty': 'ID token cannot be empty',
  }),
});

const createUserSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Valid email is required',
    'any.required': 'Email is required',
  }),
  password: Joi.string().min(8).required().messages({
    'string.min': 'Password must be at least 8 characters long',
    'any.required': 'Password is required',
  }),
  displayName: Joi.string().min(2).max(50).required().messages({
    'string.min': 'Display name must be at least 2 characters long',
    'string.max': 'Display name must not exceed 50 characters',
    'any.required': 'Display name is required',
  }),
  role: Joi.string().valid(...Object.values(config.roles)).required().messages({
    'any.only': 'Role must be one of: admin, hr, employee',
    'any.required': 'Role is required',
  }),
  employeeId: Joi.string().alphanum().min(3).max(50).required().messages({
    'string.alphanum': 'Employee ID must contain only alphanumeric characters',
    'string.min': 'Employee ID must be at least 3 characters long',
    'string.max': 'Employee ID must not exceed 50 characters',
    'any.required': 'Employee ID is required',
  }),
});

/**
 * POST /api/auth/login
 * Authenticate user with Firebase ID token
 */
router.post('/login',
  rateLimit({ maxRequests: 5, windowMs: 60 * 1000 }), // 5 login attempts per minute
  validateRequest(loginSchema, 'body'),
  async (req, res) => {
    const startTime = Date.now();
    
    try {
      const { idToken } = req.body;
      const ipAddress = getClientIP(req);
      const userAgent = req.get('User-Agent');

      // Verify the Firebase ID token
      const userInfo = await firebaseService.verifyToken(idToken);
      
      // Get additional user data
      const userData = await firebaseService.getUserData(userInfo.uid);
      
      // Check if account is active
      if (!userData.isActive) {
        await auditService.logUserLogin({
          userId: userInfo.uid,
          userEmail: userInfo.email,
          userRole: userInfo.role,
          employeeId: userInfo.employeeId,
          ipAddress,
          userAgent,
          success: false,
          errorMessage: 'Account is disabled',
          duration: Date.now() - startTime,
        });

        return res.status(403).json({
          error: 'Account is disabled',
          code: 'ACCOUNT_DISABLED',
        });
      }

      // Log successful login
      await auditService.logUserLogin({
        userId: userInfo.uid,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        employeeId: userInfo.employeeId,
        ipAddress,
        userAgent,
        loginMethod: 'firebase',
        success: true,
        duration: Date.now() - startTime,
      });

      // Update last login time
      await firebaseService.updateLastLogin(userInfo.uid);

      res.json({
        success: true,
        message: 'Login successful',
        user: {
          uid: userInfo.uid,
          email: userInfo.email,
          name: userInfo.name,
          role: userInfo.role,
          employeeId: userInfo.employeeId,
          emailVerified: userInfo.emailVerified,
          lastLogin: new Date().toISOString(),
        },
      });

    } catch (error) {
      console.error('Login error:', error);
      
      const ipAddress = getClientIP(req);
      const userAgent = req.get('User-Agent');
      
      // Log failed login attempt
      await auditService.logUserLogin({
        userEmail: 'unknown',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: error.message,
        duration: Date.now() - startTime,
      });

      res.status(401).json({
        error: 'Authentication failed',
        code: 'AUTHENTICATION_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/auth/logout
 * Logout user (client-side token invalidation)
 */
router.post('/logout',
  authenticate,
  async (req, res) => {
    try {
      // Log logout event
      await auditService.logEvent({
        eventType: config.auditEvents.USER_LOGOUT,
        userId: req.user.uid,
        userEmail: req.user.email,
        userRole: req.user.role,
        employeeId: req.user.employeeId,
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: true,
      });

      res.json({
        success: true,
        message: 'Logout successful',
      });

    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        error: 'Logout failed',
        code: 'LOGOUT_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/auth/profile
 * Get current user profile
 */
router.get('/profile',
  authenticate,
  async (req, res) => {
    try {
      const userData = await firebaseService.getUserData(req.user.uid);
      
      res.json({
        success: true,
        user: {
          uid: req.user.uid,
          email: req.user.email,
          name: req.user.name,
          role: req.user.role,
          employeeId: req.user.employeeId,
          emailVerified: req.user.emailVerified,
          lastLogin: userData.lastLogin?.toDate(),
          createdAt: userData.createdAt?.toDate(),
          profileComplete: userData.profileComplete,
          isActive: userData.isActive,
        },
      });

    } catch (error) {
      console.error('Profile retrieval error:', error);
      res.status(500).json({
        error: 'Failed to retrieve profile',
        code: 'PROFILE_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/auth/create-user
 * Create a new user (Admin only)
 */
router.post('/create-user',
  authenticate,
  requireAdmin,
  rateLimit({ maxRequests: 10, windowMs: 60 * 1000 }), // 10 user creations per minute
  validateRequest(createUserSchema, 'body'),
  async (req, res) => {
    try {
      const { email, password, displayName, role, employeeId } = req.body;

      // Create user with Firebase
      const userResult = await firebaseService.createUser({
        email,
        password,
        displayName,
        role,
        employeeId,
      });

      // Log user creation
      await auditService.logEvent({
        eventType: config.auditEvents.ROLE_CHANGE,
        userId: req.user.uid,
        userEmail: req.user.email,
        userRole: req.user.role,
        employeeId: req.user.employeeId,
        resource: {
          type: 'user',
          id: userResult.uid,
          email: userResult.email,
        },
        metadata: {
          action: 'create_user',
          newRole: role,
          newEmployeeId: employeeId,
        },
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: true,
      });

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        user: {
          uid: userResult.uid,
          email: userResult.email,
          displayName: userResult.displayName,
          role: userResult.role,
          employeeId: userResult.employeeId,
        },
      });

    } catch (error) {
      console.error('User creation error:', error);
      
      // Log failed user creation
      await auditService.logEvent({
        eventType: config.auditEvents.ROLE_CHANGE,
        userId: req.user.uid,
        userEmail: req.user.email,
        userRole: req.user.role,
        employeeId: req.user.employeeId,
        metadata: {
          action: 'create_user',
          targetEmail: req.body.email,
        },
        ipAddress: req.requestContext.ipAddress,
        userAgent: req.requestContext.userAgent,
        success: false,
        errorMessage: error.message,
      });

      if (error.code === 'auth/email-already-exists') {
        return res.status(400).json({
          error: 'Email already in use',
          code: 'EMAIL_EXISTS',
        });
      }

      res.status(500).json({
        error: 'Failed to create user',
        code: 'USER_CREATION_FAILED',
        message: error.message,
      });
    }
  }
);

/**
 * GET /api/auth/verify-token
 * Verify if the current token is valid
 */
router.get('/verify-token',
  authenticate,
  (req, res) => {
    res.json({
      success: true,
      valid: true,
      user: {
        uid: req.user.uid,
        email: req.user.email,
        role: req.user.role,
        employeeId: req.user.employeeId,
      },
    });
  }
);

/**
 * POST /api/auth/refresh
 * Refresh user session (extend session timeout)
 */
router.post('/refresh',
  authenticate,
  rateLimit({ maxRequests: 10, windowMs: 60 * 1000 }), // 10 refreshes per minute
  async (req, res) => {
    try {
      // Update last activity
      await firebaseService.updateLastLogin(req.user.uid);

      res.json({
        success: true,
        message: 'Session refreshed',
        expiresAt: new Date(Date.now() + config.security.sessionTimeout * 1000).toISOString(),
      });

    } catch (error) {
      console.error('Session refresh error:', error);
      res.status(500).json({
        error: 'Failed to refresh session',
        code: 'REFRESH_FAILED',
        message: error.message,
      });
    }
  }
);

module.exports = router;