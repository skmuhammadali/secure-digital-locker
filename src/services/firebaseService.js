const admin = require('firebase-admin');
const config = require('../config/config');

class FirebaseService {
  constructor() {
    this.initialized = false;
    this.init();
  }

  init() {
    if (this.initialized) return;

    try {
      // Initialize Firebase Admin SDK
      admin.initializeApp({
        projectId: config.firebase.projectId,
        credential: admin.credential.applicationDefault(),
      });

      this.auth = admin.auth();
      this.firestore = admin.firestore();
      this.initialized = true;
      console.log('Firebase service initialized successfully');
    } catch (error) {
      console.error('Error initializing Firebase service:', error);
      throw error;
    }
  }

  /**
   * Create a new user with custom claims
   * @param {Object} userData - User data
   * @param {string} userData.email - User email
   * @param {string} userData.password - User password
   * @param {string} userData.displayName - User display name
   * @param {string} userData.role - User role (admin, hr, employee)
   * @param {string} userData.employeeId - Employee ID
   * @returns {Promise<Object>} Created user record
   */
  async createUser(userData) {
    try {
      const { email, password, displayName, role, employeeId } = userData;

      // Create user in Firebase Auth
      const userRecord = await this.auth.createUser({
        email,
        password,
        displayName,
        emailVerified: false,
      });

      // Set custom claims for role-based access
      await this.auth.setCustomUserClaims(userRecord.uid, {
        role,
        employeeId,
        createdAt: Date.now(),
      });

      // Store additional user data in Firestore
      await this.firestore.collection(config.firestore.collections.users).doc(userRecord.uid).set({
        uid: userRecord.uid,
        email,
        displayName,
        role,
        employeeId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        lastLogin: null,
        isActive: true,
        profileComplete: false,
      });

      return {
        uid: userRecord.uid,
        email,
        displayName,
        role,
        employeeId,
      };
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Verify Firebase ID token and get user claims
   * @param {string} idToken - Firebase ID token
   * @returns {Promise<Object>} Decoded token with user claims
   */
  async verifyToken(idToken) {
    try {
      const decodedToken = await this.auth.verifyIdToken(idToken);
      
      // Get fresh user record to ensure latest custom claims
      const userRecord = await this.auth.getUser(decodedToken.uid);
      
      return {
        uid: decodedToken.uid,
        email: decodedToken.email,
        name: decodedToken.name,
        role: userRecord.customClaims?.role || config.roles.EMPLOYEE,
        employeeId: userRecord.customClaims?.employeeId,
        emailVerified: decodedToken.email_verified,
      };
    } catch (error) {
      console.error('Error verifying token:', error);
      throw new Error('Invalid or expired token');
    }
  }

  /**
   * Update user role and custom claims
   * @param {string} uid - User UID
   * @param {string} newRole - New role to assign
   * @returns {Promise<void>}
   */
  async updateUserRole(uid, newRole) {
    try {
      // Validate role
      if (!Object.values(config.roles).includes(newRole)) {
        throw new Error(`Invalid role: ${newRole}`);
      }

      // Get current user data
      const userDoc = await this.firestore.collection(config.firestore.collections.users).doc(uid).get();
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();
      
      // Update custom claims
      await this.auth.setCustomUserClaims(uid, {
        ...userData.customClaims,
        role: newRole,
        updatedAt: Date.now(),
      });

      // Update Firestore record
      await this.firestore.collection(config.firestore.collections.users).doc(uid).update({
        role: newRole,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`User ${uid} role updated to ${newRole}`);
    } catch (error) {
      console.error('Error updating user role:', error);
      throw error;
    }
  }

  /**
   * Get user data from Firestore
   * @param {string} uid - User UID
   * @returns {Promise<Object>} User data
   */
  async getUserData(uid) {
    try {
      const userDoc = await this.firestore.collection(config.firestore.collections.users).doc(uid).get();
      
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      return userDoc.data();
    } catch (error) {
      console.error('Error getting user data:', error);
      throw error;
    }
  }

  /**
   * Update user last login time
   * @param {string} uid - User UID
   * @returns {Promise<void>}
   */
  async updateLastLogin(uid) {
    try {
      await this.firestore.collection(config.firestore.collections.users).doc(uid).update({
        lastLogin: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (error) {
      console.error('Error updating last login:', error);
      // Don't throw error for non-critical operation
    }
  }

  /**
   * Get all users (admin only)
   * @returns {Promise<Array>} List of users
   */
  async getAllUsers() {
    try {
      const usersSnapshot = await this.firestore.collection(config.firestore.collections.users).get();
      
      const users = [];
      usersSnapshot.forEach(doc => {
        users.push({
          id: doc.id,
          ...doc.data(),
        });
      });

      return users;
    } catch (error) {
      console.error('Error getting all users:', error);
      throw error;
    }
  }

  /**
   * Disable user account
   * @param {string} uid - User UID
   * @returns {Promise<void>}
   */
  async disableUser(uid) {
    try {
      await this.auth.updateUser(uid, { disabled: true });
      await this.firestore.collection(config.firestore.collections.users).doc(uid).update({
        isActive: false,
        disabledAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (error) {
      console.error('Error disabling user:', error);
      throw error;
    }
  }

  /**
   * Check if user has required role
   * @param {Object} user - User object with role
   * @param {string|Array} requiredRoles - Required role(s)
   * @returns {boolean} True if user has required role
   */
  hasRole(user, requiredRoles) {
    if (!user || !user.role) return false;
    
    const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
    return roles.includes(user.role);
  }

  /**
   * Check if user can access document
   * @param {Object} user - User object
   * @param {Object} document - Document metadata
   * @returns {boolean} True if user can access document
   */
  canAccessDocument(user, document) {
    if (!user || !document) return false;

    // Admin can access all documents
    if (user.role === config.roles.ADMIN) return true;

    // HR can access all employee documents
    if (user.role === config.roles.HR) return true;

    // Employee can only access their own documents
    if (user.role === config.roles.EMPLOYEE) {
      return document.employeeId === user.employeeId || document.ownerId === user.uid;
    }

    return false;
  }
}

module.exports = new FirebaseService();