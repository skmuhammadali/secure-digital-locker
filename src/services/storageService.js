const { Storage } = require('@google-cloud/storage');
const config = require('../config/config');
const encryptionService = require('./encryptionService');
const { v4: uuidv4 } = require('uuid');

class StorageService {
  constructor() {
    this.storage = new Storage({
      projectId: config.gcp.projectId,
    });
    this.bucket = this.storage.bucket(config.storage.bucketName);
    this.init();
  }

  async init() {
    try {
      // Check if bucket exists, create if not
      const [exists] = await this.bucket.exists();
      if (!exists) {
        await this.createBucket();
      }
      console.log(`Storage service initialized with bucket: ${config.storage.bucketName}`);
    } catch (error) {
      console.error('Error initializing storage service:', error);
      throw error;
    }
  }

  /**
   * Create storage bucket with security configurations
   */
  async createBucket() {
    try {
      const [bucket] = await this.storage.createBucket(config.storage.bucketName, {
        location: config.storage.bucketLocation,
        storageClass: 'STANDARD',
        versioning: {
          enabled: true,
        },
        lifecycle: {
          rule: [
            {
              action: { type: 'Delete' },
              condition: { age: 365 }, // Delete after 1 year
            },
          ],
        },
        iamConfiguration: {
          uniformBucketLevelAccess: {
            enabled: true,
          },
        },
        encryption: {
          defaultKmsKeyName: config.kms.keyId,
        },
      });

      console.log(`Bucket ${config.storage.bucketName} created successfully`);
      return bucket;
    } catch (error) {
      console.error('Error creating bucket:', error);
      throw error;
    }
  }

  /**
   * Upload encrypted document to Cloud Storage
   * @param {Buffer} fileBuffer - File data
   * @param {Object} metadata - Document metadata
   * @param {Object} userInfo - User information
   * @returns {Promise<Object>} Upload result with document metadata
   */
  async uploadDocument(fileBuffer, metadata, userInfo) {
    try {
      // Validate file size
      if (fileBuffer.length > config.storage.maxFileSize) {
        throw new Error(`File size exceeds maximum limit of ${config.storage.maxFileSize} bytes`);
      }

      // Validate file type
      const fileExtension = metadata.originalName.split('.').pop().toLowerCase();
      if (!config.storage.allowedFileTypes.includes(fileExtension)) {
        throw new Error(`File type .${fileExtension} is not allowed`);
      }

      // Generate secure file name
      const secureFileName = encryptionService.generateSecureFileName(metadata.originalName);
      
      // Generate file hash for integrity verification
      const fileHash = encryptionService.generateFileHash(fileBuffer);

      // Encrypt the file
      const encryptedPayload = await encryptionService.encryptData(fileBuffer);

      // Prepare document metadata
      const documentMetadata = {
        id: uuidv4(),
        originalName: metadata.originalName,
        fileName: secureFileName,
        mimeType: metadata.mimeType,
        size: fileBuffer.length,
        encryptedSize: Buffer.from(encryptedPayload.encryptedData, 'base64').length,
        fileHash,
        documentType: metadata.documentType,
        employeeId: metadata.employeeId || userInfo.employeeId,
        ownerId: userInfo.uid,
        uploadedBy: userInfo.uid,
        uploadedAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
        version: 1,
        isActive: true,
        tags: metadata.tags || [],
        description: metadata.description || '',
        encryptionInfo: encryptionService.getEncryptionInfo(),
      };

      // Upload encrypted file to Cloud Storage
      const file = this.bucket.file(secureFileName);
      const encryptedBuffer = Buffer.from(encryptedPayload.encryptedData, 'base64');
      
      await file.save(encryptedBuffer, {
        metadata: {
          contentType: 'application/octet-stream', // Always use binary for encrypted files
          metadata: {
            documentId: documentMetadata.id,
            originalName: metadata.originalName,
            uploadedBy: userInfo.uid,
            encrypted: 'true',
            encryptionAlgorithm: encryptedPayload.algorithm,
          },
        },
        validation: 'crc32c',
      });

      // Store encryption metadata separately
      const encryptionMetadataFile = this.bucket.file(`${secureFileName}.enc`);
      await encryptionMetadataFile.save(JSON.stringify({
        encryptedDEK: encryptedPayload.encryptedDEK,
        iv: encryptedPayload.iv,
        authTag: encryptedPayload.authTag,
        algorithm: encryptedPayload.algorithm,
        kmsKeyId: encryptedPayload.kmsKeyId,
      }), {
        metadata: {
          contentType: 'application/json',
          metadata: {
            documentId: documentMetadata.id,
            type: 'encryption-metadata',
          },
        },
      });

      return {
        documentId: documentMetadata.id,
        fileName: secureFileName,
        metadata: documentMetadata,
        uploadSuccess: true,
      };
    } catch (error) {
      console.error('Error uploading document:', error);
      throw error;
    }
  }

  /**
   * Download and decrypt document from Cloud Storage
   * @param {string} fileName - Secure file name
   * @param {Object} userInfo - User information for access control
   * @returns {Promise<Object>} Decrypted file data and metadata
   */
  async downloadDocument(fileName, userInfo) {
    try {
      const file = this.bucket.file(fileName);
      const encryptionMetadataFile = this.bucket.file(`${fileName}.enc`);

      // Check if files exist
      const [fileExists] = await file.exists();
      const [encMetaExists] = await encryptionMetadataFile.exists();

      if (!fileExists) {
        throw new Error('Document not found');
      }

      if (!encMetaExists) {
        throw new Error('Encryption metadata not found');
      }

      // Download encrypted file
      const [encryptedData] = await file.download();

      // Download encryption metadata
      const [encryptionMetadataBuffer] = await encryptionMetadataFile.download();
      const encryptionMetadata = JSON.parse(encryptionMetadataBuffer.toString());

      // Prepare encryption payload for decryption
      const encryptionPayload = {
        encryptedData: encryptedData.toString('base64'),
        encryptedDEK: encryptionMetadata.encryptedDEK,
        iv: encryptionMetadata.iv,
        authTag: encryptionMetadata.authTag,
        algorithm: encryptionMetadata.algorithm,
      };

      // Decrypt the file
      const decryptedData = await encryptionService.decryptData(encryptionPayload);

      // Get file metadata
      const [metadata] = await file.getMetadata();

      return {
        data: decryptedData,
        metadata: {
          originalName: metadata.metadata?.originalName,
          documentId: metadata.metadata?.documentId,
          uploadedBy: metadata.metadata?.uploadedBy,
          size: decryptedData.length,
          lastModified: metadata.updated,
        },
      };
    } catch (error) {
      console.error('Error downloading document:', error);
      throw error;
    }
  }

  /**
   * Delete document from Cloud Storage
   * @param {string} fileName - Secure file name
   * @param {Object} userInfo - User information for access control
   * @returns {Promise<boolean>} Success status
   */
  async deleteDocument(fileName, userInfo) {
    try {
      const file = this.bucket.file(fileName);
      const encryptionMetadataFile = this.bucket.file(`${fileName}.enc`);

      // Delete both the encrypted file and its metadata
      await Promise.all([
        file.delete(),
        encryptionMetadataFile.delete(),
      ]);

      console.log(`Document ${fileName} deleted successfully by user ${userInfo.uid}`);
      return true;
    } catch (error) {
      console.error('Error deleting document:', error);
      throw error;
    }
  }

  /**
   * Generate signed URL for temporary access
   * @param {string} fileName - Secure file name
   * @param {Object} options - Options for signed URL
   * @returns {Promise<string>} Signed URL
   */
  async generateSignedUrl(fileName, options = {}) {
    try {
      const file = this.bucket.file(fileName);
      
      const [signedUrl] = await file.getSignedUrl({
        version: 'v4',
        action: options.action || 'read',
        expires: Date.now() + (options.expirationMinutes || 15) * 60 * 1000, // Default 15 minutes
        extensionHeaders: {
          'x-goog-content-length-range': `0,${config.storage.maxFileSize}`,
        },
      });

      return signedUrl;
    } catch (error) {
      console.error('Error generating signed URL:', error);
      throw error;
    }
  }

  /**
   * List documents in bucket (for admin purposes)
   * @param {Object} options - Listing options
   * @returns {Promise<Array>} List of documents
   */
  async listDocuments(options = {}) {
    try {
      const [files] = await this.bucket.getFiles({
        prefix: options.prefix,
        maxResults: options.maxResults || 100,
      });

      const documents = files
        .filter(file => !file.name.endsWith('.enc')) // Exclude encryption metadata files
        .map(file => ({
          name: file.name,
          size: file.metadata.size,
          created: file.metadata.timeCreated,
          updated: file.metadata.updated,
          documentId: file.metadata.metadata?.documentId,
          originalName: file.metadata.metadata?.originalName,
        }));

      return documents;
    } catch (error) {
      console.error('Error listing documents:', error);
      throw error;
    }
  }

  /**
   * Check if document exists
   * @param {string} fileName - Secure file name
   * @returns {Promise<boolean>} Existence status
   */
  async documentExists(fileName) {
    try {
      const file = this.bucket.file(fileName);
      const [exists] = await file.exists();
      return exists;
    } catch (error) {
      console.error('Error checking document existence:', error);
      return false;
    }
  }

  /**
   * Get document metadata without downloading
   * @param {string} fileName - Secure file name
   * @returns {Promise<Object>} Document metadata
   */
  async getDocumentMetadata(fileName) {
    try {
      const file = this.bucket.file(fileName);
      const [metadata] = await file.getMetadata();
      
      return {
        name: file.name,
        size: metadata.size,
        contentType: metadata.contentType,
        created: metadata.timeCreated,
        updated: metadata.updated,
        documentId: metadata.metadata?.documentId,
        originalName: metadata.metadata?.originalName,
        uploadedBy: metadata.metadata?.uploadedBy,
        encrypted: metadata.metadata?.encrypted === 'true',
      };
    } catch (error) {
      console.error('Error getting document metadata:', error);
      throw error;
    }
  }
}

module.exports = new StorageService();