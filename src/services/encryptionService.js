const { KeyManagementServiceClient } = require('@google-cloud/kms');
const crypto = require('crypto');
const config = require('../config/config');

class EncryptionService {
  constructor() {
    this.kmsClient = new KeyManagementServiceClient();
    this.keyId = config.kms.keyId;
  }

  /**
   * Encrypt data using Cloud KMS
   * @param {Buffer|string} data - Data to encrypt
   * @returns {Promise<Object>} Encrypted data with metadata
   */
  async encryptData(data) {
    try {
      // Convert string to buffer if needed
      const plaintext = Buffer.isBuffer(data) ? data : Buffer.from(data);

      // Generate a data encryption key (DEK) locally
      const dek = crypto.randomBytes(32); // 256-bit key
      const iv = crypto.randomBytes(16);   // 128-bit IV

      // Encrypt the actual data with the DEK using AES-256-GCM
      const cipher = crypto.createCipherGCM('aes-256-gcm', dek, iv);
      let encryptedData = cipher.update(plaintext);
      encryptedData = Buffer.concat([encryptedData, cipher.final()]);
      const authTag = cipher.getAuthTag();

      // Encrypt the DEK using Cloud KMS (envelope encryption)
      const [encryptResult] = await this.kmsClient.encrypt({
        name: this.keyId,
        plaintext: dek,
      });

      return {
        encryptedData: encryptedData.toString('base64'),
        encryptedDEK: encryptResult.ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        algorithm: 'aes-256-gcm',
        kmsKeyId: this.keyId,
      };
    } catch (error) {
      console.error('Error encrypting data:', error);
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt data using Cloud KMS
   * @param {Object} encryptedPayload - Encrypted data payload
   * @returns {Promise<Buffer>} Decrypted data
   */
  async decryptData(encryptedPayload) {
    try {
      const { encryptedData, encryptedDEK, iv, authTag, algorithm } = encryptedPayload;

      // Decrypt the DEK using Cloud KMS
      const [decryptResult] = await this.kmsClient.decrypt({
        name: this.keyId,
        ciphertext: Buffer.from(encryptedDEK, 'base64'),
      });

      const dek = decryptResult.plaintext;
      const ivBuffer = Buffer.from(iv, 'base64');
      const encryptedDataBuffer = Buffer.from(encryptedData, 'base64');
      const authTagBuffer = Buffer.from(authTag, 'base64');

      // Decrypt the actual data using the DEK
      const decipher = crypto.createDecipherGCM(algorithm, dek, ivBuffer);
      decipher.setAuthTag(authTagBuffer);
      
      let decryptedData = decipher.update(encryptedDataBuffer);
      decryptedData = Buffer.concat([decryptedData, decipher.final()]);

      return decryptedData;
    } catch (error) {
      console.error('Error decrypting data:', error);
      throw new Error('Decryption failed');
    }
  }

  /**
   * Encrypt file stream
   * @param {ReadableStream} inputStream - Input file stream
   * @returns {Promise<Object>} Encrypted stream and metadata
   */
  async encryptStream(inputStream) {
    try {
      // Read the entire stream into buffer
      // Note: For large files, implement streaming encryption
      const chunks = [];
      for await (const chunk of inputStream) {
        chunks.push(chunk);
      }
      const fileBuffer = Buffer.concat(chunks);

      return await this.encryptData(fileBuffer);
    } catch (error) {
      console.error('Error encrypting stream:', error);
      throw new Error('Stream encryption failed');
    }
  }

  /**
   * Generate secure hash for file integrity
   * @param {Buffer} data - File data
   * @returns {string} SHA-256 hash
   */
  generateFileHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Verify file integrity
   * @param {Buffer} data - File data
   * @param {string} expectedHash - Expected hash
   * @returns {boolean} True if hash matches
   */
  verifyFileIntegrity(data, expectedHash) {
    const actualHash = this.generateFileHash(data);
    return actualHash === expectedHash;
  }

  /**
   * Generate secure random file name
   * @param {string} originalName - Original file name
   * @returns {string} Secure file name
   */
  generateSecureFileName(originalName) {
    const ext = originalName.split('.').pop();
    const randomName = crypto.randomUUID();
    return `${randomName}.${ext}`;
  }

  /**
   * Create encrypted metadata for document
   * @param {Object} metadata - Document metadata
   * @returns {Promise<Object>} Encrypted metadata
   */
  async encryptMetadata(metadata) {
    try {
      const metadataString = JSON.stringify(metadata);
      return await this.encryptData(metadataString);
    } catch (error) {
      console.error('Error encrypting metadata:', error);
      throw new Error('Metadata encryption failed');
    }
  }

  /**
   * Decrypt metadata for document
   * @param {Object} encryptedMetadata - Encrypted metadata
   * @returns {Promise<Object>} Decrypted metadata
   */
  async decryptMetadata(encryptedMetadata) {
    try {
      const decryptedBuffer = await this.decryptData(encryptedMetadata);
      return JSON.parse(decryptedBuffer.toString());
    } catch (error) {
      console.error('Error decrypting metadata:', error);
      throw new Error('Metadata decryption failed');
    }
  }

  /**
   * Validate encryption payload structure
   * @param {Object} payload - Encryption payload
   * @returns {boolean} True if valid
   */
  validateEncryptionPayload(payload) {
    const requiredFields = ['encryptedData', 'encryptedDEK', 'iv', 'authTag', 'algorithm'];
    return requiredFields.every(field => payload.hasOwnProperty(field));
  }

  /**
   * Get encryption info for audit
   * @returns {Object} Encryption information
   */
  getEncryptionInfo() {
    return {
      algorithm: 'aes-256-gcm',
      keyManagement: 'cloud-kms',
      keyId: this.keyId,
      envelopeEncryption: true,
    };
  }
}

module.exports = new EncryptionService();