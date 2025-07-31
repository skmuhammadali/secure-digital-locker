const Joi = require('joi');
const config = require('../config/config');

const documentValidators = {
  // Document upload validation
  upload: Joi.object({
    documentType: Joi.string()
      .valid(...Object.values(config.documentTypes))
      .required()
      .messages({
        'any.only': 'Document type must be one of: {#valids}',
        'any.required': 'Document type is required',
      }),
    
    employeeId: Joi.string()
      .alphanum()
      .min(3)
      .max(50)
      .optional()
      .messages({
        'string.alphanum': 'Employee ID must contain only alphanumeric characters',
        'string.min': 'Employee ID must be at least 3 characters long',
        'string.max': 'Employee ID must not exceed 50 characters',
      }),

    description: Joi.string()
      .max(500)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Description must not exceed 500 characters',
      }),

    tags: Joi.array()
      .items(Joi.string().max(50))
      .max(10)
      .optional()
      .default([])
      .messages({
        'array.max': 'Maximum 10 tags allowed',
        'string.max': 'Each tag must not exceed 50 characters',
      }),

    viewers: Joi.array()
      .items(Joi.string().guid({ version: 'uuidv4' }))
      .max(20)
      .optional()
      .default([])
      .messages({
        'array.max': 'Maximum 20 viewers allowed',
        'string.guid': 'Invalid viewer ID format',
      }),

    editors: Joi.array()
      .items(Joi.string().guid({ version: 'uuidv4' }))
      .max(10)
      .optional()
      .default([])
      .messages({
        'array.max': 'Maximum 10 editors allowed',
        'string.guid': 'Invalid editor ID format',
      }),
  }),

  // Document listing validation
  list: Joi.object({
    documentType: Joi.string()
      .valid(...Object.values(config.documentTypes))
      .optional(),

    employeeId: Joi.string()
      .alphanum()
      .min(3)
      .max(50)
      .optional(),

    uploadedAfter: Joi.date()
      .iso()
      .optional()
      .messages({
        'date.format': 'Upload date must be in ISO format',
      }),

    uploadedBefore: Joi.date()
      .iso()
      .optional()
      .messages({
        'date.format': 'Upload date must be in ISO format',
      }),

    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .optional()
      .default(20)
      .messages({
        'number.min': 'Limit must be at least 1',
        'number.max': 'Limit must not exceed 100',
      }),

    startAfter: Joi.string()
      .guid({ version: 'uuidv4' })
      .optional()
      .messages({
        'string.guid': 'Invalid document ID format for pagination',
      }),

    sortBy: Joi.string()
      .valid('uploadedAt', 'name', 'size', 'lastAccessed')
      .optional()
      .default('uploadedAt'),

    sortOrder: Joi.string()
      .valid('asc', 'desc')
      .optional()
      .default('desc'),
  }),

  // Document ID parameter validation
  documentId: Joi.object({
    documentId: Joi.string()
      .guid({ version: 'uuidv4' })
      .required()
      .messages({
        'string.guid': 'Invalid document ID format',
        'any.required': 'Document ID is required',
      }),
  }),

  // Document sharing validation
  share: Joi.object({
    shareWith: Joi.array()
      .items(Joi.string().guid({ version: 'uuidv4' }))
      .min(1)
      .max(20)
      .required()
      .messages({
        'array.min': 'At least one user ID required',
        'array.max': 'Maximum 20 users can be shared with',
        'string.guid': 'Invalid user ID format',
        'any.required': 'Share with user IDs are required',
      }),

    message: Joi.string()
      .max(200)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Share message must not exceed 200 characters',
      }),

    expiresAt: Joi.date()
      .iso()
      .greater('now')
      .optional()
      .messages({
        'date.format': 'Expiry date must be in ISO format',
        'date.greater': 'Expiry date must be in the future',
      }),
  }),

  // Signed URL generation validation
  signedUrl: Joi.object({
    action: Joi.string()
      .valid('read', 'write')
      .optional()
      .default('read')
      .messages({
        'any.only': 'Action must be either "read" or "write"',
      }),

    expirationMinutes: Joi.number()
      .integer()
      .min(1)
      .max(1440) // 24 hours max
      .optional()
      .default(15)
      .messages({
        'number.min': 'Expiration must be at least 1 minute',
        'number.max': 'Expiration must not exceed 1440 minutes (24 hours)',
      }),
  }),

  // Document deletion validation
  delete: Joi.object({
    reason: Joi.string()
      .max(200)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Deletion reason must not exceed 200 characters',
      }),

    permanentDelete: Joi.boolean()
      .optional()
      .default(false),
  }),

  // Document search validation
  search: Joi.object({
    query: Joi.string()
      .min(2)
      .max(100)
      .required()
      .messages({
        'string.min': 'Search query must be at least 2 characters long',
        'string.max': 'Search query must not exceed 100 characters',
        'any.required': 'Search query is required',
      }),

    documentType: Joi.string()
      .valid(...Object.values(config.documentTypes))
      .optional(),

    employeeId: Joi.string()
      .alphanum()
      .min(3)
      .max(50)
      .optional(),

    dateRange: Joi.object({
      start: Joi.date().iso().required(),
      end: Joi.date().iso().greater(Joi.ref('start')).required(),
    }).optional(),

    limit: Joi.number()
      .integer()
      .min(1)
      .max(50)
      .optional()
      .default(20),
  }),

  // File metadata validation (used with multer)
  fileMetadata: Joi.object({
    originalname: Joi.string()
      .min(1)
      .max(255)
      .required()
      .pattern(/^[^<>:"/\\|?*\x00-\x1f]+$/)
      .messages({
        'string.pattern.base': 'Filename contains invalid characters',
        'string.min': 'Filename cannot be empty',
        'string.max': 'Filename must not exceed 255 characters',
        'any.required': 'Filename is required',
      }),

    mimetype: Joi.string()
      .pattern(/^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_.]*$/)
      .required()
      .messages({
        'string.pattern.base': 'Invalid MIME type format',
        'any.required': 'MIME type is required',
      }),

    size: Joi.number()
      .integer()
      .min(1)
      .max(config.storage.maxFileSize)
      .required()
      .messages({
        'number.min': 'File cannot be empty',
        'number.max': `File size must not exceed ${config.storage.maxFileSize} bytes`,
        'any.required': 'File size is required',
      }),
  }),

  // Document statistics filters
  statistics: Joi.object({
    startDate: Joi.date()
      .iso()
      .optional()
      .messages({
        'date.format': 'Start date must be in ISO format',
      }),

    endDate: Joi.date()
      .iso()
      .greater(Joi.ref('startDate'))
      .optional()
      .messages({
        'date.format': 'End date must be in ISO format',
        'date.greater': 'End date must be after start date',
      }),

    employeeId: Joi.string()
      .alphanum()
      .min(3)
      .max(50)
      .optional(),

    documentType: Joi.string()
      .valid(...Object.values(config.documentTypes))
      .optional(),

    groupBy: Joi.string()
      .valid('documentType', 'employeeId', 'uploadDate', 'accessCount')
      .optional()
      .default('documentType'),
  }),
};

// Validation for file extension based on document type
const validateFileType = (file, documentType) => {
  const allowedExtensions = {
    [config.documentTypes.OFFER_LETTER]: ['pdf', 'doc', 'docx'],
    [config.documentTypes.ID_PROOF]: ['pdf', 'jpg', 'jpeg', 'png'],
    [config.documentTypes.SALARY_SLIP]: ['pdf', 'doc', 'docx'],
    [config.documentTypes.CERTIFICATION]: ['pdf', 'jpg', 'jpeg', 'png'],
    [config.documentTypes.CONTRACT]: ['pdf', 'doc', 'docx'],
    [config.documentTypes.PERFORMANCE_REVIEW]: ['pdf', 'doc', 'docx'],
    [config.documentTypes.OTHER]: config.storage.allowedFileTypes,
  };

  const fileExtension = file.originalname.split('.').pop().toLowerCase();
  const allowed = allowedExtensions[documentType] || config.storage.allowedFileTypes;

  return allowed.includes(fileExtension);
};

// Validation for MIME type consistency with file extension
const validateMimeType = (file) => {
  const mimeTypeMap = {
    'pdf': ['application/pdf'],
    'doc': ['application/msword'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'jpg': ['image/jpeg'],
    'jpeg': ['image/jpeg'],
    'png': ['image/png'],
  };

  const fileExtension = file.originalname.split('.').pop().toLowerCase();
  const expectedMimeTypes = mimeTypeMap[fileExtension];

  if (!expectedMimeTypes) {
    return false;
  }

  return expectedMimeTypes.includes(file.mimetype);
};

module.exports = {
  ...documentValidators,
  validateFileType,
  validateMimeType,
};