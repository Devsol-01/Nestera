export interface ValidationResult {
  isValid: boolean;
  error?: string;
}

export type Validator<T = string> = (value: T) => ValidationResult;

// ============================================================================
// Stellar / Blockchain Validators
// ============================================================================

/**
 * Validates a Stellar public key (G... format)
 * Stellar addresses are 56-character base32 strings starting with 'G'
 */
export const isValidStellarAddress: Validator = (address) => {
  if (!address || typeof address !== 'string') {
    return { isValid: false, error: 'Wallet address is required' };
  }

  const trimmed = address.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Wallet address is required' };
  }

  // Stellar public key: starts with G, 56 chars, alphanumeric only
  const STELLAR_PUBKEY_REGEX = /^G[A-Z0-9]{55}$/;
  if (!STELLAR_PUBKEY_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: 'Invalid Stellar address. Must start with G and be 56 characters long.',
    };
  }

  // Additional checksum validation could go here using StrKey.decode
  return { isValid: true };
};

/**
 * Validates a Stellar contract ID (C... format)
 * Soroban contract IDs are 56-character base32 strings starting with 'C'
 */
export const isValidContractId: Validator = (contractId) => {
  if (!contractId || typeof contractId !== 'string') {
    return { isValid: false, error: 'Contract ID is required' };
  }

  const trimmed = contractId.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Contract ID is required' };
  }

  const CONTRACT_ID_REGEX = /^C[A-Z0-9]{55}$/;
  if (!CONTRACT_ID_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: 'Invalid contract ID. Must start with C and be 56 characters long.',
    };
  }

  return { isValid: true };
};

/**
 * Validates a Stellar secret key (S... format)
 * WARNING: Only use for client-side formatting checks. Never log or transmit.
 */
export const isValidSecretKey: Validator = (secretKey) => {
  if (!secretKey || typeof secretKey !== 'string') {
    return { isValid: false, error: 'Secret key is required' };
  }

  const trimmed = secretKey.trim();

  const SECRET_KEY_REGEX = /^S[A-Z0-9]{55}$/;
  if (!SECRET_KEY_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: 'Invalid secret key format.',
    };
  }

  return { isValid: true };
};

// ============================================================================
// Amount / Numeric Validators
// ============================================================================

export interface AmountValidationOptions {
  min?: number;
  max?: number;
  decimals?: number;
  allowZero?: boolean;
  currency?: string;
}

/**
 * Validates a monetary amount string
 */
export const isValidAmount = (
  amount: string,
  options: AmountValidationOptions = {}
): ValidationResult => {
  const {
    min = 0,
    max = Number.MAX_SAFE_INTEGER,
    decimals = 7,
    allowZero = false,
    currency = 'USDC',
  } = options;

  if (!amount || typeof amount !== 'string') {
    return { isValid: false, error: `Amount is required` };
  }

  const trimmed = amount.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: `Amount is required` };
  }

  // Check for valid numeric format (allows decimals, no leading zeros unless 0.x)
  const NUMERIC_REGEX = /^(0|[1-9]\d*)(\.\d+)?$/;
  if (!NUMERIC_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: `Invalid amount format. Use numbers only (e.g., 100.50)`,
    };
  }

  const num = parseFloat(trimmed);

  if (isNaN(num)) {
    return { isValid: false, error: `Invalid amount` };
  }

  // Check decimal places
  const decimalParts = trimmed.split('.');
  if (decimalParts[1] && decimalParts[1].length > decimals) {
    return {
      isValid: false,
      error: `Amount cannot have more than ${decimals} decimal places`,
    };
  }

  // Check zero
  if (!allowZero && num === 0) {
    return {
      isValid: false,
      error: `Amount must be greater than 0 ${currency}`,
    };
  }

  // Check negative (should be caught by regex, but defensive)
  if (num < 0) {
    return {
      isValid: false,
      error: `Amount cannot be negative`,
    };
  }

  // Check minimum
  if (num < min) {
    return {
      isValid: false,
      error: `Minimum amount is ${min} ${currency}`,
    };
  }

  // Check maximum
  if (num > max) {
    return {
      isValid: false,
      error: `Maximum amount is ${max} ${currency}`,
    };
  }

  return { isValid: true };
};

/**
 * Validates an interest rate percentage
 */
export const isValidInterestRate: Validator = (rate) => {
  const result = isValidAmount(rate, {
    min: 0,
    max: 100,
    decimals: 2,
    allowZero: true,
    currency: '%',
  });

  if (!result.isValid) {
    // Override currency in error message
    return {
      ...result,
      error: result.error?.replace('USDC', '%'),
    };
  }

  return result;
};

/**
 * Validates a savings duration in days
 */
export const isValidDuration: Validator = (days) => {
  return isValidAmount(days, {
    min: 1,
    max: 3650, // ~10 years
    decimals: 0,
    allowZero: false,
    currency: 'days',
  });
};

// ============================================================================
// String Validators
// ============================================================================

/**
 * Validates an email address
 */
export const isValidEmail: Validator = (email) => {
  if (!email || typeof email !== 'string') {
    return { isValid: false, error: 'Email is required' };
  }

  const trimmed = email.trim().toLowerCase();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Email is required' };
  }

  // RFC 5322 compliant simplified regex
  const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  if (!EMAIL_REGEX.test(trimmed)) {
    return { isValid: false, error: 'Please enter a valid email address' };
  }

  // Check length
  if (trimmed.length > 254) {
    return { isValid: false, error: 'Email is too long' };
  }

  return { isValid: true };
};

/**
 * Validates a user's display name
 */
export const isValidDisplayName: Validator = (name) => {
  if (!name || typeof name !== 'string') {
    return { isValid: false, error: 'Name is required' };
  }

  const trimmed = name.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Name is required' };
  }

  if (trimmed.length < 2) {
    return { isValid: false, error: 'Name must be at least 2 characters' };
  }

  if (trimmed.length > 50) {
    return { isValid: false, error: 'Name must be less than 50 characters' };
  }

  // Allow letters, numbers, spaces, hyphens, apostrophes
  const NAME_REGEX = /^[a-zA-Z0-9\s\-'.]+$/;
  if (!NAME_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: 'Name can only contain letters, numbers, spaces, hyphens, and apostrophes',
    };
  }

  return { isValid: true };
};

/**
 * Validates a savings goal name
 */
export const isValidGoalName: Validator = (name) => {
  if (!name || typeof name !== 'string') {
    return { isValid: false, error: 'Goal name is required' };
  }

  const trimmed = name.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Goal name is required' };
  }

  if (trimmed.length < 3) {
    return { isValid: false, error: 'Goal name must be at least 3 characters' };
  }

  if (trimmed.length > 100) {
    return { isValid: false, error: 'Goal name must be less than 100 characters' };
  }

  return { isValid: true };
};

/**
 * Validates a description/text field
 */
export const isValidDescription: Validator = (text) => {
  if (!text || typeof text !== 'string') {
    return { isValid: false, error: 'Description is required' };
  }

  const trimmed = text.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'Description is required' };
  }

  if (trimmed.length > 1000) {
    return { isValid: false, error: 'Description must be less than 1000 characters' };
  }

  return { isValid: true };
};

// ============================================================================
// Security / XSS Prevention
// ============================================================================

/**
 * Sanitizes user input to prevent XSS attacks
 * Removes script tags, event handlers, and dangerous HTML
 */
export const sanitizeInput = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  return (
    input
      // Remove script tags and contents
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      // Remove event handlers
      .replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '')
      // Remove javascript: and data: URLs
      .replace(/(javascript|data):/gi, '')
      // Remove iframe, object, embed tags
      .replace(/<(iframe|object|embed)[^>]*>[\s\S]*?<\/\1>/gi, '')
      // Remove style tags
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      // Remove remaining HTML tags (optional - uncomment if plain text only)
      // .replace(/<[^>]+>/g, '')
      // Trim
      .trim()
  );
};

/**
 * Validates that input does not contain XSS payloads
 */
export const isXSSSafe: Validator = (input) => {
  if (!input || typeof input !== 'string') {
    return { isValid: true }; // Empty is safe
  }

  const XSS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /data:text\/html/i,
    /expression\(/i,
  ];

  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(input)) {
      return {
        isValid: false,
        error: 'Input contains potentially unsafe content',
      };
    }
  }

  return { isValid: true };
};

// ============================================================================
// Phone / Contact Validators
// ============================================================================

/**
 * Validates an international phone number
 */
export const isValidPhoneNumber: Validator = (phone) => {
  if (!phone || typeof phone !== 'string') {
    return { isValid: false, error: 'Phone number is required' };
  }

  const trimmed = phone.trim().replace(/\s+/g, '');

  // E.164 format: + followed by 1-15 digits
  const PHONE_REGEX = /^\+[1-9]\d{1,14}$/;
  if (!PHONE_REGEX.test(trimmed)) {
    return {
      isValid: false,
      error: 'Please enter a valid phone number in international format (+1234567890)',
    };
  }

  return { isValid: true };
};

// ============================================================================
// URL Validators
// ============================================================================

/**
 * Validates a URL
 */
export const isValidURL: Validator = (url) => {
  if (!url || typeof url !== 'string') {
    return { isValid: false, error: 'URL is required' };
  }

  const trimmed = url.trim();

  if (trimmed.length === 0) {
    return { isValid: false, error: 'URL is required' };
  }

  try {
    const parsed = new URL(trimmed);
    const allowedProtocols = ['http:', 'https:'];

    if (!allowedProtocols.includes(parsed.protocol)) {
      return {
        isValid: false,
        error: 'URL must start with http:// or https://',
      };
    }

    return { isValid: true };
  } catch {
    return { isValid: false, error: 'Please enter a valid URL' };
  }
};

// ============================================================================
// Date Validators
// ============================================================================

/**
 * Validates a future date (for savings maturity, etc.)
 */
export const isValidFutureDate = (date: string | Date): ValidationResult => {
  if (!date) {
    return { isValid: false, error: 'Date is required' };
  }

  const parsed = typeof date === 'string' ? new Date(date) : date;

  if (isNaN(parsed.getTime())) {
    return { isValid: false, error: 'Invalid date format' };
  }

  const now = new Date();
  now.setHours(0, 0, 0, 0);

  if (parsed < now) {
    return { isValid: false, error: 'Date must be in the future' };
  }

  // Max 10 years ahead
  const maxDate = new Date();
  maxDate.setFullYear(maxDate.getFullYear() + 10);

  if (parsed > maxDate) {
    return { isValid: false, error: 'Date cannot be more than 10 years in the future' };
  }

  return { isValid: true };
};

// ============================================================================
// Group Savings Validators
// ============================================================================

/**
 * Validates group savings member count
 */
export const isValidMemberCount: Validator = (count) => {
  const result = isValidAmount(count, {
    min: 2,
    max: 50,
    decimals: 0,
    allowZero: false,
    currency: 'members',
  });

  if (!result.isValid) {
    return {
      ...result,
      error: result.error?.replace('USDC', 'members'),
    };
  }

  return result;
};

/**
 * Validates a group savings contribution frequency
 */
export const isValidContributionFrequency: Validator = (frequency) => {
  const validFrequencies = ['daily', 'weekly', 'biweekly', 'monthly', 'quarterly'];

  if (!frequency || typeof frequency !== 'string') {
    return { isValid: false, error: 'Contribution frequency is required' };
  }

  if (!validFrequencies.includes(frequency.toLowerCase())) {
    return {
      isValid: false,
      error: `Invalid frequency. Choose from: ${validFrequencies.join(', ')}`,
    };
  }

  return { isValid: true };
};

// ============================================================================
// Composite / Form Validators
// ============================================================================

export interface FormField {
  value: string;
  validator: Validator;
  required?: boolean;
}

/**
 * Validates an entire form object
 */
export const validateForm = (fields: Record<string, FormField>): Record<string, ValidationResult> => {
  const results: Record<string, ValidationResult> = {};

  for (const [key, field] of Object.entries(fields)) {
    if (!field.required && (!field.value || field.value.trim() === '')) {
      results[key] = { isValid: true };
      continue;
    }

    results[key] = field.validator(field.value);
  }

  return results;
};

/**
 * Checks if all form validation results are valid
 */
export const isFormValid = (results: Record<string, ValidationResult>): boolean => {
  return Object.values(results).every((result) => result.isValid);
};

/**
 * Gets the first error from form validation results
 */
export const getFirstError = (results: Record<string, ValidationResult>): string | undefined => {
  const firstInvalid = Object.values(results).find((r) => !r.isValid);
  return firstInvalid?.error;
};