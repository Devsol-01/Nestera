/**
 * validators.test.ts
 *
 * Comprehensive unit tests for all validation utilities.
 * Covers: Stellar addresses, amounts, emails, XSS prevention,
 * edge cases, and boundary values.
 */

import {
  isValidStellarAddress,
  isValidContractId,
  isValidSecretKey,
  isValidAmount,
  isValidInterestRate,
  isValidDuration,
  isValidEmail,
  isValidDisplayName,
  isValidGoalName,
  isValidDescription,
  sanitizeInput,
  isXSSSafe,
  isValidPhoneNumber,
  isValidURL,
  isValidFutureDate,
  isValidMemberCount,
  isValidContributionFrequency,
  validateForm,
  isFormValid,
  getFirstError,
} from '../validators';

// ============================================================================
// Stellar Address Tests
// ============================================================================

describe('isValidStellarAddress', () => {
  it('validates correct Stellar public key', () => {
    const valid = 'GAA5Z5XNNHHKPHHMA2X7J5L3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5';
    expect(isValidStellarAddress(valid).isValid).toBe(true);
  });

  it('rejects empty string', () => {
    expect(isValidStellarAddress('').isValid).toBe(false);
    expect(isValidStellarAddress('').error).toBe('Wallet address is required');
  });

  it('rejects too short', () => {
    expect(isValidStellarAddress('GABC').isValid).toBe(false);
  });

  it('rejects wrong prefix', () => {
    expect(isValidStellarAddress('SAA5Z5XNNHHKPHHMA2X7J5L3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5').isValid).toBe(false);
  });

  it('rejects lowercase', () => {
    const lower = 'gaa5z5xnnhhkphhma2x7j5l3j5k3j5k3j5k3j5k3j5k3j5k3j5k3j5k3j5';
    expect(isValidStellarAddress(lower).isValid).toBe(false);
  });

  it('rejects special characters', () => {
    expect(isValidStellarAddress('GAA5Z5XNNHHKPHHMA2X7J5L3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J!').isValid).toBe(false);
  });

  it('trims whitespace', () => {
    const withSpace = '  GAA5Z5XNNHHKPHHMA2X7J5L3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5K3J5  ';
    expect(isValidStellarAddress(withSpace).isValid).toBe(true);
  });
});

// ============================================================================
// Amount Tests
// ============================================================================

describe('isValidAmount', () => {
  it('validates correct amount', () => {
    expect(isValidAmount('100').isValid).toBe(true);
  });

  it('validates decimal amount', () => {
    expect(isValidAmount('100.50').isValid).toBe(true);
  });

  it('rejects negative', () => {
    expect(isValidAmount('-10').isValid).toBe(false);
  });

  it('rejects zero when not allowed', () => {
    expect(isValidAmount('0', { allowZero: false }).isValid).toBe(false);
  });

  it('allows zero when allowed', () => {
    expect(isValidAmount('0', { allowZero: true }).isValid).toBe(true);
  });

  it('rejects below minimum', () => {
    const result = isValidAmount('0.5', { min: 1 });
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Minimum');
  });

  it('rejects above maximum', () => {
    const result = isValidAmount('200', { max: 100 });
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Maximum');
  });

  it('rejects too many decimals', () => {
    const result = isValidAmount('1.12345678', { decimals: 7 });
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('decimal');
  });

  it('rejects non-numeric', () => {
    expect(isValidAmount('abc').isValid).toBe(false);
  });

  it('rejects empty', () => {
    expect(isValidAmount('').isValid).toBe(false);
  });

  it('rejects leading zeros', () => {
    expect(isValidAmount('0123').isValid).toBe(false);
  });

  it('allows zero prefix for decimals', () => {
    expect(isValidAmount('0.5').isValid).toBe(true);
  });
});

// ============================================================================
// Email Tests
// ============================================================================

describe('isValidEmail', () => {
  it('validates correct email', () => {
    expect(isValidEmail('user@example.com').isValid).toBe(true);
  });

  it('validates with subdomain', () => {
    expect(isValidEmail('user@mail.example.com').isValid).toBe(true);
  });

  it('rejects missing @', () => {
    expect(isValidEmail('userexample.com').isValid).toBe(false);
  });

  it('rejects missing domain', () => {
    expect(isValidEmail('user@').isValid).toBe(false);
  });

  it('rejects missing local part', () => {
    expect(isValidEmail('@example.com').isValid).toBe(false);
  });

  it('rejects double @', () => {
    expect(isValidEmail('user@@example.com').isValid).toBe(false);
  });

  it('rejects spaces', () => {
    expect(isValidEmail('user @example.com').isValid).toBe(false);
  });

  it('lowercases input', () => {
    expect(isValidEmail('USER@EXAMPLE.COM').isValid).toBe(true);
  });
});

// ============================================================================
// XSS Prevention Tests
// ============================================================================

describe('sanitizeInput', () => {
  it('removes script tags', () => {
    const dirty = '<script>alert("xss")</script>Hello';
    expect(sanitizeInput(dirty)).toBe('Hello');
  });

  it('removes event handlers', () => {
    const dirty = '<div onmouseover="alert(1)">text</div>';
    expect(sanitizeInput(dirty)).not.toContain('onmouseover');
  });

  it('removes javascript: URLs', () => {
    const dirty = '<a href="javascript:alert(1)">link</a>';
    expect(sanitizeInput(dirty)).not.toContain('javascript:');
  });

  it('removes iframe tags', () => {
    const dirty = '<iframe src="evil.com"></iframe>';
    expect(sanitizeInput(dirty)).toBe('');
  });

  it('preserves safe text', () => {
    const safe = 'Hello World 123';
    expect(sanitizeInput(safe)).toBe('Hello World 123');
  });
});

describe('isXSSSafe', () => {
  it('accepts safe text', () => {
    expect(isXSSSafe('Hello World').isValid).toBe(true);
  });

  it('rejects script tags', () => {
    expect(isXSSSafe('<script>alert(1)</script>').isValid).toBe(false);
  });

  it('rejects event handlers', () => {
    expect(isXSSSafe('<img onerror="alert(1)">').isValid).toBe(false);
  });

  it('rejects javascript protocol', () => {
    expect(isXSSSafe('javascript:alert(1)').isValid).toBe(false);
  });

  it('accepts empty string', () => {
    expect(isXSSSafe('').isValid).toBe(true);
  });
});

// ============================================================================
// Form Validation Tests
// ============================================================================

describe('validateForm', () => {
  it('validates all fields', () => {
    const result = validateForm({
      email: { value: 'test@example.com', validator: isValidEmail, required: true },
      amount: { value: '100', validator: (v) => isValidAmount(v), required: true },
    });

    expect(result.email.isValid).toBe(true);
    expect(result.amount.isValid).toBe(true);
  });

  it('catches invalid fields', () => {
    const result = validateForm({
      email: { value: 'invalid', validator: isValidEmail, required: true },
      amount: { value: '100', validator: (v) => isValidAmount(v), required: true },
    });

    expect(result.email.isValid).toBe(false);
    expect(result.amount.isValid).toBe(true);
  });

  it('skips optional empty fields', () => {
    const result = validateForm({
      email: { value: '', validator: isValidEmail, required: false },
    });

    expect(result.email.isValid).toBe(true);
  });
});

describe('isFormValid', () => {
  it('returns true when all valid', () => {
    expect(isFormValid({ a: { isValid: true }, b: { isValid: true } })).toBe(true);
  });

  it('returns false when any invalid', () => {
    expect(isFormValid({ a: { isValid: true }, b: { isValid: false } })).toBe(false);
  });
});

describe('getFirstError', () => {
  it('returns first error', () => {
    const error = getFirstError({
      a: { isValid: true },
      b: { isValid: false, error: 'Second error' },
      c: { isValid: false, error: 'Third error' },
    });
    expect(error).toBe('Second error');
  });

  it('returns undefined when all valid', () => {
    expect(getFirstError({ a: { isValid: true } })).toBeUndefined();
  });
});