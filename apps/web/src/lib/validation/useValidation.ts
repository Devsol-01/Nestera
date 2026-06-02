import { useState, useCallback, useRef, useEffect } from 'react';
import type { ValidationResult, Validator } from './validators';

interface UseValidationOptions {
  /** Validator function to apply */
  validator: Validator;
  /** Initial value */
  initialValue?: string;
  /** Debounce delay in ms (default: 300) */
  debounceMs?: number;
  /** Validate on blur immediately (default: true) */
  validateOnBlur?: boolean;
  /** Validate on change (default: true) */
  validateOnChange?: boolean;
  /** Sanitize input before validation (default: true) */
  sanitize?: boolean;
}

interface UseValidationReturn {
  /** Current input value */
  value: string;
  /** Set value programmatically */
  setValue: (value: string) => void;
  /** Validation result */
  validation: ValidationResult;
  /** Whether the field has been touched (blurred) */
  isTouched: boolean;
  /** Whether the field is currently focused */
  isFocused: boolean;
  /** Event handlers to bind to input */
  bind: {
    value: string;
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => void;
    onBlur: () => void;
    onFocus: () => void;
  };
  /** Reset to initial state */
  reset: () => void;
  /** Force validation */
  validate: () => ValidationResult;
  /** Whether to show error (touched and invalid) */
  showError: boolean;
}

export function useValidation(options: UseValidationOptions): UseValidationReturn {
  const {
    validator,
    initialValue = '',
    debounceMs = 300,
    validateOnBlur = true,
    validateOnChange = true,
    sanitize = true,
  } = options;

  const [value, setValueState] = useState(initialValue);
  const [validation, setValidation] = useState<ValidationResult>({ isValid: true });
  const [isTouched, setIsTouched] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sanitize helper
  const sanitizeValue = useCallback((input: string): string => {
    if (!sanitize) return input;
    // Basic sanitization - remove script tags and dangerous patterns
    return input
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '');
  }, [sanitize]);

  // Validate immediately
  const validate = useCallback(
    (inputValue: string): ValidationResult => {
      const sanitized = sanitizeValue(inputValue);
      const result = validator(sanitized);
      setValidation(result);
      return result;
    },
    [validator, sanitizeValue]
  );

  // Debounced validation
  const debouncedValidate = useCallback(
    (inputValue: string) => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }

      debounceTimer.current = setTimeout(() => {
        validate(inputValue);
      }, debounceMs);
    },
    [validate, debounceMs]
  );

  // Handle change
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
      const newValue = e.target.value;
      setValueState(newValue);

      if (validateOnChange) {
        debouncedValidate(newValue);
      }
    },
    [validateOnChange, debouncedValidate]
  );

  // Handle blur
  const handleBlur = useCallback(() => {
    setIsTouched(true);
    setIsFocused(false);

    if (validateOnBlur) {
      // Immediate validation on blur (no debounce)
      validate(value);
    }
  }, [validateOnBlur, validate, value]);

  // Handle focus
  const handleFocus = useCallback(() => {
    setIsFocused(true);
  }, []);

  // Set value programmatically
  const setValue = useCallback(
    (newValue: string) => {
      setValueState(newValue);
      validate(newValue);
    },
    [validate]
  );

  // Reset
  const reset = useCallback(() => {
    setValueState(initialValue);
    setValidation({ isValid: true });
    setIsTouched(false);
    setIsFocused(false);
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }
  }, [initialValue]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, []);

  const showError = isTouched && !validation.isValid && !isFocused;

  return {
    value,
    setValue,
    validation,
    isTouched,
    isFocused,
    bind: {
      value,
      onChange: handleChange,
      onBlur: handleBlur,
      onFocus: handleFocus,
    },
    reset,
    validate: () => validate(value),
    showError,
  };
}