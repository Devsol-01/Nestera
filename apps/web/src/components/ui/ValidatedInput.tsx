import React, { forwardRef, useId } from 'react';
import type { ValidationResult } from '@/lib/validation/validators';
import styles from './ValidatedInput.module.css';

export interface ValidatedInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  /** Input label */
  label: string;
  /** Validation result */
  validation: ValidationResult;
  /** Whether to show error (typically: touched && !valid) */
  showError: boolean;
  /** Helper text shown below input */
  helperText?: string;
  /** Icon to display before input */
  leftIcon?: React.ReactNode;
  /** Icon to display after input */
  rightIcon?: React.ReactNode;
  /** Loading state */
  isLoading?: boolean;
  /** Whether field is required */
  required?: boolean;
}

export const ValidatedInput = forwardRef<HTMLInputElement, ValidatedInputProps>(
  (
    {
      label,
      validation,
      showError,
      helperText,
      leftIcon,
      rightIcon,
      isLoading,
      required,
      className = '',
      id: propId,
      ...inputProps
    },
    ref
  ) => {
    const generatedId = useId();
    const id = propId || generatedId;
    const errorId = `${id}-error`;
    const helperId = `${id}-helper`;

    const hasError = showError && !validation.isValid;
    const inputClasses = [
      styles.input,
      hasError ? styles.inputError : '',
      leftIcon ? styles.inputWithLeftIcon : '',
      rightIcon || isLoading ? styles.inputWithRightIcon : '',
      className,
    ]
      .filter(Boolean)
      .join(' ');

    return (
      <div className={styles.container}>
        {/* Label */}
        <label htmlFor={id} className={styles.label}>
          {label}
          {required && <span className={styles.required} aria-hidden="true"> *</span>}
        </label>

        {/* Input wrapper */}
        <div className={styles.inputWrapper}>
          {leftIcon && (
            <span className={styles.leftIcon} aria-hidden="true">
              {leftIcon}
            </span>
          )}

          <input
            ref={ref}
            id={id}
            className={inputClasses}
            aria-invalid={hasError}
            aria-describedby={
              [hasError ? errorId : null, helperText ? helperId : null]
                .filter(Boolean)
                .join(' ') || undefined
            }
            aria-required={required}
            required={required}
            {...inputProps}
          />

          {isLoading && (
            <span className={styles.spinner} aria-hidden="true">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle
                  cx="8"
                  cy="8"
                  r="7"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeDasharray="32"
                  strokeDashoffset="8"
                >
                  <animateTransform
                    attributeName="transform"
                    type="rotate"
                    from="0 8 8"
                    to="360 8 8"
                    dur="1s"
                    repeatCount="indefinite"
                  />
                </circle>
              </svg>
            </span>
          )}

          {rightIcon && !isLoading && (
            <span className={styles.rightIcon} aria-hidden="true">
              {rightIcon}
            </span>
          )}
        </div>

        {/* Helper text */}
        {helperText && !hasError && (
          <span id={helperId} className={styles.helper}>
            {helperText}
          </span>
        )}

        {/* Error message */}
        {hasError && (
          <span id={errorId} className={styles.error} role="alert" aria-live="polite">
            <span className={styles.errorIcon} aria-hidden="true">⚠</span>
            {validation.error}
          </span>
        )}
      </div>
    );
  }
);

ValidatedInput.displayName = 'ValidatedInput';