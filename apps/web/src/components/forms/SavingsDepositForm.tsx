import React, { useState, useCallback } from 'react';
import { useValidation } from '@/lib/validation/useValidation';
import {
  isValidStellarAddress,
  isValidAmount,
  isValidGoalName,
  isValidDuration,
  sanitizeInput,
  validateForm,
  isFormValid,
} from '@/lib/validation/validators';
import { ValidatedInput } from '@/components/ui/ValidatedInput';
import styles from './SavingsDepositForm.module.css';

interface SavingsDepositFormData {
  walletAddress: string;
  amount: string;
  goalName: string;
  duration: string;
}

export const SavingsDepositForm: React.FC = () => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  // Real-time validation hooks
  const walletValidation = useValidation({
    validator: isValidStellarAddress,
    debounceMs: 200,
  });

  const amountValidation = useValidation({
    validator: (value) =>
      isValidAmount(value, { min: 1, max: 100000, decimals: 7, currency: 'USDC' }),
    debounceMs: 150,
  });

  const goalValidation = useValidation({
    validator: isValidGoalName,
    debounceMs: 300,
  });

  const durationValidation = useValidation({
    validator: isValidDuration,
    debounceMs: 200,
  });

  // Handle form submission
  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setSubmitError(null);
      setSubmitSuccess(false);

      // Mark all fields as touched
      walletValidation.bind.onBlur();
      amountValidation.bind.onBlur();
      goalValidation.bind.onBlur();
      durationValidation.bind.onBlur();

      // Force validate all
      const results = validateForm({
        walletAddress: {
          value: walletValidation.value,
          validator: isValidStellarAddress,
          required: true,
        },
        amount: {
          value: amountValidation.value,
          validator: (v) => isValidAmount(v, { min: 1, max: 100000, decimals: 7 }),
          required: true,
        },
        goalName: {
          value: goalValidation.value,
          validator: isValidGoalName,
          required: true,
        },
        duration: {
          value: durationValidation.value,
          validator: isValidDuration,
          required: true,
        },
      });

      if (!isFormValid(results)) {
        setSubmitError('Please fix the errors above before submitting.');
        return;
      }

      setIsSubmitting(true);

      try {
        // Sanitize all inputs before sending
        const sanitizedData: SavingsDepositFormData = {
          walletAddress: sanitizeInput(walletValidation.value).trim(),
          amount: sanitizeInput(amountValidation.value).trim(),
          goalName: sanitizeInput(goalValidation.value).trim(),
          duration: sanitizeInput(durationValidation.value).trim(),
        };

        // Submit to API
        const response = await fetch('/api/savings/deposit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(sanitizedData),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to create savings deposit');
        }

        setSubmitSuccess(true);

        // Reset form
        walletValidation.reset();
        amountValidation.reset();
        goalValidation.reset();
        durationValidation.reset();
      } catch (err) {
        setSubmitError(err instanceof Error ? err.message : 'An unexpected error occurred');
      } finally {
        setIsSubmitting(false);
      }
    },
    [
      walletValidation,
      amountValidation,
      goalValidation,
      durationValidation,
    ]
  );

  return (
    <form onSubmit={handleSubmit} className={styles.form} noValidate>
      <h2 className={styles.title}>Create Savings Deposit</h2>

      {/* Success message */}
      {submitSuccess && (
        <div className={styles.success} role="status" aria-live="polite">
          ✅ Savings deposit created successfully!
        </div>
      )}

      {/* Submit error */}
      {submitError && (
        <div className={styles.submitError} role="alert" aria-live="assertive">
          {submitError}
        </div>
      )}

      {/* Wallet Address */}
      <ValidatedInput
        label="Stellar Wallet Address"
        type="text"
        placeholder="G..."
        required
        helperText="Your Stellar public key starting with G"
        leftIcon={<span>👛</span>}
        validation={walletValidation.validation}
        showError={walletValidation.showError}
        {...walletValidation.bind}
      />

      {/* Amount */}
      <ValidatedInput
        label="Deposit Amount"
        type="text"
        placeholder="100.00"
        required
        helperText="Minimum 1 USDC, maximum 100,000 USDC"
        leftIcon={<span>💰</span>}
        validation={amountValidation.validation}
        showError={amountValidation.showError}
        {...amountValidation.bind}
      />

      {/* Goal Name */}
      <ValidatedInput
        label="Savings Goal Name"
        type="text"
        placeholder="Emergency Fund"
        required
        helperText="Give your savings goal a memorable name"
        leftIcon={<span>🎯</span>}
        validation={goalValidation.validation}
        showError={goalValidation.showError}
        {...goalValidation.bind}
      />

      {/* Duration */}
      <ValidatedInput
        label="Lock Duration (days)"
        type="text"
        placeholder="30"
        required
        helperText="How long to lock your savings (1-3650 days)"
        leftIcon={<span>📅</span>}
        validation={durationValidation.validation}
        showError={durationValidation.showError}
        {...durationValidation.bind}
      />

      {/* Submit button */}
      <button
        type="submit"
        className={styles.submitButton}
        disabled={isSubmitting}
        aria-busy={isSubmitting}
      >
        {isSubmitting ? (
          <>
            <span className={styles.buttonSpinner} aria-hidden="true" />
            Creating Deposit...
          </>
        ) : (
          'Create Savings Deposit'
        )}
      </button>
    </form>
  );
};