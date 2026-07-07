/**
 * Issue #1112 – Contract Event Schema Validation (Runtime)
 *
 * Defines the expected payload shapes for each Soroban contract event type
 * processed by the blockchain indexer, plus a lightweight schema-check helper
 * that returns structured violation descriptors without throwing.
 *
 * Design notes
 * ─────────────
 * • Uses pure TypeScript interfaces and manual checks instead of an extra
 *   runtime schema library (the project already has class-validator / joi but
 *   adding Zod just for this would be scope-creep).
 * • Every validator returns `SchemaViolation[]`.  An empty array means valid.
 * • Checks are intentionally non-throwing – callers decide how to handle
 *   violations (log, alert, reject, or continue).
 */

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type ContractEventType = 'Deposit' | 'Withdraw' | 'Yield';

/** A single schema violation found during validation. */
export interface SchemaViolation {
  /** Path to the violating field (dot-notation). */
  field: string;
  /** Human-readable description of the problem. */
  message: string;
  /** The actual value that was received (for logging; may be any type). */
  received: unknown;
}

/** Result returned by all validate* functions. */
export interface ValidationResult {
  valid: boolean;
  violations: SchemaViolation[];
}

// ---------------------------------------------------------------------------
// Base Soroban event envelope schema
// ---------------------------------------------------------------------------

/**
 * Minimal required fields that every Soroban event received by the indexer
 * must carry.  These are checked BEFORE the payload is decoded.
 */
export interface SorobanEventEnvelope {
  id?: string;
  ledger: number;
  topic?: unknown[];
  value?: unknown;
  txHash?: string;
  contractId?: string;
}

/**
 * Validate the top-level envelope of a raw Soroban event.
 *
 * @param event  Raw event object as produced by the Stellar RPC.
 * @returns      ValidationResult with any discovered violations.
 */
export function validateSorobanEventEnvelope(
  event: Record<string, unknown>,
): ValidationResult {
  const violations: SchemaViolation[] = [];

  // ledger must be a positive integer
  if (
    typeof event['ledger'] !== 'number' ||
    !Number.isInteger(event['ledger']) ||
    event['ledger'] <= 0
  ) {
    violations.push({
      field: 'ledger',
      message: 'Must be a positive integer',
      received: event['ledger'],
    });
  }

  // topic must be a non-empty array
  if (
    !Array.isArray(event['topic']) ||
    (event['topic'] as unknown[]).length === 0
  ) {
    violations.push({
      field: 'topic',
      message: 'Must be a non-empty array',
      received: event['topic'],
    });
  }

  // value must be present (not null/undefined)
  if (event['value'] === undefined || event['value'] === null) {
    violations.push({
      field: 'value',
      message: 'Must be present',
      received: event['value'],
    });
  }

  // id should be a non-empty string (warn, not error – indexer can synthesise it)
  if (
    event['id'] !== undefined &&
    (typeof event['id'] !== 'string' || event['id'].trim() === '')
  ) {
    violations.push({
      field: 'id',
      message: 'When provided, must be a non-empty string',
      received: event['id'],
    });
  }

  // txHash should be a non-empty string when provided
  if (
    event['txHash'] !== undefined &&
    (typeof event['txHash'] !== 'string' || event['txHash'].trim() === '')
  ) {
    violations.push({
      field: 'txHash',
      message: 'When provided, must be a non-empty string',
      received: event['txHash'],
    });
  }

  return { valid: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------
// Deposit payload schema
// ---------------------------------------------------------------------------

/**
 * Expected shape of the decoded Deposit event payload.
 * Produced after XDR/ScVal decoding in DepositHandler.extractPayload().
 */
export interface DepositPayloadSchema {
  publicKey: string;
  amount: string; // Numeric string, > 0
}

/**
 * Validate a decoded Deposit payload.
 */
export function validateDepositPayload(
  payload: Record<string, unknown>,
): ValidationResult {
  return validateTransferPayload('Deposit', payload);
}

// ---------------------------------------------------------------------------
// Withdraw payload schema
// ---------------------------------------------------------------------------

/**
 * Expected shape of the decoded Withdraw event payload.
 */
export interface WithdrawPayloadSchema {
  publicKey: string;
  amount: string;
}

/**
 * Validate a decoded Withdraw payload.
 */
export function validateWithdrawPayload(
  payload: Record<string, unknown>,
): ValidationResult {
  return validateTransferPayload('Withdraw', payload);
}

// ---------------------------------------------------------------------------
// Yield payload schema
// ---------------------------------------------------------------------------

/**
 * Expected shape of the decoded Yield event payload.
 * The amount represents interest earned (positive value).
 */
export interface YieldPayloadSchema {
  publicKey: string;
  amount: string;
}

/**
 * Validate a decoded Yield payload.
 */
export function validateYieldPayload(
  payload: Record<string, unknown>,
): ValidationResult {
  return validateTransferPayload('Yield', payload);
}

// ---------------------------------------------------------------------------
// Dispatch helper – validate by event type
// ---------------------------------------------------------------------------

/**
 * Validate a decoded payload against the schema for the given event type.
 *
 * @param eventType  One of 'Deposit' | 'Withdraw' | 'Yield'.
 * @param payload    Decoded (native) payload object.
 * @returns          ValidationResult.
 */
export function validateEventPayloadByType(
  eventType: ContractEventType,
  payload: Record<string, unknown>,
): ValidationResult {
  switch (eventType) {
    case 'Deposit':
      return validateDepositPayload(payload);
    case 'Withdraw':
      return validateWithdrawPayload(payload);
    case 'Yield':
      return validateYieldPayload(payload);
    default: {
      // Narrow to never so TypeScript enforces exhaustiveness at compile time
      const _exhaustive: never = eventType;
      return {
        valid: false,
        violations: [
          {
            field: 'eventType',
            message: `Unknown event type: ${String(_exhaustive)}`,
            received: _exhaustive,
          },
        ],
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Private shared validator
// ---------------------------------------------------------------------------

/**
 * Both Deposit, Withdraw and Yield have the same decoded shape:
 * { publicKey: string, amount: numericString }.
 * This function validates that shape and is reused by all three.
 */
function validateTransferPayload(
  label: string,
  payload: Record<string, unknown>,
): ValidationResult {
  const violations: SchemaViolation[] = [];

  // publicKey: non-empty string
  if (
    typeof payload['publicKey'] !== 'string' ||
    payload['publicKey'].trim() === ''
  ) {
    violations.push({
      field: 'publicKey',
      message: `${label} payload.publicKey must be a non-empty string`,
      received: payload['publicKey'],
    });
  }

  // amount: string that parses to a finite positive number
  if (
    typeof payload['amount'] !== 'string' ||
    payload['amount'].trim() === ''
  ) {
    violations.push({
      field: 'amount',
      message: `${label} payload.amount must be a non-empty string`,
      received: payload['amount'],
    });
  } else {
    const numeric = Number(payload['amount']);
    if (Number.isNaN(numeric)) {
      violations.push({
        field: 'amount',
        message: `${label} payload.amount must be a numeric string`,
        received: payload['amount'],
      });
    } else if (!Number.isFinite(numeric)) {
      violations.push({
        field: 'amount',
        message: `${label} payload.amount must be a finite number`,
        received: payload['amount'],
      });
    } else if (numeric <= 0) {
      violations.push({
        field: 'amount',
        message: `${label} payload.amount must be greater than zero`,
        received: payload['amount'],
      });
    }
  }

  return { valid: violations.length === 0, violations };
}
