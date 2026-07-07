/**
 * Issue #1112 – Contract Event Schema Validation (Runtime)
 *
 * ContractEventValidatorService is an injectable NestJS service that validates
 * incoming Soroban event envelopes and decoded payloads against the schemas
 * defined in contract-event-schema.ts.
 *
 * Design decisions
 * ─────────────────
 * • Validation is NEVER blocking.  A schema mismatch emits a structured warn /
 *   error log and returns false, but does not throw and does not halt event
 *   processing.  The caller decides whether to proceed.
 * • All log lines carry a consistent context object so they are machine-readable
 *   and compatible with the project's structured-logging patterns.
 * • The service is stateless and has no database dependencies, keeping it
 *   lightweight and easy to unit-test.
 */

import { Injectable, Logger } from '@nestjs/common';
import {
  ContractEventType,
  SchemaViolation,
  ValidationResult,
  validateSorobanEventEnvelope,
  validateEventPayloadByType,
} from './contract-event-schema';

// ---------------------------------------------------------------------------
// Public interface types
// ---------------------------------------------------------------------------

/** Context attached to every structured log / alert emitted by this service. */
export interface ValidationAlertContext {
  /** The symbolic name of the calling handler (e.g. 'DepositHandler'). */
  handlerName: string;
  /** Synthetic or raw event ID (matches indexer log convention). */
  eventId: string | null;
  /** Ledger sequence number; null when unknown. */
  ledgerSequence: number | null;
  /** Contract ID if available. */
  contractId?: string | null;
  /** Which validation step failed: 'envelope' or the event-type name. */
  validationTarget: 'envelope' | ContractEventType;
  /** Structured list of violations. */
  violations: SchemaViolation[];
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

@Injectable()
export class ContractEventValidatorService {
  readonly logger = new Logger(ContractEventValidatorService.name);

  // -------------------------------------------------------------------------
  // Envelope validation
  // -------------------------------------------------------------------------

  /**
   * Validate the raw (pre-decoding) Soroban event envelope.
   *
   * Should be called at the BEGINNING of each handler's `handle()` method,
   * before any XDR decoding, so that structurally invalid events are flagged
   * immediately.
   *
   * @returns `true` if the envelope is valid; `false` with a logged warning
   *          otherwise.  Processing can continue either way.
   */
  validateEnvelope(
    event: Record<string, unknown>,
    context: {
      handlerName: string;
      eventId: string | null;
      ledgerSequence: number | null;
      contractId?: string | null;
    },
  ): boolean {
    let result: ValidationResult;
    try {
      result = validateSorobanEventEnvelope(event);
    } catch (err) {
      // The schema function itself should never throw, but guard against it
      this.logger.error(
        'ContractEventValidatorService: unexpected error during envelope validation',
        {
          handlerName: context.handlerName,
          eventId: context.eventId,
          ledgerSequence: context.ledgerSequence,
          contractId: context.contractId ?? null,
          validationTarget: 'envelope',
          error: (err as Error).message,
        },
      );
      return false;
    }

    if (!result.valid) {
      this.emitViolationAlert({
        handlerName: context.handlerName,
        eventId: context.eventId,
        ledgerSequence: context.ledgerSequence,
        contractId: context.contractId ?? null,
        validationTarget: 'envelope',
        violations: result.violations,
      });
    }

    return result.valid;
  }

  // -------------------------------------------------------------------------
  // Decoded payload validation
  // -------------------------------------------------------------------------

  /**
   * Validate a decoded (native JS object) payload against the schema for the
   * given event type.
   *
   * Should be called immediately AFTER the handler decodes the XDR value into
   * a plain object, so that unexpected field shapes (e.g., due to a contract
   * upgrade) are detected and logged before further processing.
   *
   * @returns `true` if valid; `false` with a logged warning otherwise.
   */
  validatePayload(
    eventType: ContractEventType,
    payload: Record<string, unknown>,
    context: {
      handlerName: string;
      eventId: string | null;
      ledgerSequence: number | null;
      contractId?: string | null;
    },
  ): boolean {
    let result: ValidationResult;
    try {
      result = validateEventPayloadByType(eventType, payload);
    } catch (err) {
      this.logger.error(
        'ContractEventValidatorService: unexpected error during payload validation',
        {
          handlerName: context.handlerName,
          eventId: context.eventId,
          ledgerSequence: context.ledgerSequence,
          contractId: context.contractId ?? null,
          validationTarget: eventType,
          error: (err as Error).message,
        },
      );
      return false;
    }

    if (!result.valid) {
      this.emitViolationAlert({
        handlerName: context.handlerName,
        eventId: context.eventId,
        ledgerSequence: context.ledgerSequence,
        contractId: context.contractId ?? null,
        validationTarget: eventType,
        violations: result.violations,
      });
    }

    return result.valid;
  }

  // -------------------------------------------------------------------------
  // Alert emission
  // -------------------------------------------------------------------------

  /**
   * Emit a structured WARN log for schema violations.
   *
   * Using `warn` (not `error`) because a schema mismatch is a signal that
   * the contract may have changed, but we still want to attempt processing
   * rather than silently drop the event.  The caller can escalate to an
   * error after deciding how to handle the mismatch.
   */
  private emitViolationAlert(ctx: ValidationAlertContext): void {
    const violationSummary = ctx.violations
      .map(
        (v) =>
          `[${v.field}] ${v.message} (received: ${JSON.stringify(v.received)})`,
      )
      .join(' | ');

    this.logger.warn(
      `ContractEventValidatorService: schema violation detected on ${ctx.validationTarget}`,
      {
        handlerName: ctx.handlerName,
        eventId: ctx.eventId,
        ledgerSequence: ctx.ledgerSequence,
        contractId: ctx.contractId ?? null,
        validationTarget: ctx.validationTarget,
        violationCount: ctx.violations.length,
        violations: ctx.violations,
        violationSummary,
      },
    );
  }
}
