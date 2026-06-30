import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { scValToNative, xdr } from '@stellar/stellar-sdk';
import {
  MalformedBlockchainEvent,
  QuarantineReason,
  QuarantineStatus,
} from '../entities/malformed-blockchain-event.entity';

// ─── Types ────────────────────────────────────────────────────────────────────

/** Minimal shape that every incoming Soroban event must satisfy. */
export interface RawBlockchainEvent {
  id?: string;
  ledger?: number;
  topic?: unknown;
  value?: unknown;
  txHash?: string;
  contractId?: string;
  [key: string]: unknown;
}

/** Result of a successful parse. */
export interface ParsedEventPayload {
  publicKey: string;
  amount: string;
  eventId: string;
  txHash: string | null;
  ledgerSequence: string | null;
  /** Decoded topic items (best-effort). */
  topicSymbols: string[];
  /** Safe copy of the full raw event for audit metadata. */
  rawMeta: {
    topic: unknown;
    rawValueType: string;
  };
}

/** Returned by the parser on failure — caller must quarantine and return false. */
export interface ParseFailure {
  ok: false;
  reason: QuarantineReason;
  errorDetails: string;
}

/** Returned by the parser on success. */
export interface ParseSuccess {
  ok: true;
  payload: ParsedEventPayload;
}

export type ParseResult = ParseSuccess | ParseFailure;

// ─── BlockchainEventParser ────────────────────────────────────────────────────

/**
 * BlockchainEventParser  (#1133)
 *
 * Centralises all schema validation and XDR decoding for incoming Soroban
 * events.  When validation fails the service:
 *  1. Returns a ParseFailure with a machine-readable QuarantineReason.
 *  2. The handler then calls quarantineEvent() to persist the raw event in the
 *     `malformed_blockchain_events` table for later investigation.
 *
 * Safe defaults:
 *  - topic is treated as an empty array if missing/null.
 *  - All string coercions are guarded; BigInt is converted to string.
 *  - XDR decode errors are caught and surfaced as QuarantineReason.XDR_DECODE_ERROR.
 */
@Injectable()
export class BlockchainEventParser {
  private readonly logger = new Logger(BlockchainEventParser.name);

  constructor(
    @InjectRepository(MalformedBlockchainEvent)
    private readonly quarantineRepo: Repository<MalformedBlockchainEvent>,
  ) {}

  // ─── Core parse methods ───────────────────────────────────────────────────

  /**
   * Validates and extracts the standard (publicKey, amount) payload from an
   * event that is expected to match one of the deposit/withdraw/yield shapes.
   *
   * Accepts an optional list of candidate field names for `publicKey` and
   * `amount` so that each handler can drive the extraction from a single
   * central place.
   */
  parseStandardPayload(
    event: RawBlockchainEvent,
    opts: {
      eventType: string;
      publicKeyFields?: string[];
      amountFields?: string[];
    },
  ): ParseResult {
    const publicKeyFields = opts.publicKeyFields ?? [
      'publicKey',
      'userPublicKey',
      'user',
      'address',
      'to',
      'from',
    ];
    const amountFields = opts.amountFields ?? [
      'amount',
      'value',
      'amt',
      'yield',
      'interest',
      'user_yield',
      'actual_yield',
      'payout',
    ];

    // 1 — topic must be an array (or we normalise it to [])
    const topic = this.safeTopic(event.topic);

    // 2 — value field must be present and non-null
    if (event.value === undefined || event.value === null) {
      return {
        ok: false,
        reason: QuarantineReason.MISSING_REQUIRED_FIELDS,
        errorDetails: `${opts.eventType} event value is null/undefined`,
      };
    }

    // 3 — Decode the XDR value
    let decoded: unknown;
    try {
      decoded = this.decodeScVal(event.value);
    } catch (err) {
      return {
        ok: false,
        reason: QuarantineReason.XDR_DECODE_ERROR,
        errorDetails: `Failed to decode ${opts.eventType} value: ${(err as Error).message}`,
      };
    }

    // 4 — Normalise the decoded value to a record
    let record: Record<string, unknown>;
    try {
      record = this.toRecord(decoded, opts.eventType);
    } catch (err) {
      return {
        ok: false,
        reason: QuarantineReason.INVALID_SCHEMA,
        errorDetails: (err as Error).message,
      };
    }

    // 5 — Extract publicKey
    const publicKey = this.pickString(record, publicKeyFields);
    if (!publicKey) {
      return {
        ok: false,
        reason: QuarantineReason.MISSING_PUBLIC_KEY,
        errorDetails:
          `${opts.eventType} event is missing publicKey. ` +
          `Tried keys: [${publicKeyFields.join(', ')}]. ` +
          `Present keys: [${Object.keys(record).join(', ')}]`,
      };
    }

    // 6 — Extract amount
    const amountRaw = this.pickFirst(record, amountFields);
    const amount = this.coerceAmount(amountRaw);
    if (amount === null) {
      return {
        ok: false,
        reason: QuarantineReason.UNPARSEABLE_AMOUNT,
        errorDetails:
          `${opts.eventType} event amount is missing or not numeric. ` +
          `Tried keys: [${amountFields.join(', ')}], got: ${String(amountRaw)}`,
      };
    }

    // 7 — Build event id
    const eventId = this.resolveEventId(event, opts.eventType.toLowerCase());

    // 8 — Decode topic symbols (best-effort, never throws)
    const topicSymbols = this.decodeTopicSymbols(topic);

    return {
      ok: true,
      payload: {
        publicKey,
        amount,
        eventId,
        txHash: typeof event.txHash === 'string' ? event.txHash : null,
        ledgerSequence:
          typeof event.ledger === 'number' ? String(event.ledger) : null,
        topicSymbols,
        rawMeta: {
          topic: event.topic,
          rawValueType: typeof event.value,
        },
      },
    };
  }

  // ─── Quarantine ──────────────────────────────────────────────────────────

  /**
   * Persists a malformed event to the quarantine table.
   * Safe to call from any handler catch block — never throws.
   */
  async quarantineEvent(
    event: RawBlockchainEvent,
    reason: QuarantineReason,
    errorDetails: string,
    eventType?: string,
  ): Promise<void> {
    try {
      let rawEventJson: string;
      try {
        rawEventJson = JSON.stringify(event);
      } catch {
        // Last-resort serialisation — some fields may not be JSON-serialisable
        rawEventJson = String(event);
      }

      const entry = this.quarantineRepo.create({
        eventType: eventType ?? null,
        ledgerSequence:
          typeof event.ledger === 'number' ? event.ledger : null,
        txHash: typeof event.txHash === 'string' ? event.txHash : null,
        eventId: typeof event.id === 'string' ? event.id : null,
        reason,
        errorDetails,
        rawEvent: rawEventJson,
        status: QuarantineStatus.PENDING,
        resolutionNotes: null,
      });

      await this.quarantineRepo.save(entry);

      this.logger.warn(
        `Event quarantined: type=${eventType ?? 'unknown'} ` +
          `ledger=${event.ledger ?? 'n/a'} txHash=${event.txHash ?? 'n/a'} ` +
          `reason=${reason} details="${errorDetails}"`,
      );
    } catch (saveErr) {
      // Quarantine itself failed — log but never crash the caller
      this.logger.error(
        `CRITICAL: Failed to quarantine malformed event. ` +
          `Original error: ${errorDetails}. ` +
          `Quarantine save error: ${(saveErr as Error).message}`,
      );
    }
  }

  // ─── Validation helpers ────────────────────────────────────────────────────

  /**
   * Checks that an incoming event satisfies the bare-minimum structural
   * requirements before handlers attempt any further processing.
   *
   * Returns a ParseFailure when the event is structurally unworkable (e.g.
   * topic missing, ledger not a number).  Returns null when the event looks
   * safe to process further.
   */
  validateEventStructure(
    event: RawBlockchainEvent,
  ): ParseFailure | null {
    // ledger must be a non-negative integer
    if (typeof event.ledger !== 'number' || !Number.isFinite(event.ledger) || event.ledger < 0) {
      return {
        ok: false,
        reason: QuarantineReason.MISSING_REQUIRED_FIELDS,
        errorDetails: `Event missing valid ledger sequence (got: ${JSON.stringify(event.ledger)})`,
      };
    }

    // topic must be present (null/undefined counts as missing)
    if (event.topic === undefined || event.topic === null) {
      return {
        ok: false,
        reason: QuarantineReason.MISSING_REQUIRED_FIELDS,
        errorDetails: 'Event missing topic field',
      };
    }

    // topic must be array-like
    if (!Array.isArray(event.topic)) {
      return {
        ok: false,
        reason: QuarantineReason.INVALID_SCHEMA,
        errorDetails: `topic must be an array but got ${typeof event.topic}`,
      };
    }

    return null; // All good
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private safeTopic(topic: unknown): unknown[] {
    if (Array.isArray(topic)) return topic;
    return [];
  }

  private decodeScVal(value: unknown): unknown {
    if (
      value &&
      typeof value === 'object' &&
      'toXDR' in value &&
      typeof (value as { toXDR?: unknown }).toXDR === 'function'
    ) {
      const base64 = (value as { toXDR: (enc?: string) => string }).toXDR('base64');
      return scValToNative(xdr.ScVal.fromXDR(base64, 'base64'));
    }

    if (typeof value === 'string') {
      try {
        return scValToNative(xdr.ScVal.fromXDR(value, 'base64'));
      } catch {
        // Not XDR — return the raw string
        return value;
      }
    }

    return value;
  }

  private toRecord(value: unknown, eventType: string): Record<string, unknown> {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }

    // Some contracts emit arrays — try to map positionally
    if (Array.isArray(value)) {
      if (value.length >= 2) {
        return {
          publicKey: value[0],
          amount: value[3] ?? value[1],
        };
      }
      throw new Error(
        `${eventType} event value is an array with < 2 elements (length=${value.length})`,
      );
    }

    throw new Error(
      `Unexpected ${eventType} value shape: ${typeof value} (${String(value).slice(0, 80)})`,
    );
  }

  private pickString(
    record: Record<string, unknown>,
    keys: string[],
  ): string | null {
    for (const key of keys) {
      const val = record[key];
      if (typeof val === 'string' && val.trim().length > 0) {
        return val.trim();
      }
    }
    return null;
  }

  private pickFirst(
    record: Record<string, unknown>,
    keys: string[],
  ): unknown {
    for (const key of keys) {
      if (key in record) return record[key];
    }
    return undefined;
  }

  private coerceAmount(raw: unknown): string | null {
    if (raw === null || raw === undefined) return null;

    let str: string;
    if (typeof raw === 'bigint') {
      str = raw.toString();
    } else if (typeof raw === 'number') {
      str = String(raw);
    } else if (typeof raw === 'string') {
      str = raw.trim();
    } else {
      return null;
    }

    if (str.length === 0) return null;
    const n = Number(str);
    if (!Number.isFinite(n)) return null;
    return str;
  }

  private resolveEventId(event: RawBlockchainEvent, suffix: string): string {
    if (typeof event.id === 'string' && event.id.length > 0) {
      return event.id;
    }
    const txHash = typeof event.txHash === 'string' ? event.txHash : 'unknown';
    const ledger = typeof event.ledger === 'number' ? event.ledger : 0;
    return `${txHash}:${ledger}:${suffix}`;
  }

  private decodeTopicSymbols(topic: unknown[]): string[] {
    return topic.flatMap((item) => {
      if (typeof item === 'string') {
        try {
          const scVal = xdr.ScVal.fromXDR(item, 'base64');
          const native = scValToNative(scVal);
          return typeof native === 'string' ? [native] : [];
        } catch {
          return [item];
        }
      }
      return [];
    });
  }
}
