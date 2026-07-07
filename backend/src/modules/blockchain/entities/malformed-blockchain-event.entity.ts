import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

/**
 * MalformedBlockchainEvent — Quarantine Entity (#1133)
 *
 * When a Soroban event fails schema validation or cannot be safely parsed,
 * the raw payload is persisted here for later investigation instead of
 * silently dropped.  This prevents data loss while keeping the main event
 * pipeline crash-free.
 *
 * Rows are never updated — only inserted and (optionally) soft-deleted once
 * resolved.
 */
export enum QuarantineReason {
  /** The event does not have the required fields (e.g. missing topic or value). */
  MISSING_REQUIRED_FIELDS = 'MISSING_REQUIRED_FIELDS',
  /** A field contains an unexpected type (e.g. amount is not a string/number). */
  TYPE_MISMATCH = 'TYPE_MISMATCH',
  /** The payload object has an unexpected structure (e.g. topic is not an array). */
  INVALID_SCHEMA = 'INVALID_SCHEMA',
  /** Amount string cannot be parsed as a finite number. */
  UNPARSEABLE_AMOUNT = 'UNPARSEABLE_AMOUNT',
  /** Public key / address field is missing or empty. */
  MISSING_PUBLIC_KEY = 'MISSING_PUBLIC_KEY',
  /** XDR value could not be decoded. */
  XDR_DECODE_ERROR = 'XDR_DECODE_ERROR',
  /** A handler threw an unexpected error not covered by the above categories. */
  HANDLER_ERROR = 'HANDLER_ERROR',
  /** Catch-all for cases that don't fit any specific category. */
  UNKNOWN = 'UNKNOWN',
}

export enum QuarantineStatus {
  /** Awaiting investigation. */
  PENDING = 'PENDING',
  /** An operator is actively investigating. */
  UNDER_REVIEW = 'UNDER_REVIEW',
  /** The event was reprocessed successfully after manual remediation. */
  RESOLVED = 'RESOLVED',
  /** The event was confirmed as genuinely invalid and discarded. */
  DISCARDED = 'DISCARDED',
}

@Entity('malformed_blockchain_events')
@Index('idx_mbe_reason', ['reason'])
@Index('idx_mbe_status', ['status'])
@Index('idx_mbe_event_type', ['eventType'])
@Index('idx_mbe_ledger_sequence', ['ledgerSequence'])
@Index('idx_mbe_created_at', ['createdAt'])
export class MalformedBlockchainEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Human-readable event type resolved from the topic (e.g. 'Deposit',
   * 'Withdraw', 'Yield', or 'unknown').
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  eventType: string | null;

  /** Ledger sequence number from the event, if present. */
  @Column({ type: 'bigint', nullable: true })
  ledgerSequence: number | null;

  /** Transaction hash, if present. */
  @Column({ type: 'varchar', length: 255, nullable: true })
  txHash: string | null;

  /** Original event id from the RPC response. */
  @Column({ type: 'varchar', length: 255, nullable: true })
  eventId: string | null;

  /** Category of the schema or parsing failure. */
  @Column({ type: 'enum', enum: QuarantineReason })
  reason: QuarantineReason;

  /** Human-readable description of the specific validation error. */
  @Column({ type: 'text' })
  errorDetails: string;

  /**
   * Full raw event payload serialised to JSON.  Stored as text so that even
   * payloads that cannot be serialised cleanly are preserved.
   */
  @Column({ type: 'text' })
  rawEvent: string;

  /**
   * Investigation / remediation status.
   * Defaults to PENDING so new entries surface in triage dashboards immediately.
   */
  @Column({
    type: 'enum',
    enum: QuarantineStatus,
    default: QuarantineStatus.PENDING,
  })
  status: QuarantineStatus;

  /** Optional resolution notes added by an operator. */
  @Column({ type: 'text', nullable: true })
  resolutionNotes: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
