import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  Unique,
} from 'typeorm';

/**
 * Status of a ledger entry. Lifecycle:
 *
 *   reserve()             → `pending`
 *     ├─ commit(size)     → `committed`
 *     ├─ release(reason)  → `released`
 *     └─ expire (sweeper) → `expired`
 *
 * The signed `byteDelta` of every `committed` entry contributes to
 * `StorageQuota.usedBytes`. The signed `byteDelta` of every `released` or
 * `expired` entry restores the underlying bytes back to `reservedBytes` / free
 * quota space but does not change `usedBytes`.
 */
export enum QuotaLedgerStatus {
  PENDING = 'pending',
  COMMITTED = 'committed',
  RELEASED = 'released',
  EXPIRED = 'expired',
}

export enum QuotaUploadKind {
  AVATAR = 'avatar',
  KYC_DOCUMENT = 'kyc_document',
  DISPUTE_EVIDENCE = 'dispute_evidence',
  FEEDBACK_SCREENSHOT = 'feedback_screenshot',
  GENERIC = 'generic',
}

/**
 * Append-only ledger of every quota reservation / commit / release.
 *
 * Reconciliation semantics:
 *
 * - `byteDelta` is signed. `reserve()` writes +size, `commit()` writes 0
 *   (terminal state), `release()` writes -size, `expire` writes -size.
 * - `reservedBytes` and `usedBytes` on the parent StorageQuota row are kept
 *   consistent via atomic SQL inside StorageQuotaService. They can always be
 *   **recomputed** from this ledger if the row ever drifts.
 */
@Entity('storage_quota_ledger')
@Unique('uq_storage_quota_ledger_reservation', ['reservationId'])
@Index(['userId', 'createdAt'])
@Index(['tenantId', 'createdAt'])
@Index(['status', 'expiresAt'])
@Index(['uploadKind', 'uploadId'])
export class StorageQuotaLedger {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Stable token returned by reserve(). Other ops reference rows by this. */
  @Column({ type: 'varchar', length: 64 })
  reservationId: string;

  @Column('uuid')
  userId: string;

  @Column({ type: 'varchar', length: 64, default: '' })
  tenantId: string;

  @Column({
    type: 'enum',
    enum: QuotaUploadKind,
    default: QuotaUploadKind.GENERIC,
  })
  uploadKind: QuotaUploadKind;

  @Column({ type: 'varchar', length: 128, nullable: true })
  uploadId: string | null;

  /** Bytes signed: +N for reserve, -N for release/expire, 0 for commit. */
  @Column({ type: 'bigint' })
  byteDelta: number;

  @Column({
    type: 'enum',
    enum: QuotaLedgerStatus,
    default: QuotaLedgerStatus.PENDING,
  })
  status: QuotaLedgerStatus;

  /**
   * Pending reservations that never reach terminal state become orphans if
   * the process dies. The cleanup sweeper transitions them to `EXPIRED`.
   */
  @Column({ type: 'timestamptz', nullable: true })
  expiresAt: Date | null;

  /** Final byte size used at commit time (may differ from initial reserve). */
  @Column({ type: 'bigint', nullable: true })
  finalBytes: number | null;

  @Column({ type: 'varchar', length: 256, nullable: true })
  reason: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
