import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';

/**
 * Per-user (optionally per-tenant) storage quota state.
 *
 * Mutated **only** via atomic SQL `UPDATE ... WHERE used_bytes + $1 <= max_total_bytes`
 * expressions implemented in {@link StorageQuotaService}. Never update
 * `usedBytes` / `activeUploads` via TypeORM `save()` — that path is not
 * concurrency-safe and will cause quota drift under load.
 */
@Entity('storage_quotas')
@Unique('uq_storage_quotas_user_tenant', ['userId', 'tenantId'])
@Index(['userId'])
export class StorageQuota {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  /** Empty string when multi-tenant is disabled (single-tenant deployments). */
  @Column({ type: 'varchar', length: 64, default: '' })
  tenantId: string;

  /** Configured max bytes this user may store. Tier-driven. */
  @Column({ type: 'bigint', default: 0 })
  maxTotalBytes: number;

  /** Sum of bytes currently accounted for by `committed` ledger entries. */
  @Column({ type: 'bigint', default: 0 })
  usedBytes: number;

  /**
   * Sum of bytes currently held by `pending` (reserved-but-uncommitted) ledger
   * entries. Counts toward `maxTotalBytes` for reservation checks but does
   * not count toward `usedBytes` until the upload is committed.
   */
  @Column({ type: 'bigint', default: 0 })
  reservedBytes: number;

  @Column({ type: 'int', default: 0 })
  maxActiveUploads: number;

  @Column({ type: 'int', default: 0 })
  activeUploads: number;

  @Column({ type: 'int', default: 0 })
  maxUploadsPerHour: number;

  /**
   * Floor used by the upload-frequency limiter. Increments atomically with
   * each successful reservation, and is reset by the cleanup sweeper.
   */
  @Column({ type: 'int', default: 0 })
  uploadsThisHour: number;

  @Column({ type: 'timestamptz', nullable: true })
  uploadWindowStartedAt: Date | null;

  /** User-facing tier label captured at row creation (for audit/debug). */
  @Column({ type: 'varchar', length: 32, default: 'free' })
  tier: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  /** Lock version for migrations / admin overrides. Not used by atomic SQL. */
  @Column({ type: 'int', default: 0 })
  version: number;
}
