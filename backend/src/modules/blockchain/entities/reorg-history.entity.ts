import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

/**
 * ReorgHistory records chain reorganization events for audit and recovery.
 * Each entry represents a detected reorg with its scope and resolution status.
 *
 * Requirements: 2.1 (reorg detection logging), 2.2 (rollback tracking)
 */
@Entity('reorg_history')
export class ReorgHistory {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * The ledger sequence where the reorg was detected
   * This is the first ledger that appeared invalid
   */
  @Column({ type: 'bigint' })
  @Index()
  detectedAtLedger: number;

  /**
   * The last valid ledger before the reorg started (common ancestor)
   * Used as the rollback target
   */
  @Column({ type: 'bigint' })
  rollbackToLedger: number;

  /**
   * JSON array of affected account IDs
   * Format: ["G...", "G..."]
   */
  @Column({ type: 'json', nullable: true })
  affectedAccounts: string[] | null;

  /**
   * Number of balance snapshots that were rolled back
   */
  @Column({ type: 'integer', default: 0 })
  rolledBackSnapshots: number;

  /**
   * Number of balance snapshots that were re-applied after reorg resolution
   */
  @Column({ type: 'integer', default: 0 })
  reappliedSnapshots: number;

  /**
   * Current status of reorg handling
   */
  @Column({ type: 'varchar', length: 20, default: 'detected' })
  status: 'detected' | 'rollback_complete' | 'resolved';

  /**
   * Human-readable description of the reorg cause
   * May include external API response details
   */
  @Column({ type: 'text', nullable: true })
  description: string | null;

  /**
   * Timestamp when the reorg was first detected
   */
  @CreateDateColumn()
  detectedAt: Date;

  /**
   * Timestamp when the reorg was fully resolved
   */
  @Column({ type: 'timestamp', nullable: true })
  resolvedAt: Date | null;
}
