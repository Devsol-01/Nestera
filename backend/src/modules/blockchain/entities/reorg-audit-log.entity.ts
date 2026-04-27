import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { ReorgAffectedTransaction } from './reorg-affected-transaction.entity';

/**
 * ReorgAuditLog Entity
 *
 * Tracks blockchain reorganization events and their impact.
 * Each record represents a detected blockchain fork/reorganization.
 */
export enum ReorgStatus {
  DETECTED = 'DETECTED',
  REVERTED = 'REVERTED',
  REPROCESSED = 'REPROCESSED',
  COMPLETED = 'COMPLETED',
}

@Entity('reorg_audit_logs')
@Index('idx_reorg_audit_logs_detected_at', ['detectedAt'])
@Index('idx_reorg_audit_logs_status', ['status'])
export class ReorgAuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** The chain ID (e.g., 'testnet', 'mainnet') */
  @Column()
  chainId: string;

  /** The sequence number of the reorg point (common ancestor ledger) */
  @Column({ type: 'bigint' })
  reorgPointLedger: number;

  /** The first ledger of the old branch that was orphaned */
  @Column({ type: 'bigint' })
  oldBranchStartLedger: number;

  /** The last ledger of the old branch that was orphaned */
  @Column({ type: 'bigint' })
  oldBranchEndLedger: number;

  /** The first ledger of the new canonical branch */
  @Column({ type: 'bigint' })
  newBranchStartLedger: number;

  /** The last ledger of the new canonical branch (current) */
  @Column({ type: 'bigint' })
  newBranchEndLedger: number;

  /** Number of events affected by the reorg */
  @Column({ type: 'int', default: 0 })
  affectedEventsCount: number;

  /** Number of transactions reverted */
  @Column({ type: 'int', default: 0 })
  revertedTransactionsCount: number;

  /** Number of transactions re-applied from new chain */
  @Column({ type: 'int', default: 0 })
  reprocessedTransactionsCount: number;

  /** Number of users notified */
  @Column({ type: 'int', default: 0 })
  notifiedUsersCount: number;

  /** Current status of reorg handling */
  @Column({ type: 'enum', enum: ReorgStatus, default: ReorgStatus.DETECTED })
  status: ReorgStatus;

  /** Detected timestamp */
  @CreateDateColumn()
  detectedAt: Date;

  /** When reorg handling was completed */
  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date | null;

  /** Error message if reorg handling failed */
  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  /** Affected transactions */
  @OneToMany(() => ReorgAffectedTransaction, (t) => t.reorgAuditLog, {
    cascade: true,
  })
  affectedTransactions: ReorgAffectedTransaction[];

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;
}
