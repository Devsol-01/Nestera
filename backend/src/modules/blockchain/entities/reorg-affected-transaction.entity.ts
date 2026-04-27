import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { ReorgAuditLog } from './reorg-audit-log.entity';

/**
 * ReorgAffectedTransaction Entity
 *
 * Tracks individual transactions affected by a blockchain reorganization.
 */
export enum ReorgTransactionAction {
  REVERTED = 'REVERTED',
  REPROCESSED = 'REPROCESSED',
  FAILED_REVERT = 'FAILED_REVERT',
  FAILED_REPROCESS = 'FAILED_REPROCESS',
}

@Entity('reorg_affected_transactions')
@Index('idx_reorg_affected_transactions_event_id', ['eventId'])
@Index('idx_reorg_affected_transactions_tx_hash', ['txHash'])
export class ReorgAffectedTransaction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => ReorgAuditLog, (reorg) => reorg.affectedTransactions, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'reorgAuditLogId' })
  reorgAuditLog: ReorgAuditLog;

  @Column('uuid')
  reorgAuditLogId: string;

  /** The event ID from the processed event */
  @Column({ type: 'varchar', nullable: true })
  eventId: string | null;

  /** Transaction hash */
  @Column({ type: 'varchar', nullable: true })
  txHash: string | null;

  /** Ledger sequence where this was recorded */
  @Column({ type: 'bigint', nullable: true })
  ledgerSequence: number | null;

  /** User ID affected */
  @Column({ type: 'varchar', nullable: true })
  userId: string | null;

  /** Transaction type (DEPOSIT, WITHDRAW, etc.) */
  @Column({ type: 'varchar', nullable: true })
  transactionType: string | null;

  /** Amount involved */
  @Column({ type: 'varchar', nullable: true })
  amount: string | null;

  /** Action taken for this transaction during reorg handling */
  @Column({ type: 'enum', enum: ReorgTransactionAction, nullable: true })
  action: ReorgTransactionAction | null;

  /** Details about the action taken */
  @Column({ type: 'jsonb', nullable: true })
  actionDetails: Record<string, any> | null;

  /** Error message if action failed */
  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  @Column({ type: 'jsonb', nullable: true })
  originalEventData: Record<string, any> | null;

  @CreateDateColumn()
  createdAt: Date;
}
