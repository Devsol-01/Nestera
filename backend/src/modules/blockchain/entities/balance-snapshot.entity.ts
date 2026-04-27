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
 * BalanceSnapshot stores historical balance states for each account and asset.
 * It enables chain reorganization detection and rollback by maintaining
 * a complete audit trail of balance changes with associated ledger sequences.
 *
 * Requirements: 2.1 (reorg detection), 2.2 (rollback), 2.3 (confirmation depth)
 */
@Entity('balance_snapshots')
@Unique(['accountId', 'assetCode', 'ledgerSequence'])
export class BalanceSnapshot {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Stellar public key of the account
   */
  @Column({ type: 'varchar', length: 56 })
  @Index()
  accountId: string;

  /**
   * Asset code: 'native' for XLM, otherwise the asset code string
   */
  @Column({ type: 'varchar', length: 20 })
  @Index()
  assetCode: string;

  /**
   * Balance amount as string to avoid floating-point precision loss
   */
  @Column({ type: 'varchar' })
  balance: string;

  /**
   * The ledger sequence number when this snapshot was recorded
   * Used for reorg detection and rollback
   */
  @Column({ type: 'bigint' })
  @Index()
  ledgerSequence: number;

  /**
   * Hash of the transaction that triggered this balance change (if applicable)
   * Null for system-initiated or aggregated changes
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  transactionHash: string | null;

  /**
   * Operation ID within the transaction for precise identification
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  operationId: string | null;

  /**
   * Whether this snapshot is considered confirmed (past confirmation depth)
   * Helps optimize queries for confirmed balances
   */
  @Column({ type: 'boolean', default: false })
  isConfirmed: boolean;

  /**
   * Timestamp when the ledger containing this change was closed
   * This is closeTime of the ledger
   */
  @Column({ type: 'timestamp' })
  snapshotTime: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
