import {
  Entity,
  Column,
  PrimaryColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('processed_stellar_events')
@Index(['contractId', 'eventId'], { unique: true })
@Index('idx_processed_stellar_events_ledger', ['ledger'])
@Index('idx_processed_stellar_events_contract_ledger', ['contractId', 'ledger'])
@Index('idx_processed_stellar_events_tx_hash', ['transactionHash'])
@Index('idx_processed_stellar_events_not_reorged', ['isReorged'])
export class ProcessedStellarEvent {
  @PrimaryColumn()
  eventId: string;

  @Column()
  contractId: string;

  @Column()
  transactionHash: string;

  @Column({ type: 'bigint' })
  ledger: number;

  /** Ledger hash for reorg detection */
  @Column({ type: 'varchar', nullable: true })
  ledgerHash: string | null;

  @Column()
  eventType: string;

  @Column('jsonb')
  eventData: Record<string, any>;

  @Column({ nullable: true })
  claimId: string | null;

  /** Ledger close timestamp (helps with reorg detection) */
  @Column({ type: 'bigint', nullable: true })
  ledgerCloseTime: number | null;

  /** Indicates if this event is part of a reorg'd chain */
  @Column({ default: false })
  isReorged: boolean;

  /** The reorg audit log ID if this event was affected by a reorg */
  @Column({ type: 'varchar', nullable: true })
  reorgAuditLogId: string | null;

  @CreateDateColumn()
  processedAt: Date;
}

