import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';

export enum TxType {
  DEPOSIT = 'DEPOSIT',
  WITHDRAW = 'WITHDRAW',
  SWAP = 'SWAP',
  YIELD = 'YIELD',
}

export enum TxStatus {
  CREATED = 'CREATED',
  PENDING_CONFIRMATION = 'PENDING_CONFIRMATION',
  CONFIRMED = 'CONFIRMED',
  COMPLETED = 'COMPLETED',
  PENDING = 'PENDING',
  FAILED = 'FAILED',
  REVERSED = 'REVERSED',
  DISPUTED = 'DISPUTED',
}

export enum TransactionCategory {
  GROCERIES = 'Groceries',
  DINING = 'Dining',
  TRANSPORT = 'Transport',
  SHOPPING = 'Shopping',
  ENTERTAINMENT = 'Entertainment',
  UTILITIES = 'Utilities',
  RENT = 'Rent',
  INCOME = 'Income',
  SAVINGS = 'Savings',
  INVESTMENT = 'Investment',
  OTHER = 'Other',
}

@Entity('transactions')
@Unique(['txHash'])
export class Transaction extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Index('idx_transactions_user_id')
  @Column('uuid')
  userId: string;

  @Column('uuid', { nullable: true })
  tenantId: string | null;

  @Column({ type: 'enum', enum: TxType })
  type: TxType;

  @Column('decimal', { precision: 18, scale: 7 })
  amount: string;

  @Column({ type: 'varchar' })
  txHash?: string | null;

  @Column({ type: 'enum', enum: TxStatus, default: TxStatus.CREATED })
  status?: TxStatus;

  @Column({ type: 'varchar', nullable: true })
  publicKey: string | null;

  @Index('idx_transactions_event_id', { unique: true })
  @Column({ type: 'varchar', nullable: true })
  eventId: string | null;

  @Column({ type: 'bigint', nullable: true })
  ledgerSequence: string | null;

  @Column({ type: 'varchar', nullable: true })
  poolId: string | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown> | null;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'boolean', default: false })
  flagged: boolean;

  @Column({ type: 'varchar', nullable: true })
  category: string | null;

  // Tags stored as postgres text[] for efficient filtering/overlap checks
  @Column('text', { array: true, default: () => 'ARRAY[]::text[]' })
  tags: string[];

  get transactionHash(): string | null | undefined {
    return this.txHash;
  }

  set transactionHash(value: string | null | undefined) {
    this.txHash = value;
  }
}
