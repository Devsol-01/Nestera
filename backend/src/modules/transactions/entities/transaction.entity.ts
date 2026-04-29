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
  COMPLETED = 'COMPLETED',
  PENDING = 'PENDING',
  FAILED = 'FAILED',
}

@Entity('transactions')
@Unique(['txHash'])
@Index('idx_transactions_user_id_status', ['userId', 'status'])
@Index('idx_transactions_user_id_tx_hash', ['userId', 'txHash'])
@Index('idx_transactions_status', ['status'])
export class Transaction extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, { nullable: false, onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Index('idx_transactions_user_id')
  @Column('uuid')
  userId: string;

  @Column({ type: 'enum', enum: TxType })
  type: TxType;

  @Column('decimal', { precision: 18, scale: 7 })
  amount: string;

  @Column({ type: 'varchar' })
  txHash?: string | null;

  @Column({ type: 'enum', enum: TxStatus, default: TxStatus.COMPLETED })
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

  get transactionHash(): string | null | undefined {
    return this.txHash;
  }

  set transactionHash(value: string | null | undefined) {
    this.txHash = value;
  }
}
