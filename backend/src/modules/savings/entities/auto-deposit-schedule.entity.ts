import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { SavingsProduct } from './savings-product.entity';

export enum AutoDepositFrequency {
  DAILY = 'DAILY',
  WEEKLY = 'WEEKLY',
  BI_WEEKLY = 'BI_WEEKLY',
  MONTHLY = 'MONTHLY',
}

export enum AutoDepositStatus {
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
  CANCELLED = 'CANCELLED',
}

@Entity('auto_deposit_schedules')
export class AutoDepositSchedule {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  @Column('uuid')
  productId: string;

  @Column('decimal', { precision: 14, scale: 7 })
  amount: number;

  @Column({ type: 'enum', enum: AutoDepositFrequency })
  frequency: AutoDepositFrequency;

  @Column({
    type: 'enum',
    enum: AutoDepositStatus,
    default: AutoDepositStatus.ACTIVE,
  })
  status: AutoDepositStatus;

  /** Next scheduled execution time */
  @Column({ type: 'timestamptz' })
  nextRunAt: Date;

  /** Retry count for the current cycle */
  @Column({ type: 'int', default: 0 })
  retryCount: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @ManyToOne(() => SavingsProduct, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'productId' })
  product: SavingsProduct;
}
