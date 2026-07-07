import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { SavingsProduct } from './savings-product.entity';

export enum SubscriptionStatus {
  ACTIVE = 'ACTIVE',
  MATURED = 'MATURED',
  CANCELLED = 'CANCELLED',
}

@Entity('user_subscriptions')
export class UserSubscription {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  @Column('uuid', { nullable: true })
  tenantId: string | null;

  @Column('uuid')
  productId: string;

  @Column('decimal', { precision: 14, scale: 2 })
  amount: number;

  @Column({
    type: 'enum',
    enum: SubscriptionStatus,
    default: SubscriptionStatus.ACTIVE,
  })
  status: SubscriptionStatus;

  @Column({ type: 'date' })
  startDate: Date;

  @Column({ type: 'date', nullable: true })
  endDate: Date | null;

  @Column('decimal', { precision: 20, scale: 7, default: 0 })
  totalInterestEarned: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => SavingsProduct, (product) => product.subscriptions, {
    eager: true,
  })
  @JoinColumn({ name: 'productId' })
  product: SavingsProduct;
}
