import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { UserSubscription } from './user-subscription.entity';

export enum SavingsProductType {
  FIXED = 'FIXED',
  FLEXIBLE = 'FLEXIBLE',
}

export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

@Entity('savings_products')
export class SavingsProduct {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ type: 'enum', enum: SavingsProductType })
  type: SavingsProductType;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column('decimal', { precision: 5, scale: 2, default: 0 })
  interestRate: number;

  @Column('decimal', { precision: 14, scale: 2 })
  minAmount: number;

  @Column('decimal', { precision: 14, scale: 2 })
  maxAmount: number;

  @Column({ type: 'varchar', length: 12, default: 'USDC' })
  currencyCode: string;

  @Column('int', { nullable: true })
  tenureMonths: number | null;

  @Column({ type: 'varchar', length: 56, nullable: true })
  contractId: string | null;

  @Column('decimal', { precision: 14, scale: 2, default: 0 })
  tvlAmount: number;

  @Column('int', { nullable: true })
  capacity: number | null;

  @Column('int', { nullable: true })
  maxSubscriptionsPerUser: number | null;
  @Column({ type: 'int', default: 1 })
  version: number;

  @Column({ type: 'uuid', nullable: true })
  versionGroupId: string | null;

  @Column({ type: 'uuid', nullable: true })
  previousVersionId: string | null;
  @Column('decimal', { precision: 14, scale: 2, nullable: true })
  maxCapacity: number | null;

  @Column({ default: true })
  isActive: boolean;

  @Column({ type: 'enum', enum: RiskLevel, default: RiskLevel.LOW })
  riskLevel: RiskLevel;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => UserSubscription, (sub) => sub.product)
  subscriptions: UserSubscription[];
}
