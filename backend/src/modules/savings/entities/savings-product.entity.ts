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

  @Column('int', { nullable: true })
  tenureMonths: number | null;

  @Column({ nullable: true })
  contractId: string;

  @Column('decimal', { precision: 28, scale: 7, default: 0 })
  tvlAmount: number;

  @Column({ type: 'enum', enum: RiskLevel, default: RiskLevel.LOW })
  riskLevel: RiskLevel;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => UserSubscription, (sub) => sub.product)
  subscriptions: UserSubscription[];
}
