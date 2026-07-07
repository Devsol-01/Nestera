import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { ReferralCampaign } from './referral-campaign.entity';

export enum ReferralStatus {
  PENDING = 'pending',
  COMPLETED = 'completed',
  REWARDED = 'rewarded',
  EXPIRED = 'expired',
  QUARANTINED = 'quarantined',
  FRAUDULENT = 'fraudulent',
}

@Entity('referrals')
@Index(['referrerId'])
@Index(['refereeId'])
@Index(['referralCode'])
@Index(['status'])
export class Referral {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  referrerId: string;

  @Column('uuid', { nullable: true })
  tenantId: string | null;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'referrerId' })
  referrer: User;

  @Column('uuid', { nullable: true })
  refereeId: string | null;

  @ManyToOne(() => User, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'refereeId' })
  referee: User | null;

  @Column({ type: 'varchar', length: 20, unique: true })
  referralCode: string;

  @Column({
    type: 'enum',
    enum: ReferralStatus,
    default: ReferralStatus.PENDING,
  })
  status: ReferralStatus;

  @Column({ type: 'decimal', precision: 18, scale: 7, nullable: true })
  rewardAmount: string | null;

  @Column('uuid', { nullable: true })
  campaignId: string | null;

  @ManyToOne(() => ReferralCampaign, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'campaignId' })
  campaign: ReferralCampaign | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;

  @Column({ type: 'jsonb', nullable: true })
  fraudReasons: string[] | null;

  @Column({ type: 'boolean', default: false })
  requiresManualReview: boolean;

  @Column({ type: 'timestamp', nullable: true })
  quarantinedAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  rewardedAt: Date | null;
}
