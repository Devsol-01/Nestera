import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export enum NotificationType {
  SWEEP_COMPLETED = 'SWEEP_COMPLETED',
  CLAIM_UPDATED = 'CLAIM_UPDATED',
  CLAIM_APPROVED = 'CLAIM_APPROVED',
  CLAIM_REJECTED = 'CLAIM_REJECTED',
  YIELD_EARNED = 'YIELD_EARNED',
  DEPOSIT_RECEIVED = 'DEPOSIT_RECEIVED',
  MILESTONE_ACHIEVED = 'MILESTONE_ACHIEVED',
  WAITLIST_AVAILABLE = 'WAITLIST_AVAILABLE',
  GOAL_MILESTONE = 'GOAL_MILESTONE',
  GOAL_COMPLETED = 'GOAL_COMPLETED',
  WITHDRAWAL_COMPLETED = 'WITHDRAWAL_COMPLETED',
  CHALLENGE_BADGE_EARNED = 'CHALLENGE_BADGE_EARNED',
  PRODUCT_ALERT_TRIGGERED = 'PRODUCT_ALERT_TRIGGERED',
  REBALANCING_RECOMMENDED = 'REBALANCING_RECOMMENDED',
  ADMIN_CAPACITY_ALERT = 'ADMIN_CAPACITY_ALERT',
  GOVERNANCE_PROPOSAL_CREATED = 'GOVERNANCE_PROPOSAL_CREATED',
  ADMIN_BROADCAST = 'ADMIN_BROADCAST',
  REFERRAL_COMPLETED = 'REFERRAL_COMPLETED',
  REFERRAL_REWARD = 'REFERRAL_REWARD',
  GOVERNANCE_VOTING_REMINDER = 'GOVERNANCE_VOTING_REMINDER',
  GOVERNANCE_PROPOSAL_QUEUED = 'GOVERNANCE_PROPOSAL_QUEUED',
  GOVERNANCE_PROPOSAL_EXECUTED = 'GOVERNANCE_PROPOSAL_EXECUTED',
  GOVERNANCE_DELEGATE_VOTED = 'GOVERNANCE_DELEGATE_VOTED',
  BADGE_EARNED = 'BADGE_EARNED',
  DISPUTE_CREATED = 'DISPUTE_CREATED',
  DISPUTE_STATUS_UPDATED = 'DISPUTE_STATUS_UPDATED',
  DISPUTE_RESOLVED = 'DISPUTE_RESOLVED',
}

@Entity('notifications')
@Index(['userId', 'createdAt'])
@Index(['userId', 'read'])
export class Notification {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  @Column('uuid', { nullable: true })
  tenantId: string | null;

  @Column({ type: 'enum', enum: NotificationType })
  type: NotificationType;

  @Column()
  title: string;

  @Column('text')
  message: string;

  @Column({ type: 'boolean', default: false })
  read: boolean;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
