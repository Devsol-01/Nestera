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

export enum FeedbackCategory {
  BUG_REPORT = 'BUG_REPORT',
  FEATURE_REQUEST = 'FEATURE_REQUEST',
  GENERAL = 'GENERAL',
}

export enum FeedbackStatus {
  SUBMITTED = 'SUBMITTED',
  IN_REVIEW = 'IN_REVIEW',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  CLOSED = 'CLOSED',
}

@Entity('feedback_submissions')
export class FeedbackSubmission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({ type: 'enum', enum: FeedbackCategory })
  category: FeedbackCategory;

  @Column({ type: 'int', nullable: true })
  rating: number | null;

  @Column('text')
  comment: string;

  @Column({
    type: 'enum',
    enum: FeedbackStatus,
    default: FeedbackStatus.SUBMITTED,
  })
  status: FeedbackStatus;

  @Column({ nullable: true })
  screenshotUrl: string | null;

  /**
   * Token returned by {@link StorageQuotaService.reserve} when the
   * screenshot was accepted. Persisted so deletion of the feedback row
   * can refund quota via {@link StorageQuotaService.releaseByUpload}.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  quotaReservationId: string | null;

  @Column({ nullable: true, type: 'text' })
  adminNotes: string | null;

  @Column({ nullable: true })
  resolvedAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
