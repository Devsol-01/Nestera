import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { SavingsGoal } from './savings-goal.entity';

export enum MilestoneType {
  AUTOMATIC = 'AUTOMATIC',
  CUSTOM = 'CUSTOM',
}

@Entity('savings_goal_milestones')
@Index(['goalId', 'percentage'])
export class SavingsGoalMilestone {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  goalId: string;

  @Column('uuid')
  userId: string;

  /** Percentage threshold this milestone represents (e.g. 25, 50, 75, 100) */
  @Column('int')
  percentage: number;

  @Column({ type: 'varchar', length: 255 })
  label: string;

  @Column({
    type: 'enum',
    enum: MilestoneType,
    default: MilestoneType.AUTOMATIC,
  })
  type: MilestoneType;

  /** Whether this milestone has been achieved */
  @Column({ default: false })
  achieved: boolean;

  /** When the milestone was achieved (null if not yet reached) */
  @Column({ type: 'timestamp', nullable: true })
  achievedAt: Date | null;

  /** Bonus points awarded on achievement */
  @Column('int', { default: 0 })
  bonusPoints: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => SavingsGoal, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'goalId' })
  goal: SavingsGoal;
}
