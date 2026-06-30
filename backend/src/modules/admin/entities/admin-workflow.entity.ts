import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Role } from '../../../common/enums/role.enum';

export enum WorkflowStatus {
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  EXECUTED = 'EXECUTED',
  CANCELED = 'CANCELED',
  TIMED_OUT = 'TIMED_OUT',
}

export enum WorkflowActionType {
  EMERGENCY_WITHDRAWAL = 'EMERGENCY_WITHDRAWAL',
  LARGE_REFUND = 'LARGE_REFUND',
  GOVERNANCE_OVERRIDE = 'GOVERNANCE_OVERRIDE',
  DISPUTE_RESOLUTION = 'DISPUTE_RESOLUTION',
  BULK_USER_SUSPENSION = 'BULK_USER_SUSPENSION',
  SAVINGS_PRODUCT_MODIFY = 'SAVINGS_PRODUCT_MODIFY',
}

/**
 * AdminWorkflow Entity
 *
 * Represents a multi-step admin workflow instance. High-risk admin actions are
 * routed through this engine instead of executing immediately.
 *
 * Lifecycle: PENDING_APPROVAL → APPROVED → EXECUTED
 *                             ↘ REJECTED
 *         PENDING_APPROVAL → CANCELED (by initiator / super-admin)
 *         PENDING_APPROVAL → TIMED_OUT (cron)
 */
@Entity('admin_workflows')
@Index('idx_admin_workflows_status', ['status'])
@Index('idx_admin_workflows_action_type', ['actionType'])
@Index('idx_admin_workflows_initiator_id', ['initiatorId'])
@Index('idx_admin_workflows_expires_at', ['expiresAt'])
@Index('idx_admin_workflows_idempotency_key', ['idempotencyKey'], {
  unique: true,
  where: '"idempotency_key" IS NOT NULL',
})
export class AdminWorkflow {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Semantic action type – drives which handler executes the workflow
   */
  @Column({ type: 'enum', enum: WorkflowActionType })
  actionType: WorkflowActionType;

  /**
   * Current lifecycle state
   */
  @Column({
    type: 'enum',
    enum: WorkflowStatus,
    default: WorkflowStatus.PENDING_APPROVAL,
  })
  status: WorkflowStatus;

  /**
   * Human-readable description of the action being requested
   */
  @Column({ type: 'text' })
  description: string;

  /**
   * Minimum role required to approve this workflow step.
   * Defaults to SUPER_ADMIN for safety.
   */
  @Column({ type: 'varchar', default: Role.SUPER_ADMIN })
  requiredApproverRole: string;

  /**
   * The user (UUID) who created this workflow request
   */
  @Column({ type: 'uuid' })
  initiatorId: string;

  /**
   * Initiator email for audit display
   */
  @Column({ type: 'varchar' })
  initiatorEmail: string;

  /**
   * Payload to be acted on upon execution.
   * e.g. { withdrawalId: "...", amount: 1000, reason: "emergency" }
   */
  @Column({ type: 'jsonb' })
  payload: Record<string, any>;

  /**
   * Snapshot of the resource state before the workflow was initiated.
   * Used for before/after diff in audit logs.
   */
  @Column({ type: 'jsonb', nullable: true })
  previousState: Record<string, any> | null;

  /**
   * Snapshot of the resource state after execution.
   */
  @Column({ type: 'jsonb', nullable: true })
  executedState: Record<string, any> | null;

  /**
   * Optional idempotency key to prevent duplicate workflow creation.
   */
  @Column({ type: 'varchar', nullable: true, name: 'idempotency_key' })
  idempotencyKey: string | null;

  /**
   * Who approved this workflow
   */
  @Column({ type: 'uuid', nullable: true })
  approvedById: string | null;

  @Column({ type: 'varchar', nullable: true })
  approvedByEmail: string | null;

  @Column({ type: 'timestamp', nullable: true })
  approvedAt: Date | null;

  /**
   * Who rejected this workflow (and why)
   */
  @Column({ type: 'uuid', nullable: true })
  rejectedById: string | null;

  @Column({ type: 'varchar', nullable: true })
  rejectedByEmail: string | null;

  @Column({ type: 'text', nullable: true })
  rejectionReason: string | null;

  @Column({ type: 'timestamp', nullable: true })
  rejectedAt: Date | null;

  /**
   * Who canceled this workflow (and why)
   */
  @Column({ type: 'uuid', nullable: true })
  canceledById: string | null;

  @Column({ type: 'varchar', nullable: true })
  canceledByEmail: string | null;

  @Column({ type: 'text', nullable: true })
  cancellationReason: string | null;

  @Column({ type: 'timestamp', nullable: true })
  canceledAt: Date | null;

  /**
   * When this workflow was actually executed
   */
  @Column({ type: 'timestamp', nullable: true })
  executedAt: Date | null;

  /**
   * Deadline – workflow auto-transitions to TIMED_OUT after this
   */
  @Column({ type: 'timestamp', nullable: true })
  expiresAt: Date | null;

  /**
   * Execution error, if EXECUTE failed internally after approval
   */
  @Column({ type: 'text', nullable: true })
  executionError: string | null;

  /**
   * Any supplemental notes from the approver
   */
  @Column({ type: 'text', nullable: true })
  approverNotes: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
