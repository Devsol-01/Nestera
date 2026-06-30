import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

/**
 * AuditLog Entity
 *
 * Stores structured audit entries for all admin actions and system mutations.
 * Enables forensic traceability and incident debugging.
 *
 * Indexed by:
 * - correlation_id: Trace full request lifecycle
 * - resource_id: Find all mutations for a specific resource
 * - actor: Find all actions by a user
 * - timestamp: Time-range queries
 * - action: Filter by mutation type
 */
export enum AuditAction {
  CREATE = 'CREATE',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
  READ = 'READ',
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  APPROVE = 'APPROVE',
  REJECT = 'REJECT',
  ESCALATE = 'ESCALATE',
  RESOLVE = 'RESOLVE',
  ASSIGN = 'ASSIGN',
  EXPORT = 'EXPORT',
  DEPOSIT = 'DEPOSIT',
  WITHDRAW = 'WITHDRAW',
  VOTE = 'VOTE',
  // Background / automated job actions
  RECONCILE = 'RECONCILE',
  CLEANUP = 'CLEANUP',
  ARCHIVE = 'ARCHIVE',
  EXPORT_JOB = 'EXPORT_JOB',
}

export enum AuditResourceType {
  USER = 'USER',
  DISPUTE = 'DISPUTE',
  CLAIM = 'CLAIM',
  SAVINGS = 'SAVINGS',
  TRANSACTION = 'TRANSACTION',
  CONFIG = 'CONFIG',
  KYC = 'KYC',
  NOTIFICATION = 'NOTIFICATION',
  ADMIN = 'ADMIN',
  WITHDRAWAL_REQUEST = 'WITHDRAWAL_REQUEST',
  SYSTEM = 'SYSTEM',
  GOVERNANCE = 'GOVERNANCE',
  /** Background jobs and scheduled tasks */
  JOB = 'JOB',
}

/**
 * Canonical actor identifier used for automated/background processes.
 * Use this instead of a real user ID when there is no human initiator.
 */
export const SYSTEM_ACTOR = 'SYSTEM';

@Entity('audit_logs')
@Index('idx_audit_logs_correlation_id', ['correlationId'])
@Index('idx_audit_logs_resource_id', ['resourceId'])
@Index('idx_audit_logs_actor', ['actor'])
@Index('idx_audit_logs_timestamp', ['timestamp'])
@Index('idx_audit_logs_action', ['action'])
@Index('idx_audit_logs_resource_type', ['resourceType'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  correlationId: string;

  @Column({ nullable: true })
  requestId: string;

  /**
   * ID of the background job (Bull/BullMQ job.id) that triggered this entry.
   * Populated only for automated/system-initiated audit entries.
   */
  @Column({ nullable: true })
  jobId: string;

  @CreateDateColumn()
  timestamp: Date;

  @Column({ nullable: true })
  endpoint: string;

  @Column({ nullable: true })
  method: string;

  @Column({ type: 'enum', enum: AuditAction, nullable: true })
  action: AuditAction;

  @Column({ nullable: true })
  actor: string;

  @Column({ nullable: true, type: 'uuid' })
  resourceId: string | null;

  @Column({ type: 'enum', enum: AuditResourceType, nullable: true })
  resourceType: AuditResourceType;

  @Column({ nullable: true })
  statusCode: number;

  @Column({ nullable: true })
  durationMs: number;

  @Column({ default: true })
  success: boolean;

  @Column({ nullable: true, type: 'text' })
  errorMessage: string | null;

  @Column({ nullable: true, type: 'jsonb' })
  previousValue: Record<string, any> | null;

  @Column({ nullable: true, type: 'jsonb' })
  newValue: Record<string, any> | null;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ nullable: true })
  userAgent: string;

  @Column({ nullable: true, type: 'text' })
  description: string;
}
