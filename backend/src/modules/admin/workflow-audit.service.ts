import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  AuditLog,
  AuditAction,
  AuditResourceType,
} from '../../common/entities/audit-log.entity';
import {
  AdminWorkflow,
  WorkflowStatus,
} from './entities/admin-workflow.entity';

export interface WorkflowTransitionContext {
  correlationId: string;
  actor: string;
  actorId: string;
  fromStatus?: WorkflowStatus;
  toStatus: WorkflowStatus;
  reason?: string;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * WorkflowAuditService
 *
 * Centralises audit log emission for every workflow state transition.
 * Records before/after diffs when a workflow is created, approved, rejected,
 * canceled, executed, or timed out.
 */
@Injectable()
export class WorkflowAuditService {
  private readonly logger = new Logger(WorkflowAuditService.name);

  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
  ) {}

  /**
   * Emit an audit log entry for a workflow state transition.
   */
  async recordTransition(
    workflow: AdminWorkflow,
    ctx: WorkflowTransitionContext,
  ): Promise<void> {
    const previousState: Record<string, any> = {
      status: ctx.fromStatus ?? workflow.status,
    };

    const newState: Record<string, any> = {
      status: ctx.toStatus,
      actionType: workflow.actionType,
      initiatorEmail: workflow.initiatorEmail,
      payload: workflow.payload,
    };

    if (ctx.toStatus === WorkflowStatus.APPROVED) {
      newState['approvedByEmail'] = workflow.approvedByEmail;
      newState['approvedAt'] = workflow.approvedAt;
      newState['approverNotes'] = workflow.approverNotes;
    } else if (ctx.toStatus === WorkflowStatus.REJECTED) {
      newState['rejectedByEmail'] = workflow.rejectedByEmail;
      newState['rejectionReason'] = workflow.rejectionReason;
      newState['rejectedAt'] = workflow.rejectedAt;
    } else if (ctx.toStatus === WorkflowStatus.CANCELED) {
      newState['canceledByEmail'] = workflow.canceledByEmail;
      newState['cancellationReason'] = workflow.cancellationReason;
      newState['canceledAt'] = workflow.canceledAt;
    } else if (ctx.toStatus === WorkflowStatus.EXECUTED) {
      newState['executedAt'] = workflow.executedAt;
      newState['executedState'] = workflow.executedState;
    } else if (ctx.toStatus === WorkflowStatus.TIMED_OUT) {
      newState['expiresAt'] = workflow.expiresAt;
    }

    const action = this.resolveAuditAction(ctx.toStatus);
    const description =
      `Workflow [${workflow.actionType}] transitioned from ${ctx.fromStatus ?? 'N/A'} → ${ctx.toStatus}. ${ctx.reason ? `Reason: ${ctx.reason}` : ''}`.trim();

    try {
      const log = this.auditLogRepository.create({
        correlationId: ctx.correlationId,
        action,
        actor: ctx.actor,
        resourceId: workflow.id,
        resourceType: AuditResourceType.ADMIN,
        previousValue: previousState,
        newValue: newState,
        success: true,
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
        description,
        endpoint: `/admin/workflows/${workflow.id}`,
        method: 'PATCH',
        statusCode: 200,
        durationMs: 0,
      });
      await this.auditLogRepository.save(log);
    } catch (err) {
      // Never crash the caller; audit log failure is non-fatal but logged
      this.logger.error(
        `Failed to write workflow audit log for workflow ${workflow.id}: ${(err as Error).message}`,
        (err as Error).stack,
      );
    }
  }

  /**
   * Emit an audit log entry when workflow execution fails internally.
   */
  async recordExecutionFailure(
    workflow: AdminWorkflow,
    error: Error,
    correlationId: string,
    actor: string,
  ): Promise<void> {
    try {
      const log = this.auditLogRepository.create({
        correlationId,
        action: AuditAction.UPDATE,
        actor,
        resourceId: workflow.id,
        resourceType: AuditResourceType.ADMIN,
        previousValue: { status: WorkflowStatus.APPROVED },
        newValue: {
          status: workflow.status,
          executionError: error.message,
        },
        success: false,
        errorMessage: error.message,
        description: `Workflow [${workflow.actionType}] execution failed: ${error.message}`,
        endpoint: `/admin/workflows/${workflow.id}/execute`,
        method: 'POST',
        statusCode: 500,
        durationMs: 0,
      });
      await this.auditLogRepository.save(log);
    } catch (err) {
      this.logger.error(
        `Failed to write execution failure audit log for workflow ${workflow.id}: ${(err as Error).message}`,
      );
    }
  }

  private resolveAuditAction(status: WorkflowStatus): AuditAction {
    switch (status) {
      case WorkflowStatus.PENDING_APPROVAL:
        return AuditAction.CREATE;
      case WorkflowStatus.APPROVED:
        return AuditAction.APPROVE;
      case WorkflowStatus.REJECTED:
        return AuditAction.REJECT;
      case WorkflowStatus.CANCELED:
        return AuditAction.DELETE;
      case WorkflowStatus.EXECUTED:
        return AuditAction.UPDATE;
      case WorkflowStatus.TIMED_OUT:
        return AuditAction.UPDATE;
      default:
        return AuditAction.UPDATE;
    }
  }
}
