import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import {
  AdminWorkflow,
  WorkflowStatus,
  WorkflowActionType,
} from './entities/admin-workflow.entity';
import {
  CreateWorkflowDto,
  ApproveWorkflowDto,
  RejectWorkflowDto,
  CancelWorkflowDto,
  WorkflowFilterDto,
} from './dto/workflow.dto';
import { WorkflowAuditService } from './workflow-audit.service';
import { User } from '../user/entities/user.entity';
import { Role } from '../../common/enums/role.enum';

/** Default approval window: 60 minutes */
const DEFAULT_TIMEOUT_MINUTES = 60;

/**
 * WorkflowService
 *
 * Core engine for admin multi-step approval workflows.
 *
 * Responsibilities:
 *  - Create workflow instances and store them as PENDING_APPROVAL
 *  - Enforce role/permission gating on each transition
 *  - Approve, reject, cancel, or execute workflows with full state validation
 *  - Emit audit log entries on every transition via WorkflowAuditService
 *  - Auto-expire workflows that exceed their timeout via a cron job
 *  - Guarantee idempotency: duplicate execute calls are silently no-ops
 */
@Injectable()
export class WorkflowService {
  private readonly logger = new Logger(WorkflowService.name);

  constructor(
    @InjectRepository(AdminWorkflow)
    private readonly workflowRepository: Repository<AdminWorkflow>,
    private readonly workflowAuditService: WorkflowAuditService,
  ) {}

  // ---------------------------------------------------------------------------
  // Create
  // ---------------------------------------------------------------------------

  /**
   * Create a new workflow instance in PENDING_APPROVAL state.
   *
   * If an idempotency key is provided and a workflow with the same key already
   * exists, the existing workflow is returned (no duplicate created).
   */
  async create(
    dto: CreateWorkflowDto,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AdminWorkflow> {
    // Idempotency check
    if (dto.idempotencyKey) {
      const existing = await this.workflowRepository.findOne({
        where: { idempotencyKey: dto.idempotencyKey },
      });
      if (existing) {
        this.logger.log(
          `Idempotent workflow create: returning existing workflow ${existing.id}`,
        );
        return existing;
      }
    }

    const timeoutMinutes = dto.timeoutMinutes ?? DEFAULT_TIMEOUT_MINUTES;
    const expiresAt = new Date(Date.now() + timeoutMinutes * 60 * 1000);

    const workflow = this.workflowRepository.create({
      actionType: dto.actionType,
      description: dto.description,
      requiredApproverRole: dto.requiredApproverRole ?? Role.SUPER_ADMIN,
      payload: dto.payload,
      idempotencyKey: dto.idempotencyKey ?? null,
      expiresAt,
      status: WorkflowStatus.PENDING_APPROVAL,
      initiatorId: actor.id,
      initiatorEmail: actor.email,
    });

    const saved = await this.workflowRepository.save(workflow);

    await this.workflowAuditService.recordTransition(saved, {
      correlationId,
      actor: actor.email,
      actorId: actor.id,
      fromStatus: undefined,
      toStatus: WorkflowStatus.PENDING_APPROVAL,
      ipAddress,
      userAgent,
    });

    this.logger.log(
      `Workflow created: ${saved.id} [${saved.actionType}] by ${actor.email}`,
    );

    return saved;
  }

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  async findAll(
    filters: WorkflowFilterDto,
  ): Promise<{ workflows: AdminWorkflow[]; total: number }> {
    const page = filters.page ?? 1;
    const limit = Math.min(filters.limit ?? 20, 100);
    const skip = (page - 1) * limit;

    const query = this.workflowRepository.createQueryBuilder('workflow');

    if (filters.status) {
      query.andWhere('workflow.status = :status', { status: filters.status });
    }
    if (filters.actionType) {
      query.andWhere('workflow.actionType = :actionType', {
        actionType: filters.actionType,
      });
    }
    if (filters.initiatorId) {
      query.andWhere('workflow.initiatorId = :initiatorId', {
        initiatorId: filters.initiatorId,
      });
    }
    if (filters.fromDate) {
      query.andWhere('workflow.createdAt >= :fromDate', {
        fromDate: filters.fromDate,
      });
    }
    if (filters.toDate) {
      query.andWhere('workflow.createdAt <= :toDate', {
        toDate: filters.toDate,
      });
    }

    query.orderBy('workflow.createdAt', 'DESC').skip(skip).take(limit);

    const [workflows, total] = await query.getManyAndCount();
    return { workflows, total };
  }

  async findOne(id: string): Promise<AdminWorkflow> {
    const workflow = await this.workflowRepository.findOne({ where: { id } });
    if (!workflow) {
      throw new NotFoundException(`Workflow ${id} not found`);
    }
    return workflow;
  }

  // ---------------------------------------------------------------------------
  // Approve
  // ---------------------------------------------------------------------------

  /**
   * Approve a PENDING_APPROVAL workflow.
   *
   * Only users whose role satisfies workflow.requiredApproverRole may approve.
   * The initiator cannot approve their own request.
   */
  async approve(
    id: string,
    dto: ApproveWorkflowDto,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);

    this.assertNotExpired(workflow);
    this.assertStatus(workflow, WorkflowStatus.PENDING_APPROVAL, 'approve');
    this.assertSufficientRole(actor, workflow.requiredApproverRole);
    this.assertNotSelfApproval(workflow, actor);

    const fromStatus = workflow.status;

    workflow.status = WorkflowStatus.APPROVED;
    workflow.approvedById = actor.id;
    workflow.approvedByEmail = actor.email;
    workflow.approvedAt = new Date();
    workflow.approverNotes = dto.notes ?? null;

    const saved = await this.workflowRepository.save(workflow);

    await this.workflowAuditService.recordTransition(saved, {
      correlationId,
      actor: actor.email,
      actorId: actor.id,
      fromStatus,
      toStatus: WorkflowStatus.APPROVED,
      ipAddress,
      userAgent,
    });

    this.logger.log(`Workflow ${id} approved by ${actor.email}`);

    return saved;
  }

  // ---------------------------------------------------------------------------
  // Reject
  // ---------------------------------------------------------------------------

  /**
   * Reject a PENDING_APPROVAL workflow.
   *
   * Only users whose role satisfies workflow.requiredApproverRole may reject.
   */
  async reject(
    id: string,
    dto: RejectWorkflowDto,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);

    this.assertNotExpired(workflow);
    this.assertStatus(workflow, WorkflowStatus.PENDING_APPROVAL, 'reject');
    this.assertSufficientRole(actor, workflow.requiredApproverRole);

    const fromStatus = workflow.status;

    workflow.status = WorkflowStatus.REJECTED;
    workflow.rejectedById = actor.id;
    workflow.rejectedByEmail = actor.email;
    workflow.rejectionReason = dto.reason;
    workflow.rejectedAt = new Date();

    const saved = await this.workflowRepository.save(workflow);

    await this.workflowAuditService.recordTransition(saved, {
      correlationId,
      actor: actor.email,
      actorId: actor.id,
      fromStatus,
      toStatus: WorkflowStatus.REJECTED,
      reason: dto.reason,
      ipAddress,
      userAgent,
    });

    this.logger.log(`Workflow ${id} rejected by ${actor.email}`);

    return saved;
  }

  // ---------------------------------------------------------------------------
  // Cancel
  // ---------------------------------------------------------------------------

  /**
   * Cancel a PENDING_APPROVAL or APPROVED workflow.
   *
   * The initiator may cancel their own pending workflow.
   * A SUPER_ADMIN may cancel any pending or approved workflow.
   */
  async cancel(
    id: string,
    dto: CancelWorkflowDto,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);

    const isSuperAdmin =
      (actor.role as string) === (Role.SUPER_ADMIN as string);
    const isInitiator = workflow.initiatorId === actor.id;
    const isCancelable =
      workflow.status === WorkflowStatus.PENDING_APPROVAL ||
      (workflow.status === WorkflowStatus.APPROVED && isSuperAdmin);

    if (!isCancelable) {
      throw new BadRequestException(
        `Workflow in status ${workflow.status} cannot be canceled`,
      );
    }

    if (!isSuperAdmin && !isInitiator) {
      throw new ForbiddenException(
        'Only the initiator or a SUPER_ADMIN can cancel this workflow',
      );
    }

    const fromStatus = workflow.status;

    workflow.status = WorkflowStatus.CANCELED;
    workflow.canceledById = actor.id;
    workflow.canceledByEmail = actor.email;
    workflow.cancellationReason = dto.reason;
    workflow.canceledAt = new Date();

    const saved = await this.workflowRepository.save(workflow);

    await this.workflowAuditService.recordTransition(saved, {
      correlationId,
      actor: actor.email,
      actorId: actor.id,
      fromStatus,
      toStatus: WorkflowStatus.CANCELED,
      reason: dto.reason,
      ipAddress,
      userAgent,
    });

    this.logger.log(`Workflow ${id} canceled by ${actor.email}`);

    return saved;
  }

  // ---------------------------------------------------------------------------
  // Execute
  // ---------------------------------------------------------------------------

  /**
   * Mark an APPROVED workflow as EXECUTED and store the resulting state.
   *
   * Idempotent: if the workflow is already EXECUTED, returns it immediately
   * without re-executing. This prevents double execution on retries.
   *
   * @param executedState  The resource state after executing the action.
   *                       Callers (action handlers) provide this.
   */
  async markExecuted(
    id: string,
    executedState: Record<string, any>,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);

    // Idempotency guard: already executed → return without re-running
    if (workflow.status === WorkflowStatus.EXECUTED) {
      this.logger.warn(
        `Workflow ${id} already EXECUTED – returning idempotent result`,
      );
      return workflow;
    }

    this.assertStatus(workflow, WorkflowStatus.APPROVED, 'execute');

    const fromStatus = workflow.status;

    workflow.status = WorkflowStatus.EXECUTED;
    workflow.executedAt = new Date();
    workflow.executedState = executedState;

    const saved = await this.workflowRepository.save(workflow);

    await this.workflowAuditService.recordTransition(saved, {
      correlationId,
      actor: actor.email,
      actorId: actor.id,
      fromStatus,
      toStatus: WorkflowStatus.EXECUTED,
      ipAddress,
      userAgent,
    });

    this.logger.log(`Workflow ${id} marked EXECUTED by ${actor.email}`);

    return saved;
  }

  /**
   * Store execution error and audit it without changing status
   * (status remains APPROVED so retries can happen if needed).
   */
  async recordExecutionFailure(
    id: string,
    error: Error,
    actor: User,
    correlationId: string,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);
    workflow.executionError = error.message;
    const saved = await this.workflowRepository.save(workflow);
    await this.workflowAuditService.recordExecutionFailure(
      saved,
      error,
      correlationId,
      actor.email,
    );
    return saved;
  }

  // ---------------------------------------------------------------------------
  // Timeout (cron)
  // ---------------------------------------------------------------------------

  /**
   * Runs every 5 minutes to expire workflows whose deadline has passed.
   */
  @Cron(CronExpression.EVERY_5_MINUTES)
  async expireTimedOutWorkflows(): Promise<void> {
    const expired = await this.workflowRepository
      .createQueryBuilder('workflow')
      .where('workflow.status = :status', {
        status: WorkflowStatus.PENDING_APPROVAL,
      })
      .andWhere('workflow.expiresAt IS NOT NULL')
      .andWhere('workflow.expiresAt < :now', { now: new Date() })
      .getMany();

    if (expired.length === 0) return;

    this.logger.log(`Expiring ${expired.length} timed-out workflow(s)`);

    for (const workflow of expired) {
      const fromStatus = workflow.status;
      workflow.status = WorkflowStatus.TIMED_OUT;

      await this.workflowRepository.save(workflow);

      await this.workflowAuditService.recordTransition(workflow, {
        correlationId: `timeout-cron-${workflow.id}`,
        actor: 'system',
        actorId: 'system',
        fromStatus,
        toStatus: WorkflowStatus.TIMED_OUT,
        reason: 'Approval window expired',
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Check if a workflow requires a specific payload reference and return it.
   * Useful for action handlers to extract the payload safely.
   */
  async findOneApprovedForExecution(
    id: string,
    expectedActionType: WorkflowActionType,
  ): Promise<AdminWorkflow> {
    const workflow = await this.findOne(id);

    if (workflow.status !== WorkflowStatus.APPROVED) {
      throw new BadRequestException(
        `Workflow ${id} is not in APPROVED state (current: ${workflow.status})`,
      );
    }

    if (workflow.actionType !== expectedActionType) {
      throw new BadRequestException(
        `Workflow ${id} is of type ${workflow.actionType}, expected ${expectedActionType}`,
      );
    }

    return workflow;
  }

  private assertStatus(
    workflow: AdminWorkflow,
    expected: WorkflowStatus,
    operation: string,
  ): void {
    if (workflow.status !== expected) {
      throw new BadRequestException(
        `Cannot ${operation} workflow in status ${workflow.status} (expected ${expected})`,
      );
    }
  }

  private assertNotExpired(workflow: AdminWorkflow): void {
    if (
      workflow.expiresAt &&
      new Date() > workflow.expiresAt &&
      workflow.status === WorkflowStatus.PENDING_APPROVAL
    ) {
      throw new BadRequestException(
        `Workflow ${workflow.id} has expired and can no longer be actioned`,
      );
    }
  }

  private assertSufficientRole(actor: User, requiredRole: string): void {
    const roleHierarchy: Record<string, number> = {
      [Role.USER]: 0,
      [Role.SUPPORT]: 1,
      [Role.ANALYST]: 1,
      [Role.ADMIN]: 2,
      [Role.SUPER_ADMIN]: 3,
    };

    const actorLevel = roleHierarchy[actor.role] ?? 0;
    const requiredLevel = roleHierarchy[requiredRole] ?? 99;

    if (actorLevel < requiredLevel) {
      throw new ForbiddenException(
        `Action requires role ${requiredRole} or higher. Your role: ${actor.role}`,
      );
    }
  }

  private assertNotSelfApproval(workflow: AdminWorkflow, actor: User): void {
    if (workflow.initiatorId === actor.id) {
      throw new ForbiddenException(
        'Workflow initiators cannot approve their own requests',
      );
    }
  }
}
