import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  NotFoundException,
  Logger,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AdminWorkflow } from '../../modules/admin/entities/admin-workflow.entity';
import { Role } from '../enums/role.enum';

export const WORKFLOW_STEP_KEY = 'workflow_step';

/**
 * @WorkflowStep decorator
 *
 * Applied to controller methods that act on a specific workflow transition.
 * The guard will verify that the current user's role satisfies the
 * workflow's `requiredApproverRole` before the method executes.
 *
 * Usage:
 *   @WorkflowStep()
 *   @Patch(':id/approve')
 *   approve(@Param('id') id: string, ...) { ... }
 */
export const WorkflowStep = () => SetMetadata(WORKFLOW_STEP_KEY, true);

/**
 * WorkflowStepGuard
 *
 * Checks that the requesting user has a role at or above the workflow's
 * `requiredApproverRole` field. This provides per-workflow dynamic role gating
 * on top of the static @Roles() decorator.
 *
 * Applied on approve/reject endpoints in AdminWorkflowController via
 * @UseGuards(WorkflowStepGuard).
 */
@Injectable()
export class WorkflowStepGuard implements CanActivate {
  private readonly logger = new Logger(WorkflowStepGuard.name);

  private readonly roleHierarchy: Record<string, number> = {
    [Role.USER]: 0,
    [Role.SUPPORT]: 1,
    [Role.ANALYST]: 1,
    [Role.ADMIN]: 2,
    [Role.SUPER_ADMIN]: 3,
  };

  constructor(
    private readonly reflector: Reflector,
    @InjectRepository(AdminWorkflow)
    private readonly workflowRepository: Repository<AdminWorkflow>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isWorkflowStep = this.reflector.getAllAndOverride<boolean>(
      WORKFLOW_STEP_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Only enforce on endpoints decorated with @WorkflowStep()
    if (!isWorkflowStep) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Authentication required');
    }

    const workflowId: string = request.params?.id;
    if (!workflowId) {
      // No workflow ID in path – let the service handle the error
      return true;
    }

    const workflow = await this.workflowRepository.findOne({
      where: { id: workflowId },
    });

    if (!workflow) {
      throw new NotFoundException(`Workflow ${workflowId} not found`);
    }

    const requiredLevel =
      this.roleHierarchy[workflow.requiredApproverRole] ?? 99;
    const actorLevel = this.roleHierarchy[user.role] ?? 0;

    if (actorLevel < requiredLevel) {
      this.logger.warn(
        `User ${user.email} (${user.role}) attempted to act on workflow ${workflowId} requiring ${workflow.requiredApproverRole}`,
      );
      throw new ForbiddenException(
        `This workflow step requires role ${workflow.requiredApproverRole} or higher`,
      );
    }

    return true;
  }
}
