import {
  Controller,
  Post,
  Param,
  Body,
  UseGuards,
  ParseUUIDPipe,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiParam,
} from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  Min,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Request } from 'express';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Role } from '../../common/enums/role.enum';
import { User } from '../user/entities/user.entity';
import { WorkflowService } from './workflow.service';
import { WorkflowActionType } from './entities/admin-workflow.entity';
import { EmergencyWithdrawalWorkflowService } from './emergency-withdrawal-workflow.service';

class InitiateEmergencyWithdrawalDto {
  @ApiProperty({ description: 'UUID of the WithdrawalRequest to process' })
  @IsString()
  @IsNotEmpty()
  withdrawalId: string;

  @ApiProperty({
    description: 'Reason for the emergency withdrawal',
    maxLength: 1000,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(1000)
  reason: string;

  @ApiPropertyOptional({
    description: 'Approval timeout in minutes (default: 60, minimum: 5)',
    minimum: 5,
  })
  @IsOptional()
  @IsNumber()
  @Min(5)
  timeoutMinutes?: number;

  @ApiPropertyOptional({
    description: 'Idempotency key to prevent duplicate workflow creation',
  })
  @IsOptional()
  @IsString()
  idempotencyKey?: string;
}

/**
 * AdminEmergencyWithdrawalWorkflowController
 *
 * Handles the workflow-gated emergency withdrawal flow:
 *
 *   POST /admin/withdrawals/:id/emergency-workflow
 *     – Creates a PENDING_APPROVAL EMERGENCY_WITHDRAWAL workflow.
 *       The withdrawal is NOT processed immediately.
 *       Requires ADMIN or SUPER_ADMIN.
 *
 *   POST /admin/withdrawals/workflow/:workflowId/execute
 *     – Executes an APPROVED EMERGENCY_WITHDRAWAL workflow.
 *       Processes the withdrawal against the chain.
 *       Requires SUPER_ADMIN (must also be the approver or a different SUPER_ADMIN).
 *
 * This replaces the ad-hoc POST /admin/withdrawals/:id/approve endpoint for
 * emergency / large-amount withdrawals that require a second set of eyes.
 */
@ApiTags('admin-withdrawals')
@ApiBearerAuth()
@Controller({ path: 'admin/withdrawals', version: '1' })
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminEmergencyWithdrawalWorkflowController {
  constructor(
    private readonly workflowService: WorkflowService,
    private readonly emergencyWithdrawalWorkflowService: EmergencyWithdrawalWorkflowService,
  ) {}

  /**
   * Step 1: Initiate – creates a PENDING_APPROVAL workflow.
   *
   * POST /v1/admin/withdrawals/:id/emergency-workflow
   *
   * Any ADMIN or SUPER_ADMIN can initiate. The withdrawal is NOT touched yet.
   * A SUPER_ADMIN (different from the initiator) must approve via:
   *   PATCH /v1/admin/workflows/:workflowId/approve
   * followed by executing it via:
   *   POST  /v1/admin/withdrawals/workflow/:workflowId/execute
   */
  @Post(':id/emergency-workflow')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Initiate an emergency withdrawal workflow',
    description:
      'Creates a PENDING_APPROVAL workflow. The withdrawal will only be processed after a SUPER_ADMIN approves it and the execute endpoint is called.',
  })
  @ApiParam({
    name: 'id',
    description: 'WithdrawalRequest UUID',
    type: 'string',
  })
  @ApiResponse({ status: 201, description: 'Workflow initiated' })
  @ApiResponse({ status: 404, description: 'WithdrawalRequest not found' })
  @ApiResponse({ status: 409, description: 'Duplicate idempotency key' })
  async initiateEmergencyWorkflow(
    @Param('id', ParseUUIDPipe) withdrawalId: string,
    @Body() dto: InitiateEmergencyWithdrawalDto,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `ewf-init-${Date.now()}`;

    // Capture before-state snapshot
    const previousState =
      await this.emergencyWithdrawalWorkflowService.captureWithdrawalSnapshot(
        withdrawalId,
      );

    const workflow = await this.workflowService.create(
      {
        actionType: WorkflowActionType.EMERGENCY_WITHDRAWAL,
        description: `Emergency withdrawal for WithdrawalRequest ${withdrawalId}: ${dto.reason}`,
        requiredApproverRole: Role.SUPER_ADMIN,
        payload: {
          withdrawalId,
          reason: dto.reason,
          initiatedByAdminEmail: actor.email,
        },
        timeoutMinutes: dto.timeoutMinutes ?? 60,
        idempotencyKey: dto.idempotencyKey ?? undefined,
      },
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );

    // Backfill the previous state snapshot (workflow was just created)
    if (previousState) {
      await this.workflowService['workflowRepository'].update(
        { id: workflow.id },
        { previousState },
      );
    }

    return {
      workflow,
      message:
        'Emergency withdrawal workflow initiated. A SUPER_ADMIN must approve via PATCH /admin/workflows/:workflowId/approve, then execute via POST /admin/withdrawals/workflow/:workflowId/execute.',
    };
  }

  /**
   * Step 2 (combined approve+execute alternative): Execute an already-APPROVED workflow.
   *
   * POST /v1/admin/withdrawals/workflow/:workflowId/execute
   *
   * Requires SUPER_ADMIN. The workflow must already be in APPROVED state
   * (approved via the generic PATCH /admin/workflows/:workflowId/approve endpoint).
   *
   * Idempotent: calling this endpoint on an already-EXECUTED workflow is a no-op.
   */
  @Post('workflow/:workflowId/execute')
  @Roles(Role.SUPER_ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Execute an approved emergency withdrawal workflow',
    description:
      'Processes the withdrawal. Requires SUPER_ADMIN. Idempotent – calling twice is safe.',
  })
  @ApiParam({
    name: 'workflowId',
    description: 'AdminWorkflow UUID',
    type: 'string',
  })
  @ApiResponse({
    status: 200,
    description: 'Withdrawal processed, workflow EXECUTED',
  })
  @ApiResponse({ status: 400, description: 'Workflow not in APPROVED state' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  @ApiResponse({ status: 404, description: 'Workflow or withdrawal not found' })
  async executeApprovedWorkflow(
    @Param('workflowId', ParseUUIDPipe) workflowId: string,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `ewf-exec-${Date.now()}`;

    return this.emergencyWithdrawalWorkflowService.executeApprovedWorkflow(
      workflowId,
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );
  }
}
