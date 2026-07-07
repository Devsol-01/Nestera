import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Body,
  Query,
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
import { Request } from 'express';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { WorkflowStepGuard } from '../../common/guards/workflow-step.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Role } from '../../common/enums/role.enum';
import { User } from '../user/entities/user.entity';
import { WorkflowService } from './workflow.service';
import {
  CreateWorkflowDto,
  ApproveWorkflowDto,
  RejectWorkflowDto,
  CancelWorkflowDto,
  WorkflowFilterDto,
} from './dto/workflow.dto';

/**
 * AdminWorkflowController
 *
 * Provides REST endpoints for the admin workflow engine:
 *
 *   POST   /admin/workflows              – Initiate a new workflow
 *   GET    /admin/workflows              – List workflows (with filters)
 *   GET    /admin/workflows/:id          – Get single workflow
 *   PATCH  /admin/workflows/:id/approve  – Approve PENDING_APPROVAL workflow
 *   PATCH  /admin/workflows/:id/reject   – Reject  PENDING_APPROVAL workflow
 *   PATCH  /admin/workflows/:id/cancel   – Cancel  PENDING or APPROVED workflow
 *
 * All endpoints require JWT authentication.
 * Create requires ADMIN or higher.
 * Approve/Reject are further gated by WorkflowStepGuard (dynamic role check
 * per workflow instance based on requiredApproverRole).
 */
@ApiTags('admin-workflows')
@ApiBearerAuth()
@Controller({ path: 'admin/workflows', version: '1' })
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminWorkflowController {
  constructor(private readonly workflowService: WorkflowService) {}

  // -------------------------------------------------------------------------
  // POST /admin/workflows
  // -------------------------------------------------------------------------
  @Post()
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Initiate a new admin workflow',
    description:
      'Creates a PENDING_APPROVAL workflow instance. The action is not executed until a qualified approver acts on it.',
  })
  @ApiResponse({ status: 201, description: 'Workflow created' })
  @ApiResponse({ status: 409, description: 'Duplicate idempotency key' })
  async create(
    @Body() dto: CreateWorkflowDto,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `wf-${Date.now()}`;
    return this.workflowService.create(
      dto,
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );
  }

  // -------------------------------------------------------------------------
  // GET /admin/workflows
  // -------------------------------------------------------------------------
  @Get()
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST, Role.SUPPORT)
  @ApiOperation({ summary: 'List workflows with optional filters' })
  @ApiResponse({ status: 200, description: 'Paginated workflow list' })
  async findAll(@Query() filters: WorkflowFilterDto) {
    return this.workflowService.findAll(filters);
  }

  // -------------------------------------------------------------------------
  // GET /admin/workflows/:id
  // -------------------------------------------------------------------------
  @Get(':id')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST, Role.SUPPORT)
  @ApiOperation({ summary: 'Get a single workflow by ID' })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({ status: 200, description: 'Workflow detail' })
  @ApiResponse({ status: 404, description: 'Workflow not found' })
  async findOne(@Param('id', ParseUUIDPipe) id: string) {
    return this.workflowService.findOne(id);
  }

  // -------------------------------------------------------------------------
  // PATCH /admin/workflows/:id/approve
  // -------------------------------------------------------------------------
  @Patch(':id/approve')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @UseGuards(WorkflowStepGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Approve a PENDING_APPROVAL workflow',
    description:
      'The approver must have the role specified in requiredApproverRole. Initiators cannot self-approve.',
  })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({ status: 200, description: 'Workflow approved' })
  @ApiResponse({
    status: 400,
    description: 'Invalid state or already actioned',
  })
  @ApiResponse({
    status: 403,
    description: 'Insufficient role or self-approval attempt',
  })
  @ApiResponse({ status: 404, description: 'Workflow not found' })
  async approve(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: ApproveWorkflowDto,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `wf-approve-${Date.now()}`;
    return this.workflowService.approve(
      id,
      dto,
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );
  }

  // -------------------------------------------------------------------------
  // PATCH /admin/workflows/:id/reject
  // -------------------------------------------------------------------------
  @Patch(':id/reject')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @UseGuards(WorkflowStepGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reject a PENDING_APPROVAL workflow',
    description:
      'The rejector must have the role specified in requiredApproverRole.',
  })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({ status: 200, description: 'Workflow rejected' })
  @ApiResponse({ status: 400, description: 'Invalid state' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  @ApiResponse({ status: 404, description: 'Workflow not found' })
  async reject(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: RejectWorkflowDto,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `wf-reject-${Date.now()}`;
    return this.workflowService.reject(
      id,
      dto,
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );
  }

  // -------------------------------------------------------------------------
  // PATCH /admin/workflows/:id/cancel
  // -------------------------------------------------------------------------
  @Patch(':id/cancel')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel a PENDING_APPROVAL or APPROVED workflow',
    description:
      'Initiators may cancel their own PENDING_APPROVAL workflows. SUPER_ADMIN can cancel APPROVED workflows.',
  })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({ status: 200, description: 'Workflow canceled' })
  @ApiResponse({ status: 400, description: 'Cannot cancel in current state' })
  @ApiResponse({
    status: 403,
    description: 'Insufficient permission to cancel',
  })
  @ApiResponse({ status: 404, description: 'Workflow not found' })
  async cancel(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: CancelWorkflowDto,
    @CurrentUser() actor: User,
    @Req() req: Request,
  ) {
    const correlationId =
      (req.headers['x-correlation-id'] as string) ?? `wf-cancel-${Date.now()}`;
    return this.workflowService.cancel(
      id,
      dto,
      actor,
      correlationId,
      req.ip,
      req.headers['user-agent'],
    );
  }
}
