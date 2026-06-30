import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Body,
  Query,
  UseGuards,
  Req,
  Headers,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { Response } from 'express';
import { format as csvFormat } from '@fast-csv/format';
import { AdminDisputesService } from './admin-disputes.service';
import { AdminExportService } from './services/admin-export.service';
import {
  DisputeFilterDto,
  AssignDisputeDto,
  ResolveDisputeDto,
  EscalateDisputeDto,
  AddEvidenceDto,
  UpdateDisputeDto,
} from './dto/admin-dispute.dto';
import {
  AdminDisputeExportRequestDto,
  AdminExportJobResponseDto,
} from './dto/admin-export.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { Dispute, DisputeTimeline } from '../disputes/entities/dispute.entity';

@ApiTags('admin/disputes')
@Controller('admin/disputes')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST)
@ApiBearerAuth()
export class AdminDisputesController {
  constructor(
    private readonly adminDisputesService: AdminDisputesService,
    private readonly adminExportService: AdminExportService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Get all disputes with filters' })
  @ApiResponse({
    status: 200,
    description: 'List of disputes',
    schema: {
      properties: {
        disputes: {
          type: 'array',
          items: { $ref: '#/components/schemas/Dispute' },
        },
        total: { type: 'number' },
      },
    },
  })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: [
      'OPEN',
      'IN_PROGRESS',
      'UNDER_REVIEW',
      'RESOLVED',
      'CLOSED',
      'ESCALATED',
    ],
  })
  @ApiQuery({
    name: 'priority',
    required: false,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
  })
  @ApiQuery({ name: 'assignedTo', required: false, type: String })
  @ApiQuery({ name: 'fromDate', required: false, type: String })
  @ApiQuery({ name: 'toDate', required: false, type: String })
  async getAllDisputes(@Query() filters: DisputeFilterDto) {
    return await this.adminDisputesService.findAll(filters);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get dispute statistics' })
  @ApiResponse({
    status: 200,
    description: 'Dispute statistics',
  })
  async getStats() {
    return await this.adminDisputesService.getStats();
  }

  @Get('export')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST)
  @ApiOperation({ summary: 'Export disputes to CSV' })
  @ApiResponse({
    status: 200,
    description: 'CSV file containing filtered disputes',
  })
  async exportCsv(
    @Query() filters: DisputeFilterDto,
    @CurrentUser() user: { id: string; role: Role },
    @Res() res: Response,
  ): Promise<void> {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="admin_disputes_export.csv"',
    );

    const csvStream = csvFormat({ headers: true, quoteColumns: true });
    csvStream.pipe(res);

    await this.adminExportService.streamDisputesCsv(
      user.role,
      filters,
      csvStream,
    );
  }

  @Post('export/async')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Queue an async disputes CSV export job' })
  @ApiResponse({
    status: 202,
    description: 'Export job accepted for processing',
    type: AdminExportJobResponseDto,
  })
  async exportAsync(
    @Body() body: AdminDisputeExportRequestDto,
    @CurrentUser() user: { id: string; role: Role },
  ): Promise<AdminExportJobResponseDto> {
    return this.adminExportService.requestDisputesExportJob(
      user.id,
      user.role,
      body,
    );
  }

  @Get('export/jobs/:jobId')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST)
  @ApiOperation({ summary: 'Get disputes export job status' })
  @ApiParam({ name: 'jobId', description: 'Export job UUID' })
  @ApiResponse({
    status: 200,
    description: 'Export job status',
    type: AdminExportJobResponseDto,
  })
  async getExportJobStatus(
    @Param('jobId') jobId: string,
    @CurrentUser() user: { id: string },
  ): Promise<AdminExportJobResponseDto> {
    return this.adminExportService.getExportJobStatus(user.id, jobId);
  }

  @Get('export/jobs/:jobId/download')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN, Role.ANALYST)
  @ApiOperation({ summary: 'Download a completed disputes export job' })
  @ApiParam({ name: 'jobId', description: 'Export job UUID' })
  @ApiResponse({ status: 200, description: 'CSV export file download' })
  async downloadExportJob(
    @Param('jobId') jobId: string,
    @CurrentUser() user: { id: string },
    @Res() res: Response,
  ): Promise<void> {
    const download = await this.adminExportService.getExportJobDownload(
      user.id,
      jobId,
    );

    res.setHeader('Content-Type', download.contentType);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${download.fileName}"`,
    );
    res.sendFile(download.filePath);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get dispute by ID' })
  @ApiResponse({ status: 200, description: 'Dispute details', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async getDispute(@Param('id') id: string) {
    return await this.adminDisputesService.findOne(id);
  }

  @Get(':id/timeline')
  @ApiOperation({ summary: 'Get dispute timeline/history' })
  @ApiResponse({
    status: 200,
    description: 'Dispute timeline',
    type: [DisputeTimeline],
  })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async getDisputeTimeline(@Param('id') id: string) {
    return await this.adminDisputesService.getTimeline(id);
  }

  @Post(':id/assign')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Assign dispute to admin' })
  @ApiResponse({ status: 200, description: 'Dispute assigned', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async assignDispute(
    @Param('id') id: string,
    @Body() dto: AssignDisputeDto,
    @Req() req: any,
    @Headers('x-forwarded-for') forwardedFor?: string,
  ) {
    const ipAddress = forwardedFor || req?.ip;
    return await this.adminDisputesService.assignDispute(
      id,
      dto,
      req.user?.id || 'admin',
      ipAddress,
    );
  }

  @Post(':id/resolve')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Resolve a dispute' })
  @ApiResponse({ status: 200, description: 'Dispute resolved', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async resolveDispute(
    @Param('id') id: string,
    @Body() dto: ResolveDisputeDto,
    @Req() req: any,
    @Headers('x-forwarded-for') forwardedFor?: string,
  ) {
    const ipAddress = forwardedFor || req?.ip;
    return await this.adminDisputesService.resolveDispute(
      id,
      dto,
      req.user?.id || 'admin',
      ipAddress,
    );
  }

  @Post(':id/escalate')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Escalate dispute to senior admin' })
  @ApiResponse({ status: 200, description: 'Dispute escalated', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async escalateDispute(
    @Param('id') id: string,
    @Body() dto: EscalateDisputeDto,
    @Req() req: any,
    @Headers('x-forwarded-for') forwardedFor?: string,
  ) {
    const ipAddress = forwardedFor || req?.ip;
    return await this.adminDisputesService.escalateDispute(
      id,
      dto,
      req.user?.id || 'admin',
      ipAddress,
    );
  }

  @Post(':id/evidence')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Add evidence/document to dispute' })
  @ApiResponse({ status: 200, description: 'Evidence added', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async addEvidence(
    @Param('id') id: string,
    @Body() dto: AddEvidenceDto,
    @Req() req: any,
    @Headers('x-forwarded-for') forwardedFor?: string,
  ) {
    const ipAddress = forwardedFor || req?.ip;
    return await this.adminDisputesService.addEvidence(
      id,
      dto,
      req.user?.id || 'admin',
      ipAddress,
    );
  }

  @Patch(':id')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Update dispute status/priority' })
  @ApiResponse({ status: 200, description: 'Dispute updated', type: Dispute })
  @ApiResponse({ status: 404, description: 'Dispute not found' })
  async updateDispute(
    @Param('id') id: string,
    @Body() dto: UpdateDisputeDto,
    @Req() req: any,
    @Headers('x-forwarded-for') forwardedFor?: string,
  ) {
    const ipAddress = forwardedFor || req?.ip;
    return await this.adminDisputesService.updateDispute(
      id,
      dto,
      req.user?.id || 'admin',
      ipAddress,
    );
  }
}
