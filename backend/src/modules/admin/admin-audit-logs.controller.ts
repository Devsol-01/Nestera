import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  UseGuards,
  Res,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiProduces,
} from '@nestjs/swagger';
import { Response } from 'express';
import { AdminAuditLogsService } from './admin-audit-logs.service';
import {
  AuditLogFilterDto,
  AuditLogExportDto,
} from './dto/admin-audit-log.dto';
import { AuditLog } from '../../common/entities/audit-log.entity';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { CorrelationId } from '../../common/decorators/correlation-id.decorator';
import { JobQueueService } from '../job-queue/job-queue.service';
import { QUEUE_NAMES } from '../job-queue/job-queue.constants';
import { Job } from 'bullmq';

@ApiTags('admin/audit-logs')
@Controller('admin/audit-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminAuditLogsController {
  constructor(
    private readonly auditLogsService: AdminAuditLogsService,
    private readonly jobQueueService: JobQueueService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Get all audit logs with filters' })
  @ApiResponse({
    status: 200,
    description: 'List of audit logs',
    schema: {
      properties: {
        logs: {
          type: 'array',
          items: { $ref: '#/components/schemas/AuditLog' },
        },
        total: { type: 'number' },
        page: { type: 'number' },
        limit: { type: 'number' },
      },
    },
  })
  @ApiQuery({ name: 'actor', required: false, type: String })
  @ApiQuery({
    name: 'action',
    required: false,
    enum: [
      'CREATE',
      'UPDATE',
      'DELETE',
      'READ',
      'LOGIN',
      'LOGOUT',
      'APPROVE',
      'REJECT',
      'ESCALATE',
      'RESOLVE',
      'ASSIGN',
      'EXPORT',
    ],
  })
  @ApiQuery({
    name: 'resourceType',
    required: false,
    enum: [
      'USER',
      'DISPUTE',
      'CLAIM',
      'SAVINGS',
      'TRANSACTION',
      'CONFIG',
      'KYC',
      'NOTIFICATION',
      'ADMIN',
      'SYSTEM',
    ],
  })
  @ApiQuery({ name: 'resourceId', required: false, type: String })
  @ApiQuery({ name: 'fromDate', required: false, type: String })
  @ApiQuery({ name: 'toDate', required: false, type: String })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  async getAllAuditLogs(@Query() filters: AuditLogFilterDto) {
    return await this.auditLogsService.findAll(filters);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get audit log statistics' })
  @ApiQuery({ name: 'fromDate', required: false, type: String })
  @ApiQuery({ name: 'toDate', required: false, type: String })
  @ApiResponse({
    status: 200,
    description: 'Audit log statistics',
  })
  async getStats(
    @Query('fromDate') fromDate?: string,
    @Query('toDate') toDate?: string,
  ) {
    return await this.auditLogsService.getStats(fromDate, toDate);
  }

  @Get('retention-policy')
  @ApiOperation({ summary: 'Get audit log retention policy' })
  @ApiResponse({
    status: 200,
    description: 'Retention policy information',
  })
  async getRetentionPolicy() {
    return this.auditLogsService.getRetentionPolicy();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get audit log by ID' })
  @ApiResponse({
    status: 200,
    description: 'Audit log details',
    type: AuditLog,
  })
  @ApiResponse({ status: 404, description: 'Audit log not found' })
  async getAuditLog(@Param('id') id: string) {
    return await this.auditLogsService.findOne(id);
  }

  @Post('export')
  @ApiOperation({
    summary: 'Queue audit log export - returns job ID for async retrieval',
  })
  @ApiResponse({
    status: 202,
    description: 'Export job queued',
    schema: {
      properties: {
        jobId: { type: 'string' },
        message: { type: 'string' },
      },
    },
  })
  async queueExport(
    @Body() dto: AuditLogExportDto,
    @Query('format') format: 'csv' | 'json' = 'csv',
    @CorrelationId() correlationId?: string,
  ) {
    const job = await this.jobQueueService.addAuditLogExportJob(
      {
        filters: {
          actor: dto.actor,
          action: dto.action,
          resourceType: dto.resourceType,
          resourceId: dto.resourceId,
          fromDate: dto.fromDate,
          toDate: dto.toDate,
        },
        format,
        requestedBy: 'admin',
      },
      undefined,
      correlationId,
    );

    return {
      jobId: job.id,
      message:
        'Export job queued. Check status at /admin/audit-logs/export/status/:jobId',
    };
  }

  @Get('export/status/:jobId')
  @ApiOperation({ summary: 'Get status of an audit log export job' })
  @ApiResponse({
    status: 200,
    description: 'Job status',
    schema: {
      properties: {
        status: { type: 'string' },
        data: { type: 'object' },
      },
    },
  })
  async getExportStatus(@Param('jobId') jobId: string) {
    const queue = this.jobQueueService['getQueue'](
      QUEUE_NAMES.AUDIT_LOG_EXPORT,
    );
    if (!queue) {
      return { status: 'error', message: 'Queue not available' };
    }

    const job = await queue.getJob(jobId);
    if (!job) {
      return { status: 'not_found', message: 'Job not found' };
    }

    const state = await job.getState();
    const result = state === 'completed' ? job.returnvalue : null;

    return {
      status: state,
      data: result,
    };
  }

  @Get('export/download/:jobId')
  @ApiOperation({ summary: 'Download completed audit log export' })
  @ApiProduces('text/csv', 'application/json')
  @ApiResponse({
    status: 200,
    description: 'Exported audit logs',
    schema: {
      type: 'string',
      format: 'binary',
    },
  })
  async downloadExport(@Param('jobId') jobId: string, @Res() res: Response) {
    const queue = this.jobQueueService['getQueue'](
      QUEUE_NAMES.AUDIT_LOG_EXPORT,
    );
    if (!queue) {
      return res.status(HttpStatus.SERVICE_UNAVAILABLE).json({
        message: 'Queue not available',
      });
    }

    const job = await queue.getJob(jobId);
    if (!job) {
      return res.status(HttpStatus.NOT_FOUND).json({
        message: 'Job not found',
      });
    }

    const state = await job.getState();
    if (state !== 'completed') {
      return res.status(HttpStatus.ACCEPTED).json({
        message: `Job is still ${state}`,
      });
    }

    const result = job.returnvalue;
    const format = job.data.format;
    const contentType = format === 'json' ? 'application/json' : 'text/csv';
    const filename = `audit-logs-${new Date().toISOString().split('T')[0]}.${format}`;

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.status(HttpStatus.OK).send(result?.data || '');
  }

  @Post('cleanup')
  @ApiOperation({
    summary: 'Clean up old audit logs based on retention policy',
  })
  @ApiResponse({
    status: 200,
    description: 'Number of deleted logs',
  })
  async cleanupOldLogs() {
    const deletedCount = await this.auditLogsService.cleanupOldLogs();
    return {
      deletedCount,
      message: `Successfully cleaned up ${deletedCount} old audit logs`,
    };
  }
}
