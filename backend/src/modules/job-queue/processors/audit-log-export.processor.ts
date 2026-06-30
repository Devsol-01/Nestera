import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUE_NAMES } from '../job-queue.constants';
import { AuditLogExportJobData } from '../job-queue.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from '../../../common/entities/audit-log.entity';

@Processor(QUEUE_NAMES.AUDIT_LOG_EXPORT)
export class AuditLogExportProcessor extends WorkerHost {
  private readonly logger = new Logger(AuditLogExportProcessor.name);

  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
  ) {
    super();
  }

  async process(job: Job<AuditLogExportJobData>): Promise<any> {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(
      `${correlationPrefix}Processing audit log export job ${job.id} (attempt ${job.attemptsMade + 1})`,
    );

    const { filters, format, requestedBy } = job.data;
    const logs = await this.fetchAuditLogs(filters);
    const data = this.formatExport(logs, format);

    this.logger.log(
      `${correlationPrefix}Audit log export completed: job=${job.id} format=${format} count=${logs.length} requestedBy=${requestedBy}`,
    );

    return {
      jobId: job.id,
      format,
      recordCount: logs.length,
      data,
      requestedBy,
    };
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job<AuditLogExportJobData>, error: Error) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.error(
      `${correlationPrefix}Audit log export job ${job.id} failed after ${job.attemptsMade} attempts: ${error.message}`,
    );
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<AuditLogExportJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(`${correlationPrefix}Audit log export job ${job.id} completed`);
  }

  private async fetchAuditLogs(
    filters: AuditLogExportJobData['filters'],
  ): Promise<AuditLog[]> {
    const query = this.auditLogRepository.createQueryBuilder('auditLog');

    if (filters.actor) {
      query.andWhere('auditLog.actor LIKE :actor', {
        actor: `%${filters.actor}%`,
      });
    }

    if (filters.action) {
      query.andWhere('auditLog.action = :action', { action: filters.action });
    }

    if (filters.resourceType) {
      query.andWhere('auditLog.resourceType = :resourceType', {
        resourceType: filters.resourceType,
      });
    }

    if (filters.resourceId) {
      query.andWhere('auditLog.resourceId = :resourceId', {
        resourceId: filters.resourceId,
      });
    }

    if (filters.fromDate) {
      query.andWhere('auditLog.timestamp >= :fromDate', {
        fromDate: filters.fromDate,
      });
    }

    if (filters.toDate) {
      query.andWhere('auditLog.timestamp <= :toDate', {
        toDate: filters.toDate,
      });
    }

    query.orderBy('auditLog.timestamp', 'DESC');
    query.take(10000);

    return query.getMany();
  }

  private formatExport(logs: AuditLog[], format: 'csv' | 'json'): string {
    if (format === 'json') {
      return JSON.stringify(logs, null, 2);
    }

    const headers = [
      'ID',
      'Timestamp',
      'Action',
      'Actor',
      'Resource Type',
      'Resource ID',
      'Endpoint',
      'Method',
      'Status Code',
      'Success',
      'Duration (ms)',
      'IP Address',
      'User Agent',
      'Description',
      'Previous Value',
      'New Value',
    ];

    const csvRows = [headers.join(',')];

    for (const log of logs) {
      const row = [
        log.id,
        log.timestamp.toISOString(),
        log.action || '',
        log.actor || '',
        log.resourceType || '',
        log.resourceId || '',
        log.endpoint || '',
        log.method || '',
        log.statusCode?.toString() || '',
        log.success ? 'true' : 'false',
        log.durationMs?.toString() || '',
        log.ipAddress || '',
        log.userAgent ? `"${log.userAgent.replace(/"/g, '""')}"` : '',
        log.description ? `"${log.description.replace(/"/g, '""')}"` : '',
        log.previousValue
          ? `"${JSON.stringify(log.previousValue).replace(/"/g, '""')}"`
          : '',
        log.newValue
          ? `"${JSON.stringify(log.newValue).replace(/"/g, '""')}"`
          : '',
      ];
      csvRows.push(row.join(','));
    }

    return csvRows.join('\n');
  }
}
