import {
  BadRequestException,
  ForbiddenException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bullmq';
import { Repository, SelectQueryBuilder } from 'typeorm';
import { CsvFormatterStream } from '@fast-csv/format';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DataScopeService } from '../../../common/services/data-scope.service';
import { AuditLogService } from '../../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
  SYSTEM_ACTOR,
} from '../../../common/entities/audit-log.entity';
import { Role } from '../../../common/enums/role.enum';
import { Transaction } from '../../transactions/entities/transaction.entity';
import { Dispute } from '../../disputes/entities/dispute.entity';
import { AdminTransactionFilterDto } from '../dto/admin-transaction-filter.dto';
import { DisputeFilterDto } from '../dto/admin-dispute.dto';
import {
  AdminExportJob,
  AdminExportDataType,
  AdminExportStatus,
} from '../entities/admin-export-job.entity';
import { AdminExportJobResponseDto } from '../dto/admin-export.dto';
import {
  ADMIN_EXPORT_FILE_DIR,
  ADMIN_EXPORT_JOB_NAME,
  ADMIN_EXPORT_LINK_TTL_MS,
  ADMIN_EXPORT_QUEUE,
  DISPUTE_SENSITIVE_FIELDS,
  TRANSACTION_SENSITIVE_FIELDS,
} from '../admin-export.constants';

@Injectable()
export class AdminExportService {
  private readonly logger = new Logger(AdminExportService.name);
  private readonly exportDir = path.join(os.tmpdir(), ADMIN_EXPORT_FILE_DIR);

  constructor(
    @InjectRepository(AdminExportJob)
    private readonly exportJobRepository: Repository<AdminExportJob>,
    @InjectRepository(Transaction)
    private readonly txRepo: Repository<Transaction>,
    @InjectRepository(Dispute)
    private readonly disputeRepo: Repository<Dispute>,
    @InjectQueue(ADMIN_EXPORT_QUEUE)
    private readonly exportQueue: Queue,
    private readonly dataScopeService: DataScopeService,
    private readonly auditLogService: AuditLogService,
  ) {
    fs.mkdirSync(this.exportDir, { recursive: true });
  }

  async requestTransactionsExportJob(
    userId: string,
    role: Role,
    filters: AdminTransactionFilterDto,
  ): Promise<AdminExportJobResponseDto> {
    return this.requestExportJob(
      userId,
      role,
      AdminExportDataType.TRANSACTIONS,
      filters,
    );
  }

  async requestDisputesExportJob(
    userId: string,
    role: Role,
    filters: DisputeFilterDto,
  ): Promise<AdminExportJobResponseDto> {
    return this.requestExportJob(
      userId,
      role,
      AdminExportDataType.DISPUTES,
      filters,
    );
  }

  async getExportJobStatus(
    userId: string,
    jobId: string,
  ): Promise<AdminExportJobResponseDto> {
    const job = await this.exportJobRepository.findOne({
      where: { id: jobId },
    });
    if (!job) {
      throw new NotFoundException('Export job not found');
    }

    this.assertJobOwnership(job, userId);
    this.assertNotExpired(job);

    return this.toJobResponse(job);
  }

  async getExportJobDownload(
    userId: string,
    jobId: string,
  ): Promise<{ filePath: string; fileName: string; contentType: string }> {
    const job = await this.exportJobRepository.findOne({
      where: { id: jobId },
    });
    if (!job) {
      throw new NotFoundException('Export job not found');
    }

    this.assertJobOwnership(job, userId);
    this.assertNotExpired(job);

    if (job.status !== AdminExportStatus.COMPLETED) {
      throw new BadRequestException('Export job is not ready for download');
    }

    if (!job.filePath || !fs.existsSync(job.filePath)) {
      throw new NotFoundException('Export file not found');
    }

    return {
      filePath: job.filePath,
      fileName: job.fileName ?? this.buildFileName(job.dataType, job.id),
      contentType: 'text/csv; charset=utf-8',
    };
  }

  async streamTransactionsCsv(
    role: Role,
    query: AdminTransactionFilterDto,
    stream: CsvFormatterStream<any, any>,
  ): Promise<void> {
    const scopedQuery = this.applyScopedTransactionFilters(role, query);
    await this.writeTransactionBatches(scopedQuery, role, stream);
    stream.end();
  }

  async streamDisputesCsv(
    role: Role,
    filters: DisputeFilterDto,
    stream: CsvFormatterStream<any, any>,
  ): Promise<void> {
    const scopedFilters = this.applyScopedDisputeFilters(role, filters);
    await this.writeDisputeBatches(scopedFilters, role, stream);
    stream.end();
  }

  async processExportJob(jobId: string, bullJobId?: string): Promise<void> {
    const job = await this.exportJobRepository.findOne({
      where: { id: jobId },
    });
    if (!job) {
      throw new NotFoundException('Export job not found');
    }

    if (
      job.status === AdminExportStatus.CANCELLED ||
      job.status === AdminExportStatus.EXPIRED
    ) {
      return;
    }

    if (job.status === AdminExportStatus.COMPLETED && job.filePath) {
      return;
    }

    const startedAt = Date.now();

    // Capture before-state for audit diff
    const beforeState = {
      jobId: job.id,
      dataType: job.dataType,
      status: job.status,
      requestedBy: job.userId,
      requestedByRole: job.requestedByRole,
    };

    await this.exportJobRepository.update(job.id, {
      status: AdminExportStatus.PROCESSING,
      errorMessage: null,
    });

    const role = (job.requestedByRole as Role) || Role.ADMIN;
    const fileName = this.buildFileName(job.dataType, job.id);
    const filePath = path.join(this.exportDir, fileName);

    try {
      const rows: Record<string, unknown>[] = [];

      if (job.dataType === AdminExportDataType.TRANSACTIONS) {
        const filters = (job.requestPayload ??
          {}) as unknown as AdminTransactionFilterDto;
        const scopedQuery = this.applyScopedTransactionFilters(role, filters);
        await this.collectTransactionRows(scopedQuery, role, rows);
      } else {
        const filters = (job.requestPayload ??
          {}) as unknown as DisputeFilterDto;
        const scopedFilters = this.applyScopedDisputeFilters(role, filters);
        await this.collectDisputeRows(scopedFilters, role, rows);
      }

      const csv = this.renderCsv(rows);
      await fs.promises.writeFile(filePath, csv, 'utf8');

      const latest = await this.exportJobRepository.findOne({
        where: { id: job.id },
      });
      if (latest?.status === AdminExportStatus.CANCELLED) {
        await fs.promises.unlink(filePath).catch(() => undefined);
        return;
      }

      await this.exportJobRepository.update(job.id, {
        status: AdminExportStatus.COMPLETED,
        filePath,
        fileName,
        completedAt: new Date(),
        expiresAt: new Date(Date.now() + ADMIN_EXPORT_LINK_TTL_MS),
        errorMessage: null,
      });

      this.logger.log(`Admin export job ${job.id} completed`);

      // Audit log – successful background export
      await this.auditLogService.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.EXPORT_JOB,
        resourceType: AuditResourceType.JOB,
        resourceId: job.id,
        jobId: bullJobId ?? job.queueJobId ?? job.id,
        description: `Admin export job completed: dataType=${job.dataType}, rows=${rows.length}, requestedBy=${job.userId}`,
        previousValue: beforeState,
        newValue: {
          status: AdminExportStatus.COMPLETED,
          fileName,
          rowCount: rows.length,
          completedAt: new Date().toISOString(),
        },
        durationMs: Date.now() - startedAt,
        success: true,
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unknown export error';
      await this.exportJobRepository.update(job.id, {
        status: AdminExportStatus.FAILED,
        errorMessage: message,
      });
      this.logger.error(`Admin export job ${job.id} failed: ${message}`);

      // Audit log – failed background export
      await this.auditLogService.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.EXPORT_JOB,
        resourceType: AuditResourceType.JOB,
        resourceId: job.id,
        jobId: bullJobId ?? job.queueJobId ?? job.id,
        description: `Admin export job failed: dataType=${job.dataType}, requestedBy=${job.userId}, error=${message}`,
        previousValue: beforeState,
        newValue: { status: AdminExportStatus.FAILED, errorMessage: message },
        durationMs: Date.now() - startedAt,
        success: false,
        errorMessage: message,
      });

      throw error;
    }
  }

  applyScopedTransactionFilters(
    role: Role,
    query: AdminTransactionFilterDto,
  ): AdminTransactionFilterDto {
    const { startDate, endDate } = this.resolveDateBounds(
      role,
      query.startDate,
      query.endDate,
    );

    return {
      ...query,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
    } as AdminTransactionFilterDto;
  }

  applyScopedDisputeFilters(
    role: Role,
    filters: DisputeFilterDto,
  ): DisputeFilterDto {
    const { startDate, endDate } = this.resolveDateBounds(
      role,
      filters.fromDate,
      filters.toDate,
    );

    return {
      ...filters,
      fromDate: startDate.toISOString(),
      toDate: endDate.toISOString(),
    };
  }

  filterTransactionRow(role: Role, tx: Transaction): Record<string, unknown> {
    const row = {
      id: tx.id,
      userId: tx.userId,
      type: tx.type,
      status: tx.status,
      amount: tx.amount,
      txHash: tx.txHash ?? '',
      publicKey: tx.publicKey ?? '',
      poolId: tx.poolId ?? '',
      eventId: tx.eventId ?? '',
      ledgerSequence: tx.ledgerSequence ?? '',
      metadata: tx.metadata ? JSON.stringify(tx.metadata) : '',
      flagged: tx.flagged,
      category: tx.category ?? '',
      tags: Array.isArray(tx.tags) ? tx.tags.join('|') : '',
      createdAt: tx.createdAt.toISOString(),
    };

    return this.dataScopeService.filterSensitiveFields(role, row, [
      ...TRANSACTION_SENSITIVE_FIELDS,
    ]);
  }

  filterDisputeRow(role: Role, dispute: Dispute): Record<string, unknown> {
    const row = {
      id: dispute.id,
      claimId: dispute.claimId,
      disputedBy: dispute.disputedBy,
      reason: dispute.reason,
      status: dispute.status,
      priority: dispute.priority,
      assignedTo: dispute.assignedTo ?? '',
      assignedAt: dispute.assignedAt?.toISOString() ?? '',
      resolvedAt: dispute.resolvedAt?.toISOString() ?? '',
      resolvedBy: dispute.resolvedBy ?? '',
      resolution: dispute.resolution ?? '',
      escalatedTo: dispute.escalatedTo ?? '',
      escalatedAt: dispute.escalatedAt?.toISOString() ?? '',
      evidence: dispute.evidence ? JSON.stringify(dispute.evidence) : '',
      createdAt: dispute.createdAt.toISOString(),
      updatedAt: dispute.updatedAt.toISOString(),
    };

    return this.dataScopeService.filterSensitiveFields(role, row, [
      ...DISPUTE_SENSITIVE_FIELDS,
    ]);
  }

  private async requestExportJob(
    userId: string,
    role: Role,
    dataType: AdminExportDataType,
    payload: AdminTransactionFilterDto | DisputeFilterDto,
  ): Promise<AdminExportJobResponseDto> {
    const job = this.exportJobRepository.create({
      userId,
      dataType,
      format: 'csv',
      status: AdminExportStatus.PENDING,
      requestPayload: payload as unknown as Record<string, unknown>,
      requestedByRole: role,
      expiresAt: new Date(Date.now() + ADMIN_EXPORT_LINK_TTL_MS),
    });

    const saved = await this.exportJobRepository.save(job);

    let queueJob;
    try {
      queueJob = await this.exportQueue.add(
        ADMIN_EXPORT_JOB_NAME,
        { exportJobId: saved.id },
        {
          jobId: saved.id,
          attempts: 3,
          backoff: { type: 'exponential', delay: 1000 },
          removeOnComplete: false,
          removeOnFail: false,
        },
      );
    } catch (error) {
      await this.exportJobRepository.update(saved.id, {
        status: AdminExportStatus.FAILED,
        errorMessage:
          error instanceof Error ? error.message : 'Failed to queue export job',
      });
      throw error;
    }

    await this.exportJobRepository.update(saved.id, {
      queueJobId: String(queueJob.id ?? saved.id),
    });

    return this.toJobResponse({
      ...saved,
      queueJobId: String(queueJob.id ?? saved.id),
    });
  }

  private resolveDateBounds(
    role: Role,
    startDate?: string,
    endDate?: string,
  ): { startDate: Date; endDate: Date } {
    const end = endDate ? new Date(endDate) : new Date();
    const maxDays = this.dataScopeService.getMaxTimeRange(role);

    let start = startDate
      ? new Date(startDate)
      : new Date(end.getTime() - maxDays * 24 * 60 * 60 * 1000);

    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      throw new BadRequestException('Invalid date range');
    }

    if (start > end) {
      throw new BadRequestException('Start date must be before end date');
    }

    const requestedDays = Math.max(
      1,
      Math.ceil((end.getTime() - start.getTime()) / (24 * 60 * 60 * 1000)),
    );
    const cappedDays = this.dataScopeService.applyDateRangeFilter(
      role,
      requestedDays,
    );

    if (cappedDays < requestedDays) {
      start = new Date(end.getTime() - cappedDays * 24 * 60 * 60 * 1000);
    }

    return { startDate: start, endDate: end };
  }

  private buildTransactionQuery(
    query: AdminTransactionFilterDto,
  ): SelectQueryBuilder<Transaction> {
    const qb = this.txRepo.createQueryBuilder('tx');

    if (query.type?.length) {
      qb.andWhere('tx.type IN (:...type)', { type: query.type });
    }
    if (query.status?.length) {
      qb.andWhere('tx.status IN (:...status)', { status: query.status });
    }
    if (query.userId) {
      qb.andWhere('tx.userId = :userId', { userId: query.userId });
    }
    if (query.minAmount !== undefined) {
      qb.andWhere('CAST(tx.amount AS DECIMAL) >= :minAmount', {
        minAmount: query.minAmount,
      });
    }
    if (query.maxAmount !== undefined) {
      qb.andWhere('CAST(tx.amount AS DECIMAL) <= :maxAmount', {
        maxAmount: query.maxAmount,
      });
    }
    if (query.startDate) {
      qb.andWhere('tx.createdAt >= :startDate', { startDate: query.startDate });
    }
    if (query.endDate) {
      qb.andWhere('tx.createdAt <= :endDate', { endDate: query.endDate });
    }
    if (query.flagged !== undefined) {
      qb.andWhere('tx.flagged = :flagged', { flagged: query.flagged });
    }

    return qb.orderBy('tx.createdAt', 'ASC');
  }

  private buildDisputeQuery(
    filters: DisputeFilterDto,
  ): SelectQueryBuilder<Dispute> {
    const qb = this.disputeRepo.createQueryBuilder('dispute');

    if (filters.status) {
      qb.andWhere('dispute.status = :status', { status: filters.status });
    }
    if (filters.priority) {
      qb.andWhere('dispute.priority = :priority', {
        priority: filters.priority,
      });
    }
    if (filters.assignedTo) {
      qb.andWhere('dispute.assignedTo = :assignedTo', {
        assignedTo: filters.assignedTo,
      });
    }
    if (filters.fromDate) {
      qb.andWhere('dispute.createdAt >= :fromDate', {
        fromDate: filters.fromDate,
      });
    }
    if (filters.toDate) {
      qb.andWhere('dispute.createdAt <= :toDate', { toDate: filters.toDate });
    }

    return qb.orderBy('dispute.createdAt', 'ASC');
  }

  private async writeTransactionBatches(
    query: AdminTransactionFilterDto,
    role: Role,
    stream: CsvFormatterStream<any, any>,
  ): Promise<void> {
    const batchSize = 500;
    let offset = 0;

    while (true) {
      const batch = await this.buildTransactionQuery(query)
        .skip(offset)
        .take(batchSize)
        .getMany();

      if (!batch.length) break;

      for (const tx of batch) {
        stream.write(this.filterTransactionRow(role, tx));
      }

      offset += batchSize;
    }
  }

  private async writeDisputeBatches(
    filters: DisputeFilterDto,
    role: Role,
    stream: CsvFormatterStream<any, any>,
  ): Promise<void> {
    const batchSize = 500;
    let offset = 0;

    while (true) {
      const batch = await this.buildDisputeQuery(filters)
        .skip(offset)
        .take(batchSize)
        .getMany();

      if (!batch.length) break;

      for (const dispute of batch) {
        stream.write(this.filterDisputeRow(role, dispute));
      }

      offset += batchSize;
    }
  }

  private async collectTransactionRows(
    query: AdminTransactionFilterDto,
    role: Role,
    rows: Record<string, unknown>[],
  ): Promise<void> {
    const batchSize = 500;
    let offset = 0;

    while (true) {
      const batch = await this.buildTransactionQuery(query)
        .skip(offset)
        .take(batchSize)
        .getMany();

      if (!batch.length) break;

      for (const tx of batch) {
        rows.push(this.filterTransactionRow(role, tx));
      }

      offset += batchSize;
    }
  }

  private async collectDisputeRows(
    filters: DisputeFilterDto,
    role: Role,
    rows: Record<string, unknown>[],
  ): Promise<void> {
    const batchSize = 500;
    let offset = 0;

    while (true) {
      const batch = await this.buildDisputeQuery(filters)
        .skip(offset)
        .take(batchSize)
        .getMany();

      if (!batch.length) break;

      for (const dispute of batch) {
        rows.push(this.filterDisputeRow(role, dispute));
      }

      offset += batchSize;
    }
  }

  private renderCsv(rows: Record<string, unknown>[]): string {
    const headers = Array.from(
      new Set(rows.flatMap((row) => Object.keys(row))),
    );

    if (!headers.length) {
      return 'id\n';
    }

    const escapeCell = (value: unknown): string => {
      if (value === null || value === undefined) {
        return '';
      }
      const text = String(value);
      if (/[",\n]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
      }
      return text;
    };

    const lines = [headers.join(',')];
    for (const row of rows) {
      lines.push(headers.map((header) => escapeCell(row[header])).join(','));
    }

    return `${lines.join('\n')}\n`;
  }

  private buildFileName(dataType: AdminExportDataType, jobId: string): string {
    return `admin_${dataType}_export_${jobId}.csv`;
  }

  private assertJobOwnership(job: AdminExportJob, userId: string): void {
    if (job.userId !== userId) {
      throw new ForbiddenException('You do not have access to this export job');
    }
  }

  private assertNotExpired(job: AdminExportJob): void {
    if (job.expiresAt && job.expiresAt.getTime() < Date.now()) {
      throw new GoneException('Export job has expired');
    }
  }

  private toJobResponse(job: AdminExportJob): AdminExportJobResponseDto {
    return {
      requestId: job.id,
      status: job.status,
      dataType: job.dataType,
      fileName: job.fileName ?? undefined,
      errorMessage: job.errorMessage ?? undefined,
      createdAt: job.createdAt,
      completedAt: job.completedAt ?? null,
      expiresAt: job.expiresAt ?? null,
    };
  }
}
