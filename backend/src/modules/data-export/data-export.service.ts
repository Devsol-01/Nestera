import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Queue } from 'bullmq';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as archiver from 'archiver';
import {
  DataExportRequest,
  ExportStatus,
} from './entities/data-export-request.entity';
import { User } from '../user/entities/user.entity';
import {
  Transaction,
  TxType,
} from '../transactions/entities/transaction.entity';
import { Notification } from '../notifications/entities/notification.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from '../savings/entities/savings-goal.entity';
import { MailService } from '../mail/mail.service';
import {
  DATA_EXPORT_JOB_NAME,
  DATA_EXPORT_LINK_TTL_MS,
  DATA_EXPORT_PENDING_TTL_MS,
  DATA_EXPORT_QUEUE,
} from './data-export.constants';
import { AuditLogService } from '../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
  SYSTEM_ACTOR,
} from '../../common/entities/audit-log.entity';

const EXPORT_DIR = path.join(os.tmpdir(), 'nestera-exports');
const MAX_ACTIVE_EXPORTS_PER_USER = 2;

@Injectable()
export class DataExportService {
  private readonly logger = new Logger(DataExportService.name);

  constructor(
    @InjectRepository(DataExportRequest)
    private readonly exportRepository: Repository<DataExportRequest>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Transaction)
    private readonly transactionRepository: Repository<Transaction>,
    @InjectRepository(Notification)
    private readonly notificationRepository: Repository<Notification>,
    @InjectRepository(SavingsGoal)
    private readonly savingsGoalRepository: Repository<SavingsGoal>,
    private readonly mailService: MailService,
    @InjectQueue(DATA_EXPORT_QUEUE)
    private readonly dataExportQueue: Queue,
    private readonly auditLogService: AuditLogService,
  ) {
    fs.mkdirSync(EXPORT_DIR, { recursive: true });
  }

  async requestExport(
    userId: string,
  ): Promise<{ requestId: string; message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const activeCount = await this.exportRepository.count({
      where: [
        { userId, status: ExportStatus.PENDING },
        { userId, status: ExportStatus.PROCESSING },
      ],
    });
    if (activeCount >= MAX_ACTIVE_EXPORTS_PER_USER) {
      throw new ConflictException(
        'You already have active export requests in progress. Please wait for one to complete.',
      );
    }

    const request = this.exportRepository.create({
      userId,
      status: ExportStatus.PENDING,
    });
    const saved = await this.exportRepository.save(request);

    let queueJob;
    try {
      queueJob = await this.dataExportQueue.add(
        DATA_EXPORT_JOB_NAME,
        { requestId: saved.id },
        {
          jobId: saved.id,
          attempts: 3,
          backoff: { type: 'exponential', delay: 1000 },
          removeOnComplete: false,
          removeOnFail: false,
        },
      );
    } catch (error) {
      await this.exportRepository.update(saved.id, {
        status: ExportStatus.FAILED,
        errorMessage:
          error instanceof Error ? error.message : 'Failed to queue export job',
      });
      throw error;
    }

    await this.exportRepository.update(saved.id, {
      queueJobId: String(queueJob.id ?? saved.id),
    });

    this.logger.log(`Queued data export ${saved.id} for user ${userId}`);

    return {
      requestId: saved.id,
      message:
        'Export request received and queued. You will receive an email when your data is ready.',
    };
  }

  async getExportFile(
    token: string,
    userId: string,
  ): Promise<{ filePath: string; userId: string }> {
    const request = await this.exportRepository.findOne({ where: { token } });

    if (!request || request.status !== ExportStatus.READY) {
      throw new NotFoundException('Export not found or not ready');
    }

    // Ownership enforcement
    if (request.userId !== userId) {
      throw new NotFoundException('Export not found or not ready');
    }

    if (request.expiresAt && request.expiresAt < new Date()) {
      await this.markExpiredAndCleanup(request.id, 'Export link expired');
      throw new BadRequestException('Export link has expired');
    }

    if (!request.filePath || !fs.existsSync(request.filePath)) {
      throw new NotFoundException('Export file not found');
    }

    // Path validation: ensure resolved path remains inside EXPORT_DIR.
    const resolved = path.resolve(request.filePath);
    const exportDirResolved = path.resolve(EXPORT_DIR);
    if (!resolved.startsWith(exportDirResolved + path.sep)) {
      throw new BadRequestException('Export file path is invalid');
    }

    return { filePath: resolved, userId: request.userId };
  }

  async getExportStatus(requestId: string, userId: string) {
    const request = await this.exportRepository.findOne({
      where: { id: requestId, userId },
    });
    if (!request) throw new NotFoundException('Export request not found');
    const refreshed = await this.applyExpirationPolicy(request);
    const downloadUrl =
      refreshed.status === ExportStatus.READY && refreshed.token
        ? `/users/data/export/download/${refreshed.token}`
        : null;

    return {
      requestId: refreshed.id,
      status: refreshed.status,
      createdAt: refreshed.createdAt,
      completedAt: refreshed.completedAt,
      expiresAt: refreshed.expiresAt,
      errorMessage: refreshed.errorMessage,
      downloadUrl,
    };
  }

  async getExportHistory(userId: string) {
    const requests = await this.exportRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
      take: 50,
    });
    const normalized = await Promise.all(
      requests.map((request) => this.applyExpirationPolicy(request)),
    );

    return normalized.map(
      ({ id, status, createdAt, completedAt, expiresAt, errorMessage }) => ({
        requestId: id,
        status,
        createdAt,
        completedAt,
        expiresAt,
        errorMessage,
      }),
    );
  }

  async cancelExport(
    requestId: string,
    userId: string,
  ): Promise<{ requestId: string; status: ExportStatus; message: string }> {
    const request = await this.exportRepository.findOne({
      where: { id: requestId, userId },
    });
    if (!request) {
      throw new NotFoundException('Export request not found');
    }

    if (
      request.status === ExportStatus.FAILED ||
      request.status === ExportStatus.EXPIRED ||
      request.status === ExportStatus.CANCELLED
    ) {
      return {
        requestId: request.id,
        status: request.status,
        message: `Export request is already ${request.status}`,
      };
    }

    if (request.status === ExportStatus.READY) {
      throw new BadRequestException(
        'Completed exports cannot be cancelled. They will expire automatically.',
      );
    }

    await this.removeQueueJob(request.queueJobId);
    await this.exportRepository.update(request.id, {
      status: ExportStatus.CANCELLED,
      completedAt: new Date(),
      errorMessage: 'Cancelled by user',
    });
    await this.deleteExportFile(request.filePath);

    return {
      requestId: request.id,
      status: ExportStatus.CANCELLED,
      message: 'Export request cancelled',
    };
  }

  async processExportJob(requestId: string, bullJobId?: string): Promise<void> {
    const request = await this.exportRepository.findOne({
      where: { id: requestId },
    });
    if (!request) {
      throw new NotFoundException('Export request not found');
    }

    if (
      request.status === ExportStatus.CANCELLED ||
      request.status === ExportStatus.EXPIRED ||
      request.status === ExportStatus.READY
    ) {
      return;
    }

    if (Date.now() - request.createdAt.getTime() > DATA_EXPORT_PENDING_TTL_MS) {
      await this.markExpiredAndCleanup(request.id, 'Export request timed out');
      return;
    }

    const user = await this.userRepository.findOne({
      where: { id: request.userId },
    });
    if (!user) {
      await this.exportRepository.update(request.id, {
        status: ExportStatus.FAILED,
        errorMessage: 'User not found',
      });
      throw new NotFoundException('User not found');
    }

    const startedAt = Date.now();

    // Capture before-state for audit diff
    const beforeState = {
      requestId: request.id,
      userId: request.userId,
      status: request.status,
      createdAt: request.createdAt?.toISOString(),
    };

    await this.exportRepository.update(request.id, {
      status: ExportStatus.PROCESSING,
      errorMessage: null,
    });

    try {
      const [transactions, notifications, goals] = await Promise.all([
        this.transactionRepository.find({ where: { userId: user.id } }),
        this.notificationRepository.find({ where: { userId: user.id } }),
        this.savingsGoalRepository.find({ where: { userId: user.id } }),
      ]);

      const zipPath = path.join(EXPORT_DIR, `${request.id}.zip`);
      const exportedAt = new Date().toISOString();
      await this.buildZip(zipPath, {
        'WATERMARK.json': {
          userId: user.id,
          requestId: request.id,
          exportedAt,
          _notice:
            'This export was generated exclusively for the user identified above. Unauthorized redistribution is prohibited.',
        },
        'profile.json': {
          id: user.id,
          email: user.email,
          name: user.name,
          createdAt: user.createdAt,
        },
        'transactions.json': transactions,
        'goals.json': goals,
        'notifications.json': notifications,
      });

      const latest = await this.exportRepository.findOne({
        where: { id: request.id },
      });
      if (latest?.status === ExportStatus.CANCELLED) {
        await this.deleteExportFile(zipPath);
        return;
      }

      const token = randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + DATA_EXPORT_LINK_TTL_MS);
      await this.exportRepository.update(request.id, {
        status: ExportStatus.READY,
        token,
        filePath: zipPath,
        expiresAt,
        completedAt: new Date(),
        errorMessage: null,
      });

      const downloadUrl = `/users/data/export/download/${token}`;
      await this.mailService.sendRawMail(
        user.email,
        'Your Nestera data export is ready',
        `Hi ${user.name || 'there'},\n\nYour data export is ready. Download it here:\n${downloadUrl}\n\nThis link expires in 7 days.\n\nNestera Team`,
      );

      this.logger.log(`Export ${request.id} completed for user ${user.id}`);

      // Audit log – successful user data export job
      await this.auditLogService.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.EXPORT_JOB,
        resourceType: AuditResourceType.JOB,
        resourceId: request.id,
        jobId: bullJobId ?? request.queueJobId ?? request.id,
        correlationId: request.id,
        description: `User data export job completed: userId=${user.id}, transactions=${transactions.length}, goals=${goals.length}, notifications=${notifications.length}.`,
        previousValue: beforeState,
        newValue: {
          status: ExportStatus.READY,
          completedAt: new Date().toISOString(),
          recordCounts: {
            transactions: transactions.length,
            goals: goals.length,
            notifications: notifications.length,
          },
        },
        durationMs: Date.now() - startedAt,
        success: true,
      });
    } catch (err) {
      const latest = await this.exportRepository.findOne({
        where: { id: request.id },
      });
      if (latest?.status === ExportStatus.CANCELLED) {
        return;
      }

      const errorMessage = err instanceof Error ? err.message : 'Export failed';
      await this.exportRepository.update(request.id, {
        status: ExportStatus.FAILED,
        errorMessage,
      });

      // Audit log – failed user data export job
      await this.auditLogService.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.EXPORT_JOB,
        resourceType: AuditResourceType.JOB,
        resourceId: request.id,
        jobId: bullJobId ?? request.queueJobId ?? request.id,
        correlationId: request.id,
        description: `User data export job failed: userId=${user.id}, error=${errorMessage}.`,
        previousValue: beforeState,
        newValue: { status: ExportStatus.FAILED, errorMessage },
        durationMs: Date.now() - startedAt,
        success: false,
        errorMessage,
      });

      throw err;
    }
  }

  @Cron(CronExpression.EVERY_HOUR)
  async expireOldExports(): Promise<void> {
    const requests = await this.exportRepository.find({
      where: [
        { status: ExportStatus.PENDING },
        { status: ExportStatus.PROCESSING },
        { status: ExportStatus.READY },
      ],
      take: 500,
      order: { createdAt: 'ASC' },
    });

    for (const request of requests) {
      await this.applyExpirationPolicy(request);
    }
  }

  /**
   * Typed export: transactions for a user, with optional date range.
   */
  async exportTransactions(
    userId: string,
    from?: string,
    to?: string,
  ): Promise<Record<string, unknown>[]> {
    let qb = this.transactionRepository
      .createQueryBuilder('tx')
      .where('tx.userId = :userId', { userId });
    if (from) qb = qb.andWhere('tx.createdAt >= :from', { from });
    if (to) qb = qb.andWhere('tx.createdAt <= :to', { to });
    const rows = await qb.getMany();
    return rows.map(({ id, type, amount, status, createdAt }) => ({
      id,
      type,
      amount,
      status,
      date: createdAt?.toISOString().slice(0, 10) ?? '',
    }));
  }

  /**
   * Typed export: savings goals for a user.
   */
  async exportGoals(userId: string): Promise<Record<string, unknown>[]> {
    const goals = await this.savingsGoalRepository.find({
      where: { userId },
    });
    return goals.map(({ id, goalName, targetAmount, status, createdAt }) => ({
      id,
      name: goalName,
      targetAmount,
      status,
      createdAt: createdAt?.toISOString().slice(0, 10) ?? '',
    }));
  }

  /**
   * Typed export: portfolio summary (aggregated from transactions + goals).
   */
  async exportPortfolio(userId: string): Promise<Record<string, unknown>[]> {
    const [transactions, goals] = await Promise.all([
      this.transactionRepository.find({ where: { userId } }),
      this.savingsGoalRepository.find({ where: { userId } }),
    ]);
    const totalDeposited = transactions
      .filter((t) => t.type === TxType.DEPOSIT)
      .reduce((s, t) => s + Number(t.amount ?? 0), 0);
    const totalWithdrawn = transactions
      .filter((t) => t.type === TxType.WITHDRAW)
      .reduce((s, t) => s + Number(t.amount ?? 0), 0);
    return [
      { metric: 'total_deposited', value: totalDeposited },
      { metric: 'total_withdrawn', value: totalWithdrawn },
      { metric: 'net_position', value: totalDeposited - totalWithdrawn },
      {
        metric: 'active_goals',
        value: goals.filter((g) => g.status === SavingsGoalStatus.IN_PROGRESS)
          .length,
      },
      {
        metric: 'completed_goals',
        value: goals.filter((g) => g.status === SavingsGoalStatus.COMPLETED)
          .length,
      },
    ];
  }

  /**
   * Typed export: analytics data (transaction counts by type + date).
   */
  async exportAnalytics(
    userId: string,
    from?: string,
    to?: string,
  ): Promise<Record<string, unknown>[]> {
    let qb = this.transactionRepository
      .createQueryBuilder('tx')
      .select([
        'tx.type AS type',
        'DATE(tx.createdAt) AS date',
        'COUNT(*) AS count',
        'SUM(tx.amount) AS total',
      ])
      .where('tx.userId = :userId', { userId })
      .groupBy('tx.type, DATE(tx.createdAt)')
      .orderBy('DATE(tx.createdAt)', 'ASC');
    if (from) qb = qb.andWhere('tx.createdAt >= :from', { from });
    if (to) qb = qb.andWhere('tx.createdAt <= :to', { to });
    return qb.getRawMany();
  }

  private buildZip(
    outputPath: string,
    files: Record<string, unknown>,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(outputPath);
      const archive = archiver('zip', { zlib: { level: 6 } });

      output.on('close', resolve);
      archive.on('error', reject);
      archive.pipe(output);

      for (const [name, data] of Object.entries(files)) {
        archive.append(JSON.stringify(data, null, 2), { name });
      }

      archive.finalize();
    });
  }

  private async applyExpirationPolicy(
    request: DataExportRequest,
  ): Promise<DataExportRequest> {
    if (
      (request.status === ExportStatus.PENDING ||
        request.status === ExportStatus.PROCESSING) &&
      Date.now() - request.createdAt.getTime() > DATA_EXPORT_PENDING_TTL_MS
    ) {
      await this.markExpiredAndCleanup(request.id, 'Export request timed out');
      const updated = await this.exportRepository.findOne({
        where: { id: request.id },
      });
      return updated ?? request;
    }

    if (
      request.status === ExportStatus.READY &&
      request.expiresAt &&
      request.expiresAt.getTime() < Date.now()
    ) {
      await this.markExpiredAndCleanup(request.id, 'Export link expired');
      const updated = await this.exportRepository.findOne({
        where: { id: request.id },
      });
      return updated ?? request;
    }

    return request;
  }

  private async markExpiredAndCleanup(
    requestId: string,
    reason = 'Export expired',
  ): Promise<void> {
    const request = await this.exportRepository.findOne({
      where: { id: requestId },
    });
    if (!request) {
      return;
    }

    await this.removeQueueJob(request.queueJobId);
    await this.deleteExportFile(request.filePath);
    await this.exportRepository.update(request.id, {
      status: ExportStatus.EXPIRED,
      token: null,
      filePath: null,
      errorMessage: reason,
    });
  }

  private async removeQueueJob(queueJobId?: string | null): Promise<void> {
    if (!queueJobId) {
      return;
    }
    const queueJob = await this.dataExportQueue.getJob(queueJobId);
    if (queueJob) {
      await queueJob.remove().catch(() => undefined);
    }
  }

  private async deleteExportFile(filePath?: string | null): Promise<void> {
    if (!filePath) {
      return;
    }
    try {
      await fs.promises.unlink(filePath);
    } catch {
      // Ignore missing files during cleanup.
    }
  }
}
