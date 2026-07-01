import { createHash } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue, JobsOptions } from 'bullmq';
import { QUEUE_NAMES, JOB_NAMES } from './job-queue.constants';

export interface JobQueueAddOptions extends JobsOptions {
  idempotencyKey?: string;
}

export interface NotificationJobData {
  userId: string;
  type: string;
  title: string;
  message: string;
  metadata?: Record<string, any>;
  correlationId?: string;
}

export interface EmailJobData {
  to: string;
  subject: string;
  template: string;
  context: Record<string, any>;
  correlationId?: string;
}

export interface BlockchainJobData {
  eventId: string;
  contractId: string;
  eventType: string;
  rawEvent: Record<string, any>;
  correlationId?: string;
}

export interface ReportJobData {
  reportType: string;
  userId: string;
  params: Record<string, any>;
  scheduleId?: string;
  correlationId?: string;
}

export interface DisputeEvidenceJobData {
  evidenceId: string;
  disputeId: string;
  storagePath: string;
  mimeType: string;
  originalFilename: string;
  uploadedBy: string;
  correlationId?: string;
}

export interface AvatarJobData {
  uploadId: string;
  userId: string;
  storagePath: string;
  mimeType: string;
  originalFilename: string;
  correlationId?: string;
}

export interface AuditLogExportJobData {
  filters: {
    actor?: string;
    action?: string;
    resourceType?: string;
    resourceId?: string;
    fromDate?: string;
    toDate?: string;
  };
  format: 'csv' | 'json';
  requestedBy: string;
  correlationId?: string;
}

@Injectable()
export class JobQueueService {
  private readonly logger = new Logger(JobQueueService.name);

  constructor(
    @InjectQueue(QUEUE_NAMES.NOTIFICATIONS)
    private readonly notificationQueue: Queue,
    @InjectQueue(QUEUE_NAMES.EMAIL)
    private readonly emailQueue: Queue,
    @InjectQueue(QUEUE_NAMES.BLOCKCHAIN)
    private readonly blockchainQueue: Queue,
    @InjectQueue(QUEUE_NAMES.REPORTS)
    private readonly reportQueue: Queue,
    @InjectQueue(QUEUE_NAMES.DISPUTE_EVIDENCE)
    private readonly disputeEvidenceQueue: Queue,
    @InjectQueue(QUEUE_NAMES.AVATAR)
    private readonly avatarQueue: Queue,
    @InjectQueue(QUEUE_NAMES.AUDIT_LOG_EXPORT)
    private readonly auditLogExportQueue: Queue,
  ) {}

  async addNotificationJob(
    data: NotificationJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.notificationQueue.add(
    opts?: JobQueueAddOptions,
  ) {
    const entityId = `${data.userId}-${data.type}`;
    const job = await this.enqueueJob(
      this.notificationQueue,
      JOB_NAMES.SEND_NOTIFICATION,
      { ...data, correlationId },
      opts,
      entityId,
    );
    this.logger.debug(
      `Queued notification job ${job.id} for user ${data.userId}${correlationId ? ` correlationId=${correlationId}` : ''}`,
    );
    return job;
  }

  async addEmailJob(
    data: EmailJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.emailQueue.add(JOB_NAMES.SEND_EMAIL, { ...data, correlationId }, opts);
    this.logger.debug(`Queued email job ${job.id} to ${data.to}${correlationId ? ` correlationId=${correlationId}` : ''}`);
    return job;
  }

  async addBlockchainJob(
    data: BlockchainJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.blockchainQueue.add(
      JOB_NAMES.PROCESS_BLOCKCHAIN_EVENT,
      { ...data, correlationId },
      {
        ...opts,
        jobId: `blockchain-${data.eventId}`,
      },
  async addEmailJob(data: EmailJobData, opts?: JobQueueAddOptions) {
    const entityId = `${data.to}-${data.subject}-${data.template}`;
    const job = await this.enqueueJob(
      this.emailQueue,
      JOB_NAMES.SEND_EMAIL,
      data,
      opts,
      entityId,
    );
    this.logger.debug(`Queued email job ${job.id} to ${data.to}`);
    return job;
  }

  async addBlockchainJob(data: BlockchainJobData, opts?: JobQueueAddOptions) {
    const job = await this.enqueueJob(
      this.blockchainQueue,
      JOB_NAMES.PROCESS_BLOCKCHAIN_EVENT,
      data,
      { ...opts, jobId: opts?.jobId ?? `blockchain-${data.eventId}` },
      data.eventId,
    );
    this.logger.debug(
      `Queued blockchain job ${job.id} for event ${data.eventId}${correlationId ? ` correlationId=${correlationId}` : ''}`,
    );
    return job;
  }

  async addReportJob(
    data: ReportJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.reportQueue.add(
  async addReportJob(data: ReportJobData, opts?: JobQueueAddOptions) {
    const entityId = data.scheduleId ?? `${data.userId}-${data.reportType}`;
    const job = await this.enqueueJob(
      this.reportQueue,
      JOB_NAMES.GENERATE_REPORT,
      { ...data, correlationId },
      opts,
      entityId,
    );
    this.logger.debug(`Queued report job ${job.id} type=${data.reportType}${correlationId ? ` correlationId=${correlationId}` : ''}`);
    return job;
  }

  async addEvidenceProcessingJob(
    data: DisputeEvidenceJobData,
    opts?: JobsOptions,
    correlationId?: string,
    opts?: JobQueueAddOptions,
  ) {
    const job = await this.enqueueJob(
      this.disputeEvidenceQueue,
      JOB_NAMES.PROCESS_DISPUTE_EVIDENCE,
      { ...data, correlationId },
      {
        ...opts,
        jobId: opts?.jobId ?? `evidence-${data.evidenceId}`,
        attempts: 3,
        backoff: { type: 'exponential', delay: 3000 },
        removeOnComplete: { count: 200 },
        removeOnFail: { count: 500 },
      },
      data.evidenceId,
    );
    this.logger.debug(
      `Queued evidence processing job ${job.id} for evidenceId=${data.evidenceId} disputeId=${data.disputeId}${correlationId ? ` correlationId=${correlationId}` : ''}`,
    );
    return job;
  }

  async addAvatarProcessingJob(
    data: AvatarJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.avatarQueue.add(JOB_NAMES.PROCESS_AVATAR, { ...data, correlationId }, {
      ...opts,
      jobId: `avatar-${data.uploadId}`,
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: { count: 200 },
      removeOnFail: { count: 500 },
    });
  async addAvatarProcessingJob(data: AvatarJobData, opts?: JobQueueAddOptions) {
    const job = await this.enqueueJob(
      this.avatarQueue,
      JOB_NAMES.PROCESS_AVATAR,
      data,
      {
        ...opts,
        jobId: opts?.jobId ?? `avatar-${data.uploadId}`,
        attempts: 3,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: { count: 200 },
        removeOnFail: { count: 500 },
      },
      data.uploadId,
    );
    this.logger.debug(
      `Queued avatar processing job ${job.id} for uploadId=${data.uploadId} userId=${data.userId}${correlationId ? ` correlationId=${correlationId}` : ''}`,
    );
    return job;
  }

  async addAuditLogExportJob(
    data: AuditLogExportJobData,
    opts?: JobsOptions,
    correlationId?: string,
  ) {
    const job = await this.auditLogExportQueue.add(
    opts?: JobQueueAddOptions,
  ) {
    const filterHash = createHash('sha256')
      .update(JSON.stringify(data.filters ?? {}))
      .digest('hex')
      .slice(0, 8);
    const job = await this.enqueueJob(
      this.auditLogExportQueue,
      JOB_NAMES.EXPORT_AUDIT_LOGS,
      { ...data, correlationId },
      {
        ...opts,
        jobId:
          opts?.jobId ??
          `audit-export-${data.requestedBy}-${data.format}-${filterHash}`,
        attempts: 3,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 500 },
      },
      `${data.requestedBy}-${filterHash}`,
    );
    this.logger.debug(
      `Queued audit log export job ${job.id} for admin ${data.requestedBy}${correlationId ? ` correlationId=${correlationId}` : ''}`,
    );
    return job;
  }

  async getQueueStatus(queueName: string) {
    const queue = this.getQueue(queueName);
    if (!queue) return null;

    const [waiting, active, completed, failed, delayed] = await Promise.all([
      queue.getWaitingCount(),
      queue.getActiveCount(),
      queue.getCompletedCount(),
      queue.getFailedCount(),
      queue.getDelayedCount(),
    ]);

    const dlqSize = failed;

    return { queueName, waiting, active, completed, failed, delayed, dlqSize };
  }

  async getAllQueuesStatus() {
    const queues = Object.values(QUEUE_NAMES);
    const statuses = await Promise.all(
      queues.map((name) => this.getQueueStatus(name)),
    );
    return statuses.filter(Boolean);
  }

  async getDLQSize(queueName: string): Promise<number> {
    const queue = this.getQueue(queueName);
    if (!queue) return 0;
    return queue.getFailedCount();
  }

  async getFailedJobs(queueName: string, start = 0, end = 20) {
    const queue = this.getQueue(queueName);
    if (!queue) return [];
    return queue.getFailed(start, end);
  }

  async retryFailedJob(queueName: string, jobId: string) {
    const queue = this.getQueue(queueName);
    if (!queue) return null;

    const job = await queue.getJob(jobId);
    if (!job) return null;

    await job.retry();
    return { jobId, status: 'retried' };
  }

  private async enqueueJob<T extends object>(
    queue: Queue,
    name: string,
    data: T,
    opts?: JobQueueAddOptions,
    entityId?: string,
  ) {
    const jobId =
      opts?.jobId ??
      (entityId ? this.buildJobId(name, entityId, opts) : undefined);
    const { idempotencyKey, ...jobOptions } = opts ?? {};
    try {
      return await queue.add(name, data, { ...jobOptions, jobId });
    } catch (error) {
      if (jobId && this.isDuplicateJobError(error)) {
        const existing = await queue.getJob(jobId);
        if (existing) return existing;
      }
      throw error;
    }
  }

  private buildJobId(
    actionType: string,
    entityId: string,
    opts?: JobQueueAddOptions,
  ): string {
    const parts = [actionType, entityId];
    if (opts?.idempotencyKey) {
      parts.push(opts.idempotencyKey);
    }
    return parts
      .filter(Boolean)
      .map((segment) =>
        String(segment)
          .trim()
          .replace(/[^a-zA-Z0-9_-]+/g, '-')
          .replace(/^-+|-+$/g, ''),
      )
      .join('--');
  }

  private isDuplicateJobError(error: unknown): boolean {
    const err = error as { name?: string; message?: string };
    return Boolean(
      err?.name === 'JobAlreadyExistsError' ||
      err?.message?.includes('Job already exists') ||
      err?.message?.includes('already exists'),
    );
  }

  private getQueue(queueName: string): Queue | null {
    const map: Record<string, Queue> = {
      [QUEUE_NAMES.NOTIFICATIONS]: this.notificationQueue,
      [QUEUE_NAMES.EMAIL]: this.emailQueue,
      [QUEUE_NAMES.BLOCKCHAIN]: this.blockchainQueue,
      [QUEUE_NAMES.REPORTS]: this.reportQueue,
      [QUEUE_NAMES.DISPUTE_EVIDENCE]: this.disputeEvidenceQueue,
      [QUEUE_NAMES.AVATAR]: this.avatarQueue,
      [QUEUE_NAMES.AUDIT_LOG_EXPORT]: this.auditLogExportQueue,
    };
    return map[queueName] || null;
  }
}
