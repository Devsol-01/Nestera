import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QUEUE_NAMES } from '../job-queue.constants';
import { NotificationJobData } from '../job-queue.service';
import {
  Notification,
  NotificationType,
} from '../../notifications/entities/notification.entity';

@Processor(QUEUE_NAMES.NOTIFICATIONS, { concurrency: 5 })
export class NotificationProcessor extends WorkerHost {
  private readonly logger = new Logger(NotificationProcessor.name);

  constructor(
    @InjectRepository(Notification)
    private readonly notificationRepo: Repository<Notification>,
  ) {
    super();
  }

  async process(job: Job<NotificationJobData>): Promise<any> {
    const { correlationId } = job.data;
    const correlationPrefix = correlationId ? `[${correlationId}] ` : '';

    this.logger.debug(
      `${correlationPrefix}Processing notification job ${job.id} (attempt ${job.attemptsMade + 1})`,
    );

    const { userId, type, title, message, metadata } = job.data;

    const notification = this.notificationRepo.create({
      userId,
      type: type as NotificationType,
      title,
      message,
      metadata: metadata ?? null,
    });
    await this.notificationRepo.save(notification);

    this.logger.log(
      `${correlationPrefix}Notification dispatched: user=${userId} type=${type} title="${title}"`,
    );

    return { processed: true, userId, type, notificationId: notification.id };
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job<NotificationJobData>, error: Error) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.error(
      `${correlationPrefix}Notification job ${job.id} failed after ${job.attemptsMade} attempts: ${error.message}`,
    );

    if (job.attemptsMade >= (job.opts.attempts ?? 3)) {
      this.logger.error(
        `${correlationPrefix}Notification job ${job.id} moved to DLQ — user=${job.data.userId} type=${job.data.type}`,
      );
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<NotificationJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(`${correlationPrefix}Notification job ${job.id} completed`);
  }
}
