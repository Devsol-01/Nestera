import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUE_NAMES } from '../job-queue.constants';
import { BlockchainJobData } from '../job-queue.service';

@Processor(QUEUE_NAMES.BLOCKCHAIN, { concurrency: 5 })
export class BlockchainProcessor extends WorkerHost {
  private readonly logger = new Logger(BlockchainProcessor.name);

  async process(job: Job<BlockchainJobData>): Promise<any> {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(
      `${correlationPrefix}Processing blockchain job ${job.id} (attempt ${job.attemptsMade + 1})`,
    );

    const { eventId, contractId, eventType } = job.data;

    this.logger.log(
      `${correlationPrefix}Blockchain event processed: eventId=${eventId} contract=${contractId} type=${eventType}`,
    );

    return { processed: true, eventId, eventType };
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job<BlockchainJobData>, error: Error) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.error(
      `${correlationPrefix}Blockchain job ${job.id} failed after ${job.attemptsMade} attempts: ${error.message}`,
    );

    if (job.attemptsMade >= (job.opts.attempts ?? 5)) {
      this.logger.error(
        `${correlationPrefix}Blockchain job ${job.id} moved to DLQ — eventId=${job.data.eventId} type=${job.data.eventType}`,
      );
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<BlockchainJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(`${correlationPrefix}Blockchain job ${job.id} completed`);
  }
}
