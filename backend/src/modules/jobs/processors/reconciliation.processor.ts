import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { FeeRewardReconciliationService } from '../services/fee-reward-reconciliation.service';

@Processor('reconciliation')
export class ReconciliationProcessor {
  private readonly logger = new Logger(ReconciliationProcessor.name);

  constructor(
    private readonly reconciliationService: FeeRewardReconciliationService,
  ) {}

  @Process('fee-reward-reconciliation')
  async handleReconciliation(job: Job) {
    this.logger.log(`Processing reconciliation job: ${job.id}`);
    try {
      const result = await this.reconciliationService.reconcile({
        jobId: String(job.id),
        correlationId: (job.data as { correlationId?: string })?.correlationId,
      });
      this.logger.log(`Job ${job.id} completed: ${JSON.stringify(result)}`);
    } catch (error) {
      this.logger.error(
        `Reconciliation job ${job.id} failed: ${(error as Error).message}`,
        (error as Error).stack,
      );
      throw error; // Let Bull handle retries
    }
  }
}
