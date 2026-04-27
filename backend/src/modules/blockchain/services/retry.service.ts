import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DeadLetterEvent } from '../entities/dead-letter-event.entity';

export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
}

export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 5,
  baseDelayMs: 1000,
  maxDelayMs: 5 * 60 * 1000, // 5 minutes
  backoffMultiplier: 2,
};

@Injectable()
export class RetryService {
  private readonly logger = new Logger(RetryService.name);
  private readonly config: RetryConfig;

  constructor(
    @InjectRepository(DeadLetterEvent)
    private readonly dlqRepo: Repository<DeadLetterEvent>,
  ) {
    this.config = { ...DEFAULT_RETRY_CONFIG };
  }

  /**
   * Calculate exponential backoff delay
   */
  calculateDelay(retryCount: number): number {
    const delay =
      this.config.baseDelayMs *
      Math.pow(this.config.backoffMultiplier, retryCount);
    return Math.min(delay, this.config.maxDelayMs);
  }

  /**
   * Determine if an event should be retried based on retry count and backoff
   */
  shouldRetry(dlqEvent: DeadLetterEvent): boolean {
    if (dlqEvent.retryCount >= this.config.maxRetries) {
      return false;
    }

    // If nextRetryAt is set, wait until that time
    if (dlqEvent.nextRetryAt && new Date() < dlqEvent.nextRetryAt) {
      return false;
    }

    return true;
  }

  /**
   * Schedule a retry by updating the DLQ entry with next retry time
   */
  async scheduleRetry(dlqEvent: DeadLetterEvent): Promise<DeadLetterEvent> {
    const newRetryCount = dlqEvent.retryCount + 1;
    const delay = this.calculateDelay(newRetryCount - 1);
    const nextRetryAt = new Date(Date.now() + delay);

    this.logger.log(
      `Scheduling retry #${newRetryCount} for DLQ event ${dlqEvent.id} in ${delay}ms (ledger: ${dlqEvent.ledgerSequence})`,
    );

    return this.dlqRepo.save({
      ...dlqEvent,
      retryCount: newRetryCount,
      nextRetryAt,
      lastRetryAt: new Date(),
    });
  }

  /**
   * Mark a retry as successful - remove from DLQ
   */
  async markSuccessful(id: string): Promise<void> {
    await this.dlqRepo.delete(id);
  }

  /**
   * Get all events eligible for retry (retry count < max and nextRetryAt <= now)
   */
  async getRetryableEvents(): Promise<DeadLetterEvent[]> {
    const now = new Date();
    const all = await this.dlqRepo.find({
      order: { createdAt: 'ASC' },
    });
    return all.filter((e) => e.nextRetryAt === null || e.nextRetryAt <= now);
  }

  /**
   * Update error message for a DLQ event
   */
  async updateError(id: string, errorMessage: string): Promise<void> {
    await this.dlqRepo.update(id, {
      errorMessage: errorMessage,
      lastError: errorMessage,
    });
  }

  /**
   * Get retry statistics
   */
  async getRetryStats(): Promise<{
    total: number;
    retryable: number;
    maxRetriesReached: number;
    avgRetryCount: number;
  }> {
    const all = await this.dlqRepo.find();

    const retryable = all.filter((e) => this.shouldRetry(e)).length;
    const maxRetriesReached = all.filter(
      (e) => e.retryCount >= this.config.maxRetries,
    ).length;
    const avgRetryCount =
      all.length > 0
        ? all.reduce((sum, e) => sum + e.retryCount, 0) / all.length
        : 0;

    return {
      total: all.length,
      retryable,
      maxRetriesReached,
      avgRetryCount,
    };
  }
}
