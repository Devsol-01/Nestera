import { Injectable } from '@nestjs/common';
import {
  HealthIndicator,
  HealthIndicatorResult,
  HealthCheckError,
} from '@nestjs/terminus';
import { StellarEventListenerService } from '../stellar-event-listener.service';

/**
 * StellarEventListener Health Indicator
 * Monitors the health of the Stellar event listener service
 */
@Injectable()
export class StellarEventListenerHealthIndicator extends HealthIndicator {
  private readonly STALL_THRESHOLD_MS = 30000; // 30 seconds
  private readonly DLQ_THRESHOLD = 100; // Alert if more than 100 failed events in DLQ

  constructor(private readonly eventListener: StellarEventListenerService) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      const status = this.eventListener.getStatus();
      const now = Date.now();

      // Check if service is running
      if (!status.isRunning) {
        const result = this.getStatus(key, false, {
          message: 'Event listener is not running',
          contractId: status.contractId,
        });
        throw new HealthCheckError('Event listener stopped', result);
      }

      // Check if we've processed any events recently
      // We need to get last processed timestamp from indexer state
      // For now, check if we have a cursor (indicates some processing happened)
      if (!status.lastCursor) {
        const result = this.getStatus(key, false, {
          message: 'No events processed yet',
          contractId: status.contractId,
        });
        throw new HealthCheckError('No events processed', result);
      }

      // Check DLQ size - if too many failures, consider degraded
      const dlqStats = await this.eventListener.getDLQStats();
      const dlqHealthy = dlqStats.total < this.DLQ_THRESHOLD;

      const result = this.getStatus(key, dlqHealthy, {
        contractId: status.contractId,
        lastLedger: status.lastLedger,
        totalProcessed: status.totalProcessed,
        totalFailed: status.totalFailed,
        dlqSize: dlqStats.total,
        dlqRetryable: dlqStats.retryable,
      });

      if (!dlqHealthy) {
        throw new HealthCheckError(
          `DLQ size (${dlqStats.total}) exceeds threshold (${this.DLQ_THRESHOLD})`,
          result,
        );
      }

      return result;
    } catch (error) {
      if (error instanceof HealthCheckError) {
        throw error;
      }

      const result = this.getStatus(key, false, {
        message: error instanceof Error ? error.message : 'Unknown error',
      });

      throw new HealthCheckError('Event listener health check failed', result);
    }
  }
}
