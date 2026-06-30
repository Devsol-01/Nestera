import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Service for handling eventual consistency scenarios
 * Provides utilities to determine appropriate retry timing and response codes
 */
@Injectable()
export class EventualConsistencyService {
  private readonly logger = new Logger(EventualConsistencyService.name);
  private readonly defaultRetryAfterSeconds: number;
  private readonly indexerPollIntervalSeconds: number;

  constructor(private readonly configService: ConfigService) {
    this.defaultRetryAfterSeconds = this.configService.get<number>(
      'eventualConsistency.defaultRetryAfterSeconds',
      30,
    );
    this.indexerPollIntervalSeconds =
      (this.configService.get<number>('stellar.eventPollInterval', 10000) ||
        10000) / 1000;
  }

  /**
   * Calculate retry-after seconds based on indexer state
   * Uses the indexer poll interval as a base, with a safety margin
   */
  calculateRetryAfter(multiplier: number = 3): number {
    return Math.ceil(this.indexerPollIntervalSeconds * multiplier);
  }

  /**
   * Get default retry-after seconds for generic eventual consistency scenarios
   */
  getDefaultRetryAfter(): number {
    return this.defaultRetryAfterSeconds;
  }

  /**
   * Determine if a resource is likely pending indexing based on creation time
   */
  isLikelyPendingIndexing(createdAt: Date, maxAgeSeconds: number = 60): boolean {
    const ageSeconds = (Date.now() - createdAt.getTime()) / 1000;
    return ageSeconds < maxAgeSeconds;
  }

  /**
   * Get retry-after seconds for a recently created resource
   */
  getRetryAfterForRecentCreation(createdAt: Date): number {
    const ageSeconds = (Date.now() - createdAt.getTime()) / 1000;
    const remainingTime = Math.max(0, 60 - ageSeconds); // Assume 60s indexing window
    return Math.ceil(remainingTime + this.indexerPollIntervalSeconds);
  }
}
