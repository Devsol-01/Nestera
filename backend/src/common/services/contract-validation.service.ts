import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface ValidationFailureRecord {
  correlationId: string;
  endpoint: string;
  reason: string;
  timestamp: Date;
  details: Record<string, unknown>;
}

/**
 * ContractValidationService: Handles logging and tracking of validation failures
 * across the application. Provides insights into contract mismatches and enables
 * monitoring of strict validation behavior.
 */
@Injectable()
export class ContractValidationService {
  private readonly logger = new Logger(ContractValidationService.name);
  private readonly maxRecords = 10000; // In-memory limit
  private readonly failureLog: ValidationFailureRecord[] = [];

  constructor(private configService: ConfigService) {}

  /**
   * Record a validation failure with full context
   */
  recordValidationFailure(
    correlationId: string,
    endpoint: string,
    reason: string,
    details: Record<string, unknown>,
  ): void {
    const record: ValidationFailureRecord = {
      correlationId,
      endpoint,
      reason,
      timestamp: new Date(),
      details,
    };

    // Log to application logs
    this.logger.warn(
      `Validation failure [${correlationId}] ${endpoint}: ${reason}`,
      { details },
    );

    // Store in memory (with rotation if needed)
    this.failureLog.push(record);
    if (this.failureLog.length > this.maxRecords) {
      this.failureLog.shift();
    }
  }

  /**
   * Get validation failure records for monitoring/debugging
   * Can be filtered by endpoint, reason, or time range
   */
  getFailureRecords(options?: {
    endpoint?: string;
    reason?: string;
    limit?: number;
    since?: Date;
  }): ValidationFailureRecord[] {
    let records = [...this.failureLog];

    if (options?.endpoint) {
      records = records.filter((r) => r.endpoint.includes(options.endpoint));
    }

    if (options?.reason) {
      records = records.filter((r) => r.reason === options.reason);
    }

    if (options?.since) {
      records = records.filter((r) => r.timestamp >= options.since);
    }

    // Return most recent first
    records.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const limit = options?.limit ?? 100;
    return records.slice(0, limit);
  }

  /**
   * Get aggregated statistics on validation failures
   */
  getFailureStatistics(since?: Date): {
    totalFailures: number;
    failuresByReason: Record<string, number>;
    failuresByEndpoint: Record<string, number>;
    uniqueCorrelationIds: number;
  } {
    const records = since
      ? this.failureLog.filter((r) => r.timestamp >= since)
      : this.failureLog;

    const failuresByReason: Record<string, number> = {};
    const failuresByEndpoint: Record<string, number> = {};
    const correlationIds = new Set<string>();

    for (const record of records) {
      failuresByReason[record.reason] =
        (failuresByReason[record.reason] ?? 0) + 1;
      failuresByEndpoint[record.endpoint] =
        (failuresByEndpoint[record.endpoint] ?? 0) + 1;
      correlationIds.add(record.correlationId);
    }

    return {
      totalFailures: records.length,
      failuresByReason,
      failuresByEndpoint,
      uniqueCorrelationIds: correlationIds.size,
    };
  }

  /**
   * Clear failure log (useful for testing or reset)
   */
  clearFailureLog(): void {
    this.failureLog.length = 0;
    this.logger.debug('Validation failure log cleared');
  }

  /**
   * Get a specific failure record by correlation ID
   */
  getFailureByCorrelationId(correlationId: string): ValidationFailureRecord[] {
    return this.failureLog.filter((r) => r.correlationId === correlationId);
  }
}
