import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { IdempotencyCleanupEvent } from './idempotency-cleanup.service';

export interface IdempotencyConflictEvent {
  /** The idempotency key submitted by the client (never the payload) */
  idempotencyKey: string;
  /** SHA-256 fingerprint of the incoming request body */
  requestFingerprintHash: string;
  /** HTTP method of the conflicting request */
  method: string;
  /** Route path of the conflicting request */
  path: string;
  /** The type of conflict that occurred */
  conflictType: 'payload_mismatch' | 'concurrent_processing';
  /** ISO timestamp when the conflict was detected */
  timestamp: string;
  /** Related entity type inferred from the route, if determinable */
  relatedEntityType?: string;
}

export interface IdempotencyUsageRecord {
  /** The idempotency key submitted by the client */
  idempotencyKey: string;
  /** HTTP method */
  method: string;
  /** Route path */
  path: string;
  /** ISO timestamp of the first use */
  firstSeenAt: string;
  /** ISO timestamp of the last use / replay */
  lastSeenAt: string;
  /** Number of replay (cache-hit) requests for this key */
  replayCount: number;
}

/**
 * Trimmed copy of the cleanup-event payload that the monitor keeps
 * for admin observability.  Mirrors records in
 * `IdempotencyCleanupService.metrics` but is exposed via the same
 * admin surface as conflict / usage data.
 */
export interface IdempotencyCleanupRunRecord {
  cleanedCount: number;
  skippedCount: number;
  scannedCount: number;
  durationMs: number;
  missingExpiresAtCount: number;
  earliestActiveExpiresAt?: number;
  finishedAt: string;
  reason: string;
}

@Injectable()
export class IdempotencyMonitorService {
  private readonly logger = new Logger(IdempotencyMonitorService.name);

  /** Circular buffer for conflicts – max 1 000 entries */
  private readonly conflicts: IdempotencyConflictEvent[] = [];
  private readonly MAX_CONFLICTS = 1_000;

  /** Circular buffer for recent key usage – max 5 000 entries */
  private readonly usageMap = new Map<string, IdempotencyUsageRecord>();
  private readonly MAX_USAGE_KEYS = 5_000;

  /**
   * Circular buffer for cleanup runs – max 50 entries.  Cleanup runs
   * are much rarer than idempotency requests so a smaller cap is fine.
   */
  private readonly cleanupHistory: IdempotencyCleanupRunRecord[] = [];
  private readonly MAX_CLEANUP_RUNS = 50;

  /** Aggregate counters over the lifetime of the process. */
  private cleanupAggregate = {
    totalRuns: 0,
    successfulRuns: 0,
    skippedNotLeaderRuns: 0,
    skippedNoRedisRuns: 0,
    skippedDisabledRuns: 0,
    errorRuns: 0,
    totalCleaned: 0,
    lastStartAt: null as string | null,
  };

  constructor(private readonly eventEmitter: EventEmitter2) {}

  // ──────────────────────────────────────────────────────────────────────────
  // Event listeners (called by IdempotencyInterceptor)
  // ──────────────────────────────────────────────────────────────────────────

  @OnEvent('idempotency.conflict')
  handleConflict(event: IdempotencyConflictEvent): void {
    if (this.conflicts.length >= this.MAX_CONFLICTS) {
      this.conflicts.shift();
    }
    this.conflicts.push(event);
    this.logger.debug(
      `Idempotency conflict recorded: key=${event.idempotencyKey} type=${event.conflictType} on ${event.method} ${event.path}`,
    );
  }

  @OnEvent('idempotency.replay')
  handleReplay(record: { key: string; method: string; path: string }): void {
    const existing = this.usageMap.get(record.key);
    if (existing) {
      existing.lastSeenAt = new Date().toISOString();
      existing.replayCount += 1;
    } else {
      this.evictOldestUsageIfNeeded();
      this.usageMap.set(record.key, {
        idempotencyKey: record.key,
        method: record.method,
        path: record.path,
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        replayCount: 1,
      });
    }
  }

  /** Called on first successful processing of a new idempotency key */
  @OnEvent('idempotency.first_use')
  handleFirstUse(record: { key: string; method: string; path: string }): void {
    if (this.usageMap.has(record.key)) return;
    this.evictOldestUsageIfNeeded();
    this.usageMap.set(record.key, {
      idempotencyKey: record.key,
      method: record.method,
      path: record.path,
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      replayCount: 0,
    });
  }

  /**
   * Records metrics from the periodic background cleanup job.  Updates
   * the aggregate counter and pushes a trimmed record onto the
   * circular buffer for admin observability.
   */
  @OnEvent('idempotency.cleanup')
  handleCleanup(event: IdempotencyCleanupEvent): void {
    this.cleanupAggregate.totalRuns += 1;
    this.cleanupAggregate.lastStartAt = event.finishedAt;
    this.cleanupAggregate.totalCleaned += event.cleanedCount;

    switch (event.reason) {
      case 'cleaned':
        this.cleanupAggregate.successfulRuns += 1;
        break;
      case 'skipped-not-leader':
        this.cleanupAggregate.skippedNotLeaderRuns += 1;
        break;
      case 'skipped-no-redis':
        this.cleanupAggregate.skippedNoRedisRuns += 1;
        break;
      case 'skipped-disabled':
        this.cleanupAggregate.skippedDisabledRuns += 1;
        break;
      case 'error':
        // Recorded as a distinct category so observability surfaces
        // differentiate a Redis flap from "cleanup never ran".
        this.cleanupAggregate.errorRuns += 1;
        break;
      default:
        // Future reason labels — counted in totalRuns only.
        break;
    }

    if (this.cleanupHistory.length >= this.MAX_CLEANUP_RUNS) {
      this.cleanupHistory.shift();
    }
    this.cleanupHistory.push({
      cleanedCount: event.cleanedCount,
      skippedCount: event.skippedCount,
      scannedCount: event.scannedCount,
      durationMs: event.durationMs,
      missingExpiresAtCount: event.missingExpiresAtCount,
      earliestActiveExpiresAt: event.earliestActiveExpiresAt,
      finishedAt: event.finishedAt,
      reason: event.reason,
    });

    this.logger.debug(
      `Idempotency cleanup run recorded: reason=${event.reason} cleaned=${event.cleanedCount} skipped=${event.skippedCount} durationMs=${event.durationMs}`,
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Query methods (used by admin controller)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Returns the most recent conflicts, newest first.
   * Optionally filtered by conflictType or route path.
   */
  getRecentConflicts(
    limit = 50,
    conflictType?: 'payload_mismatch' | 'concurrent_processing',
    path?: string,
  ): IdempotencyConflictEvent[] {
    let results = [...this.conflicts].reverse();

    if (conflictType) {
      results = results.filter((c) => c.conflictType === conflictType);
    }
    if (path) {
      results = results.filter((c) => c.path.includes(path));
    }

    return results.slice(0, limit);
  }

  /** Summary stats across all tracked conflicts */
  getConflictSummary(): {
    total: number;
    last24h: number;
    last1h: number;
    byConflictType: Record<string, number>;
    byRoute: Record<string, number>;
    topConflictingKeys: { idempotencyKey: string; count: number }[];
  } {
    const now = Date.now();
    const last24hCutoff = now - 24 * 60 * 60 * 1_000;
    const last1hCutoff = now - 60 * 60 * 1_000;

    const last24h = this.conflicts.filter(
      (c) => new Date(c.timestamp).getTime() >= last24hCutoff,
    );
    const last1h = this.conflicts.filter(
      (c) => new Date(c.timestamp).getTime() >= last1hCutoff,
    );

    const byConflictType: Record<string, number> = {};
    const byRoute: Record<string, number> = {};
    const keyCounts: Record<string, number> = {};

    for (const c of last24h) {
      byConflictType[c.conflictType] =
        (byConflictType[c.conflictType] || 0) + 1;

      const routeKey = `${c.method} ${c.path}`;
      byRoute[routeKey] = (byRoute[routeKey] || 0) + 1;

      keyCounts[c.idempotencyKey] = (keyCounts[c.idempotencyKey] || 0) + 1;
    }

    const topConflictingKeys = Object.entries(keyCounts)
      .map(([idempotencyKey, count]) => ({ idempotencyKey, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      total: this.conflicts.length,
      last24h: last24h.length,
      last1h: last1h.length,
      byConflictType,
      byRoute,
      topConflictingKeys,
    };
  }

  /**
   * Returns recent key usage records, sorted by lastSeenAt descending.
   */
  getKeyUsage(limit = 50, path?: string): IdempotencyUsageRecord[] {
    let records = Array.from(this.usageMap.values());

    if (path) {
      records = records.filter((r) => r.path.includes(path));
    }

    return records
      .sort(
        (a, b) =>
          new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime(),
      )
      .slice(0, limit);
  }

  /**
   * Returns recent cleanup runs, newest first.
   */
  getCleanupHistory(limit = 20): IdempotencyCleanupRunRecord[] {
    return [...this.cleanupHistory].reverse().slice(0, limit);
  }

  /**
   * Aggregate summary of cleanup runs since process start.
   */
  getCleanupSummary(): {
    totalRuns: number;
    successfulRuns: number;
    skippedNotLeaderRuns: number;
    skippedNoRedisRuns: number;
    skippedDisabledRuns: number;
    errorRuns: number;
    totalCleaned: number;
    lastStartAt: string | null;
    recentRuns: IdempotencyCleanupRunRecord[];
  } {
    return {
      totalRuns: this.cleanupAggregate.totalRuns,
      successfulRuns: this.cleanupAggregate.successfulRuns,
      skippedNotLeaderRuns: this.cleanupAggregate.skippedNotLeaderRuns,
      skippedNoRedisRuns: this.cleanupAggregate.skippedNoRedisRuns,
      skippedDisabledRuns: this.cleanupAggregate.skippedDisabledRuns,
      errorRuns: this.cleanupAggregate.errorRuns,
      totalCleaned: this.cleanupAggregate.totalCleaned,
      lastStartAt: this.cleanupAggregate.lastStartAt,
      recentRuns: this.getCleanupHistory(10),
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Internal helpers
  // ──────────────────────────────────────────────────────────────────────────

  private evictOldestUsageIfNeeded(): void {
    if (this.usageMap.size >= this.MAX_USAGE_KEYS) {
      // Map preserves insertion order; delete the first (oldest) entry
      const firstKey = this.usageMap.keys().next().value;
      if (firstKey !== undefined) {
        this.usageMap.delete(firstKey);
      }
    }
  }
}
