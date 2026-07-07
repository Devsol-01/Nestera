import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SchedulerRegistry } from '@nestjs/schedule';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CronExpression as CronLibExpression, CronJob } from 'cron';
import { DistributedLockService } from '../distributed-lock/distributed-lock.service';
import { ShutdownTrackedTask } from '../decorators/shutdown-task.decorator';
import { IdempotencyService, IDEMPOTENCY_LOCK_SUFFIX } from './idempotency.service';

export interface IdempotencyCleanupEvent {
  /** Number of expired-and-deleted records in this run. */
  cleanedCount: number;
  /** Number of records seen but conservatively kept (active or missing expiresAt). */
  skippedCount: number;
  /** Number of records the SCAN/loop touched (cleaned + skipped + errors). */
  scannedCount: number;
  /** Wall-clock duration of the run in milliseconds. */
  durationMs: number;
  /** True when a record existed in cache but its `expiresAt` was missing. */
  missingExpiresAtCount: number;
  /** Earliest expiresAt observed among the kept (still active) records. */
  earliestActiveExpiresAt?: number;
  /** ISO timestamp of when the run completed. */
  finishedAt: string;
  /**
   * Outcome label:
   *  - 'cleaned'                — work performed
   *  - 'skipped-not-leader'     — another instance held the lock
   *  - 'skipped-no-redis'       — no ioredis-backed store detected
   *  - 'skipped-disabled'       — cleanup disabled by configuration
   *  - 'error'                  — run threw inside the lock (distinct from no-redis)
   */
  reason: string;
}

/**
 * Cumulative metrics the service keeps in-memory, exposed for the
 * admin monitoring surface and for tests.
 */
export interface IdempotencyCleanupMetrics {
  totalRuns: number;
  successfulRuns: number;
  skippedNotLeaderRuns: number;
  skippedNoRedisRuns: number;
  skippedDisabledRuns: number;
  errorRuns: number;
  totalCleaned: number;
  lastRun: IdempotencyCleanupEvent | null;
  lastStartAt: string | null;
}

const DEFAULT_CRON_SCHEDULE = '0 * * * *';
const CLEANUP_LOCK_KEY = 'cron:idempotency-cleanup';
const CLEANUP_SCAN_PATTERN = 'idempotency:*';

@Injectable()
export class IdempotencyCleanupService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(IdempotencyCleanupService.name);

  private readonly enabled: boolean;
  /** Expression registered at construction time — see OnModuleInit. */
  private readonly cronSchedule: string;
  private readonly batchSize: number;
  private readonly scanCount: number;
  private readonly lockTtlMs: number;

  private readonly metrics: IdempotencyCleanupMetrics = {
    totalRuns: 0,
    successfulRuns: 0,
    skippedNotLeaderRuns: 0,
    skippedNoRedisRuns: 0,
    skippedDisabledRuns: 0,
    errorRuns: 0,
    totalCleaned: 0,
    lastRun: null,
    lastStartAt: null,
  };

  /**
   * Tracks in-progress handler invocations so graceful shutdown can
   * wait for the current run to complete.  Cleared from
   * `OnModuleDestroy` via `OnApplicationShutdown`-style coordination
   * with `ShutdownTrackedTask`.
   */
  private isShuttingDown = false;

  constructor(
    private readonly configService: ConfigService,
    private readonly idempotencyService: IdempotencyService,
    private readonly distributedLockService: DistributedLockService,
    private readonly eventEmitter: EventEmitter2,
    private readonly schedulerRegistry: SchedulerRegistry,
  ) {
    const cfgEnabled =
      this.configService.get<boolean>('idempotency.cleanupEnabled', true);
    this.enabled = cfgEnabled !== false; // explicit false disables
    const rawSchedule =
      this.configService.get<string>(
        'idempotency.cleanupCronSchedule',
        DEFAULT_CRON_SCHEDULE,
      ) ?? DEFAULT_CRON_SCHEDULE;
    // Validate via the `cron` library's own static helper.  We don't
    // use `@nestjs/schedule`'s CronExpression here because that export
    // is a plain enum of named values, not a validator; calling
    // .validateString on it would throw TypeError at runtime.
    this.cronSchedule = this.isValidCronExpression(rawSchedule)
      ? rawSchedule
      : DEFAULT_CRON_SCHEDULE;
    this.batchSize = Math.max(
      1,
      this.configService.get<number>(
        'idempotency.cleanupBatchSize',
        500,
      ) ?? 500,
    );
    this.scanCount = Math.max(
      1,
      this.configService.get<number>(
        'idempotency.cleanupScanCount',
        200,
      ) ?? 200,
    );
    this.lockTtlMs =
      this.configService.get<number>(
        'idempotency.cleanupLockTtlMs',
        120_000,
      ) ?? 120_000;
  }

  /**
   * Registers the cleanup job with `SchedulerRegistry` so the
   * operator-configured cron expression is actually honoured.  This
   * sidesteps `@nestjs/schedule`'s class-load-time `@Cron` decorator
   * limitation which would otherwise bake the expression in at
   * compile time.
   */
  onModuleInit(): void {
    if (!this.enabled) {
      this.logger.log(
        `Idempotency cleanup is disabled by configuration (cron='${this.cronSchedule}'). Skipping scheduler registration.`,
      );
      return;
    }

    if (this.schedulerRegistry.doesExist('cron', 'idempotency-cleanup')) {
      // Idempotent re-registration (e.g. hot-reload in dev).
      this.schedulerRegistry.deleteCronJob('idempotency-cleanup');
    }

    // The CronJob constructor itself validates the expression.  Wrap
    // it so a misconfigured IDEMPOTENCY_CLEANUP_CRON does not crash
    // startup; fall back to the default hourly schedule and log.
    let job: CronJob;
    try {
      job = new CronJob(this.cronSchedule, () => {
        // Run async; don't let cron throw on rejected promises.
        void this.handleCronCleanup();
      });
    } catch (err) {
      const message = (err as Error)?.message ?? String(err);
      this.logger.error(
        `Invalid IDEMPOTENCY_CLEANUP_CRON='${this.cronSchedule}': ${message}. ` +
          `Falling back to default '${DEFAULT_CRON_SCHEDULE}'.`,
      );
      job = new CronJob(DEFAULT_CRON_SCHEDULE, () => {
        void this.handleCronCleanup();
      });
    }

    this.schedulerRegistry.addCronJob('idempotency-cleanup', job);
    job.start();
    this.logger.log(
      `Idempotency cleanup scheduled with cron='${this.cronSchedule}' batchSize=${this.batchSize} scanCount=${this.scanCount} lockTtlMs=${this.lockTtlMs}`,
    );
  }

  onModuleDestroy(): void {
    this.isShuttingDown = true;
    if (this.schedulerRegistry.doesExist('cron', 'idempotency-cleanup')) {
      try {
        this.schedulerRegistry.getCronJob('idempotency-cleanup').stop();
      } catch (err) {
        this.logger.warn(
          `Failed to stop idempotency cleanup cron: ${
            (err as Error)?.message ?? String(err)
          }`,
        );
      }
    }
  }

  /**
   * Cron handler wired via `SchedulerRegistry`.  Routed through
   * `ShutdownTrackedTask` so a graceful shutdown can wait for the
   * current run to finish before the process exits.
   */
  @ShutdownTrackedTask()
  async handleCronCleanup(): Promise<void> {
    if (this.isShuttingDown) {
      this.logger.debug(
        'Idempotency cleanup cron tick skipped: shutdown in progress',
      );
      return;
    }
    await this.handleCleanup();
  }

  /**
   * Public entry-point used by both the cron registry and by tests.
   * Returns a structured result describing the run so callers can
   * assert on outcomes without parsing logs.
   *
   * The method is fully exception-safe: a throw inside the work fn
   * is captured into a `reason: 'error'` event so observability
   * surfaces (metrics + monitor history) stay consistent even when
   * Redis flaps or SCAN fails.
   */
  async handleCleanup(): Promise<IdempotencyCleanupEvent> {
    const startedAt = Date.now();
    this.metrics.totalRuns += 1;
    this.metrics.lastStartAt = new Date(startedAt).toISOString();

    if (!this.enabled) {
      const event = this.recordOutcome(
        startedAt,
        'skipped-disabled',
        0,
        0,
        0,
        0,
        undefined,
      );
      this.metrics.skippedDisabledRuns += 1;
      this.logger.debug(
        'Idempotency cleanup run started in disabled mode (no lock taken)',
      );
      this.eventEmitter.emit('idempotency.cleanup', event);
      return event;
    }

    // The `.then(success, err)` below is the single error-capture path;
    // every rejection from `withLock` (including synchronous throws inside
    // its `acquireLock` path) is routed through the err handler, which
    // is the only place `errorRuns` increments.  We deliberately do NOT
    // wrap this in an outer try/catch to avoid double-counting when the
    // err handler itself were to throw.
    return await this.distributedLockService
      .withLock(
        CLEANUP_LOCK_KEY,
        async () => {
          const redis = this.idempotencyService.getUnderlyingRedisClient();

          if (!redis) {
            const event = this.recordOutcome(
              startedAt,
              'skipped-no-redis',
              0,
              0,
              0,
              0,
              undefined,
            );
            this.metrics.skippedNoRedisRuns += 1;
            this.logger.warn(
              'Idempotency cleanup skipped: no ioredis-backed cache store detected. ' +
                'In-memory cache-manager stores self-clean on TTL/eviction.',
            );
            this.eventEmitter.emit('idempotency.cleanup', event);
            return event;
          }

          return this.runCleanupAgainstRedis(redis, startedAt);
        },
        {
          ttlMs: this.lockTtlMs,
          retryMs: 50,
          maxRetries: 0,
        },
      )
      .then(
        (result) => {
          if (result === null) {
            const event = this.recordOutcome(
              startedAt,
              'skipped-not-leader',
              0,
              0,
              0,
              0,
              undefined,
            );
            this.metrics.skippedNotLeaderRuns += 1;
            this.logger.debug(
              'Idempotency cleanup skipped: another instance holds the cleanup lock',
            );
            this.eventEmitter.emit('idempotency.cleanup', event);
            return event;
          }
          return result;
        },
        (err) => {
          // withLock's inner fn (or its acquire path) threw.  The
          // distributed lock was still released by withLock's own
          // `finally`.  Capture the run so dashboards don't silently
          // miss a Redis flap or other transient blow-up.  IMPORTANT:
          // this is the only place errorRuns is incremented.
          const message = (err as Error)?.message ?? String(err);
          const event = this.recordOutcome(
            startedAt,
            'error',
            0,
            0,
            0,
            0,
            undefined,
          );
          this.metrics.errorRuns += 1;
          this.logger.error(`Idempotency cleanup failed: ${message}`);
          this.eventEmitter.emit('idempotency.cleanup', event);
          return event;
        },
      );
  }

  /** Read-only view of in-process metrics for admin/tests. */
  getMetrics(): IdempotencyCleanupMetrics {
    return {
      ...this.metrics,
      lastRun: this.metrics.lastRun ? { ...this.metrics.lastRun } : null,
    };
  }

  /** Returns the cron expression and enabled flag. */
  getSchedule(): { expression: string; enabled: boolean } {
    return { expression: this.cronSchedule, enabled: this.enabled };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Internal helpers
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Returns true when `expression` parses as a valid 5-field cron
   * expression via the `cron` package's `CronExpression.parseStandard`.
   * Used to short-circuit an obviously-invalid operator-supplied
   * schedule before we hand it to `new CronJob(...)`; the constructor
   * also validates, but doing so earlier keeps the log message
   * precise.
   */
  private isValidCronExpression(expression: string): boolean {
    if (typeof expression !== 'string' || expression.trim().length === 0) {
      return false;
    }
    try {
      // CronLibExpression.parseStandard returns `{ iterator: () => ... }`
      // on success and throws on parse failure.  We only care that it
      // returned without throwing.
      const parsed = CronLibExpression.parseStandard(expression.trim());
      return Boolean(parsed);
    } catch {
      return false;
    }
  }

  private async runCleanupAgainstRedis(
    redis: NonNullable<
      ReturnType<IdempotencyService['getUnderlyingRedisClient']>
    >,
    startedAt: number,
  ): Promise<IdempotencyCleanupEvent> {
    let cursor = '0';
    const collectedKeys: string[] = [];
    const deadline = startedAt + this.lockTtlMs - 5_000;

    // Phase 1 — paginate SCAN to gather a batch of candidate keys.
    // We deliberately do not delete inside the SCAN callback to keep
    // iteration non-blocking across the whole keyspace.
    do {
      const [nextCursor, keys] = await redis.scan(
        cursor,
        CLEANUP_SCAN_PATTERN,
        this.scanCount,
      );
      cursor = nextCursor;

      for (const key of keys) {
        if (collectedKeys.length >= this.batchSize) break;
        if (key.endsWith(IDEMPOTENCY_LOCK_SUFFIX)) continue;
        collectedKeys.push(key);
      }

      if (Date.now() > deadline) {
        this.logger.warn(
          `Idempotency cleanup reached lock deadline; truncating scan at cursor=${cursor}`,
        );
        break;
      }
    } while (cursor !== '0' && collectedKeys.length < this.batchSize);

    const scannedCount = collectedKeys.length;
    const now = Date.now();
    let cleanedCount = 0;
    let skippedCount = 0;
    let missingExpiresAtCount = 0;
    let earliestActiveExpiresAt: number | undefined;

    // Phase 2 — for each candidate, re-read the record via the
    // cache-manager, ask the shared helper `isExpiredByWallClock`,
    // and only then `deleteRecord`.  The cache-manager re-check is
    // the heart of the "do not delete active keys" guarantee: a key
    // written between the SCAN and the getRecord call is respected
    // because either (a) its `expiresAt` is in the future, or (b)
    // its `expiresAt` is undefined — in which case the helper returns
    // `false` and we leave the record alone.
    for (const key of collectedKeys) {
      if (Date.now() > deadline) {
        this.logger.warn(
          'Idempotency cleanup reached lock deadline mid-batch; deferring to next run',
        );
        break;
      }

      try {
        const record = await this.idempotencyService.getRecord(key);

        if (!record) {
          skippedCount += 1;
          continue;
        }

        if (
          typeof (record as { expiresAt?: number }).expiresAt !== 'number'
        ) {
          missingExpiresAtCount += 1;
          skippedCount += 1;
          continue;
        }

        if (
          !this.idempotencyService.isExpiredByWallClock(record, now)
        ) {
          skippedCount += 1;
          const expiresAt = (record as { expiresAt: number }).expiresAt;
          if (
            earliestActiveExpiresAt === undefined ||
            expiresAt < earliestActiveExpiresAt
          ) {
            earliestActiveExpiresAt = expiresAt;
          }
          continue;
        }

        await this.idempotencyService.deleteRecord(key);
        cleanedCount += 1;
        this.metrics.totalCleaned += 1;
      } catch (err) {
        this.logger.warn(
          `Idempotency cleanup failed to process key '${key}': ${
            (err as Error)?.message ?? String(err)
          }`,
        );
        skippedCount += 1;
      }
    }

    const event = this.recordOutcome(
      startedAt,
      'cleaned',
      cleanedCount,
      scannedCount,
      scannedCount - cleanedCount,
      missingExpiresAtCount,
      earliestActiveExpiresAt,
    );
    this.metrics.successfulRuns += 1;
    this.logger.log(
      JSON.stringify({
        msg: 'idempotency-cleanup-run',
        result: event.reason,
        cleanedCount,
        skippedCount: scannedCount - cleanedCount,
        scannedCount,
        missingExpiresAtCount,
        earliestActiveExpiresAt,
        durationMs: event.durationMs,
      }),
    );
    this.eventEmitter.emit('idempotency.cleanup', event);
    return event;
  }

  private recordOutcome(
    startedAt: number,
    reason: IdempotencyCleanupEvent['reason'],
    cleanedCount: number,
    scannedCount: number,
    skippedCount: number,
    missingExpiresAtCount: number,
    earliestActiveExpiresAt: number | undefined,
  ): IdempotencyCleanupEvent {
    const finishedAt = new Date();
    const event: IdempotencyCleanupEvent = {
      cleanedCount,
      skippedCount,
      scannedCount,
      missingExpiresAtCount,
      earliestActiveExpiresAt,
      durationMs: finishedAt.getTime() - startedAt,
      finishedAt: finishedAt.toISOString(),
      reason,
    };
    this.metrics.lastRun = event;
    return event;
  }
}
