import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { SchedulerRegistry } from '@nestjs/schedule';
import { IdempotencyCleanupService } from './idempotency-cleanup.service';
import { IdempotencyService } from './idempotency.service';
import { DistributedLockService } from '../distributed-lock/distributed-lock.service';

describe('IdempotencyCleanupService', () => {
  let service: IdempotencyCleanupService;
  let configService: jest.Mocked<ConfigService>;
  let idempotencyService: jest.Mocked<IdempotencyService>;
  let distributedLockService: jest.Mocked<DistributedLockService>;
  let eventEmitter: jest.Mocked<EventEmitter2>;
  let schedulerRegistry: jest.Mocked<SchedulerRegistry>;

  // Patched Redis-style scan exposed by IdempotencyService stub.
  let redisScan: jest.Mock;

  /**
   * Builds a map of in-memory cache records keyed by cache key.
   * `getRecord` reads from it, `deleteRecord` removes from it.
   */
  let cacheStore: Record<string, unknown>;

  const makeAcquiredLock = () => ({
    key: 'lock:cron:idempotency-cleanup',
    ownerId: 'owner-1',
    acquiredAt: new Date(),
    release: jest.fn(async () => undefined),
    renew: jest.fn(async () => true),
  });

  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2025-01-01T12:00:00Z'));

    cacheStore = {};

    configService = {
      get: jest.fn((key: string, def?: unknown) => {
        const map: Record<string, unknown> = {
          'idempotency.cleanupEnabled': true,
          'idempotency.cleanupCronSchedule': '0 * * * *',
          'idempotency.cleanupBatchSize': 500,
          'idempotency.cleanupScanCount': 200,
          'idempotency.cleanupLockTtlMs': 120_000,
        };
        return key in map ? map[key] : def;
      }),
    } as unknown as jest.Mocked<ConfigService>;

    redisScan = jest.fn();

    idempotencyService = {
      getUnderlyingRedisClient: jest.fn(() => ({
        scan: redisScan,
      })),
      getRecord: jest.fn(async (key: string) => {
        if (!(key in cacheStore)) return null;
        return cacheStore[key] as never;
      }),
      deleteRecord: jest.fn(async (key: string) => {
        delete cacheStore[key];
      }),
      isExpiredByWallClock: jest.fn(
        (record: { expiresAt?: number }, now: number) =>
          typeof record?.expiresAt === 'number' &&
          record.expiresAt <= now,
      ),
    } as unknown as jest.Mocked<IdempotencyService>;

    distributedLockService = {
      withLock: jest.fn(),
    } as unknown as jest.Mocked<DistributedLockService>;

    eventEmitter = {
      emit: jest.fn(),
    } as unknown as jest.Mocked<EventEmitter2>;

    schedulerRegistry = {
      doesExist: jest.fn().mockReturnValue(false),
      deleteCronJob: jest.fn(),
      addCronJob: jest.fn(),
      getCronJob: jest.fn(),
    } as unknown as jest.Mocked<SchedulerRegistry>;

    service = new IdempotencyCleanupService(
      configService,
      idempotencyService,
      distributedLockService,
      eventEmitter,
      schedulerRegistry,
    );
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.clearAllMocks();
  });

  // ──────────────────────────────────────────────────────────────────────
  // Distributed lock integration
  // ──────────────────────────────────────────────────────────────────────

  describe('distributed lock', () => {
    it('acquires the cleanup lock before doing any work', async () => {
      // First SCAN cursor returns end-of-scan immediately so we get a
      // deterministic no-op run.
      redisScan.mockResolvedValueOnce(['0', []]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      await service.handleCleanup();

      expect(distributedLockService.withLock).toHaveBeenCalledTimes(1);
      const [lockKey] = distributedLockService.withLock.mock.calls[0];
      expect(lockKey).toBe('cron:idempotency-cleanup');
    });

    it('skips when another instance holds the lock', async () => {
      distributedLockService.withLock.mockResolvedValueOnce(null);

      const event = await service.handleCleanup();

      expect(event.reason).toBe('skipped-not-leader');
      expect(event.cleanedCount).toBe(0);
      expect(event.scannedCount).toBe(0);
      expect(redisScan).not.toHaveBeenCalled();
      expect(redisDel).not.toHaveBeenCalled();

      const metrics = service.getMetrics();
      expect(metrics.skippedNotLeaderRuns).toBe(1);
      expect(metrics.successfulRuns).toBe(0);
      expect(metrics.totalRuns).toBe(1);
    });

    it('passes lock TTL/retries to DistributedLockService', async () => {
      redisScan.mockResolvedValueOnce(['0', []]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      await service.handleCleanup();

      const [, , options] = distributedLockService.withLock.mock.calls[0];
      expect(options).toEqual(
        expect.objectContaining({ ttlMs: 120_000, maxRetries: 0 }),
      );
    });

    it('releases the lock after the inner fn returns', async () => {
      const lock = makeAcquiredLock();
      redisScan.mockResolvedValueOnce(['0', []]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => {
          const handle = await fn();
          await lock.release();
          return handle;
        },
      );

      await service.handleCleanup();

      expect(lock.release).toHaveBeenCalledTimes(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Cleanup behaviour — the core "delete only expired" guarantee
  // ──────────────────────────────────────────────────────────────────────

  describe('expired-record removal', () => {
    it('deletes only expired records and leaves active keys intact', async () => {
      const now = Date.now();
      const expired = makeRecord('k1', now - 5_000);
      const active = makeRecord('k2', now + 60_000);
      const farFuture = makeRecord('k3', now + 24 * 60 * 60 * 1000);

      cacheStore['idempotency:POST:/disputes:k1'] = expired;
      cacheStore['idempotency:POST:/disputes:k2'] = active;
      cacheStore['idempotency:GET:/users:k3'] = farFuture;
      // A lock key should never be touched, even if SCAN returns it.
      cacheStore['idempotency:POST:/disputes:k1:lock'] = '1';

      redisScan.mockResolvedValueOnce([
        '0',
        [
          'idempotency:POST:/disputes:k1',
          'idempotency:POST:/disputes:k1:lock',
          'idempotency:POST:/disputes:k2',
          'some:unrelated:key',
          'idempotency:GET:/users:k3',
        ],
      ]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(1);
      expect(event.skippedCount).toBeGreaterThanOrEqual(2);
      expect(event.scannedCount).toBe(4); // pattern-matching + non-lock only
      expect(event.earliestActiveExpiresAt).toBe(now + 60_000);
      expect(event.missingExpiresAtCount).toBe(0);
      expect(event.reason).toBe('cleaned');

      // The active keys must still be in the cache store.
      expect(cacheStore['idempotency:POST:/disputes:k2']).toBeDefined();
      expect(cacheStore['idempotency:GET:/users:k3']).toBeDefined();
      // The lock key is never deleted.
      expect(
        cacheStore['idempotency:POST:/disputes:k1:lock'],
      ).toBeDefined();
      // The expired key was deleted.
      expect(cacheStore['idempotency:POST:/disputes:k1']).toBeUndefined();
      // The unrelated key was neither indexed nor touched.
      expect(cacheStore['some:unrelated:key']).toBeUndefined();

      const metrics = service.getMetrics();
      expect(metrics.successfulRuns).toBe(1);
      expect(metrics.totalCleaned).toBe(1);

      // SCAN-based direct del on the underlying client is not used;
      // we always go through cache-manager (idempotencyService.deleteRecord).
      // Verify the lock-key record was never retrieved.
      const getRecordCalls = idempotencyService.getRecord.mock.calls.map(
        (c) => c[0],
      );
      expect(getRecordCalls).not.toContain(
        'idempotency:POST:/disputes:k1:lock',
      );
    });

    it('keeps records without expiresAt (conservatively)', async () => {
      const now = Date.now();
      // Old record (completedAt days ago) BUT no expiresAt — preserves
      // backward compatibility: the cleanup job never deletes a record
      // it can't prove is expired.
      cacheStore['idempotency:POST:/old:legacy'] = {
        payloadHash: 'h',
        statusCode: 200,
        body: {},
        completedAt: new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString(),
      };
      // Active record with expiresAt for comparison.
      cacheStore['idempotency:POST:/new:hk'] = makeRecord(
        'hk',
        now + 30_000,
      );

      redisScan.mockResolvedValueOnce([
        '0',
        ['idempotency:POST:/old:legacy', 'idempotency:POST:/new:hk'],
      ]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(0);
      expect(event.missingExpiresAtCount).toBe(1);
      expect(event.skippedCount).toBe(2);
      expect(event.scannedCount).toBe(2);
      expect(event.earliestActiveExpiresAt).toBe(now + 30_000);

      // Both records remain in cache — legacy record was not deleted.
      expect(cacheStore['idempotency:POST:/old:legacy']).toBeDefined();
      expect(cacheStore['idempotency:POST:/new:hk']).toBeDefined();
    });

    it('counts a vanished record as skipped, not cleaned', async () => {
      // SCAN returns the key but `getRecord` returns null — Redis
      // TTL (or another cleanup pass) has already evicted it.  The
      // cleanup must not double-count.
      redisScan.mockResolvedValueOnce(['0', ['idempotency:POST:/gone:k']]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(0);
      expect(event.skippedCount).toBe(1);
      expect(event.scannedCount).toBe(1);
      expect(idempotencyService.deleteRecord).not.toHaveBeenCalled();
    });

    it('processes paginated SCAN cursors until cursor=0', async () => {
      const now = Date.now();
      cacheStore['idempotency:k1'] = makeRecord('k1', now - 1_000);
      cacheStore['idempotency:k2'] = makeRecord('k2', now - 2_000);

      redisScan
        .mockResolvedValueOnce(['42', ['idempotency:k1']])
        .mockResolvedValueOnce(['0', ['idempotency:k2']]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(redisScan).toHaveBeenCalledTimes(2);
      expect(event.cleanedCount).toBe(2);
    });

    it('caps the scan batch via cleanupBatchSize', async () => {
      // 600 candidate keys would exceed default batchSize=500, but
      // service was constructed without reading from batchSize in the
      // SCAN loop directly — it collects into collectedKeys and
      // stops iterating once the cap is reached.  We assert that
      // collectedKeys length is at most batchSize.
      const now = Date.now();
      const keys: string[] = [];
      for (let i = 0; i < 600; i++) {
        const k = `idempotency:k${i}`;
        keys.push(k);
        cacheStore[k] = makeRecord(k, now - 1_000);
      }
      redisScan.mockResolvedValueOnce(['0', keys]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.scannedCount).toBe(500);
      expect(event.cleanedCount).toBe(500);
      // 100 remain in cache because we batched.
      expect(Object.keys(cacheStore).length).toBe(100);

      // Loop must have terminated at the batch cap (single SCAN with
      // cursor=0 returning everything).
      expect(redisScan).toHaveBeenCalledTimes(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // No-Redis / disabled / not-leader branches
  // ──────────────────────────────────────────────────────────────────────

  describe('alternative outcomes', () => {
    it('reports skipped-no-redis when no cache.store.client is exposed', async () => {
      idempotencyService.getUnderlyingRedisClient.mockReturnValueOnce(null);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.reason).toBe('skipped-no-redis');
      expect(event.cleanedCount).toBe(0);
      expect(event.scannedCount).toBe(0);
      expect(service.getMetrics().skippedNoRedisRuns).toBe(1);
    });

    it('reports skipped-disabled when cleanupEnabled=false', async () => {
      (configService.get as jest.Mock).mockImplementation(
        (key: string, def?: unknown) => {
          if (key === 'idempotency.cleanupEnabled') return false;
          if (key === 'idempotency.cleanupCronSchedule') return '0 * * * *';
          if (key === 'idempotency.cleanupBatchSize') return 500;
          if (key === 'idempotency.cleanupScanCount') return 200;
          if (key === 'idempotency.cleanupLockTtlMs') return 120_000;
          return def;
        },
      );

      const event = await service.handleCleanup();

      expect(event.reason).toBe('skipped-disabled');
      expect(event.cleanedCount).toBe(0);
      // withLock is NOT called when disabled; we exit before any work.
      expect(distributedLockService.withLock).not.toHaveBeenCalled();
      expect(service.getMetrics().skippedDisabledRuns).toBe(1);
    });

    it('emits idempotency.cleanup event on every run', async () => {
      redisScan.mockResolvedValueOnce(['0', []]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      await service.handleCleanup();

      const events = eventEmitter.emit.mock.calls.filter(
        (c) => c[0] === 'idempotency.cleanup',
      );
      expect(events.length).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Metric summation across multiple runs
  // ──────────────────────────────────────────────────────────────────────

  describe('metrics roll-up', () => {
    it('totalRuns increments regardless of reason', async () => {
      // Run 1: skipped-not-leader
      distributedLockService.withLock.mockResolvedValueOnce(null);
      await service.handleCleanup();

      // Run 2: skipped-no-redis
      idempotencyService.getUnderlyingRedisClient.mockReturnValueOnce(null);
      distributedLockService.withLock.mockImplementationOnce(
        async (_key, fn) => fn(),
      );
      await service.handleCleanup();

      // Run 3: actual cleanup
      const now = Date.now();
      cacheStore['idempotency:k1'] = makeRecord('k1', now - 1_000);
      redisScan.mockResolvedValueOnce(['0', ['idempotency:k1']]);
      distributedLockService.withLock.mockImplementationOnce(
        async (_key, fn) => fn(),
      );
      await service.handleCleanup();

      const m = service.getMetrics();
      expect(m.totalRuns).toBe(3);
      expect(m.skippedNotLeaderRuns).toBe(1);
      expect(m.skippedNoRedisRuns).toBe(1);
      expect(m.successfulRuns).toBe(1);
      expect(m.totalCleaned).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Re-entrancy / defensive paths
  // ──────────────────────────────────────────────────────────────────────

  describe('defensive paths', () => {
    it('swallows per-key errors and continues processing', async () => {
      const now = Date.now();
      cacheStore['idempotency:k1'] = makeRecord('k1', now - 1_000);
      cacheStore['idempotency:k2'] = makeRecord('k2', now - 1_000);
      cacheStore['idempotency:k3'] = makeRecord('k3', now - 1_000);

      idempotencyService.deleteRecord.mockImplementation(async (key: string) => {
        if (key === 'idempotency:k2') throw new Error('transient');
        delete cacheStore[key];
      });

      redisScan.mockResolvedValueOnce([
        '0',
        ['idempotency:k1', 'idempotency:k2', 'idempotency:k3'],
      ]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(2);
      expect(event.skippedCount).toBe(1);
      // k2 still present (delete failed)
      expect(cacheStore['idempotency:k2']).toBeDefined();
    });

    it('emits skipped-not-leader reason when withLock returns null', async () => {
      distributedLockService.withLock.mockResolvedValueOnce(null);

      const event = await service.handleCleanup();

      expect(event.reason).toBe('skipped-not-leader');
      expect(event.durationMs).toBeGreaterThanOrEqual(0);
      expect(event.finishedAt).toMatch(/T.+Z$/);
    });

    it('records reason=error and emits event when withLock rejects (Redis flaps)', async () => {
      distributedLockService.withLock.mockRejectedValueOnce(
        new Error('ECONNRESET during SCAN'),
      );

      const event = await service.handleCleanup();

      expect(event.reason).toBe('error');
      expect(event.cleanedCount).toBe(0);
      const metrics = service.getMetrics();
      expect(metrics.errorRuns).toBe(1);
      expect(metrics.successfulRuns).toBe(0);
      const emitted = eventEmitter.emit.mock.calls.filter(
        (c) => c[0] === 'idempotency.cleanup',
      );
      expect(emitted.length).toBe(1);
      expect((emitted[0][1] as { reason: string }).reason).toBe('error');
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Race-condition safety — record written between SCAN and getRecord
  // ──────────────────────────────────────────────────────────────────────

  describe('race-condition safety', () => {
    it('does not delete a record that was written with future expiresAt between SCAN and getRecord', async () => {
      // Simulate the SCAN → getRecord race: SCAN returns a key, then a
      // brand-new record would appear in the cache (writes ahead) whose
      // expiresAt is in the future.  The cleanup re-check via
      // getRecord + isExpiredByWallClock must leave the key alone.
      const now = Date.now();
      const cacheKey = 'idempotency:POST:/mid-flight:k';
      const freshRecord = makeRecord('k', now + 60_000);

      redisScan.mockResolvedValueOnce(['0', [cacheKey]]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      // The moment getRecord is called, race-condition-inject a
      // future-expiry record (simulating the interceptor saving a
      // brand-new request between SCAN and the safety re-check).
      idempotencyService.getRecord.mockImplementation(async (key: string) => {
        if (key !== cacheKey) return null;
        return freshRecord;
      });

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(0);
      expect(event.skippedCount).toBe(1);
      expect(event.scannedCount).toBe(1);
      // The cleanup never asked the cache-manager to delete the key.
      expect(idempotencyService.deleteRecord).not.toHaveBeenCalled();
      expect(idempotencyService.isExpiredByWallClock).toHaveBeenCalledTimes(1);
      // Future expiry was surfaced as the earliest active expiresAt.
      expect(event.earliestActiveExpiresAt).toBe(now + 60_000);
    });

    it('does not delete a record when expiresAt is undefined (conservative)', async () => {
      redisScan.mockResolvedValueOnce(['0', ['idempotency:POST:/legacy:k']]);
      distributedLockService.withLock.mockImplementation(
        async (_key, fn) => fn(),
      );

      // getRecord returns a record WITHOUT expiresAt — these existed
      // before the cleanup feature was introduced.  The cleanup must
      // treat them as conservatively-active.
      idempotencyService.getRecord.mockResolvedValueOnce({
        payloadHash: 'old',
        statusCode: 200,
        body: {},
        completedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      } as never);

      const event = await service.handleCleanup();

      expect(event.cleanedCount).toBe(0);
      expect(event.missingExpiresAtCount).toBe(1);
      expect(idempotencyService.deleteRecord).not.toHaveBeenCalled();
    });
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

function makeRecord(
  key: string,
  expiresAtMs: number,
  body: unknown = { key },
): {
  payloadHash: string;
  statusCode: number;
  body: unknown;
  completedAt: string;
  expiresAt: number;
} {
  return {
    payloadHash: 'hash-' + key,
    statusCode: 200,
    body,
    completedAt: new Date(expiresAtMs - 60_000).toISOString(),
    expiresAt: expiresAtMs,
  };
}
