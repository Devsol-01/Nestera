import { Test, TestingModule } from '@nestjs/testing';
import { CacheStrategyService, CacheTTL } from './cache-strategy.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildModule(
  overrides: Partial<Pick<Cache, 'get' | 'set' | 'del'>> = {},
): Promise<TestingModule> {
  return Test.createTestingModule({
    providers: [
      CacheStrategyService,
      {
        provide: CACHE_MANAGER,
        useValue: {
          get: jest.fn().mockResolvedValue(undefined),
          set: jest.fn().mockResolvedValue(undefined),
          del: jest.fn().mockResolvedValue(undefined),
          ...overrides,
        },
      },
    ],
  }).compile();
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

describe('CacheStrategyService', () => {
  let service: CacheStrategyService;
  let cacheManager: jest.Mocked<Cache>;

  beforeEach(async () => {
    const module = await buildModule();
    service = module.get<CacheStrategyService>(CacheStrategyService);
    cacheManager = module.get(CACHE_MANAGER);
  });

  afterEach(() => jest.clearAllMocks());

  // ─── CacheTTL enum ────────────────────────────────────────────────────────

  describe('CacheTTL enum', () => {
    it('should have correct millisecond values', () => {
      expect(CacheTTL.REALTIME).toBe(30_000);
      expect(CacheTTL.VOLATILE).toBe(2 * 60_000);
      expect(CacheTTL.SHORT).toBe(5 * 60_000);
      expect(CacheTTL.MEDIUM).toBe(10 * 60_000);
      expect(CacheTTL.LONG).toBe(30 * 60_000);
      expect(CacheTTL.STATIC).toBe(24 * 3_600_000);
    });

    it('should have ascending duration order', () => {
      expect(CacheTTL.REALTIME).toBeLessThan(CacheTTL.VOLATILE);
      expect(CacheTTL.VOLATILE).toBeLessThan(CacheTTL.SHORT);
      expect(CacheTTL.SHORT).toBeLessThan(CacheTTL.MEDIUM);
      expect(CacheTTL.MEDIUM).toBeLessThan(CacheTTL.LONG);
      expect(CacheTTL.LONG).toBeLessThan(CacheTTL.STATIC);
    });
  });

  // ─── get() ────────────────────────────────────────────────────────────────

  describe('get()', () => {
    it('should return the cached value on a hit', async () => {
      cacheManager.get.mockResolvedValueOnce('hello');
      const result = await service.get<string>('my-key');
      expect(result).toBe('hello');
    });

    it('should return undefined on a cache miss', async () => {
      cacheManager.get.mockResolvedValueOnce(undefined);
      const result = await service.get('missing-key');
      expect(result).toBeUndefined();
    });

    it('should treat a null response from the store as a miss and return undefined', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(null);
      const result = await service.get('null-key');
      expect(result).toBeUndefined();
    });

    it('should increment hits counter on a cache hit', async () => {
      cacheManager.get.mockResolvedValueOnce('data');
      await service.get('key');
      expect(service.getMetrics().hits).toBe(1);
      expect(service.getMetrics().misses).toBe(0);
    });

    it('should increment misses counter on a cache miss', async () => {
      cacheManager.get.mockResolvedValueOnce(undefined);
      await service.get('key');
      expect(service.getMetrics().hits).toBe(0);
      expect(service.getMetrics().misses).toBe(1);
    });

    it('should accumulate per-key metrics for hits and misses', async () => {
      cacheManager.get.mockResolvedValueOnce('v').mockResolvedValueOnce(undefined);
      await service.get('k1');
      await service.get('k1');

      const km = service.getMetrics().keyMetrics.find((m) => m.key === 'k1')!;
      expect(km.hits).toBe(1);
      expect(km.misses).toBe(1);
    });

    it('should return undefined and not throw when the cache store throws', async () => {
      cacheManager.get.mockRejectedValueOnce(new Error('Redis down'));
      await expect(service.get('key')).resolves.toBeUndefined();
    });

    it('should record get latency in metrics', async () => {
      cacheManager.get.mockResolvedValueOnce('v');
      await service.get('lat-key');
      expect(service.getMetrics().latency.get.count).toBe(1);
    });
  });

  // ─── set() ────────────────────────────────────────────────────────────────

  describe('set()', () => {
    it('should write the value to the cache store', async () => {
      await service.set('k', 'v', 5000);
      expect(cacheManager.set).toHaveBeenCalledWith('k', 'v', 5000);
    });

    it('should use the provided TTL override instead of adaptive TTL', async () => {
      const customTTL = 60_000;
      await service.set('custom-key', 'value', customTTL);
      expect(cacheManager.set).toHaveBeenCalledWith('custom-key', 'value', customTTL);
    });

    it('should fall back to adaptive/default TTL when no TTL is provided', async () => {
      await service.set('test-key', 'value');
      // First write has no history → should use resource-mapped or SHORT default
      expect(cacheManager.set).toHaveBeenCalledWith('test-key', 'value', CacheTTL.SHORT);
    });

    it('should use resource-mapped TTL for known resource prefixes', async () => {
      await service.set('user:123', 'data');
      expect(cacheManager.set).toHaveBeenCalledWith('user:123', 'data', CacheTTL.SHORT);

      cacheManager.set.mockClear();
      await service.set('savings:abc', 'data');
      expect(cacheManager.set).toHaveBeenCalledWith('savings:abc', 'data', CacheTTL.MEDIUM);

      cacheManager.set.mockClear();
      await service.set('analytics:weekly', 'data');
      expect(cacheManager.set).toHaveBeenCalledWith('analytics:weekly', 'data', CacheTTL.LONG);

      cacheManager.set.mockClear();
      await service.set('blockchain:slot', 'data');
      expect(cacheManager.set).toHaveBeenCalledWith('blockchain:slot', 'data', CacheTTL.VOLATILE);
    });

    it('should increment the sets counter', async () => {
      await service.set('k', 'v');
      expect(service.getMetrics().sets).toBe(1);
    });

    it('should register the key under supplied tags', async () => {
      // First get call for the tag key in the store returns nothing
      cacheManager.get.mockResolvedValue(undefined);
      await service.set('tagged-key', 'v', 1000, ['tagA', 'tagB']);
      // cacheManager.set is called for the value AND for each tag entry
      const setKeys = cacheManager.set.mock.calls.map(([k]) => k);
      expect(setKeys).toContain('tagged-key');
      expect(setKeys).toContain('__tags:tagA');
      expect(setKeys).toContain('__tags:tagB');
    });

    it('should not throw and should silently swallow store errors', async () => {
      cacheManager.set.mockRejectedValueOnce(new Error('timeout'));
      await expect(service.set('k', 'v', 1000)).resolves.toBeUndefined();
    });

    it('should record set latency in metrics', async () => {
      await service.set('k', 'v', 1000);
      expect(service.getMetrics().latency.set.count).toBe(1);
    });
  });

  // ─── del() ────────────────────────────────────────────────────────────────

  describe('del()', () => {
    it('should delete the key from the store', async () => {
      await service.del('remove-me');
      expect(cacheManager.del).toHaveBeenCalledWith('remove-me');
    });

    it('should increment deletes and evictions counters', async () => {
      await service.del('k');
      const m = service.getMetrics();
      expect(m.deletes).toBe(1);
      expect(m.evictions).toBe(1);
    });

    it('should not throw when the store errors on delete', async () => {
      cacheManager.del.mockRejectedValueOnce(new Error('oops'));
      await expect(service.del('k')).resolves.toBeUndefined();
    });

    it('should record del latency in metrics', async () => {
      await service.del('k');
      expect(service.getMetrics().latency.del.count).toBe(1);
    });
  });

  // ─── invalidate() / invalidateKeys() ─────────────────────────────────────

  describe('invalidate() and invalidateKeys()', () => {
    it('invalidate() should delegate to del()', async () => {
      const spy = jest.spyOn(service, 'del');
      await service.invalidate('key-a');
      expect(spy).toHaveBeenCalledWith('key-a');
    });

    it('invalidateKeys() should delete all provided keys', async () => {
      await service.invalidateKeys(['k1', 'k2', 'k3']);
      expect(cacheManager.del).toHaveBeenCalledTimes(3);
      ['k1', 'k2', 'k3'].forEach((k) =>
        expect(cacheManager.del).toHaveBeenCalledWith(k),
      );
    });

    it('invalidateKeys() should no-op for an empty array', async () => {
      await service.invalidateKeys([]);
      expect(cacheManager.del).not.toHaveBeenCalled();
    });
  });

  // ─── invalidateByTag() ────────────────────────────────────────────────────

  describe('invalidateByTag()', () => {
    it('should delete all keys registered under a tag', async () => {
      // Register two keys under tagX
      cacheManager.get.mockResolvedValue(undefined); // no existing Redis tag entries
      await service.set('k1', 'v', 1000, ['tagX']);
      await service.set('k2', 'v', 1000, ['tagX']);
      cacheManager.del.mockClear();

      // invalidateByTag merges local mirror + Redis store result
      cacheManager.get.mockResolvedValueOnce(['k1', 'k2']); // simulate Redis returning tag keys
      await service.invalidateByTag('tagX');

      // Should have deleted k1, k2 and the tag entry itself
      expect(cacheManager.del).toHaveBeenCalledWith('k1');
      expect(cacheManager.del).toHaveBeenCalledWith('k2');
      expect(cacheManager.del).toHaveBeenCalledWith('__tags:tagX');
    });

    it('should merge in-memory mirror with Redis-backed set before deleting', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      // Register k1 locally
      await service.set('k1', 'v', 1000, ['tagMerge']);
      cacheManager.del.mockClear();

      // Redis has an additional key k2 that this process doesn't know about
      cacheManager.get.mockResolvedValueOnce(['k2']);
      await service.invalidateByTag('tagMerge');

      expect(cacheManager.del).toHaveBeenCalledWith('k1');
      expect(cacheManager.del).toHaveBeenCalledWith('k2');
    });

    it('should be a no-op when the tag has no registered keys', async () => {
      cacheManager.get.mockResolvedValueOnce([]); // empty tag in Redis
      await service.invalidateByTag('unknown-tag');
      // Only the tag cleanup call happens
      expect(cacheManager.del).toHaveBeenCalledWith('__tags:unknown-tag');
    });

    it('should clear the local tag index after invalidation', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      await service.set('k', 'v', 1000, ['tagClear']);
      cacheManager.get.mockResolvedValueOnce([]);
      await service.invalidateByTag('tagClear');

      // Tag should be gone from in-memory mirror
      const tagIndex: Map<string, Set<string>> = service['tagIndex'];
      expect(tagIndex.has('tagClear')).toBe(false);
    });

    it('should not throw when the store errors during tag invalidation', async () => {
      cacheManager.get.mockRejectedValueOnce(new Error('Redis timeout'));
      await expect(service.invalidateByTag('bad-tag')).resolves.toBeUndefined();
    });
  });

  // ─── invalidateByPattern() ────────────────────────────────────────────────

  describe('invalidateByPattern()', () => {
    it('should delete all keys whose key string includes the pattern', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      await service.set('user:1', 'v', 1000, ['users']);
      await service.set('user:2', 'v', 1000, ['users']);
      await service.set('savings:1', 'v', 1000, ['savings']);
      cacheManager.del.mockClear();

      await service.invalidateByPattern('user:');

      expect(cacheManager.del).toHaveBeenCalledWith('user:1');
      expect(cacheManager.del).toHaveBeenCalledWith('user:2');
      expect(cacheManager.del).not.toHaveBeenCalledWith('savings:1');
    });

    it('should be a no-op when no key matches the pattern', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      await service.set('analytics:1', 'v', 1000, ['a']);
      cacheManager.del.mockClear();

      await service.invalidateByPattern('nonexistent:');
      expect(cacheManager.del).not.toHaveBeenCalled();
    });

    it('should not throw when a store error occurs', async () => {
      // Force del to throw on first call
      cacheManager.get.mockResolvedValue(undefined);
      await service.set('k', 'v', 1000, ['t']);
      cacheManager.del.mockRejectedValueOnce(new Error('fail'));

      await expect(service.invalidateByPattern('k')).resolves.toBeUndefined();
    });
  });

  // ─── getOrSet() / stampede prevention ─────────────────────────────────────

  describe('getOrSet() – stampede prevention', () => {
    it('should return cached value without calling loader', async () => {
      cacheManager.get.mockResolvedValueOnce('cached');
      const loader = jest.fn().mockResolvedValue('fresh');
      const result = await service.getOrSet('key', loader, 1000);
      expect(result).toBe('cached');
      expect(loader).not.toHaveBeenCalled();
    });

    it('should call loader and cache the result on a miss', async () => {
      cacheManager.get.mockResolvedValueOnce(undefined);
      const loader = jest.fn().mockResolvedValue('loaded');
      const result = await service.getOrSet('key', loader, 2000);
      expect(result).toBe('loaded');
      expect(cacheManager.set).toHaveBeenCalledWith('key', 'loaded', 2000);
    });

    it('should coalesce concurrent requests for the same key (stampede protection)', async () => {
      // get always returns undefined (cold cache)
      cacheManager.get.mockResolvedValue(undefined);

      let resolveLoader!: (v: string) => void;
      const loaderPromise = new Promise<string>((res) => {
        resolveLoader = res;
      });
      const loader = jest.fn().mockReturnValue(loaderPromise);

      // Fire 5 concurrent requests
      const promises = Array.from({ length: 5 }, () =>
        service.getOrSet('stampede-key', loader, 1000),
      );

      resolveLoader('data');

      const results = await Promise.all(promises);
      // Loader must be called exactly once
      expect(loader).toHaveBeenCalledTimes(1);
      results.forEach((r) => expect(r).toBe('data'));
    });

    it('should remove the inflight entry after the loader resolves', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      const loader = jest.fn().mockResolvedValue('val');
      await service.getOrSet('key', loader, 1000);
      expect(service['inflight'].has('key')).toBe(false);
    });

    it('should remove the inflight entry even when the loader rejects', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      const loader = jest.fn().mockRejectedValue(new Error('load fail'));
      await expect(service.getOrSet('key', loader, 1000)).rejects.toThrow('load fail');
      expect(service['inflight'].has('key')).toBe(false);
    });

    it('should update inflightPeak metric', async () => {
      cacheManager.get.mockResolvedValue(undefined);

      let resolveAll!: (v: string) => void;
      const shared = new Promise<string>((res) => { resolveAll = res; });
      const loader = jest.fn().mockReturnValue(shared);

      const p1 = service.getOrSet('key-a', loader, 1000);
      const p2 = service.getOrSet('key-b', loader, 1000);

      resolveAll('ok');
      await Promise.all([p1, p2]);

      expect(service.getMetrics().inflightPeak).toBeGreaterThanOrEqual(1);
    });

    it('should write loader result to cache with provided tags', async () => {
      cacheManager.get.mockResolvedValue(undefined);
      const loader = jest.fn().mockResolvedValue('fresh');
      await service.getOrSet('tagged', loader, 1000, ['t1']);

      const setCalls = cacheManager.set.mock.calls.map(([k]) => k);
      expect(setCalls).toContain('tagged');
      expect(setCalls).toContain('__tags:t1');
    });
  });

  // ─── warmCache() ─────────────────────────────────────────────────────────

  describe('warmCache()', () => {
    it('should preload the cache with data from the loader', async () => {
      const loader = jest.fn().mockResolvedValue({ ready: true });
      await service.warmCache('warm-key', loader, 5000);
      expect(cacheManager.set).toHaveBeenCalledWith('warm-key', { ready: true }, 5000);
    });

    it('should not throw when the loader rejects', async () => {
      const loader = jest.fn().mockRejectedValue(new Error('fail'));
      await expect(service.warmCache('key', loader, 1000)).resolves.toBeUndefined();
    });
  });

  // ─── staleWhileRevalidate() ──────────────────────────────────────────────

  describe('staleWhileRevalidate()', () => {
    it('should return cached value when cache is warm', async () => {
      cacheManager.get.mockResolvedValueOnce('stale');
      const loader = jest.fn().mockResolvedValue('fresh');
      const result = await service.staleWhileRevalidate('swr-key', loader, 1000, 500);
      expect(result).toBe('stale');
      expect(loader).not.toHaveBeenCalled();
    });

    it('should call loader and cache with ttl+staleTime when cold', async () => {
      cacheManager.get.mockResolvedValueOnce(undefined);
      const loader = jest.fn().mockResolvedValue('fresh');
      const result = await service.staleWhileRevalidate('swr-key', loader, 1000, 500);
      expect(result).toBe('fresh');
      // stored TTL = ttl + staleTime
      expect(cacheManager.set).toHaveBeenCalledWith('swr-key', 'fresh', 1500);
    });

    it('should treat a null cache response as a miss', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(null);
      const loader = jest.fn().mockResolvedValue('data');
      const result = await service.staleWhileRevalidate('swr-null', loader, 1000, 200);
      expect(result).toBe('data');
    });
  });

  // ─── Adaptive TTL ────────────────────────────────────────────────────────

  describe('Adaptive TTL', () => {
    it('should return base TTL when no update history exists', async () => {
      await service.set('test-key', 'value');
      expect(cacheManager.set).toHaveBeenCalledWith('test-key', 'value', CacheTTL.SHORT);
    });

    it('should decrease TTL for high-volatility keys', async () => {
      for (let i = 0; i < 60; i++) {
        await service.set('analytics-volatile-key', `value-${i}`);
      }
      const lastCall = cacheManager.set.mock.calls.at(-1)!;
      const adaptiveTTL = lastCall[2];
      expect(adaptiveTTL).toBeLessThan(CacheTTL.LONG);
      expect(adaptiveTTL).toBeGreaterThanOrEqual(service['adaptiveConfig'].minTTL);
    });

    it('should never go below minTTL for extremely volatile keys', async () => {
      for (let i = 0; i < 200; i++) {
        await service.set('extreme-volatile-key', `v-${i}`);
      }
      const lastCall = cacheManager.set.mock.calls.at(-1)!;
      expect(lastCall[2]).toBeGreaterThanOrEqual(service['adaptiveConfig'].minTTL);
    });

    it('should never exceed maxTTL for extremely stable keys', async () => {
      await service.set('analytics-key', 'value', CacheTTL.LONG);
      const lastCall = cacheManager.set.mock.calls.at(-1)!;
      expect(lastCall[2]).toBeLessThanOrEqual(service['adaptiveConfig'].maxTTL);
    });

    it('setResourceTTL() should allow overriding the default TTL for a resource', async () => {
      service.setResourceTTL('custom-resource', CacheTTL.REALTIME);
      await service.set('custom-resource:entry', 'v');
      expect(cacheManager.set).toHaveBeenCalledWith(
        'custom-resource:entry',
        'v',
        CacheTTL.REALTIME,
      );
    });
  });

  // ─── TTL boundaries ──────────────────────────────────────────────────────

  describe('TTL boundary conditions', () => {
    it('should accept TTL = 0 (no caching) as a valid value', async () => {
      await service.set('zero-ttl-key', 'v', 0);
      expect(cacheManager.set).toHaveBeenCalledWith('zero-ttl-key', 'v', 0);
    });

    it('should accept very large TTL values', async () => {
      const largeTTL = Number.MAX_SAFE_INTEGER;
      await service.set('large-ttl-key', 'v', largeTTL);
      expect(cacheManager.set).toHaveBeenCalledWith('large-ttl-key', 'v', largeTTL);
    });

    it('should handle negative TTL without throwing', async () => {
      await expect(service.set('neg-ttl-key', 'v', -1)).resolves.toBeUndefined();
    });
  });

  // ─── Null / falsy value caching ──────────────────────────────────────────

  describe('Null and falsy value caching', () => {
    it('get() should return undefined for a null store response (not treat null as cached)', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(null);
      expect(await service.get('null-key')).toBeUndefined();
    });

    it('get() should return false when false is cached', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(false);
      // false is truthy enough in the hit path only if the store returns it
      // The service returns value ?? undefined — false ?? undefined === false
      const result = await service.get<boolean>('false-key');
      expect(result).toBe(false);
    });

    it('get() should return 0 when zero is cached', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(0);
      const result = await service.get<number>('zero-key');
      expect(result).toBe(0);
    });

    it('get() should return empty string when empty string is cached', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce('');
      const result = await service.get<string>('empty-string-key');
      expect(result).toBe('');
    });

    it('getOrSet() should re-invoke loader for null cached values', async () => {
      // Null in the cache → treated as a miss → loader is called
      (cacheManager.get as jest.Mock).mockResolvedValueOnce(null);
      const loader = jest.fn().mockResolvedValue('refreshed');
      const result = await service.getOrSet('null-cached', loader, 1000);
      expect(result).toBe('refreshed');
      expect(loader).toHaveBeenCalledTimes(1);
    });
  });

  // ─── Metrics ─────────────────────────────────────────────────────────────

  describe('getMetrics()', () => {
    it('should report 0 for all counters on a fresh service', () => {
      const m = service.getMetrics();
      expect(m.hits).toBe(0);
      expect(m.misses).toBe(0);
      expect(m.sets).toBe(0);
      expect(m.deletes).toBe(0);
      expect(m.evictions).toBe(0);
      expect(m.inflightNow).toBe(0);
      expect(m.inflightPeak).toBe(0);
    });

    it('should calculate hitRate as a percentage string', async () => {
      cacheManager.get
        .mockResolvedValueOnce('v') // hit
        .mockResolvedValueOnce(undefined); // miss
      await service.get('k');
      await service.get('k');
      const m = service.getMetrics();
      expect(m.hitRate).toBe('50.00%');
      expect(m.missRate).toBe('50.00%');
      expect(m.hitRatio).toBeCloseTo(0.5);
      expect(m.missRatio).toBeCloseTo(0.5);
    });

    it('should report 0% hit rate when there are no requests', () => {
      const m = service.getMetrics();
      expect(m.hitRate).toBe('0.00%');
      expect(m.hitRatio).toBe(0);
    });

    it('should include per-key metrics for each accessed key', async () => {
      cacheManager.get.mockResolvedValueOnce('v');
      await service.get('key-a');
      const m = service.getMetrics();
      const km = m.keyMetrics.find((k) => k.key === 'key-a')!;
      expect(km).toBeDefined();
      expect(km.hits).toBe(1);
      expect(km.hitRate).toBe('100.00%');
    });

    it('should summarise latency (avg / p95 / p99)', async () => {
      for (let i = 0; i < 10; i++) {
        cacheManager.get.mockResolvedValueOnce('v');
        await service.get('k');
      }
      const lat = service.getMetrics().latency.get;
      expect(lat.count).toBe(10);
      expect(lat.avg).toBeGreaterThanOrEqual(0);
      expect(lat.p95).toBeGreaterThanOrEqual(0);
      expect(lat.p99).toBeGreaterThanOrEqual(0);
    });

    it('should return zeroed latency stats when no operations have run', () => {
      const lat = service.getMetrics().latency.get;
      expect(lat).toEqual({ avg: 0, p95: 0, p99: 0, count: 0 });
    });
  });

  // ─── resetMetrics() ──────────────────────────────────────────────────────

  describe('resetMetrics()', () => {
    it('should reset all counters to zero', async () => {
      cacheManager.get.mockResolvedValueOnce('v');
      await service.get('k');
      await service.set('k', 'v', 1000);
      await service.del('k');

      service.resetMetrics();
      const m = service.getMetrics();

      expect(m.hits).toBe(0);
      expect(m.misses).toBe(0);
      expect(m.sets).toBe(0);
      expect(m.deletes).toBe(0);
      expect(m.evictions).toBe(0);
      expect(m.keyMetrics).toHaveLength(0);
      expect(m.latency.get.count).toBe(0);
    });
  });

  // ─── getAdaptiveTTLStats() ────────────────────────────────────────────────

  describe('getAdaptiveTTLStats()', () => {
    it('should return zero counts when no keys have been set', () => {
      const stats = service.getAdaptiveTTLStats();
      expect(stats.totalKeys).toBe(0);
      expect(stats.keysWithAdaptiveTTL).toBe(0);
      expect(stats.averageUpdateFrequency).toBe(0);
    });

    it('should return correct structure', async () => {
      await service.set('k1', 'v');
      const stats = service.getAdaptiveTTLStats();
      expect(stats).toHaveProperty('totalKeys');
      expect(stats).toHaveProperty('keysWithAdaptiveTTL');
      expect(stats).toHaveProperty('averageUpdateFrequency');
      expect(stats).toHaveProperty('config');
    });

    it('should reflect the adaptive config values', () => {
      const stats = service.getAdaptiveTTLStats();
      expect(stats.config).toEqual({
        minTTL: CacheTTL.SHORT,
        maxTTL: CacheTTL.LONG,
        volatilityThreshold: 5,
        sampleWindow: 10,
      });
    });

    it('should count keys that have update history', async () => {
      await service.set('key1', 'v');
      await service.set('key2', 'v');
      const stats = service.getAdaptiveTTLStats();
      expect(stats.totalKeys).toBe(2);
      expect(stats.keysWithAdaptiveTTL).toBe(2);
    });

    it('should calculate a positive averageUpdateFrequency after multiple writes', async () => {
      for (let i = 0; i < 10; i++) await service.set('freq-key', `v-${i}`);
      const stats = service.getAdaptiveTTLStats();
      expect(stats.averageUpdateFrequency).toBeGreaterThan(0);
    });
  });

  // ─── Latency rolling window ───────────────────────────────────────────────

  describe('Latency rolling window (MAX_LATENCY_SAMPLES)', () => {
    it('should cap the samples array at 500 entries', async () => {
      for (let i = 0; i < 600; i++) {
        cacheManager.get.mockResolvedValueOnce('v');
        await service.get('k');
      }
      // Access the private metrics directly for this assertion
      const bucket = service['metrics'].latency.get;
      expect(bucket.samples.length).toBeLessThanOrEqual(500);
    });
  });

  // ─── Edge cases ──────────────────────────────────────────────────────────

  describe('Edge cases', () => {
    it('should handle objects with complex nested structures as cache values', async () => {
      const complex = { a: { b: [1, 2, 3] }, c: new Date('2024-01-01') };
      await service.set('complex-key', complex, 1000);
      expect(cacheManager.set).toHaveBeenCalledWith('complex-key', complex, 1000);
    });

    it('should support setting and getting arrays as cache values', async () => {
      (cacheManager.get as jest.Mock).mockResolvedValueOnce([1, 2, 3]);
      const result = await service.get<number[]>('array-key');
      expect(result).toEqual([1, 2, 3]);
    });

    it('should support cache keys with special characters', async () => {
      const key = 'user:123:profile/v2?locale=en-US';
      await service.set(key, 'data', 1000);
      expect(cacheManager.set).toHaveBeenCalledWith(key, 'data', 1000);
    });

    it('should support very long cache keys', async () => {
      const key = 'a'.repeat(2048);
      await service.set(key, 'v', 1000);
      expect(cacheManager.set).toHaveBeenCalledWith(key, 'v', 1000);
    });

    it('getOrSet() should propagate loader errors to all concurrent callers', async () => {
      cacheManager.get.mockResolvedValue(undefined);

      let rejectLoader!: (e: Error) => void;
      const failPromise = new Promise<string>((_, rej) => { rejectLoader = rej; });
      const loader = jest.fn().mockReturnValue(failPromise);

      const p1 = service.getOrSet('err-key', loader, 1000);
      const p2 = service.getOrSet('err-key', loader, 1000);

      rejectLoader(new Error('service unavailable'));

      await expect(p1).rejects.toThrow('service unavailable');
      await expect(p2).rejects.toThrow('service unavailable');
      expect(loader).toHaveBeenCalledTimes(1);
    });
  });
});
