import { Injectable, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject } from '@nestjs/common';
import { Cache } from 'cache-manager';

/**
 * Named TTL tiers ordered by data volatility.
 * Use these instead of raw millisecond literals so intent is clear at the call site.
 */
export enum CacheTTL {
  REALTIME = 30_000,         // 30s  — live prices, RPC slot data
  VOLATILE = 2 * 60_000,     // 2m   — blockchain / contract state
  SHORT    = 5 * 60_000,     // 5m   — user profiles, session data
  MEDIUM   = 10 * 60_000,    // 10m  — product listings, subscriptions
  LONG     = 30 * 60_000,    // 30m  — analytics aggregates
  STATIC   = 24 * 3_600_000, // 24h  — config tables, reference data
}

export interface CacheConfig {
  ttl: number;
  key: string;
  tags?: string[];
}

interface LatencyBucket {
  sum: number;
  count: number;
  /** Rolling window of the last MAX_LATENCY_SAMPLES observations (ms). */
  samples: number[];
}

interface CacheMetrics {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  evictions: number;
  inflightPeak: number;
  latency: {
    get: LatencyBucket;
    set: LatencyBucket;
    del: LatencyBucket;
  };
  keyMetrics: Map<string, { hits: number; misses: number; sets: number; updateFrequency: number; lastUpdatedAt: Date }>;
}

const MAX_LATENCY_SAMPLES = 500;

// Tag→key mappings are stored in the cache store itself under this prefix so
// they survive process restarts and are shared across multiple instances.
const TAG_PREFIX = '__tags:';
const TAG_TTL = CacheTTL.STATIC; // 24h

interface AdaptiveTTLConfig {
  minTTL: number;
  maxTTL: number;
  volatilityThreshold: number; // updates per minute
  sampleWindow: number; // minutes
}

@Injectable()
export class CacheStrategyService {
  private readonly logger = new Logger(CacheStrategyService.name);

  private metrics: CacheMetrics = this.freshMetrics();

  private readonly resourceTTLs = new Map<string, number>([
    ['user',       CacheTTL.SHORT],
    ['savings',    CacheTTL.MEDIUM],
    ['analytics',  CacheTTL.LONG],
    ['blockchain', CacheTTL.VOLATILE],
  ]);

  private readonly adaptiveConfig: AdaptiveTTLConfig = {
    minTTL: CacheTTL.SHORT,
    maxTTL: CacheTTL.LONG,
    volatilityThreshold: 5, // 5 updates per minute
    sampleWindow: 10, // 10 minutes
  };

  private readonly keyUpdateHistory = new Map<string, number[]>(); // timestamps of updates

  /**
   * In-memory mirror of tag→key sets.
   * Built up as keys flow through `set()`; used by `invalidateByPattern`.
   * Complements the Redis-backed tag store for cross-instance correctness.
   */
  private readonly tagIndex = new Map<string, Set<string>>();

  /** Active loader promises keyed by cache key — the stampede gate. */
  private readonly inflight = new Map<string, Promise<unknown>>();
  private inflightCount = 0;

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  // ─── Core Read / Write ────────────────────────────────────────────────────

  async get<T>(key: string): Promise<T | undefined> {
    const t0 = Date.now();
    try {
      const value = await this.cacheManager.get<T>(key);
      this.recordLatency('get', Date.now() - t0);

      if (value !== undefined && value !== null) {
        this.metrics.hits++;
        this.updateKeyMetrics(key, 'hits');
        this.logger.debug(`Cache HIT  ${key}`);
      } else {
        this.metrics.misses++;
        this.updateKeyMetrics(key, 'misses');
        this.logger.debug(`Cache MISS ${key}`);
      }
      return value ?? undefined;
    } catch (error) {
      this.logger.error(`Cache get error for key "${key}":`, error);
      return undefined;
    }
  }

  async set<T>(
    key: string,
    value: T,
    ttl?: number,
    tags?: string[],
  ): Promise<void> {
    const t0 = Date.now();
    try {
      const finalTTL = ttl ?? this.calculateAdaptiveTTL(key);
      await this.cacheManager.set(key, value, finalTTL);
      this.recordLatency('set', Date.now() - t0);
      this.metrics.sets++;
      this.updateKeyMetrics(key, 'sets');
      this.recordKeyUpdate(key);

      if (tags?.length) {
        await this.trackKeyInTags(key, tags);
      }

      this.logger.debug(`Cache SET  ${key} ttl=${finalTTL}ms`);
    } catch (error) {
      this.logger.error(`Cache set error for key "${key}":`, error);
    }
  }

  async del(key: string): Promise<void> {
    const t0 = Date.now();
    try {
      await this.cacheManager.del(key);
      this.recordLatency('del', Date.now() - t0);
      this.metrics.deletes++;
      this.metrics.evictions++;
      this.logger.debug(`Cache DEL  ${key}`);
    } catch (error) {
      this.logger.error(`Cache delete error for key "${key}":`, error);
    }
  }

  // ─── Write-Side Invalidation ──────────────────────────────────────────────

  /** Invalidate a single key on write. Prefer this over `del` in service code
   *  to make the intent explicit at the call site. */
  async invalidate(key: string): Promise<void> {
    await this.del(key);
  }

  /** Bulk write-side invalidation — call after any mutation that touches
   *  multiple cache keys (e.g., admin batch updates). */
  async invalidateKeys(keys: string[]): Promise<void> {
    if (keys.length === 0) return;
    await Promise.all(keys.map((k) => this.del(k)));
    this.logger.log(`Invalidated ${keys.length} cache keys`);
  }

  // ─── Tag-Based Invalidation ───────────────────────────────────────────────

  /**
   * Invalidate all keys associated with `tag`.
   *
   * Correctness guarantee: merges the local in-memory mirror (fast, reflects
   * the current process) with the Redis-backed set (cross-instance, survives
   * restarts) before deleting, then removes the tag entry from both stores.
   */
  async invalidateByTag(tag: string): Promise<void> {
    try {
      const [redisKeys, localKeys] = await Promise.all([
        this.getRedisTagKeys(tag),
        Promise.resolve(Array.from(this.tagIndex.get(tag) ?? [])),
      ]);

      const allKeys = new Set([...redisKeys, ...localKeys]);

      if (allKeys.size > 0) {
        await Promise.all(Array.from(allKeys).map((k) => this.del(k)));
        this.logger.log(`Tag "${tag}": invalidated ${allKeys.size} key(s)`);
      }

      // Clean up tag tracking in both stores
      await this.cacheManager.del(`${TAG_PREFIX}${tag}`);
      this.tagIndex.delete(tag);
    } catch (error) {
      this.logger.error(`Tag invalidation error for "${tag}":`, error);
    }
  }

  /**
   * Invalidate all tracked keys whose string includes `pattern`.
   * Operates on the in-memory tag index, so only covers keys that have been
   * written through this service with tags attached.
   */
  async invalidateByPattern(pattern: string): Promise<void> {
    try {
      const allKeys = new Set<string>();
      for (const keys of this.tagIndex.values()) {
        for (const k of keys) allKeys.add(k);
      }

      const matched = Array.from(allKeys).filter((k) => k.includes(pattern));
      if (matched.length > 0) {
        await this.invalidateKeys(matched);
        this.logger.log(
          `Pattern "${pattern}": invalidated ${matched.length} key(s)`,
        );
      }
    } catch (error) {
      this.logger.error(`Pattern invalidation error for "${pattern}":`, error);
    }
  }

  // ─── Stampede-Protected Loader ────────────────────────────────────────────

  /**
   * Get-or-set with request coalescing.
   *
   * When the cache is cold and multiple callers request the same key
   * concurrently, only one loader invocation is issued; all others
   * receive the same promise (cache stampede protection).
   */
  async getOrSet<T>(
    key: string,
    loader: () => Promise<T>,
    ttl?: number,
    tags?: string[],
  ): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== undefined && cached !== null) return cached;

    // Piggyback on an in-flight load for the same key
    const existing = this.inflight.get(key);
    if (existing) {
      this.logger.debug(`Stampede coalesced: ${key}`);
      return existing as Promise<T>;
    }

    const promise = (async (): Promise<T> => {
      try {
        this.inflightCount++;
        if (this.inflightCount > this.metrics.inflightPeak) {
          this.metrics.inflightPeak = this.inflightCount;
        }
        const data = await loader();
        await this.set(key, data, ttl, tags);
        return data;
      } finally {
        this.inflightCount--;
        this.inflight.delete(key);
      }
    })();

    this.inflight.set(key, promise);
    return promise;
  }

  // ─── Cache Warming Helpers ────────────────────────────────────────────────

  async warmCache(
    key: string,
    loader: () => Promise<unknown>,
    ttl?: number,
    tags?: string[],
  ): Promise<void> {
    try {
      const data = await loader();
      await this.set(key, data, ttl, tags);
      this.logger.log(`Cache warmed: ${key}`);
    } catch (error) {
      this.logger.error(`Cache warming error for key "${key}":`, error);
    }
  }

  async staleWhileRevalidate<T>(
    key: string,
    loader: () => Promise<T>,
    ttl: number,
    staleTime: number,
    tags?: string[],
  ): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== undefined && cached !== null) return cached;

    const data = await loader();
    await this.set(key, data, ttl + staleTime, tags);
    return data;
  }

  // ─── Metrics ──────────────────────────────────────────────────────────────

  getMetrics() {
    const { hits, misses, sets, deletes, inflightPeak, latency, keyMetrics } =
      this.metrics;
    const total = hits + misses;
    const hitRatio = total > 0 ? hits / total : 0;
    const missRatio = total > 0 ? misses / total : 0;

    return {
      hits,
      misses,
      sets,
      deletes,
      evictions: this.metrics.evictions,
      inflightNow: this.inflightCount,
      inflightPeak,
      hitRate: `${(hitRatio * 100).toFixed(2)}%`,
      missRate: `${(missRatio * 100).toFixed(2)}%`,
      hitRatio,
      missRatio,
      latency: {
        get: this.summariseLatency(latency.get),
        set: this.summariseLatency(latency.set),
        del: this.summariseLatency(latency.del),
      },
      keyMetrics: Array.from(keyMetrics.entries()).map(([key, km]) => ({
        key,
        ...km,
        hitRate:
          km.hits + km.misses > 0
            ? `${((km.hits / (km.hits + km.misses)) * 100).toFixed(2)}%`
            : '0%',
      })),
    };
  }

  resetMetrics(): void {
    this.metrics = this.freshMetrics();
  }

  setResourceTTL(resource: string, ttl: number): void {
    this.resourceTTLs.set(resource, ttl);
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  private getDefaultTTL(key: string): number {
    for (const [resource, ttl] of this.resourceTTLs) {
      if (key.includes(resource)) return ttl;
    }
    return CacheTTL.SHORT;
  }

  private updateKeyMetrics(key: string, type: 'hits' | 'misses' | 'sets'): void {
    if (!this.metrics.keyMetrics.has(key)) {
      this.metrics.keyMetrics.set(key, { 
        hits: 0, 
        misses: 0, 
        sets: 0, 
        updateFrequency: 0, 
        lastUpdatedAt: new Date() 
      });
    }
    this.metrics.keyMetrics.get(key)![type]++;
  }

  private recordKeyUpdate(key: string): void {
    const now = Date.now();
    if (!this.keyUpdateHistory.has(key)) {
      this.keyUpdateHistory.set(key, []);
    }
    
    const history = this.keyUpdateHistory.get(key)!;
    history.push(now);
    
    // Keep only updates within the sample window
    const cutoff = now - (this.adaptiveConfig.sampleWindow * 60 * 1000);
    const recentUpdates = history.filter(timestamp => timestamp > cutoff);
    this.keyUpdateHistory.set(key, recentUpdates);
    
    // Update metrics
    if (this.metrics.keyMetrics.has(key)) {
      const metrics = this.metrics.keyMetrics.get(key)!;
      metrics.updateFrequency = recentUpdates.length;
      metrics.lastUpdatedAt = new Date(now);
    }
  }

  private calculateAdaptiveTTL(key: string): number {
    const baseTTL = this.getDefaultTTL(key);
    const updateHistory = this.keyUpdateHistory.get(key);
    
    if (!updateHistory || updateHistory.length === 0) {
      return baseTTL;
    }
    
    // Calculate update frequency (updates per minute)
    const now = Date.now();
    const cutoff = now - (this.adaptiveConfig.sampleWindow * 60 * 1000);
    const recentUpdates = updateHistory.filter(timestamp => timestamp > cutoff);
    const updatesPerMinute = recentUpdates.length / this.adaptiveConfig.sampleWindow;
    
    // Adaptive TTL: higher volatility = lower TTL
    if (updatesPerMinute > this.adaptiveConfig.volatilityThreshold) {
      // High volatility - use shorter TTL
      const ratio = Math.min(updatesPerMinute / this.adaptiveConfig.volatilityThreshold, 2);
      const adaptiveTTL = Math.max(
        this.adaptiveConfig.minTTL,
        baseTTL / ratio
      );
      this.logger.debug(
        `Adaptive TTL for ${key}: ${adaptiveTTL}ms (base: ${baseTTL}ms, updates/min: ${updatesPerMinute.toFixed(2)})`
      );
      return adaptiveTTL;
    } else {
      // Low volatility - can use longer TTL
      const ratio = Math.max(updatesPerMinute / this.adaptiveConfig.volatilityThreshold, 0.5);
      const adaptiveTTL = Math.min(
        this.adaptiveConfig.maxTTL,
        baseTTL / ratio
      );
      this.logger.debug(
        `Adaptive TTL for ${key}: ${adaptiveTTL}ms (base: ${baseTTL}ms, updates/min: ${updatesPerMinute.toFixed(2)})`
      );
      return adaptiveTTL;
    }
  }

  private recordLatency(op: 'get' | 'set' | 'del', ms: number): void {
    const bucket = this.metrics.latency[op];
    bucket.sum += ms;
    bucket.count++;
    bucket.samples.push(ms);
    if (bucket.samples.length > MAX_LATENCY_SAMPLES) bucket.samples.shift();
  }

  private summariseLatency(bucket: LatencyBucket) {
    if (bucket.count === 0) return { avg: 0, p95: 0, p99: 0, count: 0 };
    const avg = Math.round(bucket.sum / bucket.count);
    const sorted = [...bucket.samples].sort((a, b) => a - b);
    const at = (pct: number) =>
      sorted[Math.floor(sorted.length * pct)] ?? sorted[sorted.length - 1] ?? 0;
    return { avg, p95: at(0.95), p99: at(0.99), count: bucket.count };
  }

  /** Fetch the persisted tag→key list from the cache store. */
  private async getRedisTagKeys(tag: string): Promise<string[]> {
    return (
      (await this.cacheManager.get<string[]>(`${TAG_PREFIX}${tag}`)) ?? []
    );
  }

  /**
   * Register `key` under each `tags` entry in both the local mirror and
   * the cache store (Redis in production).  The cache-store copy survives
   * restarts and is visible to all instances.
   */
  private async trackKeyInTags(key: string, tags: string[]): Promise<void> {
    await Promise.all(
      tags.map(async (tag) => {
        // Local mirror
        if (!this.tagIndex.has(tag)) this.tagIndex.set(tag, new Set());
        this.tagIndex.get(tag)!.add(key);

        // Persistent store
        const tagStoreKey = `${TAG_PREFIX}${tag}`;
        const existing =
          (await this.cacheManager.get<string[]>(tagStoreKey)) ?? [];
        if (!existing.includes(key)) {
          existing.push(key);
          await this.cacheManager.set(tagStoreKey, existing, TAG_TTL);
        }
      }),
    );
  }

  private freshMetrics(): CacheMetrics {
    return {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      evictions: 0,
      inflightPeak: 0,
      latency: {
        get: { sum: 0, count: 0, samples: [] },
        set: { sum: 0, count: 0, samples: [] },
        del: { sum: 0, count: 0, samples: [] },
      },
      keyMetrics: new Map(),
    };
  }

  /**
   * Get adaptive TTL statistics for monitoring
   */
  getAdaptiveTTLStats(): {
    totalKeys: number;
    keysWithAdaptiveTTL: number;
    averageUpdateFrequency: number;
    config: AdaptiveTTLConfig;
  } {
    const totalKeys = this.keyUpdateHistory.size;
    const keysWithAdaptiveTTL = Array.from(this.keyUpdateHistory.values()).filter(
      history => history.length > 0
    ).length;
    
    let totalFrequency = 0;
    let count = 0;
    
    for (const metrics of this.metrics.keyMetrics.values()) {
      if (metrics.updateFrequency > 0) {
        totalFrequency += metrics.updateFrequency;
        count++;
      }
    }
    
    const averageUpdateFrequency = count > 0 ? totalFrequency / count : 0;
    
    return {
      totalKeys,
      keysWithAdaptiveTTL,
      averageUpdateFrequency,
      config: this.adaptiveConfig,
    };
  }
}
