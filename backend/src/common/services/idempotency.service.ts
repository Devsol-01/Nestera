import { Injectable, Inject, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

/**
 * Shape of an idempotency record that the background cleanup job can
 * reason about.  Mirrors `StoredIdempotencyRecord` in the interceptor
 * but is declared here so the cleanup service can stay decoupled from
 * the HTTP layer.
 */
export interface IdempotencyStoredRecord {
  payloadHash: string;
  statusCode: number;
  body: unknown;
  completedAt: string;
  /** Absolute unix-ms expiry used for the cleanup safety check. */
  expiresAt?: number;
}

/** Lock keys carry no absolute expiry and must never be cleanup-deleted. */
export const IDEMPOTENCY_LOCK_SUFFIX = ':lock';
// Backward-compatible alias retained for the existing interceptor import.
export const LOCK_SUFFIX = IDEMPOTENCY_LOCK_SUFFIX;

@Injectable()
export class IdempotencyService {
  private readonly logger = new Logger(IdempotencyService.name);
  private readonly TTL = 24 * 60 * 60 * 1000; // 24 hours

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  async getResponse(key: string, userId: string): Promise<any> {
    const fullKey = this.getFullKey(key, userId);
    return await this.cacheManager.get(fullKey);
  }

  async saveResponse(
    key: string,
    userId: string,
    response: any,
  ): Promise<void> {
    const fullKey = this.getFullKey(key, userId);
    await this.cacheManager.set(fullKey, response, this.TTL);
  }

  async isProcessing(key: string, userId: string): Promise<boolean> {
    const lockKey = this.getLockKey(key, userId);
    const processing = await this.cacheManager.get(lockKey);
    return !!processing;
  }

  async setProcessing(key: string, userId: string): Promise<void> {
    const lockKey = this.getLockKey(key, userId);
    await this.cacheManager.set(lockKey, true, 30000); // 30 seconds lock
  }

  async removeProcessing(key: string, userId: string): Promise<void> {
    const lockKey = this.getLockKey(key, userId);
    await this.cacheManager.del(lockKey);
  }

  /**
   * Returns the underlying ioredis client's `scan` capability when the
   * registered cache-manager store wraps ioredis.  Used by the cleanup
   * service to iterate `idempotency:*` keys without relying on key
   * iteration through the cache-manager abstraction.
   *
   * Returns null for in-memory stores and any unknown store shape so
   * the caller can skip cleanup safely rather than crash.
   */
  getUnderlyingRedisClient(): {
    scan: (
      cursor: string | number,
      match: string,
      count: number,
    ) => Promise<[string, string[]]>;
  } | null {
    const manager = this.cacheManager as Cache & {
      store?: unknown;
      stores?: unknown[];
    };

    const store = (manager.store ?? manager.stores?.[0]) as unknown;
    if (!store || typeof store !== 'object') {
      return null;
    }

    const candidate = store as {
      client?: {
        scan?: (...args: unknown[]) => Promise<unknown>;
      };
      getClient?: () => unknown;
    };

    const client =
      typeof candidate.getClient === 'function'
        ? candidate.getClient()
        : candidate.client;

    if (
      !client ||
      typeof (client as { scan?: unknown }).scan !== 'function'
    ) {
      return null;
    }

    return {
      scan: async (cursor, match, count) => {
        const result = await (client as {
          scan: (...args: unknown[]) => Promise<unknown>;
        }).scan(cursor, 'MATCH', match, 'COUNT', count);
        if (!Array.isArray(result) || result.length < 2) {
          // Defensive — ioredis always returns [cursor, keys[]], but
          // some wrappers may diverge.  Returning an empty batch is
          // safer than throwing.
          return ['0', []];
        }
        const [nextCursor, keys] = result as [unknown, unknown];
        return [
          typeof nextCursor === 'string' || typeof nextCursor === 'number'
            ? String(nextCursor)
            : '0',
          Array.isArray(keys) ? (keys as string[]) : [],
        ];
      },
    };
  }

  /**
   * Cache-manager accessor used by the cleanup service so it does not
   * depend directly on the @Inject(CACHE_MANAGER) internals.
   */
  async getRecord(cacheKey: string): Promise<IdempotencyStoredRecord | null> {
    return (await this.cacheManager.get(cacheKey)) as
      | IdempotencyStoredRecord
      | null;
  }

  async deleteRecord(cacheKey: string): Promise<void> {
    await this.cacheManager.del(cacheKey);
  }

  /**
   * Returns true when the supplied record is logically expired OR was
   * never stamped with an explicit expiry.  Records without an
   * `expiresAt` field are conservatively treated as not-expiring here;
   * the cleanup job relies on Redis TTL + the new grace window to
   * surface them, so deleting via this helper would be unsafe.
   *
   * This helper is intentionally only used by the cleanup service so
   * that callers do not race the interceptor by reviving just-deleted
   * records; cleanup always re-checks via `getRecord` immediately
   * before calling `deleteRecord`.
   */
  isExpiredByWallClock(record: IdempotencyStoredRecord, now: number): boolean {
    if (typeof record?.expiresAt !== 'number') {
      return false;
    }
    return record.expiresAt <= now;
  }

  private getFullKey(key: string, userId: string): string {
    return `idempotency:res:${userId}:${key}`;
  }

  private getLockKey(key: string, userId: string): string {
    return `idempotency:lock:${userId}:${key}`;
  }
}
