import { SetMetadata } from '@nestjs/common';

/**
 * Upload-rate limiting metadata key. Reused by custom guards / interceptors
 * to layer per-endpoint upload caps on top of the TieredThrottlerGuard.
 *
 * The upper bound of the throttler bucket is already tier-aware via
 * `TieredThrottlerGuard` — this decorator is for explicit per-route caps.
 *
 * Usage:
 *   @UploadRateLimit({ maxPerMinute: 5 })
 *   async uploadAvatar(...) { ... }
 */
export const UPLOAD_RATE_LIMIT_KEY = 'nestera.uploadRateLimit';

export interface UploadRateLimitConfig {
  /** Hard cap of upload operations per minute from this endpoint. */
  maxPerMinute?: number;
  /** Hard cap of upload operations per hour from this endpoint. */
  maxUploadsPerHour?: number;
}

export const UploadRateLimit = (config: UploadRateLimitConfig) =>
  SetMetadata(UPLOAD_RATE_LIMIT_KEY, config);

/**
 * Decorator inverse: opt out of upload rate limits for a specific endpoint
 * (admin tools, batch imports, etc.).
 */
export const SkipUploadRateLimit = () =>
  SetMetadata(UPLOAD_RATE_LIMIT_KEY, { disabled: true });
