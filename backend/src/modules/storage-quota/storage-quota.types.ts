import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Quota defaults indexed by user tier. Mirrors `TieredThrottlerGuard.UserTier`
 * values. All values can be overridden by environment variables — see
 * `ResettableStorageQuotaConfig`.
 */
export interface TierQuotaDefaults {
  /** Maximum bytes a user at this tier may have stored. */
  maxTotalBytes: number;
  /** Maximum concurrent (in-flight) uploads. */
  maxActiveUploads: number;
  /** Maximum uploads a user may initiate in a 1-hour window. */
  maxUploadsPerHour: number;
}

export const TIER_QUOTA_DEFAULTS: Record<string, TierQuotaDefaults> = {
  free: {
    maxTotalBytes: 100 * 1024 * 1024, // 100 MB
    maxActiveUploads: 5,
    maxUploadsPerHour: 30,
  },
  verified: {
    maxTotalBytes: 500 * 1024 * 1024, // 500 MB
    maxActiveUploads: 15,
    maxUploadsPerHour: 120,
  },
  premium: {
    maxTotalBytes: 2 * 1024 * 1024 * 1024, // 2 GB
    maxActiveUploads: 30,
    maxUploadsPerHour: 360,
  },
  enterprise: {
    maxTotalBytes: 10 * 1024 * 1024 * 1024, // 10 GB
    maxActiveUploads: 100,
    maxUploadsPerHour: 1200,
  },
  admin: {
    maxTotalBytes: 50 * 1024 * 1024 * 1024, // 50 GB
    maxActiveUploads: 250,
    maxUploadsPerHour: 3600,
  },
};

/**
 * Resolved quota configuration for the StorageQuotaService.
 * All values can be overridden by environment variables so that ops can
 * tune limits without a redeploy.
 */
@Injectable()
export class StorageQuotaConfig {
  /** Hours before a pending reservation is considered orphaned. */
  readonly reservationTtlHours: number;
  /** How often (in minutes) the cleanup sweeper runs. */
  readonly cleanupIntervalMinutes: number;
  /** When multi-tenant feature flag is on, tenant overrides take this key shape. */
  readonly multiTenantEnabled: boolean;

  constructor(configService: ConfigService) {
    this.reservationTtlHours =
      configService.get<number>('storageQuota.reservationTtlHours') ?? 4;
    this.cleanupIntervalMinutes =
      configService.get<number>('storageQuota.cleanupIntervalMinutes') ?? 15;
    this.multiTenantEnabled =
      configService.get<boolean>('multiTenant.enabled') ?? false;
  }

  /** Resolve tier defaults, preferring env-overridden values when present. */
  resolveTierDefaults(tier: string): TierQuotaDefaults {
    const fallback = TIER_QUOTA_DEFAULTS[tier] ?? TIER_QUOTA_DEFAULTS.free;
    return {
      maxTotalBytes:
        process.env[`STORAGE_QUOTA_${tier.toUpperCase()}_MAX_TOTAL_BYTES`] !==
        undefined
          ? parseInt(
              process.env[
                `STORAGE_QUOTA_${tier.toUpperCase()}_MAX_TOTAL_BYTES`
              ]!,
              10,
            )
          : fallback.maxTotalBytes,
      maxActiveUploads:
        process.env[
          `STORAGE_QUOTA_${tier.toUpperCase()}_MAX_ACTIVE_UPLOADS`
        ] !== undefined
          ? parseInt(
              process.env[
                `STORAGE_QUOTA_${tier.toUpperCase()}_MAX_ACTIVE_UPLOADS`
              ]!,
              10,
            )
          : fallback.maxActiveUploads,
      maxUploadsPerHour:
        process.env[
          `STORAGE_QUOTA_${tier.toUpperCase()}_MAX_UPLOADS_PER_HOUR`
        ] !== undefined
          ? parseInt(
              process.env[
                `STORAGE_QUOTA_${tier.toUpperCase()}_MAX_UPLOADS_PER_HOUR`
              ]!,
              10,
            )
          : fallback.maxUploadsPerHour,
    };
  }
}

/**
 * Static error class thrown when a quota rule would be violated.
 *
 * Carries a stable `code` so the global HTTP exception filter can map it to
 * a 402 Payment Required / 413 Payload Too Large response without leaking
 * the implementation layer's HTTP decisions to callers.
 */
export class StorageQuotaExceededException extends Error {
  readonly code: string;
  readonly kind: 'storage' | 'concurrency' | 'frequency';
  readonly meta: Record<string, unknown>;

  constructor(
    kind: 'storage' | 'concurrency' | 'frequency',
    message: string,
    meta: Record<string, unknown>,
  ) {
    super(message);
    this.code = 'STORAGE_QUOTA_EXCEEDED';
    this.kind = kind;
    this.meta = meta;
    this.name = 'StorageQuotaExceededException';
  }
}
