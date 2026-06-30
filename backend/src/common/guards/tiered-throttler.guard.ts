import {
  Injectable,
  ExecutionContext,
  Inject,
  Logger,
  Optional,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';
import { Request, Response } from 'express';
import { RateLimitMonitorService } from '../services/rate-limit-monitor.service';

/**
 * User tiers for rate limiting.
 * Tier is derived from user role + KYC status.
 */
export enum UserTier {
  FREE = 'free',
  VERIFIED = 'verified', // KYC approved
  PREMIUM = 'premium', // Future: paid plan
  ENTERPRISE = 'enterprise', // Future: enterprise plan
  ADMIN = 'admin',
}

/**
 * Rate limit configuration per tier.
 * Each tier defines limits for each named throttler.
 */
const TIER_LIMITS: Record<
  UserTier,
  Record<string, { limit: number; ttl: number }>
> = {
  [UserTier.FREE]: {
    default: { limit: 60, ttl: 60000 },
    auth: { limit: 5, ttl: 15 * 60 * 1000 },
    otp: { limit: 3, ttl: 15 * 60 * 1000 },
    'wallet-link': { limit: 3, ttl: 60 * 60 * 1000 },
    rpc: { limit: 5, ttl: 60000 },
    export: { limit: 1, ttl: 15 * 60 * 1000 },
    vote: { limit: 5, ttl: 60_000 },
    upload: { limit: 10, ttl: 60_000 },
    'admin-high-risk': { limit: 0, ttl: 5 * 60 * 1000 }, // Not allowed
  },
  [UserTier.VERIFIED]: {
    default: { limit: 150, ttl: 60000 },
    auth: { limit: 10, ttl: 15 * 60 * 1000 },
    otp: { limit: 5, ttl: 15 * 60 * 1000 },
    'wallet-link': { limit: 5, ttl: 60 * 60 * 1000 },
    rpc: { limit: 15, ttl: 60000 },
    export: { limit: 3, ttl: 15 * 60 * 1000 },
    vote: { limit: 10, ttl: 60_000 },
    upload: { limit: 30, ttl: 60_000 },
    'admin-high-risk': { limit: 0, ttl: 5 * 60 * 1000 }, // Not allowed
  },
  [UserTier.PREMIUM]: {
    default: { limit: 300, ttl: 60000 },
    auth: { limit: 15, ttl: 15 * 60 * 1000 },
    otp: { limit: 5, ttl: 15 * 60 * 1000 },
    'wallet-link': { limit: 10, ttl: 60 * 60 * 1000 },
    rpc: { limit: 30, ttl: 60000 },
    export: { limit: 4, ttl: 15 * 60 * 1000 },
    vote: { limit: 20, ttl: 60_000 },
    upload: { limit: 60, ttl: 60_000 },
    'admin-high-risk': { limit: 0, ttl: 5 * 60 * 1000 }, // Not allowed
  },
  [UserTier.ENTERPRISE]: {
    default: { limit: 1000, ttl: 60000 },
    auth: { limit: 30, ttl: 15 * 60 * 1000 },
    otp: { limit: 10, ttl: 15 * 60 * 1000 },
    'wallet-link': { limit: 20, ttl: 60 * 60 * 1000 },
    rpc: { limit: 100, ttl: 60000 },
    export: { limit: 8, ttl: 15 * 60 * 1000 },
    vote: { limit: 30, ttl: 60_000 },
    upload: { limit: 120, ttl: 60_000 },
    'admin-high-risk': { limit: 0, ttl: 5 * 60 * 1000 }, // Not allowed
  },
  [UserTier.ADMIN]: {
    default: { limit: 1000, ttl: 60000 },
    auth: { limit: 50, ttl: 15 * 60 * 1000 },
    otp: { limit: 20, ttl: 15 * 60 * 1000 },
    'wallet-link': { limit: 20, ttl: 60 * 60 * 1000 },
    rpc: { limit: 100, ttl: 60000 },
    export: { limit: 6, ttl: 15 * 60 * 1000 },
    vote: { limit: 30, ttl: 60_000 },
    upload: { limit: 240, ttl: 60_000 },
    'admin-high-risk': { limit: 2, ttl: 5 * 60 * 1000 }, // 2 per 5 minutes
  },
};

/**
 * TieredThrottlerGuard - Rate limiting based on user tier.
 *
 * Determines user tier from JWT payload (role + kycStatus)
 * and applies appropriate rate limits. Injects standard
 * rate limit headers into every response.
 */
@Injectable()
export class TieredThrottlerGuard extends ThrottlerGuard {
  private readonly logger = new Logger(TieredThrottlerGuard.name);

  @Optional()
  @Inject(RateLimitMonitorService)
  private readonly monitorService?: RateLimitMonitorService;

  /**
   * Resolve the user's tier from the request context.
   */
  static resolveUserTier(user?: {
    role?: string;
    kycStatus?: string;
    tier?: string;
  }): UserTier {
    if (!user) return UserTier.FREE;

    // Explicit tier override (for future paid plans)
    if (user.tier === 'enterprise') return UserTier.ENTERPRISE;
    if (user.tier === 'premium') return UserTier.PREMIUM;

    // Admin always gets highest limits
    if (user.role === 'ADMIN') return UserTier.ADMIN;

    // KYC-verified users get higher limits
    if (user.kycStatus === 'APPROVED') return UserTier.VERIFIED;

    return UserTier.FREE;
  }

  /**
   * Get the rate limit config for a user tier and throttler name.
   */
  static getLimitsForTier(
    tier: UserTier,
    throttlerName: string,
  ): { limit: number; ttl: number } {
    const tierConfig = TIER_LIMITS[tier];
    return tierConfig[throttlerName] || tierConfig['default'];
  }

  protected async getTracker(req: Record<string, any>): Promise<string> {
    const user = req.user;
    if (user?.id) {
      return `tiered-throttle:${user.id}`;
    }
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    return `tiered-throttle:${ip}`;
  }

  protected async handleRequest(requestProps: {
    context: ExecutionContext;
    limit: number;
    ttl: number;
    throttler: { name: string; limit: number; ttl: number };
    blockDuration: number;
    getTracker: (req: Record<string, any>) => Promise<string>;
    generateKey: (
      context: ExecutionContext,
      tracker: string,
      throttlerName: string,
    ) => string;
  }): Promise<boolean> {
    const { context, throttler } = requestProps;
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const user = (request as any).user;

    const tier = TieredThrottlerGuard.resolveUserTier(user);
    const tierLimits = TieredThrottlerGuard.getLimitsForTier(
      tier,
      throttler.name,
    );

    // Override the limit and ttl with tier-based values
    requestProps.limit = tierLimits.limit;
    requestProps.ttl = tierLimits.ttl;

    // Set rate limit headers on every response
    response.setHeader('X-RateLimit-Limit', tierLimits.limit);
    response.setHeader('X-RateLimit-Tier', tier);

    try {
      const result = await super.handleRequest(requestProps);
      return result;
    } catch (error) {
      if (error instanceof ThrottlerException) {
        const retryAfter = Math.ceil(tierLimits.ttl / 1000);
        const resetAt = new Date(Date.now() + tierLimits.ttl).toISOString();
        this.logger.warn(
          `[Rate Limit] Tier: ${tier} | User: ${user?.id || 'anon'} | ` +
            `Route: ${request.method} ${request.path} | ` +
            `Throttler: ${throttler.name} | ` +
            `Limit: ${tierLimits.limit}/${Math.round(tierLimits.ttl / 1000)}s`,
        );

        this.monitorService?.recordViolation({
          userId: user?.id || null,
          ip: request.ip || 'unknown',
          tier,
          route: request.path,
          method: request.method,
          throttlerName: throttler.name,
          limit: tierLimits.limit,
          ttl: tierLimits.ttl,
          timestamp: new Date(),
        });

        response.setHeader('Retry-After', retryAfter);
        response.setHeader('X-RateLimit-Remaining', 0);
        response.setHeader('X-RateLimit-Reset', resetAt);

        throw new HttpException(
          {
            success: false,
            statusCode: HttpStatus.TOO_MANY_REQUESTS,
            errorCode: 'THROTTLED',
            message: `Rate limit exceeded for ${tier} tier.`,
            endpoint: `${request.method} ${request.path}`,
            retryAfter,
            resetAt,
            limit: tierLimits.limit,
            ttl: tierLimits.ttl,
          },
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
      throw error;
    }
  }
}
