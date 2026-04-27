import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { AuthRateLimitService } from '../services/auth-rate-limit.service';
import {
  AUTH_RATE_LIMIT_KEY,
  AuthRateLimitConfig,
} from '../decorators/auth-rate-limit.decorator';

/**
 * AuthRateLimitGuard - Enforces strict rate limiting on authentication endpoints
 *
 * Features:
 * - Checks IP bans and account locks
 * - Applies progressive delays
 * - Integrates with AuthRateLimitService
 * - Sets appropriate HTTP headers
 */
@Injectable()
export class AuthRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(AuthRateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly authRateLimitService: AuthRateLimitService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const config = this.reflector.get<AuthRateLimitConfig>(
      AUTH_RATE_LIMIT_KEY,
      context.getHandler(),
    );

    // If no rate limit config, allow request
    if (!config) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse();
    const ip = this.getClientIp(request);

    // Extract identifier from request body (email, publicKey, etc.)
    const identifier = this.extractIdentifier(request);

    if (!identifier) {
      // If we can't identify the user, just use IP
      this.logger.debug(`No identifier found, using IP: ${ip}`);
    }

    const identifierOrIp = identifier || ip;

    // Check if request should be blocked (IP ban or account lock)
    const blockCheck = await this.authRateLimitService.shouldBlockRequest(
      identifierOrIp,
      ip,
    );

    if (blockCheck.blocked) {
      response.setHeader('Retry-After', blockCheck.retryAfter || 3600);
      response.setHeader('X-RateLimit-Blocked', 'true');
      response.setHeader('X-RateLimit-Reason', blockCheck.reason || 'Blocked');

      this.logger.warn(
        `Blocked request: ${identifierOrIp} from ${ip} - ${blockCheck.reason}`,
      );

      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: blockCheck.reason,
          retryAfter: blockCheck.retryAfter,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Apply progressive delay based on previous failed attempts
    await this.authRateLimitService.applyProgressiveDelay(identifierOrIp);

    // Set rate limit headers
    const failedAttempts =
      await this.authRateLimitService.getFailedAttemptCount(identifierOrIp);
    response.setHeader('X-RateLimit-Limit', config.limit);
    response.setHeader(
      'X-RateLimit-Remaining',
      Math.max(0, config.limit - failedAttempts),
    );
    response.setHeader(
      'X-RateLimit-Reset',
      new Date(Date.now() + config.ttl).toISOString(),
    );

    return true;
  }

  /**
   * Extract client IP from request
   */
  private getClientIp(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (request.headers['x-real-ip'] as string) ||
      request.ip ||
      request.socket.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Extract identifier from request body
   */
  private extractIdentifier(request: Request): string | null {
    const body = request.body;
    if (!body) return null;

    // Try to extract email, publicKey, or userId
    return body.email || body.publicKey || body.userId || null;
  }
}
