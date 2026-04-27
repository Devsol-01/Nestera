import { Injectable, Logger, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { EventEmitter2 } from '@nestjs/event-emitter';

export interface FailedAttempt {
  identifier: string; // email, publicKey, or IP
  timestamp: number;
  reason: 'invalid_credentials' | 'invalid_signature' | 'nonce_mismatch';
  ip: string;
}

export interface IpBanInfo {
  ip: string;
  bannedAt: number;
  expiresAt: number;
  reason: string;
  attemptCount: number;
}

export interface AccountLockInfo {
  identifier: string; // email or publicKey
  lockedAt: number;
  expiresAt: number;
  attemptCount: number;
  requiresEmailVerification: boolean;
}

/**
 * AuthRateLimitService - Advanced rate limiting and security for authentication
 *
 * Features:
 * - Progressive delays on failed attempts
 * - IP-based tracking and temporary bans
 * - Account lockout after repeated failures
 * - Redis-backed persistence
 * - Comprehensive logging and monitoring
 */
@Injectable()
export class AuthRateLimitService {
  private readonly logger = new Logger(AuthRateLimitService.name);

  // Progressive delay configuration (in milliseconds)
  private readonly PROGRESSIVE_DELAYS = [0, 2000, 5000, 30000]; // 0s, 2s, 5s, 30s

  // IP ban configuration
  private readonly IP_BAN_THRESHOLD = 10; // Failed attempts before ban
  private readonly IP_BAN_DURATION = 3600000; // 1 hour in milliseconds
  private readonly IP_BAN_WINDOW = 900000; // 15 minutes tracking window

  // Account lockout configuration
  private readonly ACCOUNT_LOCK_THRESHOLD = 5; // Failed attempts before lock
  private readonly ACCOUNT_LOCK_DURATION = 3600000; // 1 hour in milliseconds

  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  /**
   * Record a failed authentication attempt
   */
  async recordFailedAttempt(
    identifier: string,
    ip: string,
    reason: FailedAttempt['reason'],
  ): Promise<void> {
    const attempt: FailedAttempt = {
      identifier,
      timestamp: Date.now(),
      reason,
      ip,
    };

    // Store in Redis with 15-minute TTL
    const key = `auth:failed:${identifier}`;
    const attempts = (await this.cacheManager.get<FailedAttempt[]>(key)) || [];
    attempts.push(attempt);

    // Keep only attempts within the tracking window
    const cutoff = Date.now() - this.IP_BAN_WINDOW;
    const recentAttempts = attempts.filter((a) => a.timestamp > cutoff);

    await this.cacheManager.set(key, recentAttempts, this.IP_BAN_WINDOW);

    // Also track by IP
    await this.recordIpAttempt(ip, identifier);

    // Check if account should be locked
    if (recentAttempts.length >= this.ACCOUNT_LOCK_THRESHOLD) {
      await this.lockAccount(identifier, recentAttempts.length);
    }

    // Check if IP should be banned
    const ipAttempts = await this.getIpAttemptCount(ip);
    if (ipAttempts >= this.IP_BAN_THRESHOLD) {
      await this.banIp(ip, ipAttempts);
    }

    // Emit event for monitoring
    this.eventEmitter.emit('auth.failed-attempt', attempt);

    this.logger.warn(
      `Failed auth attempt: ${identifier} from ${ip} (${reason}) - ` +
        `Total: ${recentAttempts.length}/${this.ACCOUNT_LOCK_THRESHOLD}`,
    );
  }

  /**
   * Get progressive delay based on failed attempt count
   */
  async getProgressiveDelay(identifier: string): Promise<number> {
    const attempts = await this.getFailedAttemptCount(identifier);
    const delayIndex = Math.min(
      attempts - 1,
      this.PROGRESSIVE_DELAYS.length - 1,
    );
    return delayIndex >= 0 ? this.PROGRESSIVE_DELAYS[delayIndex] : 0;
  }

  /**
   * Apply progressive delay (sleep)
   */
  async applyProgressiveDelay(identifier: string): Promise<void> {
    const delay = await this.getProgressiveDelay(identifier);
    if (delay > 0) {
      this.logger.debug(
        `Applying progressive delay: ${delay}ms for ${identifier}`,
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  /**
   * Get failed attempt count for an identifier
   */
  async getFailedAttemptCount(identifier: string): Promise<number> {
    const key = `auth:failed:${identifier}`;
    const attempts = (await this.cacheManager.get<FailedAttempt[]>(key)) || [];
    return attempts.length;
  }

  /**
   * Clear failed attempts (on successful auth)
   */
  async clearFailedAttempts(identifier: string): Promise<void> {
    const key = `auth:failed:${identifier}`;
    await this.cacheManager.del(key);
    this.logger.debug(`Cleared failed attempts for ${identifier}`);
  }

  /**
   * Record IP attempt
   */
  private async recordIpAttempt(ip: string, identifier: string): Promise<void> {
    const key = `auth:ip:${ip}`;
    const attempts = (await this.cacheManager.get<string[]>(key)) || [];
    attempts.push(identifier);

    // Keep only recent attempts
    const cutoff = Date.now() - this.IP_BAN_WINDOW;
    const recentAttempts = attempts.slice(-this.IP_BAN_THRESHOLD * 2); // Keep some history

    await this.cacheManager.set(key, recentAttempts, this.IP_BAN_WINDOW);
  }

  /**
   * Get IP attempt count
   */
  async getIpAttemptCount(ip: string): Promise<number> {
    const key = `auth:ip:${ip}`;
    const attempts = (await this.cacheManager.get<string[]>(key)) || [];
    return attempts.length;
  }

  /**
   * Check if IP is banned
   */
  async isIpBanned(ip: string): Promise<boolean> {
    const key = `auth:ip:banned:${ip}`;
    const banInfo = await this.cacheManager.get<IpBanInfo>(key);
    if (!banInfo) return false;

    // Check if ban has expired
    if (Date.now() > banInfo.expiresAt) {
      await this.cacheManager.del(key);
      return false;
    }

    return true;
  }

  /**
   * Ban an IP address
   */
  async banIp(ip: string, attemptCount: number): Promise<void> {
    const banInfo: IpBanInfo = {
      ip,
      bannedAt: Date.now(),
      expiresAt: Date.now() + this.IP_BAN_DURATION,
      reason: `Too many failed authentication attempts (${attemptCount})`,
      attemptCount,
    };

    const key = `auth:ip:banned:${ip}`;
    await this.cacheManager.set(key, banInfo, this.IP_BAN_DURATION);

    this.eventEmitter.emit('auth.ip-banned', banInfo);

    this.logger.warn(
      `IP banned: ${ip} for ${this.IP_BAN_DURATION / 1000}s ` +
        `(${attemptCount} failed attempts)`,
    );
  }

  /**
   * Get IP ban info
   */
  async getIpBanInfo(ip: string): Promise<IpBanInfo | null> {
    const key = `auth:ip:banned:${ip}`;
    const result = await this.cacheManager.get<IpBanInfo>(key);
    return result || null;
  }

  /**
   * Manually unban an IP (admin function)
   */
  async unbanIp(ip: string): Promise<void> {
    const key = `auth:ip:banned:${ip}`;
    await this.cacheManager.del(key);
    this.logger.log(`IP unbanned by admin: ${ip}`);
  }

  /**
   * Check if account is locked
   */
  async isAccountLocked(identifier: string): Promise<boolean> {
    const key = `auth:locked:${identifier}`;
    const lockInfo = await this.cacheManager.get<AccountLockInfo>(key);
    if (!lockInfo) return false;

    // Check if lock has expired
    if (Date.now() > lockInfo.expiresAt) {
      await this.cacheManager.del(key);
      return false;
    }

    return true;
  }

  /**
   * Lock an account
   */
  async lockAccount(identifier: string, attemptCount: number): Promise<void> {
    const lockInfo: AccountLockInfo = {
      identifier,
      lockedAt: Date.now(),
      expiresAt: Date.now() + this.ACCOUNT_LOCK_DURATION,
      attemptCount,
      requiresEmailVerification:
        attemptCount >= this.ACCOUNT_LOCK_THRESHOLD + 5, // Extra strict after 10 attempts
    };

    const key = `auth:locked:${identifier}`;
    await this.cacheManager.set(key, lockInfo, this.ACCOUNT_LOCK_DURATION);

    this.eventEmitter.emit('auth.account-locked', lockInfo);

    this.logger.warn(
      `Account locked: ${identifier} for ${this.ACCOUNT_LOCK_DURATION / 1000}s ` +
        `(${attemptCount} failed attempts)`,
    );
  }

  /**
   * Get account lock info
   */
  async getAccountLockInfo(
    identifier: string,
  ): Promise<AccountLockInfo | null> {
    const key = `auth:locked:${identifier}`;
    const result = await this.cacheManager.get<AccountLockInfo>(key);
    return result || null;
  }

  /**
   * Manually unlock an account (admin function)
   */
  async unlockAccount(identifier: string): Promise<void> {
    const key = `auth:locked:${identifier}`;
    await this.cacheManager.del(key);
    await this.clearFailedAttempts(identifier);
    this.logger.log(`Account unlocked by admin: ${identifier}`);
  }

  /**
   * Get security metrics
   */
  async getSecurityMetrics(): Promise<{
    totalFailedAttempts: number;
    bannedIps: number;
    lockedAccounts: number;
  }> {
    // Note: This is a simplified version. In production, you'd want to
    // track these metrics more efficiently (e.g., using Redis counters)
    return {
      totalFailedAttempts: 0, // Would need to scan Redis keys
      bannedIps: 0, // Would need to scan Redis keys
      lockedAccounts: 0, // Would need to scan Redis keys
    };
  }

  /**
   * Check if request should be blocked
   */
  async shouldBlockRequest(
    identifier: string,
    ip: string,
  ): Promise<{ blocked: boolean; reason?: string; retryAfter?: number }> {
    // Check IP ban
    if (await this.isIpBanned(ip)) {
      const banInfo = await this.getIpBanInfo(ip);
      return {
        blocked: true,
        reason: 'IP address temporarily banned due to suspicious activity',
        retryAfter: banInfo
          ? Math.ceil((banInfo.expiresAt - Date.now()) / 1000)
          : 3600,
      };
    }

    // Check account lock
    if (await this.isAccountLocked(identifier)) {
      const lockInfo = await this.getAccountLockInfo(identifier);
      return {
        blocked: true,
        reason: lockInfo?.requiresEmailVerification
          ? 'Account locked. Email verification required to unlock.'
          : 'Account temporarily locked due to multiple failed attempts',
        retryAfter: lockInfo
          ? Math.ceil((lockInfo.expiresAt - Date.now()) / 1000)
          : 3600,
      };
    }

    return { blocked: false };
  }
}
