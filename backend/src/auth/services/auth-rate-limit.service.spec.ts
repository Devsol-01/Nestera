import { Test, TestingModule } from '@nestjs/testing';
import { AuthRateLimitService } from './auth-rate-limit.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { EventEmitter2 } from '@nestjs/event-emitter';

describe('AuthRateLimitService', () => {
  let service: AuthRateLimitService;
  let cacheManager: Cache;
  let eventEmitter: EventEmitter2;

  const mockCacheManager = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  };

  const mockEventEmitter = {
    emit: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthRateLimitService,
        {
          provide: CACHE_MANAGER,
          useValue: mockCacheManager,
        },
        {
          provide: EventEmitter2,
          useValue: mockEventEmitter,
        },
      ],
    }).compile();

    service = module.get<AuthRateLimitService>(AuthRateLimitService);
    cacheManager = module.get<Cache>(CACHE_MANAGER);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  describe('recordFailedAttempt', () => {
    it('should record a failed attempt', async () => {
      mockCacheManager.get.mockResolvedValue([]);

      await service.recordFailedAttempt(
        'test@example.com',
        '192.168.1.1',
        'invalid_credentials',
      );

      expect(mockCacheManager.set).toHaveBeenCalledWith(
        'auth:failed:test@example.com',
        expect.arrayContaining([
          expect.objectContaining({
            identifier: 'test@example.com',
            ip: '192.168.1.1',
            reason: 'invalid_credentials',
          }),
        ]),
        900000, // 15 minutes
      );

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'auth.failed-attempt',
        expect.any(Object),
      );
    });

    it('should lock account after 5 failed attempts', async () => {
      const existingAttempts = Array(4).fill({
        identifier: 'test@example.com',
        timestamp: Date.now(),
        reason: 'invalid_credentials',
        ip: '192.168.1.1',
      });

      mockCacheManager.get.mockResolvedValue(existingAttempts);

      await service.recordFailedAttempt(
        'test@example.com',
        '192.168.1.1',
        'invalid_credentials',
      );

      // Should emit account locked event
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'auth.account-locked',
        expect.objectContaining({
          identifier: 'test@example.com',
          attemptCount: 5,
        }),
      );
    });

    it('should ban IP after 10 failed attempts', async () => {
      // Setup: 9 previous attempts, this will be the 10th
      const existingIpAttempts = Array(9).fill('user@example.com');

      mockCacheManager.get
        .mockResolvedValueOnce([]) // Failed attempts for identifier
        .mockResolvedValueOnce(existingIpAttempts) // IP attempts (9 existing)
        .mockResolvedValueOnce(existingIpAttempts); // getIpAttemptCount call

      await service.recordFailedAttempt(
        'test@example.com',
        '192.168.1.1',
        'invalid_credentials',
      );

      // Should emit both failed-attempt and ip-banned events
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'auth.failed-attempt',
        expect.any(Object),
      );

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'auth.ip-banned',
        expect.objectContaining({
          ip: '192.168.1.1',
        }),
      );
    });
  });

  describe('getProgressiveDelay', () => {
    it('should return 0ms for first attempt', async () => {
      mockCacheManager.get.mockResolvedValue([
        { timestamp: Date.now(), identifier: 'test@example.com' },
      ]);

      const delay = await service.getProgressiveDelay('test@example.com');
      expect(delay).toBe(0);
    });

    it('should return 2000ms for second attempt', async () => {
      mockCacheManager.get.mockResolvedValue([
        { timestamp: Date.now() },
        { timestamp: Date.now() },
      ]);

      const delay = await service.getProgressiveDelay('test@example.com');
      expect(delay).toBe(2000);
    });

    it('should return 5000ms for third attempt', async () => {
      mockCacheManager.get.mockResolvedValue([
        { timestamp: Date.now() },
        { timestamp: Date.now() },
        { timestamp: Date.now() },
      ]);

      const delay = await service.getProgressiveDelay('test@example.com');
      expect(delay).toBe(5000);
    });

    it('should return 30000ms for fourth+ attempt', async () => {
      mockCacheManager.get.mockResolvedValue(
        Array(5).fill({ timestamp: Date.now() }),
      );

      const delay = await service.getProgressiveDelay('test@example.com');
      expect(delay).toBe(30000);
    });
  });

  describe('applyProgressiveDelay', () => {
    it('should not delay on first attempt', async () => {
      mockCacheManager.get.mockResolvedValue([]);

      const start = Date.now();
      await service.applyProgressiveDelay('test@example.com');
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(100); // Should be nearly instant
    });

    it('should delay 2 seconds on second attempt', async () => {
      mockCacheManager.get.mockResolvedValue([
        { timestamp: Date.now() },
        { timestamp: Date.now() },
      ]);

      const start = Date.now();
      await service.applyProgressiveDelay('test@example.com');
      const elapsed = Date.now() - start;

      expect(elapsed).toBeGreaterThanOrEqual(1900); // Allow some variance
      expect(elapsed).toBeLessThan(2200);
    }, 10000);
  });

  describe('isIpBanned', () => {
    it('should return false if IP is not banned', async () => {
      mockCacheManager.get.mockResolvedValue(null);

      const isBanned = await service.isIpBanned('192.168.1.1');
      expect(isBanned).toBe(false);
    });

    it('should return true if IP is banned and not expired', async () => {
      mockCacheManager.get.mockResolvedValue({
        ip: '192.168.1.1',
        bannedAt: Date.now(),
        expiresAt: Date.now() + 3600000,
        reason: 'Too many failed attempts',
        attemptCount: 12,
      });

      const isBanned = await service.isIpBanned('192.168.1.1');
      expect(isBanned).toBe(true);
    });

    it('should return false and delete if ban has expired', async () => {
      mockCacheManager.get.mockResolvedValue({
        ip: '192.168.1.1',
        bannedAt: Date.now() - 7200000,
        expiresAt: Date.now() - 3600000, // Expired 1 hour ago
        reason: 'Too many failed attempts',
        attemptCount: 12,
      });

      const isBanned = await service.isIpBanned('192.168.1.1');
      expect(isBanned).toBe(false);
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:ip:banned:192.168.1.1',
      );
    });
  });

  describe('isAccountLocked', () => {
    it('should return false if account is not locked', async () => {
      mockCacheManager.get.mockResolvedValue(null);

      const isLocked = await service.isAccountLocked('test@example.com');
      expect(isLocked).toBe(false);
    });

    it('should return true if account is locked and not expired', async () => {
      mockCacheManager.get.mockResolvedValue({
        identifier: 'test@example.com',
        lockedAt: Date.now(),
        expiresAt: Date.now() + 3600000,
        attemptCount: 7,
        requiresEmailVerification: false,
      });

      const isLocked = await service.isAccountLocked('test@example.com');
      expect(isLocked).toBe(true);
    });

    it('should return false and delete if lock has expired', async () => {
      mockCacheManager.get.mockResolvedValue({
        identifier: 'test@example.com',
        lockedAt: Date.now() - 7200000,
        expiresAt: Date.now() - 3600000, // Expired 1 hour ago
        attemptCount: 7,
        requiresEmailVerification: false,
      });

      const isLocked = await service.isAccountLocked('test@example.com');
      expect(isLocked).toBe(false);
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:locked:test@example.com',
      );
    });
  });

  describe('clearFailedAttempts', () => {
    it('should clear failed attempts from cache', async () => {
      await service.clearFailedAttempts('test@example.com');

      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:failed:test@example.com',
      );
    });
  });

  describe('shouldBlockRequest', () => {
    it('should not block if no issues', async () => {
      mockCacheManager.get.mockResolvedValue(null);

      const result = await service.shouldBlockRequest(
        'test@example.com',
        '192.168.1.1',
      );

      expect(result.blocked).toBe(false);
    });

    it('should block if IP is banned', async () => {
      mockCacheManager.get
        .mockResolvedValueOnce({
          // IP ban check
          ip: '192.168.1.1',
          bannedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          reason: 'Too many failed attempts',
          attemptCount: 12,
        })
        .mockResolvedValueOnce({
          // Get ban info
          ip: '192.168.1.1',
          bannedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          reason: 'Too many failed attempts',
          attemptCount: 12,
        });

      const result = await service.shouldBlockRequest(
        'test@example.com',
        '192.168.1.1',
      );

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain('IP address temporarily banned');
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should block if account is locked', async () => {
      mockCacheManager.get
        .mockResolvedValueOnce(null) // IP not banned
        .mockResolvedValueOnce({
          // Account locked
          identifier: 'test@example.com',
          lockedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          attemptCount: 7,
          requiresEmailVerification: false,
        })
        .mockResolvedValueOnce({
          // Get lock info
          identifier: 'test@example.com',
          lockedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          attemptCount: 7,
          requiresEmailVerification: false,
        });

      const result = await service.shouldBlockRequest(
        'test@example.com',
        '192.168.1.1',
      );

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain('Account temporarily locked');
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should require email verification for severe lockouts', async () => {
      mockCacheManager.get
        .mockResolvedValueOnce(null) // IP not banned
        .mockResolvedValueOnce({
          // Account locked with email verification required
          identifier: 'test@example.com',
          lockedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          attemptCount: 12,
          requiresEmailVerification: true,
        })
        .mockResolvedValueOnce({
          // Get lock info
          identifier: 'test@example.com',
          lockedAt: Date.now(),
          expiresAt: Date.now() + 3600000,
          attemptCount: 12,
          requiresEmailVerification: true,
        });

      const result = await service.shouldBlockRequest(
        'test@example.com',
        '192.168.1.1',
      );

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain('Email verification required');
    });
  });

  describe('unlockAccount', () => {
    it('should unlock account and clear failed attempts', async () => {
      await service.unlockAccount('test@example.com');

      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:locked:test@example.com',
      );
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:failed:test@example.com',
      );
    });
  });

  describe('unbanIp', () => {
    it('should unban IP', async () => {
      await service.unbanIp('192.168.1.1');

      expect(mockCacheManager.del).toHaveBeenCalledWith(
        'auth:ip:banned:192.168.1.1',
      );
    });
  });
});
