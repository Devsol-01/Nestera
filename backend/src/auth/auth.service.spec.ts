import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from '../modules/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as StellarSdk from '@stellar/stellar-sdk';
import { AuthRateLimitService } from './services/auth-rate-limit.service';

describe('AuthService - Nonce Security', () => {
  let service: AuthService;
  let cacheManager: Cache;
  let userService: UserService;

  const mockCacheManager = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  };

  const mockUserService = {
    findByEmail: jest.fn(),
    findByPublicKey: jest.fn(),
    create: jest.fn(),
    linkWalletAddress: jest.fn(),
  };

  const mockJwtService = {
    sign: jest.fn().mockReturnValue('mock-jwt-token'),
  };

  const mockEventEmitter = {
    emit: jest.fn(),
  };

  const mockAuthRateLimitService = {
    recordFailedAttempt: jest.fn(),
    clearFailedAttempts: jest.fn(),
    applyProgressiveDelay: jest.fn(),
    shouldBlockRequest: jest.fn().mockResolvedValue({ blocked: false }),
    getProgressiveDelay: jest.fn().mockResolvedValue(0),
    getFailedAttemptCount: jest.fn().mockResolvedValue(0),
    isIpBanned: jest.fn().mockResolvedValue(false),
    isAccountLocked: jest.fn().mockResolvedValue(false),
  };

  // Generate a valid Stellar keypair for testing
  const testKeypair = StellarSdk.Keypair.random();
  const testPublicKey = testKeypair.publicKey();

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: mockUserService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: EventEmitter2,
          useValue: mockEventEmitter,
        },
        {
          provide: CACHE_MANAGER,
          useValue: mockCacheManager,
        },
        {
          provide: AuthRateLimitService,
          useValue: mockAuthRateLimitService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    cacheManager = module.get<Cache>(CACHE_MANAGER);
    userService = module.get<UserService>(UserService);
  });

  describe('generateNonce', () => {
    it('should generate a nonce and store it in cache with TTL', async () => {
      mockCacheManager.get.mockResolvedValue(0);

      const result = await service.generateNonce(testPublicKey);

      expect(result).toHaveProperty('nonce');
      expect(typeof result.nonce).toBe('string');
      expect(result.nonce).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      );

      // Verify cache was called with correct parameters
      expect(mockCacheManager.set).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
        expect.objectContaining({
          nonce: result.nonce,
          timestamp: expect.any(Number),
        }),
        300000, // 5 minutes TTL
      );
    });

    it('should reject invalid Stellar public key format', async () => {
      const invalidKey = 'INVALID_KEY';

      await expect(service.generateNonce(invalidKey)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.generateNonce(invalidKey)).rejects.toThrow(
        'Invalid Stellar public key format',
      );
    });

    it('should implement rate limiting (max 5 requests per 15 minutes)', async () => {
      mockCacheManager.get.mockResolvedValue(5); // Already at limit

      await expect(service.generateNonce(testPublicKey)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.generateNonce(testPublicKey)).rejects.toThrow(
        'Too many nonce requests',
      );
    });

    it('should increment rate limit counter on each request', async () => {
      mockCacheManager.get.mockResolvedValue(2); // 2 previous requests

      await service.generateNonce(testPublicKey);

      expect(mockCacheManager.set).toHaveBeenCalledWith(
        `nonce:ratelimit:${testPublicKey}`,
        3,
        900000, // 15 minutes
      );
    });

    it('should initialize rate limit counter for first request', async () => {
      mockCacheManager.get.mockResolvedValue(null); // No previous requests

      await service.generateNonce(testPublicKey);

      expect(mockCacheManager.set).toHaveBeenCalledWith(
        `nonce:ratelimit:${testPublicKey}`,
        1,
        900000,
      );
    });
  });

  describe('verifySignature - Nonce Security', () => {
    const mockNonce = 'test-nonce-uuid';
    const mockTimestamp = Date.now();

    beforeEach(() => {
      mockUserService.findByPublicKey.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        role: 'USER',
      });
    });

    it('should reject if nonce is not found in cache', async () => {
      mockCacheManager.get.mockResolvedValue(null);

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Nonce not found or expired');
    });

    it('should reject if nonce has expired (timestamp validation)', async () => {
      const expiredTimestamp = Date.now() - 400000; // 6+ minutes ago
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: expiredTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow(UnauthorizedException);

      // Verify expired nonce was deleted
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
      );
    });

    it('should reject if nonce does not match', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: 'different-nonce',
        timestamp: mockTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Nonce mismatch');
    });

    it('should reject if signature is invalid', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      const invalidSignature = 'invalid-signature-hex';

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature: invalidSignature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow(UnauthorizedException);

      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature: invalidSignature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Invalid signature');
    });

    it('should atomically consume nonce after successful verification', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await service.verifySignature({
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      // Verify nonce was deleted immediately after verification
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
      );
      expect(mockCacheManager.del).toHaveBeenCalledTimes(1);
    });

    it('should prevent replay attacks by consuming nonce', async () => {
      const nonceData = {
        nonce: mockNonce,
        timestamp: mockTimestamp,
      };

      // First request - nonce exists
      mockCacheManager.get.mockResolvedValueOnce(nonceData);

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      // First verification should succeed
      await service.verifySignature({
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      // Second request - nonce has been consumed
      mockCacheManager.get.mockResolvedValueOnce(null);

      // Second verification with same nonce should fail
      await expect(
        service.verifySignature({
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Nonce not found or expired');
    });

    it('should successfully verify valid signature with valid nonce', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      const result = await service.verifySignature({
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      expect(result).toHaveProperty('accessToken');
      expect(result.accessToken).toBe('mock-jwt-token');
      expect(mockCacheManager.del).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
      );
    });

    it('should create new user if not found', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      mockUserService.findByPublicKey.mockResolvedValue(null);
      mockUserService.create.mockResolvedValue({
        id: 'new-user-123',
        email: `${testPublicKey.substring(0, 10)}@stellar.wallet`,
        role: 'USER',
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await service.verifySignature({
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      expect(mockUserService.create).toHaveBeenCalledWith({
        publicKey: testPublicKey,
        email: `${testPublicKey.substring(0, 10)}@stellar.wallet`,
        name: 'Stellar Wallet User',
      });
    });
  });

  describe('linkWallet - Nonce Security', () => {
    const mockNonce = 'test-nonce-uuid';
    const mockTimestamp = Date.now();
    const userId = 'user-123';

    beforeEach(() => {
      mockUserService.linkWalletAddress.mockResolvedValue({
        id: userId,
        walletAddress: testPublicKey,
      });
    });

    it('should reject if nonce is not found in cache', async () => {
      mockCacheManager.get.mockResolvedValue(null);

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await expect(
        service.linkWallet(userId, {
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Nonce not found or expired');
    });

    it('should reject expired nonce for wallet linking', async () => {
      const expiredTimestamp = Date.now() - 400000;
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: expiredTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await expect(
        service.linkWallet(userId, {
          publicKey: testPublicKey,
          signature,
          nonce: mockNonce,
        }),
      ).rejects.toThrow('Nonce has expired');

      expect(mockCacheManager.del).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
      );
    });

    it('should atomically consume nonce after successful wallet linking', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      await service.linkWallet(userId, {
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      expect(mockCacheManager.del).toHaveBeenCalledWith(
        `nonce:${testPublicKey}`,
      );
    });

    it('should successfully link wallet with valid nonce and signature', async () => {
      mockCacheManager.get.mockResolvedValue({
        nonce: mockNonce,
        timestamp: mockTimestamp,
      });

      const signature = testKeypair
        .sign(Buffer.from(mockNonce))
        .toString('hex');

      const result = await service.linkWallet(userId, {
        publicKey: testPublicKey,
        signature,
        nonce: mockNonce,
      });

      expect(result).toEqual({
        walletAddress: testPublicKey,
        message: 'Wallet linked successfully',
      });
      expect(mockUserService.linkWalletAddress).toHaveBeenCalledWith(
        userId,
        testPublicKey,
      );
    });
  });

  describe('Security Edge Cases', () => {
    it('should handle concurrent nonce requests correctly', async () => {
      mockCacheManager.get.mockResolvedValue(0);

      const promises = [
        service.generateNonce(testPublicKey),
        service.generateNonce(testPublicKey),
        service.generateNonce(testPublicKey),
      ];

      const results = await Promise.all(promises);

      // All should succeed and generate unique nonces
      expect(results).toHaveLength(3);
      expect(new Set(results.map((r) => r.nonce)).size).toBe(3);
    });

    it('should handle cache failures gracefully', async () => {
      mockCacheManager.get.mockRejectedValue(new Error('Cache error'));

      await expect(service.generateNonce(testPublicKey)).rejects.toThrow();
    });

    it('should validate public key format before any cache operations', async () => {
      const invalidKey = 'INVALID';

      await expect(service.generateNonce(invalidKey)).rejects.toThrow(
        BadRequestException,
      );

      // Cache should not be called for invalid keys
      expect(mockCacheManager.get).not.toHaveBeenCalled();
      expect(mockCacheManager.set).not.toHaveBeenCalled();
    });
  });
});
