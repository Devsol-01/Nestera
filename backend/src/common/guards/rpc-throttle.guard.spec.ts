import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, HttpException } from '@nestjs/common';
import {
  ThrottlerException,
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';
import { RpcThrottleGuard } from './rpc-throttle.guard';

describe('RpcThrottleGuard', () => {
  let guard: RpcThrottleGuard;
  let mockExecutionContext: Partial<ExecutionContext>;
  let mockRequest: any;
  let mockResponse: any;
  let mockReflector: any;
  let mockStorageService: any;

  beforeEach(() => {
    // Mock Reflector
    mockReflector = {
      get: jest.fn().mockReturnValue(undefined),
    };

    // Mock ThrottlerStorage
    mockStorageService = {
      increment: jest.fn().mockResolvedValue([1, 60]),
      reset: jest.fn(),
    };

    // Mock ThrottlerModuleOptions
    const mockOptions: Partial<ThrottlerModuleOptions> = {
      throttlers: [],
    };

    // Initialize the guard with mocked dependencies
    guard = new RpcThrottleGuard(
      mockOptions as any,
      mockStorageService,
      mockReflector,
    );

    // Mock response object
    mockResponse = {
      setHeader: jest.fn(),
    };

    // Mock request object
    mockRequest = {
      ip: '127.0.0.1',
      method: 'GET',
      path: '/savings/my-subscriptions',
      user: null,
      connection: {
        remoteAddress: '127.0.0.1',
      },
    };

    // Mock execution context
    mockExecutionContext = {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(mockRequest),
        getResponse: jest.fn().mockReturnValue(mockResponse),
      }),
    };
  });

  describe('getTracker', () => {
    it('should return user ID-based tracker when user is authenticated', async () => {
      mockRequest.user = { id: 'user-123', email: 'test@example.com' };

      const tracker = await (guard as any).getTracker(mockRequest);
      expect(tracker).toBe('rpc-throttle:user-123');
    });

    it('should return IP-based tracker when user is not authenticated', async () => {
      mockRequest.user = null;
      mockRequest.ip = '192.168.0.1';

      const tracker = await (guard as any).getTracker(mockRequest);
      expect(tracker).toBe('rpc-throttle:192.168.0.1');
    });

    it('should fallback to connection.remoteAddress if req.ip is not available', async () => {
      mockRequest.user = null;
      mockRequest.ip = null;
      mockRequest.connection.remoteAddress = '10.0.0.1';

      const tracker = await (guard as any).getTracker(mockRequest);
      expect(tracker).toBe('rpc-throttle:10.0.0.1');
    });

    it('should return "unknown" if both ip and remoteAddress are unavailable', async () => {
      mockRequest.user = null;
      mockRequest.ip = null;
      mockRequest.connection = null;

      const tracker = await (guard as any).getTracker(mockRequest);
      expect(tracker).toBe('rpc-throttle:unknown');
    });

    it('should prefer user ID over IP even if IP is available', async () => {
      mockRequest.user = { id: 'user-456', email: 'another@example.com' };
      mockRequest.ip = '192.168.1.1';

      const tracker = await (guard as any).getTracker(mockRequest);
      expect(tracker).toBe('rpc-throttle:user-456');
    });
  });

  describe('onLimitExceeded', () => {
    it('should throw ThrottlerException with correct message', async () => {
      const context = mockExecutionContext as ExecutionContext;
      const limit = 10;
      const ttl = 60000; // 1 minute

      await expect(guard.onLimitExceeded(context, limit, ttl)).rejects.toThrow(
        'Too many RPC requests',
      );
    });

    it('should set Retry-After header', async () => {
      const context = mockExecutionContext as ExecutionContext;
      const limit = 10;
      const ttl = 60000;

      try {
        await guard.onLimitExceeded(context, limit, ttl);
      } catch (e) {
        // Expected to throw
      }

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Retry-After',
        expect.any(Number),
      );
    });

    it('should set X-RateLimit headers', async () => {
      const context = mockExecutionContext as ExecutionContext;
      const limit = 10;
      const ttl = 60000;

      try {
        await guard.onLimitExceeded(context, limit, ttl);
      } catch (e) {
        // Expected to throw
      }

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Limit',
        limit,
      );
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Remaining',
        0,
      );
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Reset',
        expect.any(String),
      );
    });

    it('should include user ID in log message when available', async () => {
      mockRequest.user = { id: 'user-789', email: 'user@example.com' };
      const context = mockExecutionContext as ExecutionContext;
      const loggerWarnSpy = jest.spyOn((guard as any).logger, 'warn');

      try {
        await guard.onLimitExceeded(context, 10, 60000);
      } catch (e) {
        // Expected to throw
      }

      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('user-789'),
      );
    });

    it('should calculate Retry-After in seconds', async () => {
      const context = mockExecutionContext as ExecutionContext;
      const limit = 10;
      const ttl = 30000; // 30 seconds

      try {
        await guard.onLimitExceeded(context, limit, ttl);
      } catch (e) {
        // Expected to throw
      }

      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Retry-After',
        30, // 30000ms / 1000 = 30 seconds (rounded up)
      );
    });
  });

  describe('User-ID Based Tracking', () => {
    it('should allow different users to have independent rate limits', async () => {
      const user1Request = {
        ...mockRequest,
        user: { id: 'user-1' },
      };
      const user2Request = {
        ...mockRequest,
        user: { id: 'user-2' },
      };

      const tracker1 = await (guard as any).getTracker(user1Request);
      const tracker2 = await (guard as any).getTracker(user2Request);

      expect(tracker1).not.toBe(tracker2);
      expect(tracker1).toBe('rpc-throttle:user-1');
      expect(tracker2).toBe('rpc-throttle:user-2');
    });

    it('should treat different IPs from same user as same tracker', async () => {
      mockRequest.user = { id: 'user-same' };
      mockRequest.ip = '192.168.0.1';

      const tracker1 = await (guard as any).getTracker(mockRequest);

      mockRequest.ip = '10.0.0.1'; // Different IP
      const tracker2 = await (guard as any).getTracker(mockRequest);

      expect(tracker1).toBe(tracker2);
      expect(tracker1).toBe('rpc-throttle:user-same');
    });
  });
});
