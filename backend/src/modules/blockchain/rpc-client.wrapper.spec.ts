import { Logger } from '@nestjs/common';
import { RpcClientWrapper, RpcEndpoint } from './rpc-client.wrapper';

// Mock the Logger
jest.mock('@nestjs/common', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    log: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  })),
}));

describe('RpcClientWrapper', () => {
  let rpcEndpoints: RpcEndpoint[];
  let horizonEndpoints: RpcEndpoint[];

  beforeEach(() => {
    rpcEndpoints = [
      { url: 'https://rpc-primary.stellar.org', priority: 0, type: 'rpc' },
      { url: 'https://rpc-backup1.stellar.org', priority: 1, type: 'rpc' },
      { url: 'https://rpc-backup2.stellar.org', priority: 2, type: 'rpc' },
    ];

    horizonEndpoints = [
      {
        url: 'https://horizon-primary.stellar.org',
        priority: 0,
        type: 'horizon',
      },
      {
        url: 'https://horizon-backup1.stellar.org',
        priority: 1,
        type: 'horizon',
      },
    ];
  });

  describe('initialization', () => {
    it('should sort endpoints by priority', () => {
      const unsortedEndpoints = [
        { url: 'https://rpc3.stellar.org', priority: 2, type: 'rpc' as const },
        { url: 'https://rpc1.stellar.org', priority: 0, type: 'rpc' as const },
        { url: 'https://rpc2.stellar.org', priority: 1, type: 'rpc' as const },
      ];

      const wrapper = new RpcClientWrapper(unsortedEndpoints, [], {
        maxRetries: 2,
        retryDelay: 100,
        timeoutMs: 5000,
      });

      const status = wrapper.getEndpointsStatus();
      expect(status.rpc.endpoints[0].url).toBe('https://rpc1.stellar.org');
      expect(status.rpc.endpoints[1].url).toBe('https://rpc2.stellar.org');
      expect(status.rpc.endpoints[2].url).toBe('https://rpc3.stellar.org');
    });

    it('should log initialization', () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints);
      expect(Logger).toHaveBeenCalled();
    });
  });

  describe('executeWithRetry', () => {
    it('should succeed on first attempt with primary endpoint', async () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints, {
        maxRetries: 2,
        retryDelay: 100,
        timeoutMs: 5000,
      });

      const mockOperation = jest.fn().mockResolvedValue({ status: 'healthy' });

      const result = await wrapper.executeWithRetry(mockOperation, 'rpc');

      expect(result).toEqual({ status: 'healthy' });
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    it('should retry on failure and succeed on second attempt', async () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints, {
        maxRetries: 3,
        retryDelay: 100,
        timeoutMs: 5000,
      });

      const mockOperation = jest
        .fn()
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({ status: 'healthy' });

      const result = await wrapper.executeWithRetry(mockOperation, 'rpc');

      expect(result).toEqual({ status: 'healthy' });
      expect(mockOperation).toHaveBeenCalledTimes(2);
    });

    it('should failover to next endpoint after exhausting retries', async () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints, {
        maxRetries: 2,
        retryDelay: 50,
        timeoutMs: 5000,
      });

      let callCount = 0;
      const mockOperation = jest.fn().mockImplementation(() => {
        callCount++;
        // Fail first endpoint (2 retries), succeed on second endpoint
        if (callCount <= 2) {
          return Promise.reject(new Error('Primary endpoint down'));
        }
        return Promise.resolve({ status: 'healthy' });
      });

      const result = await wrapper.executeWithRetry(mockOperation, 'rpc');

      expect(result).toEqual({ status: 'healthy' });
      expect(mockOperation).toHaveBeenCalledTimes(3); // 2 fails + 1 success
    });

    it('should throw error when all endpoints and retries are exhausted', async () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints, {
        maxRetries: 2,
        retryDelay: 50,
        timeoutMs: 5000,
      });

      const mockOperation = jest
        .fn()
        .mockRejectedValue(new Error('All endpoints down'));

      await expect(
        wrapper.executeWithRetry(mockOperation, 'rpc'),
      ).rejects.toThrow('All rpc RPC endpoints failed');

      // 3 endpoints * 2 retries = 6 total attempts
      expect(mockOperation).toHaveBeenCalledTimes(6);
    });

    it('should handle timeout correctly', async () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints, {
        maxRetries: 1,
        retryDelay: 50,
        timeoutMs: 100,
      });

      const mockOperation = jest.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => resolve({ status: 'healthy' }), 200);
          }),
      );

      await expect(
        wrapper.executeWithRetry(mockOperation, 'rpc'),
      ).rejects.toThrow();
    });

    it('should throw error when no endpoints are configured', async () => {
      const wrapper = new RpcClientWrapper([], horizonEndpoints, {
        maxRetries: 2,
        retryDelay: 100,
        timeoutMs: 5000,
      });

      const mockOperation = jest.fn();

      await expect(
        wrapper.executeWithRetry(mockOperation, 'rpc'),
      ).rejects.toThrow('No rpc endpoints configured');
    });
  });

  describe('getCurrentRpcServer', () => {
    it('should return current RPC server instance', () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints);
      const server = wrapper.getCurrentRpcServer();
      expect(server).toBeDefined();
    });

    it('should throw error when no RPC endpoints configured', () => {
      const wrapper = new RpcClientWrapper([], horizonEndpoints);
      expect(() => wrapper.getCurrentRpcServer()).toThrow(
        'No RPC endpoints configured',
      );
    });
  });

  describe('getCurrentHorizonServer', () => {
    it('should return current Horizon server instance', () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints);
      const server = wrapper.getCurrentHorizonServer();
      expect(server).toBeDefined();
    });

    it('should throw error when no Horizon endpoints configured', () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, []);
      expect(() => wrapper.getCurrentHorizonServer()).toThrow(
        'No Horizon endpoints configured',
      );
    });
  });

  describe('getEndpointsStatus', () => {
    it('should return status of all endpoints', () => {
      const wrapper = new RpcClientWrapper(rpcEndpoints, horizonEndpoints);
      const status = wrapper.getEndpointsStatus();

      expect(status.rpc.endpoints).toHaveLength(3);
      expect(status.rpc.currentIndex).toBe(0);
      expect(status.rpc.currentUrl).toBe('https://rpc-primary.stellar.org');

      expect(status.horizon.endpoints).toHaveLength(2);
      expect(status.horizon.currentIndex).toBe(0);
      expect(status.horizon.currentUrl).toBe(
        'https://horizon-primary.stellar.org',
      );
    });
  });
});
