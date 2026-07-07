import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ContractValidationService } from './contract-validation.service';

describe('ContractValidationService', () => {
  let service: ContractValidationService;
  let module: TestingModule;

  beforeEach(async () => {
    module = await Test.createTestingModule({
      providers: [
        ContractValidationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<ContractValidationService>(ContractValidationService);
  });

  afterEach(async () => {
    service.clearFailureLog();
    await module.close();
  });

  describe('recordValidationFailure', () => {
    it('should record validation failure with full context', () => {
      const correlationId = 'req_123';
      const endpoint = 'POST /users';
      const reason = 'validation_failed';
      const details = { field: 'email', error: 'invalid format' };

      service.recordValidationFailure(correlationId, endpoint, reason, details);

      const records = service.getFailureRecords();
      expect(records.length).toBe(1);
      expect(records[0]).toMatchObject({
        correlationId,
        endpoint,
        reason,
        details,
      });
    });

    it('should record multiple failures', () => {
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {});
      service.recordValidationFailure('req_2', 'PUT /users/1', 'validation_failed', {});
      service.recordValidationFailure('req_3', 'POST /orders', 'unknown_fields_rejected', {});

      const records = service.getFailureRecords();
      expect(records.length).toBe(3);
    });
  });

  describe('getFailureRecords', () => {
    beforeEach(() => {
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {});
      service.recordValidationFailure('req_2', 'PUT /users/1', 'validation_failed', {});
      service.recordValidationFailure('req_3', 'POST /orders', 'unknown_fields_rejected', {});
    });

    it('should return all failure records', () => {
      const records = service.getFailureRecords();
      expect(records.length).toBe(3);
    });

    it('should filter by endpoint', () => {
      const records = service.getFailureRecords({ endpoint: 'POST /users' });
      expect(records.length).toBe(1);
      expect(records[0].endpoint).toContain('POST /users');
    });

    it('should filter by reason', () => {
      const records = service.getFailureRecords({
        reason: 'unknown_fields_rejected',
      });
      expect(records.length).toBe(1);
      expect(records[0].reason).toBe('unknown_fields_rejected');
    });

    it('should filter by time range', () => {
      const past = new Date(Date.now() - 60000); // 1 minute ago
      const future = new Date(Date.now() + 60000); // 1 minute in future

      const recentRecords = service.getFailureRecords({ since: past });
      expect(recentRecords.length).toBeGreaterThan(0);

      const futureRecords = service.getFailureRecords({ since: future });
      expect(futureRecords.length).toBe(0);
    });

    it('should limit results', () => {
      const records = service.getFailureRecords({ limit: 2 });
      expect(records.length).toBe(2);
    });

    it('should return most recent first', () => {
      // Add a slightly delayed third record to ensure ordering
      service.recordValidationFailure('req_4', 'POST /products', 'validation_failed', {});

      const records = service.getFailureRecords();
      expect(records[0].correlationId).toBe('req_4');
      expect(records[records.length - 1].correlationId).toBe('req_1');
    });

    it('should apply multiple filters', () => {
      const records = service.getFailureRecords({
        endpoint: 'POST',
        reason: 'validation_failed',
        limit: 1,
      });

      expect(records.length).toBeLessThanOrEqual(1);
    });
  });

  describe('getFailureStatistics', () => {
    beforeEach(() => {
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {});
      service.recordValidationFailure('req_2', 'PUT /users/1', 'validation_failed', {});
      service.recordValidationFailure('req_3', 'POST /orders', 'unknown_fields_rejected', {});
      service.recordValidationFailure('req_3', 'POST /orders', 'unknown_fields_rejected', {}); // Duplicate corr ID
    });

    it('should calculate total failures', () => {
      const stats = service.getFailureStatistics();
      expect(stats.totalFailures).toBe(4);
    });

    it('should aggregate failures by reason', () => {
      const stats = service.getFailureStatistics();
      expect(stats.failuresByReason['validation_failed']).toBe(2);
      expect(stats.failuresByReason['unknown_fields_rejected']).toBe(2);
    });

    it('should aggregate failures by endpoint', () => {
      const stats = service.getFailureStatistics();
      expect(stats.failuresByEndpoint['POST /users']).toBe(1);
      expect(stats.failuresByEndpoint['PUT /users/1']).toBe(1);
      expect(stats.failuresByEndpoint['POST /orders']).toBe(2);
    });

    it('should count unique correlation IDs', () => {
      const stats = service.getFailureStatistics();
      expect(stats.uniqueCorrelationIds).toBe(3); // req_1, req_2, req_3
    });

    it('should respect time filter', () => {
      const future = new Date(Date.now() + 60000);
      const stats = service.getFailureStatistics(future);
      expect(stats.totalFailures).toBe(0);
    });
  });

  describe('getFailureByCorrelationId', () => {
    beforeEach(() => {
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {});
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {}); // Same corr ID
      service.recordValidationFailure('req_2', 'PUT /users/1', 'validation_failed', {});
    });

    it('should return all records with matching correlation ID', () => {
      const records = service.getFailureByCorrelationId('req_1');
      expect(records.length).toBe(2);
      expect(records.every((r) => r.correlationId === 'req_1')).toBe(true);
    });

    it('should return empty array for non-existent correlation ID', () => {
      const records = service.getFailureByCorrelationId('non-existent');
      expect(records).toEqual([]);
    });
  });

  describe('clearFailureLog', () => {
    it('should clear all failure records', () => {
      service.recordValidationFailure('req_1', 'POST /users', 'validation_failed', {});
      service.recordValidationFailure('req_2', 'PUT /users/1', 'validation_failed', {});

      expect(service.getFailureRecords().length).toBe(2);

      service.clearFailureLog();

      expect(service.getFailureRecords().length).toBe(0);
    });
  });

  describe('Memory management', () => {
    it('should enforce maximum record limit', () => {
      // Create a service instance to check max records
      const maxRecords = 10000;

      // Add records beyond the limit
      for (let i = 0; i < maxRecords + 100; i++) {
        service.recordValidationFailure(
          `req_${i}`,
          `POST /endpoint`,
          'validation_failed',
          {},
        );
      }

      // Should not exceed max records
      const records = service.getFailureRecords({ limit: 20000 });
      expect(records.length).toBeLessThanOrEqual(maxRecords);
    });
  });

  describe('Concurrent operations', () => {
    it('should handle concurrent recording and retrieval', async () => {
      const promises = [];

      // Simulate concurrent recording
      for (let i = 0; i < 100; i++) {
        promises.push(
          Promise.resolve(
            service.recordValidationFailure(
              `req_${i}`,
              `POST /endpoint`,
              'validation_failed',
              {},
            ),
          ),
        );
      }

      await Promise.all(promises);

      const records = service.getFailureRecords({ limit: 200 });
      expect(records.length).toBe(100);
    });
  });
});
