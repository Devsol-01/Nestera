import { Test, TestingModule } from '@nestjs/testing';
import { AdminIdempotencyController } from './admin-idempotency.controller';
import { IdempotencyMonitorService } from '../../common/services/idempotency-monitor.service';
import {
  IdempotencyConflictQueryDto,
  IdempotencyUsageQueryDto,
} from './dto/admin-idempotency.dto';

describe('AdminIdempotencyController', () => {
  let controller: AdminIdempotencyController;
  let monitorService: jest.Mocked<IdempotencyMonitorService>;

  const mockSummary = {
    total: 10,
    last24h: 5,
    last1h: 1,
    byConflictType: { payload_mismatch: 4, concurrent_processing: 1 },
    byRoute: { 'POST /savings/deposit': 3 },
    topConflictingKeys: [{ idempotencyKey: 'top-key', count: 3 }],
  };

  const mockConflicts = [
    {
      idempotencyKey: 'key-1',
      requestFingerprintHash: 'sha256abc',
      method: 'POST',
      path: '/savings/deposit',
      conflictType: 'payload_mismatch' as const,
      timestamp: '2026-06-30T02:00:00.000Z',
      relatedEntityType: 'savings',
    },
  ];

  const mockUsage = [
    {
      idempotencyKey: 'key-1',
      method: 'POST',
      path: '/savings/deposit',
      firstSeenAt: '2026-06-30T01:55:00.000Z',
      lastSeenAt: '2026-06-30T02:00:00.000Z',
      replayCount: 2,
    },
  ];

  beforeEach(async () => {
    monitorService = {
      getConflictSummary: jest.fn().mockReturnValue(mockSummary),
      getRecentConflicts: jest.fn().mockReturnValue(mockConflicts),
      getKeyUsage: jest.fn().mockReturnValue(mockUsage),
      handleConflict: jest.fn(),
      handleReplay: jest.fn(),
      handleFirstUse: jest.fn(),
    } as unknown as jest.Mocked<IdempotencyMonitorService>;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminIdempotencyController],
      providers: [
        {
          provide: IdempotencyMonitorService,
          useValue: monitorService,
        },
      ],
    }).compile();

    controller = module.get<AdminIdempotencyController>(
      AdminIdempotencyController,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /admin/idempotency/conflicts/summary
  // ──────────────────────────────────────────────────────────────────────────

  describe('getConflictSummary', () => {
    it('calls getConflictSummary on the monitor service', () => {
      const result = controller.getConflictSummary();
      expect(monitorService.getConflictSummary).toHaveBeenCalledTimes(1);
      expect(result).toEqual(mockSummary);
    });

    it('returns an object with the expected shape', () => {
      const result = controller.getConflictSummary();
      expect(result).toHaveProperty('total');
      expect(result).toHaveProperty('last24h');
      expect(result).toHaveProperty('last1h');
      expect(result).toHaveProperty('byConflictType');
      expect(result).toHaveProperty('byRoute');
      expect(result).toHaveProperty('topConflictingKeys');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /admin/idempotency/conflicts
  // ──────────────────────────────────────────────────────────────────────────

  describe('getRecentConflicts', () => {
    it('calls getRecentConflicts with defaults when no query params are given', () => {
      const query: IdempotencyConflictQueryDto = {};
      controller.getRecentConflicts(query);
      expect(monitorService.getRecentConflicts).toHaveBeenCalledWith(
        50,
        undefined,
        undefined,
      );
    });

    it('passes limit, conflictType and path from the query DTO', () => {
      const query: IdempotencyConflictQueryDto = {
        limit: 10,
        conflictType: 'payload_mismatch',
        path: '/savings',
      };
      controller.getRecentConflicts(query);
      expect(monitorService.getRecentConflicts).toHaveBeenCalledWith(
        10,
        'payload_mismatch',
        '/savings',
      );
    });

    it('returns the data from the monitor service', () => {
      const result = controller.getRecentConflicts({});
      expect(result).toEqual(mockConflicts);
    });

    it('does not expose sensitive payload data in the response', () => {
      const result = controller.getRecentConflicts({});
      for (const item of result) {
        // Only fingerprint hash must be present, not any raw body field
        expect(item).toHaveProperty('requestFingerprintHash');
        expect(item).not.toHaveProperty('body');
        expect(item).not.toHaveProperty('payload');
      }
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /admin/idempotency/usage
  // ──────────────────────────────────────────────────────────────────────────

  describe('getKeyUsage', () => {
    it('calls getKeyUsage with defaults when no query params are given', () => {
      const query: IdempotencyUsageQueryDto = {};
      controller.getKeyUsage(query);
      expect(monitorService.getKeyUsage).toHaveBeenCalledWith(50, undefined);
    });

    it('passes limit and path from the query DTO', () => {
      const query: IdempotencyUsageQueryDto = {
        limit: 20,
        path: '/transactions',
      };
      controller.getKeyUsage(query);
      expect(monitorService.getKeyUsage).toHaveBeenCalledWith(
        20,
        '/transactions',
      );
    });

    it('returns the data from the monitor service', () => {
      const result = controller.getKeyUsage({});
      expect(result).toEqual(mockUsage);
    });

    it('includes replay count in the response', () => {
      const result = controller.getKeyUsage({});
      expect(result[0]).toHaveProperty('replayCount');
      expect(result[0].replayCount).toBe(2);
    });

    it('includes related entity type (route) in the response', () => {
      const result = controller.getKeyUsage({});
      for (const item of result) {
        expect(item).toHaveProperty('path');
      }
    });
  });
});
