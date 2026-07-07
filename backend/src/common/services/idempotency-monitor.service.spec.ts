import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  IdempotencyMonitorService,
  IdempotencyConflictEvent,
} from './idempotency-monitor.service';

describe('IdempotencyMonitorService', () => {
  let service: IdempotencyMonitorService;

  const makeConflict = (
    overrides?: Partial<IdempotencyConflictEvent>,
  ): IdempotencyConflictEvent => ({
    idempotencyKey: 'key-1',
    requestFingerprintHash: 'hash-abc',
    method: 'POST',
    path: '/savings/deposit',
    conflictType: 'payload_mismatch',
    timestamp: new Date().toISOString(),
    relatedEntityType: 'savings',
    ...overrides,
  });

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IdempotencyMonitorService,
        {
          provide: EventEmitter2,
          useValue: { emit: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<IdempotencyMonitorService>(IdempotencyMonitorService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // handleConflict / getRecentConflicts
  // ──────────────────────────────────────────────────────────────────────────

  describe('handleConflict', () => {
    it('stores a conflict and returns it', () => {
      service.handleConflict(makeConflict());
      const conflicts = service.getRecentConflicts();
      expect(conflicts).toHaveLength(1);
      expect(conflicts[0].idempotencyKey).toBe('key-1');
    });

    it('returns conflicts newest first', () => {
      service.handleConflict(makeConflict({ idempotencyKey: 'first' }));
      service.handleConflict(makeConflict({ idempotencyKey: 'second' }));

      const conflicts = service.getRecentConflicts(10);
      expect(conflicts[0].idempotencyKey).toBe('second');
      expect(conflicts[1].idempotencyKey).toBe('first');
    });

    it('caps at MAX_CONFLICTS (1000) using circular buffer', () => {
      for (let i = 0; i < 1050; i++) {
        service.handleConflict(makeConflict({ idempotencyKey: `key-${i}` }));
      }
      // Buffer should not exceed 1000
      const all = service.getRecentConflicts(2000);
      expect(all.length).toBeLessThanOrEqual(1000);
    });

    it('evicts the oldest entry when the buffer is full', () => {
      // Fill to capacity
      for (let i = 0; i < 1000; i++) {
        service.handleConflict(
          makeConflict({ idempotencyKey: `old-key-${i}` }),
        );
      }
      // Add one more
      service.handleConflict(makeConflict({ idempotencyKey: 'newest' }));

      const all = service.getRecentConflicts(2000);
      // Newest should be present
      expect(all.some((c) => c.idempotencyKey === 'newest')).toBe(true);
      // The very first entry should have been evicted
      expect(all.some((c) => c.idempotencyKey === 'old-key-0')).toBe(false);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // getRecentConflicts – filtering
  // ──────────────────────────────────────────────────────────────────────────

  describe('getRecentConflicts filtering', () => {
    beforeEach(() => {
      service.handleConflict(
        makeConflict({
          conflictType: 'payload_mismatch',
          path: '/savings/deposit',
        }),
      );
      service.handleConflict(
        makeConflict({
          conflictType: 'concurrent_processing',
          path: '/transactions/send',
        }),
      );
      service.handleConflict(
        makeConflict({
          conflictType: 'payload_mismatch',
          path: '/transactions/refund',
        }),
      );
    });

    it('filters by conflictType', () => {
      const mismatches = service.getRecentConflicts(10, 'payload_mismatch');
      expect(mismatches).toHaveLength(2);
      expect(
        mismatches.every((c) => c.conflictType === 'payload_mismatch'),
      ).toBe(true);
    });

    it('filters by path (partial match)', () => {
      const tx = service.getRecentConflicts(10, undefined, '/transactions');
      expect(tx).toHaveLength(2);
    });

    it('applies both conflictType and path filters', () => {
      const result = service.getRecentConflicts(
        10,
        'payload_mismatch',
        '/transactions',
      );
      expect(result).toHaveLength(1);
      expect(result[0].path).toBe('/transactions/refund');
    });

    it('respects the limit parameter', () => {
      const result = service.getRecentConflicts(1);
      expect(result).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // getConflictSummary
  // ──────────────────────────────────────────────────────────────────────────

  describe('getConflictSummary', () => {
    it('returns zero counts when there are no conflicts', () => {
      const summary = service.getConflictSummary();
      expect(summary.total).toBe(0);
      expect(summary.last24h).toBe(0);
      expect(summary.last1h).toBe(0);
      expect(summary.topConflictingKeys).toHaveLength(0);
    });

    it('counts conflicts by type', () => {
      service.handleConflict(
        makeConflict({ conflictType: 'payload_mismatch' }),
      );
      service.handleConflict(
        makeConflict({ conflictType: 'payload_mismatch' }),
      );
      service.handleConflict(
        makeConflict({ conflictType: 'concurrent_processing' }),
      );

      const summary = service.getConflictSummary();
      expect(summary.byConflictType['payload_mismatch']).toBe(2);
      expect(summary.byConflictType['concurrent_processing']).toBe(1);
    });

    it('counts conflicts by route', () => {
      service.handleConflict(
        makeConflict({ method: 'POST', path: '/savings/deposit' }),
      );
      service.handleConflict(
        makeConflict({ method: 'POST', path: '/savings/deposit' }),
      );
      service.handleConflict(
        makeConflict({ method: 'POST', path: '/transactions/send' }),
      );

      const summary = service.getConflictSummary();
      expect(summary.byRoute['POST /savings/deposit']).toBe(2);
      expect(summary.byRoute['POST /transactions/send']).toBe(1);
    });

    it('identifies top conflicting keys', () => {
      for (let i = 0; i < 5; i++) {
        service.handleConflict(makeConflict({ idempotencyKey: 'top-key' }));
      }
      service.handleConflict(makeConflict({ idempotencyKey: 'one-time' }));

      const summary = service.getConflictSummary();
      expect(summary.topConflictingKeys[0].idempotencyKey).toBe('top-key');
      expect(summary.topConflictingKeys[0].count).toBe(5);
    });

    it('includes total regardless of timestamp', () => {
      service.handleConflict(makeConflict());
      service.handleConflict(makeConflict());
      const summary = service.getConflictSummary();
      expect(summary.total).toBe(2);
    });

    it('has correct shape', () => {
      const summary = service.getConflictSummary();
      expect(summary).toHaveProperty('total');
      expect(summary).toHaveProperty('last24h');
      expect(summary).toHaveProperty('last1h');
      expect(summary).toHaveProperty('byConflictType');
      expect(summary).toHaveProperty('byRoute');
      expect(summary).toHaveProperty('topConflictingKeys');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // handleReplay / handleFirstUse / getKeyUsage
  // ──────────────────────────────────────────────────────────────────────────

  describe('handleFirstUse and handleReplay', () => {
    it('records first use', () => {
      service.handleFirstUse({ key: 'k1', method: 'POST', path: '/savings' });
      const usage = service.getKeyUsage();
      expect(usage).toHaveLength(1);
      expect(usage[0].idempotencyKey).toBe('k1');
      expect(usage[0].replayCount).toBe(0);
    });

    it('increments replay count on subsequent calls', () => {
      service.handleFirstUse({ key: 'k2', method: 'POST', path: '/savings' });
      service.handleReplay({ key: 'k2', method: 'POST', path: '/savings' });
      service.handleReplay({ key: 'k2', method: 'POST', path: '/savings' });

      const usage = service.getKeyUsage();
      const record = usage.find((r) => r.idempotencyKey === 'k2')!;
      expect(record.replayCount).toBe(2);
    });

    it('creates a new usage record when handleReplay is called for an unknown key', () => {
      service.handleReplay({ key: 'k3', method: 'GET', path: '/transactions' });
      const usage = service.getKeyUsage();
      const record = usage.find((r) => r.idempotencyKey === 'k3');
      expect(record).toBeDefined();
      expect(record!.replayCount).toBe(1);
    });

    it('ignores duplicate handleFirstUse calls for the same key', () => {
      service.handleFirstUse({ key: 'k4', method: 'POST', path: '/savings' });
      service.handleFirstUse({ key: 'k4', method: 'POST', path: '/savings' });
      const usage = service.getKeyUsage();
      expect(usage.filter((r) => r.idempotencyKey === 'k4')).toHaveLength(1);
    });

    it('sorts results by lastSeenAt descending (most recently replayed first)', () => {
      // 'older-sort' is registered and never replayed
      service.handleFirstUse({ key: 'older-sort', method: 'POST', path: '/a' });
      // 'newer-sort' is registered and then replayed — its lastSeenAt is updated
      service.handleFirstUse({ key: 'newer-sort', method: 'POST', path: '/b' });
      service.handleReplay({ key: 'newer-sort', method: 'POST', path: '/b' });

      const usage = service.getKeyUsage();
      // Both entries must be present
      const newerRecord = usage.find((r) => r.idempotencyKey === 'newer-sort');
      const olderRecord = usage.find((r) => r.idempotencyKey === 'older-sort');
      expect(newerRecord).toBeDefined();
      expect(olderRecord).toBeDefined();

      // 'newer-sort' must have a later or equal lastSeenAt compared to 'older-sort'
      expect(
        new Date(newerRecord!.lastSeenAt).getTime(),
      ).toBeGreaterThanOrEqual(new Date(olderRecord!.lastSeenAt).getTime());

      // 'newer-sort' should have replayCount > 0, confirming it was updated last
      expect(newerRecord!.replayCount).toBeGreaterThan(0);
    });
  });

  describe('getKeyUsage filtering', () => {
    beforeEach(() => {
      service.handleFirstUse({
        key: 'k1',
        method: 'POST',
        path: '/savings/deposit',
      });
      service.handleFirstUse({
        key: 'k2',
        method: 'POST',
        path: '/transactions/send',
      });
    });

    it('filters by path (partial match)', () => {
      const savings = service.getKeyUsage(10, '/savings');
      expect(savings).toHaveLength(1);
      expect(savings[0].idempotencyKey).toBe('k1');
    });

    it('returns all records when no path filter is given', () => {
      expect(service.getKeyUsage(10)).toHaveLength(2);
    });

    it('respects the limit parameter', () => {
      expect(service.getKeyUsage(1)).toHaveLength(1);
    });
  });
});
