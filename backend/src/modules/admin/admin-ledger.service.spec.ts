import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConflictException, BadRequestException } from '@nestjs/common';
import { AdminLedgerService } from './admin-ledger.service';
import {
  AdminCorrectionLedger,
  CorrectionType,
} from './entities/admin-correction-ledger.entity';
import { CreateAdminCorrectionDto } from './dto/create-admin-correction.dto';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ADMIN_ID = 'admin-uuid-001';

function makeDto(
  overrides: Partial<CreateAdminCorrectionDto> = {},
): CreateAdminCorrectionDto {
  return {
    targetId: 'tx-001',
    targetType: 'transaction',
    correctionType: CorrectionType.BALANCE_CREDIT,
    delta: '50.00',
    reason: 'Customer reported missing credit from March 2026.',
    requestId: 'req-abc-001',
    ...overrides,
  };
}

function makeEntry(
  overrides: Partial<AdminCorrectionLedger> = {},
): AdminCorrectionLedger {
  return {
    id: 'entry-uuid-001',
    adminId: ADMIN_ID,
    targetId: 'tx-001',
    targetType: 'transaction',
    correctionType: CorrectionType.BALANCE_CREDIT,
    delta: '50.00',
    previousValue: null,
    newValue: null,
    reason: 'Customer reported missing credit from March 2026.',
    requestId: 'req-abc-001',
    workflowId: null,
    metadata: null,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  } as AdminCorrectionLedger;
}

// ─── Factory to build a mock repository ──────────────────────────────────────

type MockRepo = {
  [K in keyof Repository<AdminCorrectionLedger>]: jest.Mock;
} & {
  createQueryBuilder: jest.Mock;
};

function buildMockRepo(): MockRepo {
  const qb = {
    select: jest.fn().mockReturnThis(),
    addSelect: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    groupBy: jest.fn().mockReturnThis(),
    addGroupBy: jest.fn().mockReturnThis(),
    orderBy: jest.fn().mockReturnThis(),
    addOrderBy: jest.fn().mockReturnThis(),
    getRawMany: jest.fn().mockResolvedValue([]),
  };

  return {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOne: jest.fn(),
    createQueryBuilder: jest.fn().mockReturnValue(qb),
  } as unknown as MockRepo;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('AdminLedgerService', () => {
  let service: AdminLedgerService;
  let repo: MockRepo;

  beforeEach(async () => {
    repo = buildMockRepo();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminLedgerService,
        {
          provide: getRepositoryToken(AdminCorrectionLedger),
          useValue: repo,
        },
      ],
    }).compile();

    service = module.get<AdminLedgerService>(AdminLedgerService);
  });

  afterEach(() => jest.clearAllMocks());

  // ─── appendCorrection ──────────────────────────────────────────────────────

  describe('appendCorrection', () => {
    it('creates and saves a new ledger entry', async () => {
      const dto = makeDto();
      const entry = makeEntry();
      repo.findOne.mockResolvedValue(null); // no duplicate
      repo.create.mockReturnValue(entry);
      repo.save.mockResolvedValue(entry);

      const result = await service.appendCorrection(ADMIN_ID, dto);

      expect(repo.findOne).toHaveBeenCalledWith({
        where: { requestId: dto.requestId },
      });
      expect(repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          adminId: ADMIN_ID,
          targetId: dto.targetId,
          targetType: dto.targetType,
          correctionType: dto.correctionType,
          delta: dto.delta,
          reason: dto.reason,
          requestId: dto.requestId,
        }),
      );
      expect(repo.save).toHaveBeenCalledWith(entry);
      expect(result).toBe(entry);
    });

    it('appends without requestId (no duplicate check performed)', async () => {
      const dto = makeDto({ requestId: undefined });
      const entry = makeEntry({ requestId: null });
      repo.create.mockReturnValue(entry);
      repo.save.mockResolvedValue(entry);

      await service.appendCorrection(ADMIN_ID, dto);

      // findOne should NOT be called when there is no requestId
      expect(repo.findOne).not.toHaveBeenCalled();
    });

    it('throws ConflictException when requestId already exists', async () => {
      const dto = makeDto();
      repo.findOne.mockResolvedValue(makeEntry()); // duplicate found

      await expect(service.appendCorrection(ADMIN_ID, dto)).rejects.toThrow(
        ConflictException,
      );
      expect(repo.save).not.toHaveBeenCalled();
    });

    it('throws BadRequestException for non-numeric delta', async () => {
      const dto = makeDto({ delta: 'not-a-number' });
      repo.findOne.mockResolvedValue(null);

      await expect(service.appendCorrection(ADMIN_ID, dto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws BadRequestException for a zero delta', async () => {
      const dto = makeDto({ delta: '0' });
      repo.findOne.mockResolvedValue(null);

      await expect(service.appendCorrection(ADMIN_ID, dto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('accepts a negative delta (debit correction)', async () => {
      const dto = makeDto({
        delta: '-25.50',
        correctionType: CorrectionType.BALANCE_DEBIT,
      });
      const entry = makeEntry({ delta: '-25.50' });
      repo.findOne.mockResolvedValue(null);
      repo.create.mockReturnValue(entry);
      repo.save.mockResolvedValue(entry);

      const result = await service.appendCorrection(ADMIN_ID, dto);
      expect(result.delta).toBe('-25.50');
    });

    it('does NOT expose any update or delete method', () => {
      // Append-only guarantee: the service must not have mutating helpers
      expect((service as any).updateCorrection).toBeUndefined();
      expect((service as any).deleteCorrection).toBeUndefined();
      expect((service as any).removeCorrection).toBeUndefined();
    });
  });

  // ─── findByTarget ──────────────────────────────────────────────────────────

  describe('findByTarget', () => {
    it('returns all entries for the target ordered ASC', async () => {
      const entries = [
        makeEntry({ id: '1', createdAt: new Date('2026-01-01') }),
        makeEntry({ id: '2', createdAt: new Date('2026-01-02') }),
      ];
      repo.find.mockResolvedValue(entries);

      const result = await service.findByTarget('tx-001');

      expect(repo.find).toHaveBeenCalledWith({
        where: { targetId: 'tx-001' },
        order: { createdAt: 'ASC' },
      });
      expect(result).toHaveLength(2);
    });

    it('returns an empty array when no entries exist', async () => {
      repo.find.mockResolvedValue([]);
      const result = await service.findByTarget('nonexistent');
      expect(result).toEqual([]);
    });
  });

  // ─── findByAdmin ───────────────────────────────────────────────────────────

  describe('findByAdmin', () => {
    it('delegates to repository with adminId filter', async () => {
      repo.find.mockResolvedValue([makeEntry()]);
      const result = await service.findByAdmin(ADMIN_ID);
      expect(repo.find).toHaveBeenCalledWith({
        where: { adminId: ADMIN_ID },
        order: { createdAt: 'DESC' },
      });
      expect(result).toHaveLength(1);
    });
  });

  // ─── findByRequestId ───────────────────────────────────────────────────────

  describe('findByRequestId', () => {
    it('returns the matching entry', async () => {
      const entry = makeEntry();
      repo.findOne.mockResolvedValue(entry);

      const result = await service.findByRequestId('req-abc-001');
      expect(result).toBe(entry);
    });

    it('returns null when not found', async () => {
      repo.findOne.mockResolvedValue(null);
      const result = await service.findByRequestId('nonexistent');
      expect(result).toBeNull();
    });
  });

  // ─── reconcileTarget ───────────────────────────────────────────────────────

  describe('reconcileTarget', () => {
    it('returns a ReconciliationSummary with correct netDelta', async () => {
      const rawRows = [
        {
          correctionType: CorrectionType.BALANCE_CREDIT,
          entryCount: '3',
          totalDelta: '150.00',
          firstCorrectedAt: new Date('2026-01-01'),
          lastCorrectedAt: new Date('2026-01-03'),
        },
        {
          correctionType: CorrectionType.BALANCE_DEBIT,
          entryCount: '1',
          totalDelta: '-50.00',
          firstCorrectedAt: new Date('2026-01-02'),
          lastCorrectedAt: new Date('2026-01-02'),
        },
      ];

      // Stub createQueryBuilder chain
      const qb = repo.createQueryBuilder();
      qb.getRawMany.mockResolvedValue(rawRows);

      const result = await service.reconcileTarget('tx-001');

      expect(result.targetId).toBe('tx-001');
      expect(result.rows).toHaveLength(2);
      expect(result.rows[0].entryCount).toBe(3);
      expect(result.rows[0].totalDelta).toBe('150.00');
      expect(result.rows[1].totalDelta).toBe('-50.00');
      // Net = 150 + (-50) = 100
      expect(parseFloat(result.netDelta)).toBeCloseTo(100.0);
    });

    it('returns a summary with empty rows when no corrections exist', async () => {
      const qb = repo.createQueryBuilder();
      qb.getRawMany.mockResolvedValue([]);

      const result = await service.reconcileTarget('tx-no-corrections');
      expect(result.rows).toHaveLength(0);
      expect(result.netDelta).toBe('0');
    });
  });

  // ─── reconcileMany ─────────────────────────────────────────────────────────

  describe('reconcileMany', () => {
    it('groups results by targetId', async () => {
      const rawRows = [
        {
          targetId: 'tx-001',
          correctionType: CorrectionType.BALANCE_CREDIT,
          entryCount: '2',
          totalDelta: '100.00',
          firstCorrectedAt: new Date('2026-01-01'),
          lastCorrectedAt: new Date('2026-01-02'),
        },
        {
          targetId: 'tx-002',
          correctionType: CorrectionType.FEE_WAIVER,
          entryCount: '1',
          totalDelta: '-5.00',
          firstCorrectedAt: new Date('2026-01-03'),
          lastCorrectedAt: new Date('2026-01-03'),
        },
      ];

      const qb = repo.createQueryBuilder();
      qb.getRawMany.mockResolvedValue(rawRows);

      const result = await service.reconcileMany(['tx-001', 'tx-002']);

      expect(result.size).toBe(2);
      expect(result.get('tx-001')!.rows).toHaveLength(1);
      expect(parseFloat(result.get('tx-001')!.netDelta)).toBeCloseTo(100.0);
      expect(parseFloat(result.get('tx-002')!.netDelta)).toBeCloseTo(-5.0);
    });

    it('applies targetIds filter when provided', async () => {
      const qb = repo.createQueryBuilder();
      qb.getRawMany.mockResolvedValue([]);

      await service.reconcileMany(['tx-A', 'tx-B']);
      // Verify the WHERE clause was called on the query builder
      expect(qb.where).toHaveBeenCalledWith(
        'acl.targetId IN (:...targetIds)',
        { targetIds: ['tx-A', 'tx-B'] },
      );
    });

    it('does NOT apply WHERE clause when targetIds is undefined (all records)', async () => {
      const qb = repo.createQueryBuilder();
      qb.getRawMany.mockResolvedValue([]);

      await service.reconcileMany(undefined);
      expect(qb.where).not.toHaveBeenCalled();
    });
  });
});
