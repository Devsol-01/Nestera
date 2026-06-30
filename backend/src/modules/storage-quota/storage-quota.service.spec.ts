import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { StorageQuotaService } from './storage-quota.service';
import { StorageQuota } from './entities/storage-quota.entity';
import {
  QuotaLedgerStatus,
  QuotaUploadKind,
  StorageQuotaLedger,
} from './entities/storage-quota-ledger.entity';
import {
  StorageQuotaConfig,
  StorageQuotaExceededException,
} from './storage-quota.types';

/**
 * Minimal in-memory fake of a TypeORM repository. Keeps behaviour focused:
 * the SQL `UPDATE ... WHERE` rules we actually care about are exercised by
 * the atomic `manager.query` shim below.
 */
class FakeRepo<T> {
  private rows: T[] = [];
  public updateCalls: Array<{ criteria: any; partial: any }> = [];

  create(input: Partial<T>): T {
    return { ...input } as T;
  }
  async save(row: T): Promise<T> {
    const idx = this.rows.findIndex((r: any) => r.id === (row as any).id);
    if (idx >= 0) this.rows[idx] = { ...this.rows[idx], ...row };
    else this.rows.push(row);
    return row;
  }
  async findOne(opts: any): Promise<T | null> {
    return (
      this.rows.find((r: any) => {
        for (const k of Object.keys(opts.where ?? {})) {
          if (r[k] !== opts.where[k]) return false;
        }
        return true;
      }) ?? null
    );
  }
  async find(opts: any): Promise<T[]> {
    return this.rows.filter((r: any) => {
      for (const k of Object.keys(opts.where ?? {})) {
        if (r[k] !== opts.where[k]) return false;
      }
      return true;
    });
  }
  // SQL shim used by atomic updates; the test below exercises the
  // resulting `usedBytes` / `reservedBytes` mutations.
  applySql(
    userId: string,
    tenantId: string,
    reservedDelta: number,
    usedDelta: number,
  ): boolean {
    const row = this.rows.find(
      (r: any) => r.userId === userId && r.tenantId === tenantId,
    ) as any;
    if (!row) return false;
    const nextReserved = Math.max(
      Number(row.reservedBytes ?? 0) + reservedDelta,
      0,
    );
    const nextUsed = Math.max(Number(row.usedBytes ?? 0) + usedDelta, 0);
    if (nextReserved > Number(row.maxTotalBytes ?? 0)) return false;
    if (nextReserved + nextUsed > Number(row.maxTotalBytes ?? 0)) return false;
    row.reservedBytes = nextReserved;
    row.usedBytes = nextUsed;
    if (reservedDelta > 0) row.activeUploads = (row.activeUploads ?? 0) + 1;
    else if (reservedDelta < 0)
      row.activeUploads = Math.max((row.activeUploads ?? 0) - 1, 0);
    return true;
  }
  async insert(row: any): Promise<void> {
    if (!this.rows.find((r: any) => r.id === row.id)) {
      this.rows.push(row);
    }
  }
}

describe('StorageQuotaService', () => {
  let service: StorageQuotaService;
  let quotaRepo: FakeRepo<StorageQuota>;
  let ledgerRepo: any;
  let dataSource: any;

  beforeEach(async () => {
    quotaRepo = new FakeRepo<StorageQuota>();
    ledgerRepo = new FakeRepo<StorageQuotaLedger>();
    ledgerRepo.createQueryBuilder = () => ({
      setLock: () => ({
        where: () => ({
          getOne: async () => ledgerRepo.rows[0] ?? null,
        }),
      }),
    });
    dataSource = {
      transaction: async (cb: (mgr: any) => Promise<any>) => {
        const mgr = {
          getRepository: () => quotaRepo,
          query: async (_sql: string, params: any[]) => {
            // Dispatch the atomic UPDATE semantics we care about.
            const reserved = Number(params[1] ?? 0);
            const userId = params[3];
            const tenantId = params[4];
            const usedDelta =
              reserved < 0 ? 0 : Number(params[2] ?? 0) - reserved;
            const ok = quotaRepo.applySql(
              userId,
              tenantId,
              reserved,
              usedDelta,
            );
            if (ok) return [{ id: 'quota-row' }];
            return [];
          },
        };
        return cb(mgr);
      },
      query: async (sql: string, params: any[]) => {
        if (sql.includes('INSERT INTO storage_quotas')) {
          const [
            userId,
            tenantId,
            maxTotalBytes,
            maxActiveUploads,
            maxUploadsPerHour,
            tier,
          ] = params;
          quotaRepo.insert({
            id: `quota-${userId}-${tenantId}`,
            userId,
            tenantId,
            maxTotalBytes,
            maxActiveUploads,
            maxUploadsPerHour,
            tier,
            usedBytes: 0,
            reservedBytes: 0,
            activeUploads: 0,
            uploadsThisHour: 0,
          });
        }
        return [];
      },
    };

    const module = await Test.createTestingModule({
      providers: [
        StorageQuotaService,
        {
          provide: getRepositoryToken(StorageQuota),
          useValue: quotaRepo,
        },
        {
          provide: getRepositoryToken(StorageQuotaLedger),
          useValue: ledgerRepo,
        },
        { provide: DataSource, useValue: dataSource },
        StorageQuotaConfig,
      ],
    }).compile();

    service = module.get(StorageQuotaService);
  });

  // ── reserve ────────────────────────────────────────────────────────────

  it('rejects reservation size <= 0', async () => {
    await expect(
      service.reserve('user-1', 0, { uploadKind: QuotaUploadKind.AVATAR }),
    ).rejects.toBeInstanceOf(StorageQuotaExceededException);
  });

  it('lazily provisions a quota row on first reservation', async () => {
    // No row exists yet; reserve() should provision one via the
    // INSERT … ON CONFLICT path before incrementing.
    const res = await service.reserve('user-X', 1024, {
      uploadKind: QuotaUploadKind.AVATAR,
    });
    expect(res.reservationId).toBeDefined();
    expect(res.reservedBytes).toBe(1024);
    expect((quotaRepo as any).rows.length).toBe(1);
  });

  it('returns a reservation that can be committed', async () => {
    const res = await service.reserve('user-1', 2048, {
      uploadKind: QuotaUploadKind.AVATAR,
    });
    await service.commit(res.reservationId, { finalBytes: 2048 });

    const row = (await quotaRepo.findOne({
      where: { userId: 'user-1', tenantId: '' },
    })) as any;
    expect(Number(row.usedBytes)).toBe(2048);
    expect(Number(row.reservedBytes)).toBe(0);
  });

  it('rejects commit on unknown reservation id (idempotent no-op)', async () => {
    await expect(
      service.commit('does-not-exist', { finalBytes: 10 }),
    ).resolves.toBeUndefined();
  });

  it('returns a reservation that can be released (refunds bytes + slot)', async () => {
    const res = await service.reserve('user-1', 4096, {
      uploadKind: QuotaUploadKind.AVATAR,
    });
    await service.release(res.reservationId, { reason: 'test-cancel' });

    const row = (await quotaRepo.findOne({
      where: { userId: 'user-1', tenantId: '' },
    })) as any;
    expect(Number(row.reservedBytes)).toBe(0);
    expect(Number(row.usedBytes)).toBe(0);
    expect(row.activeUploads).toBe(0);
  });

  it('allows commit to use a different finalBytes than the reservation', async () => {
    const res = await service.reserve('user-1', 10_000, {
      uploadKind: QuotaUploadKind.AVATAR,
    });
    // Processed avatar ends up smaller (typical: thumb < raw)
    await service.commit(res.reservationId, { finalBytes: 1500 });

    const row = (await quotaRepo.findOne({
      where: { userId: 'user-1', tenantId: '' },
    })) as any;
    expect(Number(row.usedBytes)).toBe(1500);
  });

  // ── reconcile via releaseByUpload ───────────────────────────────────────

  it('releaseByUpload refunds committed bytes for a known upload', async () => {
    const res = await service.reserve('user-1', 5000, {
      uploadKind: QuotaUploadKind.DISPUTE_EVIDENCE,
    });
    await service.commit(res.reservationId, { finalBytes: 5000 });
    // The ledger row would have `uploadId` set in production — for the
    // test we patch it manually since storage flows aren't in scope.
    ledgerRepo.rows[0].uploadId = 'evidence-1';
    const released = await service.releaseByUpload(
      QuotaUploadKind.DISPUTE_EVIDENCE,
      'evidence-1',
      'evidence-deleted',
    );
    expect(released).toBe(true);

    const row = (await quotaRepo.findOne({
      where: { userId: 'user-1', tenantId: '' },
    })) as any;
    expect(Number(row.usedBytes)).toBe(0);
  });

  // ── idempotency under double release ────────────────────────────────────

  it('release on an already-released reservation is a no-op', async () => {
    const res = await service.reserve('user-1', 1024, {
      uploadKind: QuotaUploadKind.AVATAR,
    });
    await service.release(res.reservationId, { reason: 'first' });
    await service.release(res.reservationId, { reason: 'second' });
    const row = (await quotaRepo.findOne({
      where: { userId: 'user-1', tenantId: '' },
    })) as any;
    expect(Number(row.reservedBytes)).toBe(0);
    expect(row.activeUploads).toBe(0);
  });
});
