import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { randomUUID } from 'crypto';

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
 * Numeric tier value used to fetch defaults. Kept open-ended as a string so
 * new tiers can be added without enum churn in entities.
 */
export type StorageQuotaTier = string;

/**
 * Slim context returned by {@link StorageQuotaService.reserve}. Caller
 * supplies the token to commit/release after the storage write completes.
 */
export interface QuotaReservation {
  reservationId: string;
  userId: string;
  tenantId: string;
  reservedBytes: number;
}

export interface ReserveOptions {
  uploadKind: QuotaUploadKind;
  uploadId?: string;
  reason?: string;
  /** Override tier for this reservation (defaults to resolve from user). */
  tier?: StorageQuotaTier;
}

export interface CommitOptions {
  /** Actual bytes used after processing. May differ from reserved size. */
  finalBytes: number;
  reason?: string;
}

export interface ReleaseOptions {
  reason: string;
}

export interface QuotaSnapshot {
  userId: string;
  tenantId: string;
  tier: string;
  usedBytes: number;
  reservedBytes: number;
  maxTotalBytes: number;
  activeUploads: number;
  maxActiveUploads: number;
  uploadsThisHour: number;
  maxUploadsPerHour: number;
}

@Injectable()
export class StorageQuotaService {
  private readonly logger = new Logger(StorageQuotaService.name);

  constructor(
    @InjectRepository(StorageQuota)
    private readonly quotaRepo: Repository<StorageQuota>,
    @InjectRepository(StorageQuotaLedger)
    private readonly ledgerRepo: Repository<StorageQuotaLedger>,
    private readonly dataSource: DataSource,
    private readonly quotaConfig: StorageQuotaConfig,
    @Optional() private readonly configService?: ConfigService,
  ) {}

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Atomically reserves storage space + active upload slot + frequency unit
   * for a user. Returns a reservation token that the caller must either
   * `commit()` (when the bytes are durably stored) or `release()` (when the
   * write fails or is abandoned).
   *
   * The whole operation runs in a single SQL transaction so the quota row
   * and the ledger row are written together — either both succeed or neither
   * has any visible effect.
   */
  async reserve(
    userId: string,
    size: number,
    options: ReserveOptions,
  ): Promise<QuotaReservation> {
    if (size <= 0) {
      throw new StorageQuotaExceededException(
        'storage',
        'Reservation size must be positive',
        { size },
      );
    }

    const tenantId = '';
    const tier = options.tier ?? this.resolveUserTier(userId);
    const defaults = this.quotaConfig.resolveTierDefaults(tier);
    const reservationId = randomUUID();
    const expiresAt = new Date(
      Date.now() + this.quotaConfig.reservationTtlHours * 60 * 60 * 1000,
    );

    return this.dataSource.transaction(async (manager) => {
      const quotaRepo = manager.getRepository(StorageQuota);
      const ledgerRepo = manager.getRepository(StorageQuotaLedger);

      // 1. Lazy-create the quota row inside the same transaction so brand-new
      // users always have a row before the atomic UPDATE runs. ON CONFLICT
      // DO NOTHING keeps it cheap for users who already have one.
      const defaults = this.quotaConfig.resolveTierDefaults(tier);
      await manager.query(
        `
        INSERT INTO storage_quotas
          ("userId", "tenantId", "maxTotalBytes", "maxActiveUploads",
           "maxUploadsPerHour", "tier")
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT ON CONSTRAINT uq_storage_quotas_user_tenant DO NOTHING
        `,
        [
          userId,
          tenantId,
          defaults.maxTotalBytes,
          defaults.maxActiveUploads,
          defaults.maxUploadsPerHour,
          tier,
        ],
      );

      // 2. Atomic UPDATE returning the row. The WHERE clause is the entire
      // quota check; if any rule fails, zero rows are returned and we
      // throw a typed error with diagnostics.
      const updateResult = await manager.query(
        `
        UPDATE storage_quotas AS q
        SET
          "reservedBytes" = q."reservedBytes" + $2,
          "activeUploads" = CASE
            WHEN q."uploadWindowStartedAt" IS NULL
                 OR q."uploadWindowStartedAt" < (now() - INTERVAL '1 hour')
            THEN 1
            ELSE q."activeUploads" + 1
          END,
          "uploadsThisHour" = CASE
            WHEN q."uploadWindowStartedAt" IS NULL
                 OR q."uploadWindowStartedAt" < (now() - INTERVAL '1 hour')
            THEN 1
            ELSE q."uploadsThisHour" + 1
          END,
          "uploadWindowStartedAt" = CASE
            WHEN q."uploadWindowStartedAt" IS NULL
                 OR q."uploadWindowStartedAt" < (now() - INTERVAL '1 hour')
            THEN now()
            ELSE q."uploadWindowStartedAt"
          END
        WHERE q."userId" = $1
          AND q."tenantId" = $3
          AND (q."usedBytes" + q."reservedBytes" + $2) <= q."maxTotalBytes"
          AND (CASE
                 WHEN q."uploadWindowStartedAt" IS NULL
                      OR q."uploadWindowStartedAt" < (now() - INTERVAL '1 hour')
                 THEN 1
                 ELSE q."activeUploads" + 1
               END) <= q."maxActiveUploads"
          AND (CASE
                 WHEN q."uploadWindowStartedAt" IS NULL
                      OR q."uploadWindowStartedAt" < (now() - INTERVAL '1 hour')
                 THEN 1
                 ELSE q."uploadsThisHour" + 1
               END) <= q."maxUploadsPerHour"
        RETURNING q."id", q."tier"
      `,
        [userId, size, tenantId],
      );

      if (!updateResult || updateResult.length === 0) {
        await this.throwWithDiagnostics(
          quotaRepo,
          userId,
          tenantId,
          size,
          tier,
        );
      }

      // 2. Append ledger entry — PENDING row that references the
      // reservation. The atomic UPDATE above already reserved the space.
      const ledger = ledgerRepo.create({
        reservationId,
        userId,
        tenantId,
        uploadKind: options.uploadKind,
        uploadId: options.uploadId ?? null,
        byteDelta: size,
        status: QuotaLedgerStatus.PENDING,
        expiresAt,
        reason: options.reason ?? null,
        finalBytes: null,
      });
      await ledgerRepo.save(ledger);

      this.logger.debug(
        `[quota] reserved ${size}B user=${userId} reservationId=${reservationId} kind=${options.uploadKind}`,
      );

      return {
        reservationId,
        userId,
        tenantId,
        reservedBytes: size,
      };
    });
  }

  /**
   * Convert a pending reservation into a permanent charge. Called once the
   * storage backend and DB row for the upload are durably persisted.
   *
   * Pass `finalBytes` (commit options) to adjust the actually-stored size,
   * which may differ from the original reservation (e.g. avatar processing
   * swaps the raw upload for smaller processed images).
   */
  async commit(reservationId: string, options: CommitOptions): Promise<void> {
    const finalBytes = Math.max(0, Math.floor(options.finalBytes));
    await this.dataSource.transaction(async (manager) => {
      const ledgerRepo = manager.getRepository(StorageQuotaLedger);
      const ledger = await manager
        .createQueryBuilder(StorageQuotaLedger, 'l')
        .setLock('pessimistic_write')
        .where('l.reservationId = :rid', { rid: reservationId })
        .getOne();

      if (!ledger) {
        this.logger.warn(
          `[quota] commit on unknown reservationId=${reservationId}`,
        );
        return;
      }

      if (ledger.status !== QuotaLedgerStatus.PENDING) {
        this.logger.warn(
          `[quota] commit on non-pending reservationId=${reservationId} status=${ledger.status}; idempotent no-op`,
        );
        return;
      }

      const reservedBytes = Number(ledger.byteDelta);
      const tenantId = ledger.tenantId;
      const userId = ledger.userId;

      // Move reservedBytes -> usedBytes (atomic). Note we keep
      // ledger.byteDelta at the original reservation amount so the audit
      // trail remains reconstructable from the signed deltas alone
      // (Σ byteDelta where status=committed.equals Σ finalBytes).
      await manager.query(
        `
        UPDATE storage_quotas AS q
        SET
          "reservedBytes" = GREATEST(q."reservedBytes" - $2, 0),
          "usedBytes" = q."usedBytes" + $3,
          "activeUploads" = GREATEST(q."activeUploads" - 1, 0)
        WHERE q."userId" = $4
          AND q."tenantId" = $5
      `,
        [reservedBytes, finalBytes, userId, tenantId],
      );

      ledger.status = QuotaLedgerStatus.COMMITTED;
      ledger.finalBytes = finalBytes;
      // Do NOT overwrite byteDelta — it must remain the original +reservedBytes
      // so Σ byteDelta over committed entries reconstructs original usage.
      ledger.reason = options.reason ?? ledger.reason;
      await ledgerRepo.save(ledger);

      this.logger.debug(
        `[quota] committed reservationId=${reservationId} reservedB=${reservedBytes} finalB=${finalBytes}`,
      );
    });
  }

  /**
   * Refund a pending reservation. Called when:
   *   - the storage write failed before durably persisting
   *   - the upload was abandoned / the user navigated away
   *   - cleanup sweep expired an orphan reservation
   *
   * Has no effect on rows already in COMMITTED / RELEASED / EXPIRED state.
   */
  async release(reservationId: string, options: ReleaseOptions): Promise<void> {
    await this.dataSource.transaction(async (manager) => {
      const ledgerRepo = manager.getRepository(StorageQuotaLedger);
      const ledger = await manager
        .createQueryBuilder(StorageQuotaLedger, 'l')
        .setLock('pessimistic_write')
        .where('l.reservationId = :rid', { rid: reservationId })
        .getOne();

      if (!ledger) {
        return;
      }

      if (ledger.status !== QuotaLedgerStatus.PENDING) {
        this.logger.debug(
          `[quota] release on non-pending reservationId=${reservationId} status=${ledger.status}`,
        );
        return;
      }

      const tenantId = ledger.tenantId;
      const userId = ledger.userId;
      const reservedBytes = Number(ledger.byteDelta);

      await manager.query(
        `
        UPDATE storage_quotas AS q
        SET
          "reservedBytes" = GREATEST(q."reservedBytes" - $2, 0),
          "activeUploads" = GREATEST(q."activeUploads" - 1, 0)
        WHERE q."userId" = $3
          AND q."tenantId" = $4
      `,
        [reservedBytes, userId, tenantId],
      );

      ledger.status = QuotaLedgerStatus.RELEASED;
      ledger.byteDelta = -reservedBytes;
      ledger.reason = options.reason;
      await ledgerRepo.save(ledger);

      this.logger.debug(
        `[quota] released reservationId=${reservationId} bytes=${reservedBytes} reason=${options.reason}`,
      );
    });
  }

  /**
   * Refund a previously committed upload (used by deletion or cleanup).
   * Reduces `usedBytes` by the actual stored size of `uploadId`.
   *
   * Returns true if any quota was released, false if nothing matched.
   */
  async releaseByUpload(
    uploadKind: QuotaUploadKind,
    uploadId: string,
    reason: string,
  ): Promise<boolean> {
    return this.dataSource.transaction(async (manager) => {
      const ledgerRepo = manager.getRepository(StorageQuotaLedger);
      const matches = await ledgerRepo.find({
        where: {
          uploadKind,
          uploadId,
          status: QuotaLedgerStatus.COMMITTED,
        },
      });

      if (matches.length === 0) {
        return false;
      }

      let totalReleased = 0;
      for (const entry of matches) {
        const bytes = Number(entry.finalBytes ?? entry.byteDelta);
        if (bytes <= 0) continue;
        totalReleased += bytes;

        await manager.query(
          `
          UPDATE storage_quotas AS q
          SET "usedBytes" = GREATEST(q."usedBytes" - $2, 0)
          WHERE q."userId" = $3 AND q."tenantId" = $4
          `,
          [bytes, entry.userId, entry.tenantId],
        );

        entry.status = QuotaLedgerStatus.RELEASED;
        entry.byteDelta = -bytes;
        entry.reason = reason;
        await ledgerRepo.save(entry);
      }

      this.logger.debug(
        `[quota] released by upload kind=${uploadKind} uploadId=${uploadId} bytes=${totalReleased} reason=${reason}`,
      );
      return true;
    });
  }

  /**
   * Sweep reservations that never reached a terminal state within TTL.
   * Called by {@link StorageQuotaCleanupService} on a schedule.
   *
   * Safe to run concurrently with uploads — pending rows are picked up with
   * a pessimistic write lock and transitioned to `EXPIRED` in the same txn.
   */
  async sweepExpiredReservations(now: Date = new Date()): Promise<number> {
    return this.dataSource.transaction(async (manager) => {
      const ledgerRepo = manager.getRepository(StorageQuotaLedger);

      const expired = await manager
        .createQueryBuilder(StorageQuotaLedger, 'l')
        .setLock('pessimistic_write')
        .where('l.status = :status', { status: QuotaLedgerStatus.PENDING })
        .andWhere('l.expiresAt IS NOT NULL AND l.expiresAt < :now', { now })
        .getMany();

      if (expired.length === 0) {
        return 0;
      }

      // Group by (userId, tenantId) so we touch each StorageQuota row once.
      const byUser = new Map<
        string,
        { userId: string; tenantId: string; bytes: number }
      >();
      for (const entry of expired) {
        const key = `${entry.userId}|${entry.tenantId}`;
        const acc = byUser.get(key) ?? {
          userId: entry.userId,
          tenantId: entry.tenantId,
          bytes: 0,
        };
        acc.bytes += Number(entry.byteDelta);
        byUser.set(key, acc);
      }

      for (const acc of byUser.values()) {
        if (acc.bytes <= 0) continue;
        await manager.query(
          `
          UPDATE storage_quotas AS q
          SET
            "reservedBytes" = GREATEST(q."reservedBytes" - $2, 0),
            "activeUploads" = GREATEST(q."activeUploads" - 1, 0)
          WHERE q."userId" = $3 AND q."tenantId" = $4
          `,
          [acc.bytes, acc.userId, acc.tenantId],
        );
      }

      for (const entry of expired) {
        entry.status = QuotaLedgerStatus.EXPIRED;
        entry.byteDelta = -Number(entry.byteDelta);
        entry.reason = 'sweep:ttl-expired';
      }
      await ledgerRepo.save(expired);

      this.logger.log(
        `[quota] sweep expired reservations: ${expired.length} entries`,
      );
      return expired.length;
    });
  }

  /**
   * Idempotent upsert that ensures every user has a quota row. Called on
   * first reservation / on tier upgrades.
   *
   * Uses `INSERT ... ON CONFLICT DO NOTHING` so repeated calls are cheap.
   */
  async ensureQuotaRow(
    userId: string,
    tier: StorageQuotaTier,
    tenantId: string = '',
  ): Promise<StorageQuota> {
    const defaults = this.quotaConfig.resolveTierDefaults(tier);
    await this.dataSource.query(
      `
      INSERT INTO storage_quotas
        ("userId", "tenantId", "maxTotalBytes", "maxActiveUploads",
         "maxUploadsPerHour", "tier")
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT ON CONSTRAINT uq_storage_quotas_user_tenant DO NOTHING
      `,
      [
        userId,
        tenantId,
        defaults.maxTotalBytes,
        defaults.maxActiveUploads,
        defaults.maxUploadsPerHour,
        tier,
      ],
    );

    const row = await this.quotaRepo.findOne({
      where: { userId, tenantId },
    });

    if (!row) {
      throw new Error(
        `Failed to fetch storage_quota row for user=${userId} tenant=${tenantId}`,
      );
    }
    return row;
  }

  /** Read a snapshot of the user's quota for UI display. */
  async getSnapshot(
    userId: string,
    tenantId: string = '',
  ): Promise<QuotaSnapshot> {
    // Lazy-create so first-time UI calls always have something to show.
    await this.ensureQuotaRow(userId, this.resolveUserTier(userId), tenantId);
    const row = await this.quotaRepo.findOne({ where: { userId, tenantId } });
    if (!row) {
      throw new Error('storage_quota row missing after ensureQuotaRow');
    }
    return {
      userId,
      tenantId,
      tier: row.tier,
      usedBytes: Number(row.usedBytes),
      reservedBytes: Number(row.reservedBytes),
      maxTotalBytes: Number(row.maxTotalBytes),
      activeUploads: row.activeUploads,
      maxActiveUploads: row.maxActiveUploads,
      uploadsThisHour: row.uploadsThisHour,
      maxUploadsPerHour: row.maxUploadsPerHour,
    };
  }

  /** Admin helper: change the user's effective tier (with audit). */
  async setTier(
    userId: string,
    tier: StorageQuotaTier,
    tenantId: string = '',
  ): Promise<StorageQuota> {
    const defaults = this.quotaConfig.resolveTierDefaults(tier);
    await this.dataSource.query(
      `
      INSERT INTO storage_quotas
        ("userId", "tenantId", "maxTotalBytes", "maxActiveUploads",
         "maxUploadsPerHour", "tier")
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT ON CONSTRAINT uq_storage_quotas_user_tenant DO UPDATE
        SET "maxTotalBytes" = EXCLUDED."maxTotalBytes",
            "maxActiveUploads" = EXCLUDED."maxActiveUploads",
            "maxUploadsPerHour" = EXCLUDED."maxUploadsPerHour",
            "tier" = EXCLUDED."tier",
            "updatedAt" = now(),
            "version" = "storage_quotas"."version" + 1
      `,
      [
        userId,
        tenantId,
        defaults.maxTotalBytes,
        defaults.maxActiveUploads,
        defaults.maxUploadsPerHour,
        tier,
      ],
    );
    const row = await this.quotaRepo.findOne({ where: { userId, tenantId } });
    if (!row) {
      throw new Error(`Failed to upsert storage_quota for user=${userId}`);
    }
    return row;
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  /**
   * Best-effort mapping of user → tier label. Mirrors TieredThrottler's
   * FREE / VERIFIED etc. but reads from request context when available.
   *
   * The default returns 'free'; uploads from admin users will typically
   * have a tier resolved upstream and pushed via `ReserveOptions.tier`.
   */
  private resolveUserTier(_userId: string): StorageQuotaTier {
    return 'free';
  }

  /**
   * Translate a failed atomic UPDATE into a typed exception. The diagnostics
   * scan is best-effort: a missing row means the user has never uploaded
   * before and we should still get a clean error.
   */
  private async throwWithDiagnostics(
    quotaRepo: Repository<StorageQuota>,
    userId: string,
    tenantId: string,
    requested: number,
    _tier: StorageQuotaTier,
  ): Promise<never> {
    let row: StorageQuota | null = null;
    try {
      row = await quotaRepo.findOne({ where: { userId, tenantId } });
    } catch {
      row = null;
    }

    if (!row) {
      throw new StorageQuotaExceededException(
        'storage',
        'Quota row not provisioned for user; reservation failed before initialize',
        {
          userId,
          requestedBytes: requested,
        },
      );
    }

    const used = Number(row.usedBytes);
    const reserved = Number(row.reservedBytes);
    const max = Number(row.maxTotalBytes);

    if (used + reserved + requested > max) {
      throw new StorageQuotaExceededException(
        'storage',
        `Storage quota exceeded: ${used + reserved + requested} > ${max} bytes`,
        {
          userId,
          requestedBytes: requested,
          usedBytes: used,
          reservedBytes: reserved,
          maxTotalBytes: max,
        },
      );
    }

    if (row.activeUploads + 1 > row.maxActiveUploads) {
      throw new StorageQuotaExceededException(
        'concurrency',
        `Active uploads limit reached: ${row.activeUploads}/${row.maxActiveUploads}`,
        {
          userId,
          activeUploads: row.activeUploads,
          maxActiveUploads: row.maxActiveUploads,
        },
      );
    }

    if (row.uploadsThisHour + 1 > row.maxUploadsPerHour) {
      throw new StorageQuotaExceededException(
        'frequency',
        `Hourly upload limit reached: ${row.uploadsThisHour}/${row.maxUploadsPerHour}`,
        {
          userId,
          uploadsThisHour: row.uploadsThisHour,
          maxUploadsPerHour: row.maxUploadsPerHour,
        },
      );
    }

    // Unknown race between SELECT and diagnosis; surface a generic rejection.
    throw new StorageQuotaExceededException(
      'storage',
      'Storage quota reservation rejected',
      { userId, requestedBytes: requested },
    );
  }
}
