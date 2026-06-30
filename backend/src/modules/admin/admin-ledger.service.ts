import {
  Injectable,
  Logger,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  AdminCorrectionLedger,
  CorrectionType,
} from '../entities/admin-correction-ledger.entity';
import { CreateAdminCorrectionDto } from '../dto/create-admin-correction.dto';

export interface ReconciliationRow {
  targetId: string;
  correctionType: CorrectionType;
  entryCount: number;
  /** Sum of all `delta` values for this group (as a string for precision). */
  totalDelta: string;
  firstCorrectedAt: Date;
  lastCorrectedAt: Date;
}

export interface ReconciliationSummary {
  targetId: string;
  rows: ReconciliationRow[];
  /** Grand total across all correctionTypes for this targetId. */
  netDelta: string;
}

/**
 * AdminLedgerService
 *
 * Provides APPEND-ONLY writes to the `admin_correction_ledger` table and
 * reconciliation queries.  No update or delete methods exist by design.
 *
 * Finance-safety guarantees:
 *  1. appendCorrection() rejects duplicate requestIds to prevent double-write.
 *  2. The delta string is validated as a numeric string before persistence.
 *  3. Reconciliation queries aggregate the raw DB values so callers can compare
 *     them against the live balances independently.
 */
@Injectable()
export class AdminLedgerService {
  private readonly logger = new Logger(AdminLedgerService.name);

  constructor(
    @InjectRepository(AdminCorrectionLedger)
    private readonly ledgerRepo: Repository<AdminCorrectionLedger>,
  ) {}

  // ─── Write ───────────────────────────────────────────────────────────────

  /**
   * Appends a new correction entry.  This is the ONLY mutating method.
   *
   * @throws ConflictException  when requestId has already been used.
   * @throws BadRequestException  when delta is not a valid numeric string.
   */
  async appendCorrection(
    adminId: string,
    dto: CreateAdminCorrectionDto,
  ): Promise<AdminCorrectionLedger> {
    this.validateDelta(dto.delta);

    // Idempotency guard — reject duplicate requestIds
    if (dto.requestId) {
      const duplicate = await this.ledgerRepo.findOne({
        where: { requestId: dto.requestId },
      });
      if (duplicate) {
        throw new ConflictException(
          `A correction with requestId "${dto.requestId}" already exists (id: ${duplicate.id}). ` +
            'Use a new requestId to apply a distinct correction.',
        );
      }
    }

    const entry = this.ledgerRepo.create({
      adminId,
      targetId: dto.targetId,
      targetType: dto.targetType,
      correctionType: dto.correctionType,
      delta: dto.delta,
      previousValue: dto.previousValue ?? null,
      newValue: dto.newValue ?? null,
      reason: dto.reason,
      requestId: dto.requestId ?? null,
      workflowId: dto.workflowId ?? null,
      metadata: null,
    });

    const saved = await this.ledgerRepo.save(entry);
    this.logger.log(
      `AdminLedger: correction appended id=${saved.id} ` +
        `target=${saved.targetType}:${saved.targetId} ` +
        `type=${saved.correctionType} delta=${saved.delta} ` +
        `admin=${adminId} requestId=${saved.requestId ?? 'n/a'}`,
    );

    return saved;
  }

  // ─── Read ────────────────────────────────────────────────────────────────

  /**
   * Returns all ledger entries for a specific target resource.
   * Ordered by `createdAt ASC` so the caller sees the chronological chain.
   */
  async findByTarget(targetId: string): Promise<AdminCorrectionLedger[]> {
    return this.ledgerRepo.find({
      where: { targetId },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Returns all ledger entries created by a specific admin.
   */
  async findByAdmin(adminId: string): Promise<AdminCorrectionLedger[]> {
    return this.ledgerRepo.find({
      where: { adminId },
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Returns all entries linked to an external workflow.
   */
  async findByWorkflow(workflowId: string): Promise<AdminCorrectionLedger[]> {
    return this.ledgerRepo.find({
      where: { workflowId },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Returns the single entry whose requestId matches, or null.
   * Useful for idempotency checks by the caller.
   */
  async findByRequestId(
    requestId: string,
  ): Promise<AdminCorrectionLedger | null> {
    return this.ledgerRepo.findOne({ where: { requestId } });
  }

  // ─── Reconciliation ──────────────────────────────────────────────────────

  /**
   * Reconciliation query for a single target resource.
   *
   * Returns one row per correctionType, with the entry count and sum of
   * deltas.  Also returns the net aggregate delta across all types.
   *
   * Finance teams can compare `netDelta` against the actual balance change
   * recorded in the transactions table to verify consistency.
   */
  async reconcileTarget(targetId: string): Promise<ReconciliationSummary> {
    const raw: Array<{
      correctionType: CorrectionType;
      entryCount: string;
      totalDelta: string;
      firstCorrectedAt: Date;
      lastCorrectedAt: Date;
    }> = await this.ledgerRepo
      .createQueryBuilder('acl')
      .select('acl.correctionType', 'correctionType')
      .addSelect('COUNT(*)', 'entryCount')
      .addSelect('SUM(CAST(acl.delta AS NUMERIC))', 'totalDelta')
      .addSelect('MIN(acl.createdAt)', 'firstCorrectedAt')
      .addSelect('MAX(acl.createdAt)', 'lastCorrectedAt')
      .where('acl.targetId = :targetId', { targetId })
      .groupBy('acl.correctionType')
      .getRawMany();

    const rows: ReconciliationRow[] = raw.map((r) => ({
      targetId,
      correctionType: r.correctionType,
      entryCount: Number(r.entryCount),
      totalDelta: r.totalDelta ?? '0',
      firstCorrectedAt: r.firstCorrectedAt,
      lastCorrectedAt: r.lastCorrectedAt,
    }));

    const netDelta = rows
      .reduce((acc, row) => acc + parseFloat(row.totalDelta), 0)
      .toString();

    return { targetId, rows, netDelta };
  }

  /**
   * Bulk reconciliation over a set of targetIds (or all if none specified).
   *
   * Returns a map keyed by targetId for quick lookup.
   */
  async reconcileMany(
    targetIds?: string[],
  ): Promise<Map<string, ReconciliationSummary>> {
    const qb = this.ledgerRepo
      .createQueryBuilder('acl')
      .select('acl.targetId', 'targetId')
      .addSelect('acl.correctionType', 'correctionType')
      .addSelect('COUNT(*)', 'entryCount')
      .addSelect('SUM(CAST(acl.delta AS NUMERIC))', 'totalDelta')
      .addSelect('MIN(acl.createdAt)', 'firstCorrectedAt')
      .addSelect('MAX(acl.createdAt)', 'lastCorrectedAt')
      .groupBy('acl.targetId')
      .addGroupBy('acl.correctionType')
      .orderBy('acl.targetId')
      .addOrderBy('acl.correctionType');

    if (targetIds && targetIds.length > 0) {
      qb.where('acl.targetId IN (:...targetIds)', { targetIds });
    }

    const raw: Array<{
      targetId: string;
      correctionType: CorrectionType;
      entryCount: string;
      totalDelta: string;
      firstCorrectedAt: Date;
      lastCorrectedAt: Date;
    }> = await qb.getRawMany();

    const map = new Map<string, ReconciliationSummary>();

    for (const r of raw) {
      if (!map.has(r.targetId)) {
        map.set(r.targetId, { targetId: r.targetId, rows: [], netDelta: '0' });
      }
      const summary = map.get(r.targetId)!;
      summary.rows.push({
        targetId: r.targetId,
        correctionType: r.correctionType,
        entryCount: Number(r.entryCount),
        totalDelta: r.totalDelta ?? '0',
        firstCorrectedAt: r.firstCorrectedAt,
        lastCorrectedAt: r.lastCorrectedAt,
      });
    }

    // Compute net delta per target
    for (const summary of map.values()) {
      summary.netDelta = summary.rows
        .reduce((acc, row) => acc + parseFloat(row.totalDelta), 0)
        .toString();
    }

    return map;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private validateDelta(delta: string): void {
    if (!/^-?\d+(\.\d+)?$/.test(delta)) {
      throw new BadRequestException(
        `delta must be a numeric string (e.g. "50.00" or "-12.5"). Got: "${delta}"`,
      );
    }
    if (delta === '0' || delta === '0.0' || parseFloat(delta) === 0) {
      throw new BadRequestException(
        'delta must be non-zero — a correction of 0 has no effect.',
      );
    }
  }
}
