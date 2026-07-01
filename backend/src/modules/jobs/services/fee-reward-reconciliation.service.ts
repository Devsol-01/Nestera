import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ReconciliationRecord } from '../entities/reconciliation-record.entity';
import { AuditLogService } from '../../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
  SYSTEM_ACTOR,
} from '../../../common/entities/audit-log.entity';

export interface ReconciliationOptions {
  /** Bull/BullMQ job ID – forwarded to the audit log for traceability. */
  jobId?: string;
  /** Optional correlation ID (e.g. request-id header propagated from the scheduler). */
  correlationId?: string;
}

@Injectable()
export class FeeRewardReconciliationService {
  private readonly logger = new Logger(FeeRewardReconciliationService.name);

  constructor(
    @InjectRepository(ReconciliationRecord)
    private readonly reconciliationRepo: Repository<ReconciliationRecord>,
    private readonly auditLogService: AuditLogService,
  ) {}

  // Main reconciliation method: compares expected vs actual fees/rewards
  // and records discrepancies, optionally auto-correcting within safe bounds.
  async reconcile(
    options: ReconciliationOptions = {},
  ): Promise<{ totalChecked: number; discrepancies: number; corrected: number }> {
    this.logger.log('Starting fee/reward reconciliation...');

    const startedAt = new Date();

    // Snapshot state before reconciliation for before/after diff
    const beforeSnapshot = await this.buildSnapshot();

    // Placeholder: In production, fetch expected and actual data from respective sources.
    // For example:
    // - Expected fees from fee schedule or off-chain calculations
    // - Actual fees from transactions ledger
    // - Expected rewards from reward profiles
    // - Actual rewards from reward payout records

    const itemsToCheck = await this.fetchItemsToReconcile();

    let discrepancies = 0;
    let corrected = 0;

    for (const item of itemsToCheck) {
      const discrepancy = item.expectedAmount - item.actualAmount;
      const absDiscrepancy = Math.abs(discrepancy);

      // Define safe bounds
      const safeBound = 0.01;
      const percentageBound = 0.001 * item.expectedAmount;
      const maxAllowedDiscrepancy = Math.max(safeBound, percentageBound);

      if (absDiscrepancy > 0) {
        discrepancies++;
        if (absDiscrepancy <= maxAllowedDiscrepancy) {
          await this.autoCorrect(item, discrepancy);
          corrected++;
        } else {
          await this.reportDiscrepancy(item, discrepancy);
        }
      }

      // Save reconciliation record
      const record = Object.assign(this.reconciliationRepo.create(), {
        recordType: item.recordType,
        referenceId: item.referenceId,
        expectedAmount: item.expectedAmount,
        actualAmount: item.actualAmount,
        discrepancy: discrepancy,
        status:
          absDiscrepancy === 0
            ? 'pending'
            : absDiscrepancy <= maxAllowedDiscrepancy
              ? 'corrected'
              : 'discrepancy_reported',
        autoCorrected:
          absDiscrepancy > 0 && absDiscrepancy <= maxAllowedDiscrepancy,
        correctedAt: (absDiscrepancy > 0 && absDiscrepancy <= maxAllowedDiscrepancy
          ? new Date()
          : null) as unknown as Date,
        notes: `Discrepancy: ${discrepancy}. ${absDiscrepancy > maxAllowedDiscrepancy ? 'Reported for manual review.' : 'Auto-corrected.'}`,
      });
      await this.reconciliationRepo.save(record);
    }

    const result = {
      totalChecked: itemsToCheck.length,
      discrepancies,
      corrected,
    };

    this.logger.log(
      `Reconciliation completed: ${result.totalChecked} checked, ${result.discrepancies} discrepancies, ${result.corrected} auto-corrected.`,
    );

    // Build after-snapshot for diff
    const afterSnapshot = {
      totalChecked: result.totalChecked,
      discrepancies: result.discrepancies,
      corrected: result.corrected,
      completedAt: new Date().toISOString(),
    };

    const durationMs = Date.now() - startedAt.getTime();
    const success = true;

    await this.auditLogService.log({
      actor: SYSTEM_ACTOR,
      action: AuditAction.RECONCILE,
      resourceType: AuditResourceType.JOB,
      jobId: options.jobId,
      correlationId: options.correlationId,
      description: `Fee/reward reconciliation completed: ${result.totalChecked} records checked, ${result.discrepancies} discrepancies found, ${result.corrected} auto-corrected.`,
      previousValue: beforeSnapshot,
      newValue: afterSnapshot,
      durationMs,
      success,
    });

    return result;
  }

  /**
   * Build a lightweight before-snapshot of reconciliation state.
   * In production, this could capture aggregate counts from the DB.
   */
  private async buildSnapshot(): Promise<Record<string, any>> {
    const totalRecords = await this.reconciliationRepo.count();
    return {
      totalRecordsBeforeRun: totalRecords,
      snapshotAt: new Date().toISOString(),
    };
  }

  // In production, implement actual data fetching from appropriate sources.
  private async fetchItemsToReconcile(): Promise<
    Array<{
      recordType: string;
      referenceId: string;
      expectedAmount: number;
      actualAmount: number;
    }>
  > {
    // Simulated data
    return [
      {
        recordType: 'fee',
        referenceId: 'txn-001',
        expectedAmount: 0.5,
        actualAmount: 0.5,
      },
      {
        recordType: 'fee',
        referenceId: 'txn-002',
        expectedAmount: 1.0,
        actualAmount: 1.05,
      }, // small discrepancy
      {
        recordType: 'reward',
        referenceId: 'user-100',
        expectedAmount: 100.0,
        actualAmount: 98.5,
      }, // larger discrepancy
    ];
  }

  private async autoCorrect(
    item: {
      recordType: string;
      referenceId: string;
      expectedAmount: number;
      actualAmount: number;
    },
    discrepancy: number,
  ): Promise<void> {
    this.logger.warn(
      `Auto-correcting discrepancy of ${discrepancy} for ${item.recordType} ${item.referenceId}. Expected ${item.expectedAmount}, actual ${item.actualAmount}.`,
    );
    // TODO: Implement actual correction logic:
    // - For fees: adjust transaction record or create adjustment entry.
    // - For rewards: adjust reward payout or user balance.
  }

  private async reportDiscrepancy(
    item: {
      recordType: string;
      referenceId: string;
      expectedAmount: number;
      actualAmount: number;
    },
    discrepancy: number,
  ): Promise<void> {
    this.logger.error(
      `Significant discrepancy for ${item.recordType} ${item.referenceId}: expected ${item.expectedAmount}, actual ${item.actualAmount}, diff ${discrepancy}.`,
    );
    // TODO: Create admin ticket via ticketing system, send notification, etc.
  }
}
