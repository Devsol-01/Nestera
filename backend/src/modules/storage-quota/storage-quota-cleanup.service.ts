import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { StorageQuotaService } from './storage-quota.service';
import { StorageQuotaConfig } from './storage-quota.types';

/**
 * Periodic sweeper that turns orphaned PENDING reservations into EXPIRED
 * rows and refunds the corresponding quota. Runs every
 * `cleanupIntervalMinutes` minutes.
 *
 * Lazily provisions quota rows on `ensureForUser()` so quota rows exist
 * for any user who has ever authenticated (call from auth / id-resolver
 * middleware if you want a stricter guarantee).
 */
@Injectable()
export class StorageQuotaCleanupService implements OnModuleInit {
  private readonly logger = new Logger(StorageQuotaCleanupService.name);

  constructor(
    private readonly quotaService: StorageQuotaService,
    private readonly quotaConfig: StorageQuotaConfig,
    private readonly schedulerRegistry: SchedulerRegistry,
  ) {}

  onModuleInit(): void {
    const minutes = this.quotaConfig.cleanupIntervalMinutes;
    if (minutes <= 0) {
      this.logger.log('[quota] cleanup scheduler disabled (interval=0)');
      return;
    }
    const interval = setInterval(
      () => this.runSweepSafely(),
      minutes * 60 * 1000,
    );
    // Allow the process to exit cleanly on shutdown even if the interval
    // timer is still scheduled.
    if (typeof interval.unref === 'function') {
      interval.unref();
    }
    this.schedulerRegistry.addInterval('storage-quota-cleanup', interval);
    this.logger.log(
      `[quota] cleanup scheduler registered: every ${minutes} minutes`,
    );
  }

  /**
   * Lazy provisioning for first-touch UX. Safe to call from any context
   * where a user identity is known (e.g. global auth guard).
   */
  async ensureForUser(userId: string, tier: string): Promise<void> {
    try {
      await this.quotaService.ensureQuotaRow(userId, tier);
    } catch (err) {
      this.logger.warn(
        `[quota] ensureForUser failed user=${userId}: ${(err as Error).message}`,
      );
    }
  }

  /** Public for tests / ad-hoc tooling. */
  async runSweepOnce(): Promise<number> {
    return this.quotaService.sweepExpiredReservations();
  }

  private async runSweepSafely(): Promise<void> {
    try {
      const expired = await this.quotaService.sweepExpiredReservations();
      if (expired > 0) {
        this.logger.log(
          `[quota] sweep processed ${expired} expired reservations`,
        );
      }
    } catch (err) {
      this.logger.error(
        `[quota] sweep failed: ${(err as Error).message}`,
        (err as Error).stack,
      );
    }
  }
}
