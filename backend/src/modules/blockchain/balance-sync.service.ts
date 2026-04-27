import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
  Inject,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Horizon } from '@stellar/stellar-sdk';
import { StellarService } from './stellar.service';
import { ProtocolMetrics } from '../admin-analytics/entities/protocol-metrics.entity';
import { BalanceSnapshot } from './entities/balance-snapshot.entity';
import { ReorgHistory } from './entities/reorg-history.entity';
import {
  BalanceChangedEvent,
  BALANCE_CHANGED_EVENT,
  REORG_DETECTED_EVENT,
  REORG_RESOLVED_EVENT,
  BALANCE_ROLLBACK_EVENT,
  BALANCE_CONFIRMED_EVENT,
  ConnectionMetricsSummary,
  StreamHandle,
  PendingBalanceUpdate,
  BalanceSyncConfig,
  ReorgDetectedEvent,
  ReorgResolvedEvent,
  BalanceRollbackEvent,
} from './balance-sync.types';

const CONFIG_DEFAULTS = {
  cacheTtlSeconds: 300,
  pollIntervalMs: 5000,
  reconnectInitialDelayMs: 1000,
  reconnectMaxDelayMs: 60000,
  metricsPersistIntervalMs: 60000,
  // New reorg-related config
  confirmationDepth: 3,
  maxPendingQueueSize: 100,
  enableReorgDetection: true,
  reconciliationCron: '0 2 * * *', // 2am UTC daily
} as const;

@Injectable()
export class BalanceSyncService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BalanceSyncService.name);

  private handles: Map<string, StreamHandle> = new Map();

  // Config values
  private cacheTtlSeconds: number;
  private pollIntervalMs: number;
  private reconnectInitialDelayMs: number;
  private reconnectMaxDelayMs: number;
  private metricsPersistIntervalMs: number;
  private confirmationDepth: number;
  private maxPendingQueueSize: number;
  private enableReorgDetection: boolean;
  private reconciliationCron: string;

  // Timers
  private metricsTimer: NodeJS.Timeout | null = null;
  private ledgerRefreshTimer: NodeJS.Timeout | null = null;
  private reconciliationTimer: NodeJS.Timeout | null = null;

  // Global chain state
  private currentLedger: number = 0;
  private ledgerHashes: Map<number, string> = new Map(); // recent ledger hash cache
  private readonly ledgerHashRetention: number = 1000; // keep last 1000 ledger hashes

  // Pending unconfirmed balance updates per account
  private pendingUpdates: Map<string, PendingBalanceUpdate[]> = new Map();

  // Reorg detection state
  private totalReorgsDetected: number = 0;
  private lastReorgDetectedAt: number = 0;
  private ledgerStreamHandle: { close: () => void; connected: boolean } | null =
    null;
  private ledgerReconnectTimer: NodeJS.Timeout | null = null;
  private ledgerReconnectAttempt: number = 0;

  // Repositories
  constructor(
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    private readonly eventEmitter: EventEmitter2,
    private readonly stellarService: StellarService,
    @InjectRepository(ProtocolMetrics)
    private readonly protocolMetricsRepo: Repository<ProtocolMetrics>,
    @InjectRepository(BalanceSnapshot)
    private readonly balanceSnapshotsRepo: Repository<BalanceSnapshot>,
    @InjectRepository(ReorgHistory)
    private readonly reorgHistoryRepo: Repository<ReorgHistory>,
    private readonly dataSource: DataSource,
  ) {}

  async onModuleInit(): Promise<void> {
    this.cacheTtlSeconds = this.resolveConfig(
      'balanceSync.cacheTtlSeconds',
      CONFIG_DEFAULTS.cacheTtlSeconds,
    );

    this.pollIntervalMs = this.resolveConfig(
      'balanceSync.pollIntervalMs',
      CONFIG_DEFAULTS.pollIntervalMs,
    );

    this.reconnectInitialDelayMs = this.resolveConfig(
      'balanceSync.reconnectInitialDelayMs',
      CONFIG_DEFAULTS.reconnectInitialDelayMs,
    );

    this.reconnectMaxDelayMs = this.resolveConfig(
      'balanceSync.reconnectMaxDelayMs',
      CONFIG_DEFAULTS.reconnectMaxDelayMs,
    );

    this.metricsPersistIntervalMs = this.resolveConfig(
      'balanceSync.metricsPersistIntervalMs',
      CONFIG_DEFAULTS.metricsPersistIntervalMs,
    );

    // New config
    this.confirmationDepth = this.resolveConfig(
      'balanceSync.confirmationDepth',
      CONFIG_DEFAULTS.confirmationDepth,
    );
    this.maxPendingQueueSize = this.resolveConfig(
      'balanceSync.maxPendingQueueSize',
      CONFIG_DEFAULTS.maxPendingQueueSize,
    );
    this.enableReorgDetection = this.resolveConfig(
      'balanceSync.enableReorgDetection',
      CONFIG_DEFAULTS.enableReorgDetection,
    );
    this.reconciliationCron = this.resolveConfig(
      'balanceSync.reconciliationCron',
      CONFIG_DEFAULTS.reconciliationCron,
    );

    // Validate pollIntervalMs range (Requirement 8.3)
    if (this.pollIntervalMs <= 0 || this.pollIntervalMs > 60000) {
      this.logger.error(
        `pollIntervalMs value ${this.pollIntervalMs} is out of range (must be > 0 and <= 60000). ` +
          `Substituting default: ${CONFIG_DEFAULTS.pollIntervalMs}`,
      );
      this.pollIntervalMs = CONFIG_DEFAULTS.pollIntervalMs;
    }

    // Validate confirmationDepth
    if (this.confirmationDepth < 1) {
      this.logger.warn(
        `confirmationDepth ${this.confirmationDepth} is less than 1, using 1. Reorg protection will be minimal.`,
      );
      this.confirmationDepth = 1;
    }

    this.logger.log(
      `BalanceSyncService initialised with config: ` +
        `cacheTtlSeconds=${this.cacheTtlSeconds}, ` +
        `pollIntervalMs=${this.pollIntervalMs}, ` +
        `reconnectInitialDelayMs=${this.reconnectInitialDelayMs}, ` +
        `reconnectMaxDelayMs=${this.reconnectMaxDelayMs}, ` +
        `metricsPersistIntervalMs=${this.metricsPersistIntervalMs}, ` +
        `confirmationDepth=${this.confirmationDepth}, ` +
        `maxPendingQueueSize=${this.maxPendingQueueSize}, ` +
        `enableReorgDetection=${this.enableReorgDetection}, ` +
        `reconciliationCron=${this.reconciliationCron}`,
    );

    // Start metrics persistence
    this.metricsTimer = setInterval(() => {
      void this.persistMetrics();
    }, this.metricsPersistIntervalMs);

    // Initialize ledger hash cache from recent ledgers
    if (this.enableReorgDetection) {
      await this.initializeLedgerCache();
      this.openLedgerStream();
    }

    // Periodic ledger refresh (as fallback if ledger stream dies)
    this.ledgerRefreshTimer = setInterval(() => {
      void this.refreshCurrentLedger();
    }, this.pollIntervalMs);

    // Schedule daily reconciliation job (simple interval)
    // Using 24-hour interval; cron expression config stored but not parsed
    this.reconciliationTimer = setInterval(
      () => {
        void this.reconcileBalances();
      },
      24 * 60 * 60 * 1000,
    );
    this.logger.log(`Scheduled daily reconciliation job (every 24 hours)`);
  }

  onModuleDestroy(): void {
    this.logger.log('BalanceSyncService destroying');

    if (this.metricsTimer !== null) {
      clearInterval(this.metricsTimer);
      this.metricsTimer = null;
    }

    if (this.ledgerRefreshTimer !== null) {
      clearInterval(this.ledgerRefreshTimer);
      this.ledgerRefreshTimer = null;
    }

    if (this.reconciliationTimer !== null) {
      clearInterval(this.reconciliationTimer);
      this.reconciliationTimer = null;
    }

    // Close ledger stream
    if (this.ledgerStreamHandle) {
      this.ledgerStreamHandle.close();
      this.ledgerStreamHandle = null;
    }

    if (this.ledgerReconnectTimer !== null) {
      clearTimeout(this.ledgerReconnectTimer);
      this.ledgerReconnectTimer = null;
    }

    const accountCount = this.handles.size;
    for (const publicKey of this.handles.keys()) {
      this.unsubscribe(publicKey);
    }

    this.logger.log(`Cleaned up ${accountCount} account(s)`);
  }

  subscribe(publicKey: string): void {
    if (this.handles.has(publicKey)) {
      this.logger.debug(`Already subscribed to account ${publicKey}, skipping`);
      return;
    }

    // Initialize pending queue for this account
    this.pendingUpdates.set(publicKey, []);

    const handle: StreamHandle = {
      close: () => {},
      connected: false,
      reconnect: {
        delayMs: this.reconnectInitialDelayMs,
        attempt: 0,
        timer: null,
      },
      pollTimer: null,
      metrics: {
        publicKey,
        streamUptimeSeconds: 0,
        reconnectCount: 0,
        fallbackActive: false,
        connectedAt: null,
        pendingUpdateCount: 0,
        lastLedgerSequence: 0,
        lastConfirmedLedger: 0,
      },
      pendingQueue: [],
      highestLedgerSeen: 0,
    };

    this.handles.set(publicKey, handle);
    this.openStream(publicKey);
  }

  unsubscribe(publicKey: string): void {
    if (!this.handles.has(publicKey)) {
      this.logger.debug(
        `unsubscribe called for unknown account ${publicKey}, skipping`,
      );
      return;
    }

    const handle = this.handles.get(publicKey)!;

    handle.close();

    if (handle.reconnect.timer !== null) {
      clearTimeout(handle.reconnect.timer);
    }

    this.deactivatePollingFallback(publicKey);
    this.handles.delete(publicKey);
    this.pendingUpdates.delete(publicKey);

    this.logger.log(`Unsubscribed account ${publicKey}`);
  }

  getMetricsSummary(): ConnectionMetricsSummary {
    const accounts = Array.from(this.handles.entries()).map(([, handle]) => {
      const streamUptimeSeconds =
        handle.connected && handle.metrics.connectedAt
          ? Math.floor(
              (Date.now() - handle.metrics.connectedAt.getTime()) / 1000,
            )
          : handle.metrics.streamUptimeSeconds;

      const queue = this.pendingUpdates.get(handle.metrics.publicKey);
      const pendingCount = queue?.length ?? 0;

      return {
        ...handle.metrics,
        streamUptimeSeconds,
        pendingUpdateCount: pendingCount,
        lastConfirmedLedger:
          handle.metrics.lastConfirmedLedger > 0
            ? handle.metrics.lastConfirmedLedger
            : handle.metrics.lastLedgerSequence - this.confirmationDepth + 1,
      };
    });

    const anyFallbackActive = accounts.some((a) => a.fallbackActive);
    const totalReconnects = accounts.reduce(
      (sum, a) => sum + a.reconnectCount,
      0,
    );
    const totalPending = accounts.reduce(
      (sum, a) => sum + a.pendingUpdateCount,
      0,
    );

    return {
      accounts,
      anyFallbackActive,
      totalReconnects,
      totalPendingUpdates: totalPending,
      lastReorgDetectedAt: this.lastReorgDetectedAt,
      totalReorgsDetected: this.totalReorgsDetected,
    };
  }

  /**
   * Process an incoming account record from the Horizon stream.
   * For each asset balance, queue the update until confirmation depth is reached.
   * Requirements: 2.3 (queue balance updates until confirmed)
   */
  private async processAccountUpdate(
    accountRecord: Horizon.AccountResponse,
  ): Promise<void> {
    const accountId = accountRecord.account_id;

    // Extract ledger sequence from the account record (last_modified_ledger)
    const ledgerSequence = (accountRecord as any).last_modified_ledger as
      | number
      | undefined;
    if (!ledgerSequence || ledgerSequence <= 0) {
      this.logger.warn(
        `Account update for ${accountId} missing ledger sequence, skipping`,
      );
      return;
    }

    // Update highest ledger seen for this account
    const handle = this.handles.get(accountId);
    if (handle) {
      handle.highestLedgerSeen = Math.max(
        handle.highestLedgerSeen,
        ledgerSequence,
      );
      handle.metrics.lastLedgerSequence = ledgerSequence;
    }

    // Queue updates for each balance
    for (const balance of accountRecord.balances) {
      const assetCode =
        balance.asset_type === 'native'
          ? 'native'
          : (balance as Horizon.HorizonApi.BalanceLineAsset).asset_code;

      const newBalance = balance.balance;

      const pending: PendingBalanceUpdate = {
        accountId,
        assetCode,
        newBalance,
        ledgerSequence,
        queuedAt: new Date(),
      };

      await this.enqueuePendingUpdate(pending);
    }

    // After enqueuing, try to promote any updates that are now confirmed
    await this.processPendingQueue();
  }

  /**
   * Add a pending balance update to the per-account queue.
   * Enforces max queue size by dropping oldest entries if needed.
   * Requirements: 2.3 (queue balance updates)
   */
  private async enqueuePendingUpdate(
    pending: PendingBalanceUpdate,
  ): Promise<void> {
    let queue = this.pendingUpdates.get(pending.accountId);
    if (!queue) {
      queue = [];
      this.pendingUpdates.set(pending.accountId, queue);
    }

    queue.push(pending);
    // Keep queue sorted by ledgerSequence ascending for processing order
    queue.sort((a, b) => a.ledgerSequence - b.ledgerSequence);

    if (queue.length > this.maxPendingQueueSize) {
      const removed = queue.shift()!;
      this.logger.warn(
        `Pending queue overflow for ${pending.accountId}, dropped update from ledger ${removed.ledgerSequence}`,
      );
    }

    // Update metrics
    const handle = this.handles.get(pending.accountId);
    if (handle) {
      handle.metrics.pendingUpdateCount = queue.length;
    }
  }

  /**
   * Write a balance entry to the cache.
   * Key: `balance:{publicKey}:{assetCode}`
   * On any error: log at warn level and do not rethrow (Requirement 2.4).
   */
  private async writeBalanceToCache(
    publicKey: string,
    assetCode: string,
    balance: string,
  ): Promise<void> {
    const key = `balance:${publicKey}:${assetCode}`;
    try {
      const value = JSON.stringify({
        balance,
        updatedAt: new Date().toISOString(),
      });
      const ttl = this.cacheTtlSeconds * 1000; // cache-manager uses milliseconds
      await this.cacheManager.set(key, value, ttl);
    } catch (err) {
      this.logger.warn(
        `Failed to write balance cache for key "${key}": ${(err as Error).message}`,
      );
    }
  }

  /**
   * Read a balance entry from the cache.
   * Returns the `balance` field from the stored JSON, or null on miss/error.
   */
  private async readBalanceFromCache(
    publicKey: string,
    assetCode: string,
  ): Promise<string | null> {
    const key = `balance:${publicKey}:${assetCode}`;
    try {
      const result = await this.cacheManager.get<string>(key);
      if (typeof result === 'string') {
        const parsed = JSON.parse(result) as { balance: string };
        return parsed.balance;
      }
      return null;
    } catch (err) {
      this.logger.warn(
        `Failed to read balance cache for key "${key}": ${(err as Error).message}`,
      );
      return null;
    }
  }

  /**
   * Initialize ledger hash cache with recent ledgers from Horizon.
   * Called on startup to populate the ledgerHashes map for reorg detection.
   */
  private async initializeLedgerCache(): Promise<void> {
    try {
      const horizon = this.stellarService.getHorizonServer();
      const response = await horizon
        .ledgers()
        .limit(this.ledgerHashRetention)
        .order('desc')
        .call();
      const records = (response as any).records || [];
      for (const ledger of records) {
        const seq = ledger.sequence as number;
        const hash = ledger.hash as string;
        this.ledgerHashes.set(seq, hash);
      }
      if (records.length > 0) {
        const maxSeq = Math.max(...records.map((l: any) => l.sequence));
        this.currentLedger = maxSeq;
      }
      this.logger.log(
        `Initialized ledger cache with ${this.ledgerHashes.size} recent ledgers, currentLedger=${this.currentLedger}`,
      );
    } catch (err) {
      this.logger.warn(
        `Failed to initialize ledger cache: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Open a global Horizon SSE stream for ledger close events.
   * Used to track current ledger height and detect chain reorganizations.
   */
  private openLedgerStream(): void {
    const horizonServer = this.stellarService.getHorizonServer();

    const closeStream = horizonServer.ledgers().stream({
      onmessage: (ledgerRecord: any) => {
        try {
          const sequence = ledgerRecord.sequence as number;
          const hash = ledgerRecord.hash as string;

          if (!sequence || !hash) {
            this.logger.warn('Ledger stream message missing sequence or hash');
            return;
          }

          // Check for reorg BEFORE updating the cache
          if (this.enableReorgDetection) {
            const existingHash = this.ledgerHashes.get(sequence);
            if (existingHash && existingHash !== hash) {
              // Reorg detected!
              this.logger.error(
                `Chain reorganization detected at ledger ${sequence}: hash mismatch (stored ${existingHash}, new ${hash})`,
              );
              this.handleReorg(sequence, hash);
            }
          }

          // Update current ledger
          if (sequence > this.currentLedger) {
            this.currentLedger = sequence;
          }

          // Store/update ledger hash
          this.ledgerHashes.set(sequence, hash);
          // Trim old entries
          if (this.ledgerHashes.size > this.ledgerHashRetention) {
            const oldest = Math.min(...this.ledgerHashes.keys());
            this.ledgerHashes.delete(oldest);
          }

          // After advancing ledger, process pending queue
          this.processPendingQueue();
        } catch (err) {
          this.logger.error(
            `Error processing ledger message: ${(err as Error).message}`,
          );
        }
      },
      onerror: (err) => {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Ledger stream error: ${message}`);
        if (this.ledgerStreamHandle) {
          this.ledgerStreamHandle.connected = false;
        }
        this.scheduleLedgerReconnect();
      },
    });

    this.ledgerStreamHandle = { close: closeStream, connected: true };
    this.logger.log('Opened Horizon ledger stream');
  }

  /**
   * Open a Horizon SSE stream for the given account.
   * Stores the SDK-returned close function on the handle.
   * Requirements: 1.1, 1.2, 1.3
   */
  private openStream(publicKey: string): void {
    const handle = this.handles.get(publicKey);
    if (!handle) return;

    const horizonServer = this.stellarService.getHorizonServer();

    const closeStream = horizonServer
      .accounts()
      .accountId(publicKey)
      .stream({
        onmessage: (accountRecord) => {
          handle.connected = true;
          handle.metrics.connectedAt = handle.metrics.connectedAt ?? new Date();
          this.processAccountUpdate(
            accountRecord as unknown as Horizon.AccountResponse,
          ).catch((err) =>
            this.logger.error(
              `Error processing account update for ${publicKey}: ${(err as Error).message}`,
            ),
          );
        },
        onerror: (err) => {
          const message = err instanceof Error ? err.message : String(err);
          this.logger.warn(`Stream error for ${publicKey}: ${message}`);
          handle.connected = false;
          this.scheduleReconnect(publicKey);
          this.activatePollingFallback(publicKey);
        },
      });

    handle.close = closeStream;
    this.logger.log(`Opened Horizon SSE stream for account ${publicKey}`);
  }

  /**
   * Schedule an exponential back-off reconnect attempt for the given account.
   * Requirements: 4.1, 4.2, 4.3, 4.4
   */
  private scheduleReconnect(publicKey: string): void {
    const handle = this.handles.get(publicKey);
    if (!handle) return;

    // Already scheduled — don't double-schedule
    if (handle.reconnect.timer !== null) return;

    const delay = Math.min(
      this.reconnectInitialDelayMs * Math.pow(2, handle.reconnect.attempt),
      this.reconnectMaxDelayMs,
    );
    handle.reconnect.delayMs = delay;

    this.logger.log(
      `Scheduling reconnect for ${publicKey}: attempt ${handle.reconnect.attempt + 1}, delay ${delay} ms`,
    );

    handle.reconnect.timer = setTimeout(() => {
      handle.reconnect.timer = null;
      handle.reconnect.attempt++;
      handle.metrics.reconnectCount++;

      try {
        this.openStream(publicKey);
        // Stream opened without throwing — reset back-off state
        handle.reconnect.attempt = 0;
        handle.reconnect.delayMs = this.reconnectInitialDelayMs;
        this.logger.log(`Stream recovered for account ${publicKey}`);
        this.deactivatePollingFallback(publicKey);
      } catch (err) {
        this.logger.error(
          `Reconnect attempt failed for ${publicKey}: ${(err as Error).message}`,
        );
        this.scheduleReconnect(publicKey);
      }
    }, delay);
  }

  /**
   * Activate the polling fallback for an account whose stream is down.
   * Requirements: 5.1, 5.2, 5.3, 5.4
   */
  private activatePollingFallback(publicKey: string): void {
    const handle = this.handles.get(publicKey);
    if (!handle) return;

    // Idempotent — already polling
    if (handle.pollTimer !== null) return;

    handle.metrics.fallbackActive = true;
    this.logger.log(`Activating polling fallback for account ${publicKey}`);

    handle.pollTimer = setInterval(async () => {
      try {
        const horizonServer = this.stellarService.getHorizonServer();
        const account = await horizonServer
          .accounts()
          .accountId(publicKey)
          .call();
        await this.processAccountUpdate(
          account as unknown as Horizon.AccountResponse,
        );
      } catch (err) {
        this.logger.warn(
          `Polling fallback error for ${publicKey}: ${(err as Error).message}`,
        );
      }
    }, this.pollIntervalMs);
  }

  /**
   * Deactivate the polling fallback once the stream is re-established.
   * Requirements: 5.1, 5.2, 5.3, 5.4
   */
  private deactivatePollingFallback(publicKey: string): void {
    const handle = this.handles.get(publicKey);
    if (!handle) return;

    // Idempotent — not polling
    if (handle.pollTimer === null) return;

    clearInterval(handle.pollTimer);
    handle.pollTimer = null;
    handle.metrics.fallbackActive = false;
    this.logger.log(`Polling fallback deactivated for account ${publicKey}`);
  }

  /**
   * Process the pending update queues, promoting any updates that have
   * reached the required confirmation depth.
   * Requirements: 2.3 (confirmation depth enforced)
   */
  private async processPendingQueue(): Promise<void> {
    if (this.currentLedger < this.confirmationDepth) {
      // Not enough ledgers yet to confirm anything
      return;
    }

    const confirmationThreshold =
      this.currentLedger - this.confirmationDepth + 1;

    for (const [accountId, queue] of this.pendingUpdates.entries()) {
      if (queue.length === 0) continue;

      // Find index of first unconfirmed update (ledgerSequence > threshold)
      // Since queue is sorted ascending, once we find one unconfirmed, the rest are also unconfirmed
      let i = 0;
      for (; i < queue.length; i++) {
        if (queue[i].ledgerSequence > confirmationThreshold) {
          break;
        }
      }

      if (i === 0) {
        // Nothing confirmed yet
        continue;
      }

      const toConfirm = queue.slice(0, i);
      const remaining = queue.slice(i);

      // Process confirmed updates in order
      for (const update of toConfirm) {
        try {
          await this.applyConfirmedUpdate(update);
        } catch (err) {
          this.logger.error(
            `Failed to apply confirmed update for ${update.accountId}/${update.assetCode} ledger ${update.ledgerSequence}: ${(err as Error).message}`,
          );
          // Continue processing others; this update might be retried later if still in queue? But it's removed from queue after this.
          // To be safe, we could leave it in queue; but then it would block later updates. Simpler: skip and drop, as later reconciliation will fix.
        }
      }

      // Update queue
      this.pendingUpdates.set(accountId, remaining);

      // Update metrics
      const handle = this.handles.get(accountId);
      if (handle) {
        handle.metrics.pendingUpdateCount = remaining.length;
        if (toConfirm.length > 0) {
          handle.metrics.lastConfirmedLedger =
            toConfirm[toConfirm.length - 1].ledgerSequence;
        }
      }
    }
  }

  /**
   * Persist the current connection metrics snapshot to ProtocolMetrics.
   * Upserts into the most recent record, or creates a minimal one if none exists.
   * Requirements: 6.5
   */
  private async persistMetrics(): Promise<void> {
    try {
      const summary = this.getMetricsSummary();
      const record = await this.protocolMetricsRepo.findOne({
        where: {},
        order: { createdAt: 'DESC' },
      });
      if (record) {
        record.connectionMetrics = summary;
        await this.protocolMetricsRepo.save(record);
      } else {
        const newRecord = this.protocolMetricsRepo.create({
          snapshotDate: new Date(),
          totalValueLockedUsd: 0,
          totalValueLockedXlm: 0,
          savingsProductCount: 0,
          connectionMetrics: summary,
        });
        await this.protocolMetricsRepo.save(newRecord);
      }
    } catch (err) {
      this.logger.warn(
        `Failed to persist connection metrics: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Apply a balance update that has reached required confirmations.
   * Persists snapshot, updates cache, and emits confirmed event.
   * Requirements: 2.3 (confirmations), 3.1, 3.3, 3.4
   */
  private async applyConfirmedUpdate(
    update: PendingBalanceUpdate,
  ): Promise<void> {
    // Read previous balance from cache (last confirmed state)
    const previousBalance = await this.readBalanceFromCache(
      update.accountId,
      update.assetCode,
    );

    // Create snapshot
    const snapshot = this.balanceSnapshotsRepo.create({
      accountId: update.accountId,
      assetCode: update.assetCode,
      balance: update.newBalance,
      ledgerSequence: update.ledgerSequence,
      transactionHash: update.transactionHash,
      isConfirmed: true,
      snapshotTime: new Date(),
    });
    await this.balanceSnapshotsRepo.save(snapshot);

    // Update cache
    await this.writeBalanceToCache(
      update.accountId,
      update.assetCode,
      update.newBalance,
    );

    // Emit event
    const event = new BalanceChangedEvent();
    event.accountId = update.accountId;
    event.assetCode = update.assetCode;
    event.previousBalance = previousBalance ?? '0';
    event.newBalance = update.newBalance;
    event.changedAt = new Date();
    event.ledgerSequence = update.ledgerSequence;
    event.confirmations = this.currentLedger - update.ledgerSequence + 1;
    event.isConfirmed = true;
    event.transactionHash = update.transactionHash;
    event.source = 'stream';

    this.eventEmitter.emit(BALANCE_CHANGED_EVENT, event);
  }

  /**
   * Resolve a config value, logging a warning and using the default if absent.
   */
  private resolveConfig<T>(key: string, defaultValue: T): T {
    const value = this.configService.get<T>(key);
    if (value === undefined || value === null) {
      this.logger.warn(
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
        `Config key "${key}" is absent. Using default: ${defaultValue}`,
      );
      return defaultValue;
    }
    return value;
  }

  /**
   * Scheduled job: Reconcile balances daily by fetching from Horizon and
   * correcting any inconsistencies.
   * Requirements: 2.5 (reconciliation job runs daily)
   */
  private async reconcileBalances(): Promise<void> {
    this.logger.log('Starting daily balance reconciliation job');

    try {
      // Get current ledger once and update internal state
      const currentLedger = await this.getCurrentLedgerFromAPI();
      if (currentLedger > this.currentLedger) {
        this.currentLedger = currentLedger;
      }

      // Find accounts with recent activity (have snapshots in last 30 days)
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      const recentSnapshots = await this.balanceSnapshotsRepo
        .createQueryBuilder('snap')
        .where('snap.createdAt >= :date', { date: thirtyDaysAgo })
        .select('DISTINCT snap.accountId')
        .getMany();

      const accounts = recentSnapshots.map((s) => s.accountId);
      this.logger.log(`Reconciliation: checking ${accounts.length} accounts`);

      const horizonServer = this.stellarService.getHorizonServer();
      let correctedCount = 0;

      for (const accountId of accounts) {
        try {
          // Fetch current balances from Horizon
          const account = await horizonServer
            .accounts()
            .accountId(accountId)
            .call();
          const balances = account.balances;

          for (const balance of balances) {
            const assetCode =
              balance.asset_type === 'native'
                ? 'native'
                : (balance as Horizon.HorizonApi.BalanceLineAsset).asset_code;
            const currentBalance = balance.balance;

            // Find latest confirmed snapshot for this asset
            const latestSnapshot = await this.balanceSnapshotsRepo.findOne({
              where: { accountId, assetCode, isConfirmed: true },
              order: { ledgerSequence: 'DESC' },
            });

            if (!latestSnapshot || latestSnapshot.balance !== currentBalance) {
              // Inconsistency detected, create correction snapshot
              const correction = this.balanceSnapshotsRepo.create({
                accountId,
                assetCode,
                balance: currentBalance,
                ledgerSequence: currentLedger,
                isConfirmed: true,
                snapshotTime: new Date(),
              });
              await this.balanceSnapshotsRepo.save(correction);

              // Update cache
              await this.writeBalanceToCache(
                accountId,
                assetCode,
                currentBalance,
              );

              // Emit correction event
              const event = new BalanceChangedEvent();
              event.accountId = accountId;
              event.assetCode = assetCode;
              event.previousBalance = latestSnapshot?.balance ?? '0';
              event.newBalance = currentBalance;
              event.changedAt = new Date();
              event.ledgerSequence = currentLedger;
              event.confirmations = this.confirmationDepth; // considered confirmed
              event.isConfirmed = true;
              event.transactionHash = undefined;
              event.source = 'reconciliation';
              this.eventEmitter.emit(BALANCE_CHANGED_EVENT, event);

              correctedCount++;
            }
          }
        } catch (err) {
          this.logger.warn(
            `Reconciliation error for account ${accountId}: ${(err as Error).message}`,
          );
        }
      }

      this.logger.log(
        `Reconciliation complete: corrected ${correctedCount} balances`,
      );
    } catch (err) {
      this.logger.error(
        `Reconciliation job failed: ${(err as Error).message}`,
        err,
      );
    }
  }

  /**
   * Fetch the current ledger number from Horizon API.
   * Used as fallback when ledger stream is unavailable.
   */
  private async getCurrentLedgerFromAPI(): Promise<number> {
    try {
      const response = await this.stellarService
        .getHorizonServer()
        .ledgers()
        .limit(1)
        .order('desc')
        .call();
      const records = response as any;
      if (records && records.records && records.records.length > 0) {
        return records.records[0].sequence as number;
      }
      return this.currentLedger; // fallback
    } catch (err) {
      this.logger.warn(
        `Failed to fetch current ledger from API: ${(err as Error).message}`,
      );
      return this.currentLedger;
    }
  }

  /**
   * Periodic fallback to refresh current ledger from API if stream fails.
   */
  private async refreshCurrentLedger(): Promise<void> {
    try {
      const latest = await this.getCurrentLedgerFromAPI();
      if (latest > this.currentLedger) {
        this.currentLedger = latest;
        // Also process pending queue with new height
        await this.processPendingQueue();
      }
    } catch (err) {
      this.logger.warn(
        `Failed to refresh current ledger: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Find common ancestor ledger between old and new chain.
   * Returns the highest ledger less than detectedAt where stored hash matches the current chain.
   */
  private async findCommonAncestor(detectedAt: number): Promise<number> {
    const horizon = this.stellarService.getHorizonServer();
    // Search backwards from detectedAt-1 down to max(1, detectedAt - 1000) limited by cache retention
    const startSeq = detectedAt - 1;
    const minSeq = Math.max(1, detectedAt - this.ledgerHashRetention);
    for (let seq = startSeq; seq >= minSeq; seq--) {
      const storedHash = this.ledgerHashes.get(seq);
      if (!storedHash) continue;

      try {
        const ledger = await horizon.ledgers().ledger(seq).call();
        const newHash = (ledger as any).hash as string;
        if (newHash === storedHash) {
          this.logger.debug(`Reorg: common ancestor found at ledger ${seq}`);
          return seq;
        }
      } catch (err) {
        this.logger.warn(
          `Failed to fetch ledger ${seq} during reorg detection: ${(err as Error).message}`,
        );
      }
    }
    this.logger.warn(
      'Reorg: no common ancestor within cache; rolling back to genesis (0)',
    );
    return 0;
  }

  /**
   * Handle a detected chain reorganization.
   * 1. Find common ancestor ledger
   * 2. Roll back affected balance snapshots
   * 3. Rebuild affected account caches
   * 4. Clear pending updates in the reorged range
   * 5. Emit events
   *
   * Requirements: 2.1 (reorg detection), 2.2 (rollback mechanism)
   */
  private async handleReorg(
    detectedAt: number,
    newHash: string,
  ): Promise<void> {
    const startTime = Date.now();
    this.totalReorgsDetected++;
    this.lastReorgDetectedAt = detectedAt;

    try {
      // Find common ancestor ledger (last known good)
      const commonAncestor = await this.findCommonAncestor(detectedAt);
      this.logger.log(
        `Reorg: rolling back from ledger ${detectedAt} to ledger ${commonAncestor}`,
      );

      // Find all snapshots with ledgerSequence > commonAncestor
      const rolledBackSnapshots = await this.balanceSnapshotsRepo
        .createQueryBuilder('snap')
        .where('snap.ledgerSequence > :ancestor', { ancestor: commonAncestor })
        .orderBy('snap.ledgerSequence', 'ASC')
        .getMany();

      if (rolledBackSnapshots.length === 0) {
        this.logger.warn('Reorg: no snapshots needed to roll back');
        return;
      }

      // Group by accountId to revert
      const accountsAffected = new Set<string>();
      let rolledBackCount = 0;

      // Use a transaction to ensure consistency
      await this.dataSource.transaction(async (transactionalEntityManager) => {
        const snapshotRepo =
          transactionalEntityManager.getRepository(BalanceSnapshot);
        // Delete snapshots in the reorged range
        await snapshotRepo
          .createQueryBuilder()
          .where('ledgerSequence > :ancestor', { ancestor: commonAncestor })
          .delete()
          .execute();

        // For each affected account, reapply the state at commonAncestor
        const accountIds = Array.from(
          new Set(rolledBackSnapshots.map((s) => s.accountId)),
        );

        for (const accountId of accountIds) {
          accountsAffected.add(accountId);
          // Find latest snapshot <= commonAncestor for each asset
          const latestBefore = rolledBackSnapshots
            .filter(
              (s) =>
                s.accountId === accountId && s.ledgerSequence <= commonAncestor,
            )
            .sort((a, b) => b.ledgerSequence - a.ledgerSequence);

          // Build a map of the latest snapshot per asset
          const latestByAsset: Record<string, BalanceSnapshot> = {};
          for (const snap of latestBefore) {
            if (!latestByAsset[snap.assetCode]) {
              latestByAsset[snap.assetCode] = snap;
            }
          }

          // For each asset, emit rollback event and update cache to reverted state
          for (const [assetCode, snapshot] of Object.entries(latestByAsset)) {
            // Write the reverted balance to cache
            await this.writeBalanceToCache(
              accountId,
              assetCode,
              snapshot.balance,
            );

            const rollbackEvent = new BalanceRollbackEvent();
            rollbackEvent.accountId = accountId;
            rollbackEvent.assetCode = assetCode;
            rollbackEvent.rolledBackToBalance = snapshot.balance;
            rollbackEvent.fromLedger = detectedAt;
            rollbackEvent.toLedger = commonAncestor;
            rollbackEvent.rolledBackAt = new Date();
            this.eventEmitter.emit(BALANCE_ROLLBACK_EVENT, rollbackEvent);
          }

          // Clear pending updates for this account that were in the rolled range
          const queue = this.pendingUpdates.get(accountId);
          if (queue) {
            const remaining = queue.filter(
              (u) => u.ledgerSequence <= commonAncestor,
            );
            this.pendingUpdates.set(accountId, remaining);
            const handle = this.handles.get(accountId);
            if (handle) {
              handle.metrics.pendingUpdateCount = remaining.length;
            }
          }
        }

        rolledBackCount = rolledBackSnapshots.length;
      });

      // Prune ledger hashes for rolled-back ledgers to free memory and avoid future false positives
      for (const seq of Array.from(this.ledgerHashes.keys())) {
        if (seq > commonAncestor) {
          this.ledgerHashes.delete(seq);
        }
      }

      // Record reorg history
      const reorgRecord = this.reorgHistoryRepo.create({
        detectedAtLedger: detectedAt,
        rollbackToLedger: commonAncestor,
        affectedAccounts: Array.from(accountsAffected),
        rolledBackSnapshots: rolledBackCount,
        reappliedSnapshots: 0,
        status: 'rollback_complete',
        description: `Reorg at ledger ${detectedAt}; rolled back ${rolledBackCount} snapshots`,
        resolvedAt: null,
      });
      await this.reorgHistoryRepo.save(reorgRecord);

      // Emit reorg detected event
      const detectedEvent = new ReorgDetectedEvent();
      detectedEvent.detectedAtLedger = detectedAt;
      detectedEvent.rollbackToLedger = commonAncestor;
      detectedEvent.affectedAccounts = Array.from(accountsAffected);
      detectedEvent.detectedAt = new Date();
      this.eventEmitter.emit(REORG_DETECTED_EVENT, detectedEvent);

      const durationMs = Date.now() - startTime;
      this.logger.log(
        `Reorg handled: rolled back ${rolledBackCount} snapshots for ${accountsAffected.size} accounts in ${durationMs}ms`,
      );
    } catch (err) {
      this.logger.error(
        `Failed to handle reorg: ${(err as Error).message}`,
        err,
      );
    }
  }

  /**
   * Ledger stream reconnection with exponential backoff.
   */
  private scheduleLedgerReconnect(): void {
    if (this.ledgerReconnectTimer !== null) return;

    const delay = Math.min(
      this.reconnectInitialDelayMs * Math.pow(2, this.ledgerReconnectAttempt),
      this.reconnectMaxDelayMs,
    );

    this.logger.log(
      `Scheduling ledger stream reconnect: attempt ${this.ledgerReconnectAttempt + 1}, delay ${delay} ms`,
    );

    this.ledgerReconnectTimer = setTimeout(() => {
      this.ledgerReconnectTimer = null;
      this.ledgerReconnectAttempt++;
      try {
        this.openLedgerStream();
        this.logger.log('Ledger stream reconnected');
        this.ledgerReconnectAttempt = 0;
      } catch (err) {
        this.logger.error(
          `Ledger stream reconnect failed: ${(err as Error).message}`,
        );
        this.scheduleLedgerReconnect();
      }
    }, delay);
  }
}
