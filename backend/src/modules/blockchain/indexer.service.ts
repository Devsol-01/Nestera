import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, In } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { rpc } from '@stellar/stellar-sdk';
import { v4 as uuidv4 } from 'uuid';

import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { IndexerState } from './entities/indexer-state.entity';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { ReorgAuditLog } from './entities/reorg-audit-log.entity';
import { ReorgAffectedTransaction } from './entities/reorg-affected-transaction.entity';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';
import { StellarService } from './stellar.service';
import { MailService } from '../mail/mail.service';
import { User } from '../user/entities/user.entity';
import { LedgerTransaction } from './entities/transaction.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';

/** Shape of a raw Soroban event as returned by the RPC. */
interface SorobanEvent {
  id?: string;
  ledger: number;
  topic?: unknown[];
  value?: unknown;
  txHash?: string;
  [key: string]: unknown;
}

/**
 * Audit log entry for internal tracking
 * Uses the common AuditLog entity for system-wide audit trail
 */
interface ReorgAuditEntry {
  action: string;
  description: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}

type EventType = 'deposit' | 'withdraw' | 'yield';

@Injectable()
export class IndexerService implements OnModuleInit {
  private readonly logger = new Logger(IndexerService.name);

  private rpcServer: rpc.Server | null = null;

  /** In-memory cache of contract IDs to monitor */
  private contractIds: Set<string> = new Set();

  /** In-memory state synced with DB */
  private indexerState: IndexerState | null = null;

  /**
   * Number of recent ledgers to check for reorgs
   * Stellar typically has a max reorg depth of around 50 ledgers
   */
  private readonly REORG_CHECK_WINDOW = 60;

  constructor(
    private readonly configService: ConfigService,
    private readonly stellarService: StellarService,
    private readonly dataSource: DataSource,
    @InjectRepository(DeadLetterEvent)
    private readonly dlqRepo: Repository<DeadLetterEvent>,
    @InjectRepository(IndexerState)
    private readonly indexerStateRepo: Repository<IndexerState>,
    @InjectRepository(ProcessedStellarEvent)
    private readonly processedEventRepo: Repository<ProcessedStellarEvent>,
    @InjectRepository(ReorgAuditLog)
    private readonly reorgAuditLogRepo: Repository<ReorgAuditLog>,
    @InjectRepository(ReorgAffectedTransaction)
    private readonly reorgAffectedTxRepo: Repository<ReorgAffectedTransaction>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(LedgerTransaction)
    private readonly txRepo: Repository<LedgerTransaction>,
    @InjectRepository(UserSubscription)
    private readonly subscriptionRepo: Repository<UserSubscription>,
    @InjectRepository(SavingsProduct)
    private readonly savingsProductRepo: Repository<SavingsProduct>,
    private readonly depositHandler: DepositHandler,
    private readonly withdrawHandler: WithdrawHandler,
    private readonly yieldHandler: YieldHandler,
    private readonly mailService: MailService,
  ) {}

  async onModuleInit() {
    this.logger.log('Initializing Blockchain Event Indexer...');

    this.rpcServer = this.stellarService.getRpcServer();

    await this.initializeIndexerState();
    await this.loadContractIds();

    this.logger.log(
      `Blockchain indexer initialized. Monitoring ${this.contractIds.size} contract(s).`,
    );
  }

  /**
   * Main indexer cycle - runs every 5 seconds to process new events
   */
  @Cron(CronExpression.EVERY_5_SECONDS)
  async runIndexerCycle(): Promise<void> {
    if (!this.indexerState) return;

    // Reload contract IDs to ensure we're watching any new active products
    await this.loadContractIds();
    if (this.contractIds.size === 0) {
      this.logger.debug('No active contracts to monitor');
      return;
    }

    try {
      const events = await this.fetchEvents();

      if (events.length === 0) {
        this.logger.debug('No new events found');
        return;
      }

      let processed = 0;
      let failed = 0;

      for (const event of events) {
        const ok = await this.processEvent(event);
        if (ok) {
          processed++;
        } else {
          failed++;
        }
      }

      this.logger.log(
        `Processed ${processed} events (Failed: ${failed}) from ledger ${events[0].ledger} to ${events[events.length - 1].ledger}`,
      );

      this.indexerState.totalEventsProcessed += processed;
      this.indexerState.totalEventsFailed += failed;
      this.indexerState.updatedAt = new Date();

      await this.saveIndexerState();
    } catch (err) {
      this.logger.error(`Indexer cycle failed: ${(err as Error).message}`);
    }
  }

  /**
   * Reorg detection cron job - runs every 60 seconds
   * Checks recent processed ledgers against the canonical chain
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async detectAndHandleReorgs(): Promise<void> {
    this.logger.debug('Running reorg detection check...');

    if (!this.indexerState) return;

    try {
      // Get recently processed ledgers to check
      const recentEvents = await this.processedEventRepo
        .createQueryBuilder('event')
        .where('event.ledger > :minLedger', {
          minLedger:
            this.indexerState.lastProcessedLedger - this.REORG_CHECK_WINDOW,
        })
        .andWhere('event.isReorged = :isReorged', { isReorged: false })
        .orderBy('event.ledger', 'ASC')
        .groupBy('event.ledger')
        .select(['event.ledger', 'event.ledgerHash'])
        .limit(this.REORG_CHECK_WINDOW)
        .getMany();

      if (recentEvents.length === 0) return;

      const ledgerSequences = recentEvents.map((e) => e.ledger);
      const currentLedgerInfo = await this.stellarService.getLedgers(
        ledgerSequences,
      );

      // Find ledgers where hash doesn't match (reorged)
      const reorgedLedgers: number[] = [];

      for (const event of recentEvents) {
        const currentInfo = currentLedgerInfo[event.ledger];
        if (!currentInfo) continue; // Ledger not found - could be pruned

        // Compare stored hash with current hash
        if (event.ledgerHash && event.ledgerHash !== currentInfo.hash) {
          this.logger.warn(
            `Reorg detected at ledger ${event.ledger}: stored hash ${event.ledgerHash} != current ${currentInfo.hash}`,
          );
          reorgedLedgers.push(event.ledger);
        } else if (!event.ledgerHash) {
          // If no hash stored, we can't verify - mark as suspicious
          this.logger.warn(
            `No ledger hash stored for ledger ${event.ledger}, cannot verify reorg status`,
          );
        }
      }

      // If reorg detected, handle it
      if (reorgedLedgers.length > 0) {
        this.logger.warn(
          `Reorg detected affecting ${reorgedLedgers.length} ledgers: ${reorgedLedgers.join(', ')}`,
        );
        await this.handleReorg(reorgedLedgers);
      }
    } catch (err) {
      this.logger.error(`Reorg detection failed: ${(err as Error).message}`);
    }
  }

  /**
   * Main reorg handler - reverts and reprocesses affected events
   */
  private async handleReorg(reorgedLedgerSequences: number[]): Promise<void> {
    const minLedger = Math.min(...reorgedLedgerSequences);
    const maxLedger = Math.max(...reorgedLedgerSequences);

    const reorgAuditLogId = uuidv4();

    try {
      // Step 1: Create audit log
      await this.createReorgAuditLog(reorgAuditLogId, minLedger, maxLedger);

      // Step 2: Fetch all events in the reorganized range
      const affectedEvents = await this.processedEventRepo.find({
        where: {
          ledger: In(reorgedLedgerSequences),
          isReorged: false,
        },
        order: { ledger: 'ASC' },
      });

      if (affectedEvents.length === 0) {
        this.logger.info('No events found in reorg range');
        return;
      }

      // Step 3: Mark existing events as reorged
      await this.markEventsAsReorged(affectedEvents, reorgAuditLogId);

      // Step 4: Revert transactions for affected events
      const revertedTxCount = await this.revertTransactionsForEvents(
        affectedEvents,
        reorgAuditLogId,
      );

      // Step 5: Fetch new events from canonical chain
      const newEvents = await this.fetchEventsFromChain(minLedger, maxLedger);

      // Step 6: Reprocess events from new canonical chain
      const reprocessedCount = await this.reprocessEventsFromChain(
        newEvents,
        reorgAuditLogId,
      );

      // Step 7: Notify users of reverted transactions
      await this.notifyUsersOfRevertedTransactions(affectedEvents, reorgAuditLogId);

      // Step 8: Update audit log with completion
      await this.finalizeReorgAuditLog(reorgAuditLogId, {
        affectedEventsCount: affectedEvents.length,
        revertedTransactionsCount: revertedTxCount,
        reprocessedTransactionsCount: reprocessedCount,
      });

      this.logger.log(
        `Reorg handling completed: ${revertedTxCount} reverted, ${reprocessedCount} reprocessed`,
      );
    } catch (err) {
      this.logger.error(`Reorg handling failed: ${(err as Error).message}`, err);
      await this.markReorgFailed(reorgAuditLogId, (err as Error).message);
    }
  }

  /**
   * Create audit log entry for the reorg event
   */
  private async createReorgAuditLog(
    id: string,
    oldBranchStart: number,
    oldBranchEnd: number,
  ): Promise<void> {
    const chainId = this.configService.get<string>('stellar.network') || 'unknown';

    // For reorg, the new branch is the current canonical chain
    const newBranchStart = oldBranchStart;
    const newBranchEnd = this.indexerState?.lastProcessedLedger || oldBranchEnd;

    await this.reorgAuditLogRepo.save(
      this.reorgAuditLogRepo.create({
        id,
        chainId,
        reorgPointLedger: oldBranchStart,
        oldBranchStartLedger: oldBranchStart,
        oldBranchEndLedger: oldBranchEnd,
        newBranchStartLedger: newBranchStart,
        newBranchEndLedger: newBranchEnd,
        status: 'DETECTED',
      }),
    );

    this.logger.log(`Created reorg audit log ${id}`);
  }

  /**
   * Mark events as reorged
   */
  private async markEventsAsReorged(
    events: ProcessedStellarEvent[],
    reorgAuditLogId: string,
  ): Promise<void> {
    for (const event of events) {
      event.isReorged = true;
      event.reorgAuditLogId = reorgAuditLogId;
    }

    await this.processedEventRepo.save(events);
    this.logger.log(`Marked ${events.length} events as reorged`);
  }

  /**
   * Revert state changes for affected transactions
   * - Deposits: subtract from user subscription amount
   * - Withdrawals: add back to user subscription amount
   * - Yield: subtract from totalInterestEarned
   */
  private async revertTransactionsForEvents(
    events: ProcessedStellarEvent[],
    reorgAuditLogId: string,
  ): Promise<number> {
    let revertedCount = 0;

    for (const event of events) {
      try {
        const tx = await this.txRepo.findOne({
          where: { eventId: event.eventId },
        });

        if (!tx) {
          this.logger.warn(
            `No transaction found for event ${event.eventId}`,
          );
          continue;
        }

        // Mark the transaction as reverted (soft delete logic would be different)
        // Instead of deleting, we'll create a record and reverse the subscription effects
        const user = await this.userRepo.findOne({
          where: { id: tx.userId },
        });

        if (!user) {
          this.logger.warn(`User not found for transaction ${tx.id}`);
          continue;
        }

        // Get active subscription
        const subscription = await this.subscriptionRepo.findOne({
          where: {
            userId: user.id,
            status: 'ACTIVE',
          },
          order: { createdAt: 'DESC' },
        });

        if (!subscription) {
          this.logger.warn(
            `No active subscription for user ${user.id} during revert`,
          );
        }

        const amount = Number(tx.amount);
        let actionDetails: Record<string, any> = {};

        // Delete the old transaction record to allow reprocessing with new eventId
        await this.txRepo.delete({ id: tx.id });

        switch (tx.type) {
          case 'DEPOSIT':
            // Reverse: subtract the deposit amount
            if (subscription) {
              await this.subscriptionRepo
                .createQueryBuilder()
                .update(UserSubscription)
                .set({ amount: () => 'amount - ' + amount })
                .where('id = :id', { id: subscription.id })
                .execute();
            }
            actionDetails = { reversedType: 'DEPOSIT', amount };
            break;

          case 'WITHDRAW':
            // Reverse: add back the withdrawn amount
            if (subscription) {
              await this.subscriptionRepo
                .createQueryBuilder()
                .update(UserSubscription)
                .set({ amount: () => 'amount + ' + amount })
                .where('id = :id', { id: subscription.id })
                .execute();
            }
            actionDetails = { reversedType: 'WITHDRAW', amount };
            break;

          case 'YIELD':
            // Reverse: subtract the yield from totalInterestEarned
            if (subscription) {
              await this.subscriptionRepo
                .createQueryBuilder()
                .update(UserSubscription)
                .set({
                  totalInterestEarned: () =>
                    'CAST(totalInterestEarned AS numeric) - ' + amount,
                })
                .where('id = :id', { id: subscription.id })
                .execute();
            }
            actionDetails = { reversedType: 'YIELD', amount };
            break;

          default:
            this.logger.warn(`Unknown transaction type ${tx.type} for revert`);
            continue;
        }

        // Record affected transaction
        await this.reorgAffectedTxRepo.save(
          this.reorgAffectedTxRepo.create({
            reorgAuditLogId,
            eventId: event.eventId,
            txHash: tx.txHash,
            ledgerSequence: tx.ledgerSequence ? Number(tx.ledgerSequence) : null,
            userId: user.id,
            transactionType: tx.type,
            amount: tx.amount,
            action: 'REVERTED',
            actionDetails,
            originalEventData: event.eventData,
          }),
        );

        revertedCount++;
      } catch (err) {
        this.logger.error(
          `Failed to revert event ${event.eventId}: ${(err as Error).message}`,
        );

        await this.reorgAffectedTxRepo.save(
          this.reorgAffectedTxRepo.create({
            reorgAuditLogId,
            eventId: event.eventId,
            action: 'FAILED_REVERT',
            errorMessage: (err as Error).message,
            originalEventData: event.eventData,
          }),
        );
      }
    }

    return revertedCount;
  }

  /**
   * Fetch events from the canonical chain for the given ledger range
   */
  private async fetchEventsFromChain(
    startLedger: number,
    endLedger: number,
  ): Promise<SorobanEvent[]> {
    try {
      // Fetch events from RPC in the range
      const allEvents = await this.stellarService.getEvents(
        startLedger,
        Array.from(this.contractIds),
      );

      // Filter to only events within our range and sort
      return allEvents
        .filter((e) => {
          const ledger = parseInt(e.ledger, 10);
          return ledger >= startLedger && ledger <= endLedger;
        })
        .map((e) => ({
          id: e.id,
          ledger: parseInt(e.ledger, 10),
          topic: e.topic,
          value: e.value,
          txHash: e.txHash,
        }))
        .sort((a, b) => a.ledger - b.ledger);
    } catch (err) {
      this.logger.error(
        `Failed to fetch events from chain: ${(err as Error).message}`,
      );
      return [];
    }
  }

  /**
   * Reprocess events from the new canonical chain
   */
  private async reprocessEventsFromChain(
    events: SorobanEvent[],
    reorgAuditLogId: string,
  ): Promise<number> {
    let reprocessedCount = 0;

    for (const event of events) {
      try {
        // Fetch ledger hash
        const ledgerInfo = await this.stellarService.getLedgers([event.ledger]);
        const ledgerHash = ledgerInfo[event.ledger]?.hash || null;

        // Determine event type
        let eventType: EventType = 'deposit';
        if (this.withdrawHandler['isWithdrawTopic'](event.topic)) {
          eventType = 'withdraw';
        } else if (this.yieldHandler['isYieldTopic'](event.topic)) {
          eventType = 'yield';
        }

        const eventId = this.resolveEventId(event, eventType);

        // Mark previous reorged event as processed again with new eventId
        // The handleEvent will recreate the transaction
        await this.handleEvent(event);

        // Persist the new processed event
        await this.persistProcessedEvent(event, ledgerHash);

        // Record the reprocessing
        await this.reorgAffectedTxRepo.save(
          this.reorgAffectedTxRepo.create({
            reorgAuditLogId,
            eventId,
            txHash: event.txHash,
            ledgerSequence: event.ledger,
            action: 'REPROCESSED',
            originalEventData: event as Record<string, any>,
          }),
        );

        reprocessedCount++;

        // Update indexer state to reflect we've processed up to this ledger
        if (
          this.indexerState &&
          event.ledger > this.indexerState.lastProcessedLedger
        ) {
          this.indexerState.lastProcessedLedger = event.ledger;
          this.indexerState.lastProcessedTimestamp = Date.now();
        }
      } catch (err) {
        this.logger.error(
          `Failed to reprocess event ${event.id || event.txHash}: ${(err as Error).message}`,
        );

        await this.reorgAffectedTxRepo.save(
          this.reorgAffectedTxRepo.create({
            reorgAuditLogId,
            eventId: event.id,
            action: 'FAILED_REPROCESS',
            errorMessage: (err as Error).message,
            originalEventData: event as Record<string, any>,
          }),
        );
      }
    }

    // Save indexer state after reprocessing
    await this.saveIndexerState();

    return reprocessedCount;
  }

  /**
   * Send email notifications to users affected by reverted transactions
   */
  private async notifyUsersOfRevertedTransactions(
    events: ProcessedStellarEvent[],
    reorgAuditLogId: string,
  ): Promise<void> {
    // Collect unique user IDs from affected events
    const eventIds = events.map((e) => e.eventId);
    const transactions = await this.txRepo.find({
      where: { eventId: In(eventIds) },
    });

    const userIds = [...new Set(transactions.map((tx) => tx.userId))];

    // Fetch users with email
    const users = await this.userRepo.find({
      where: { id: In(userIds) },
    });

    let notifiedCount = 0;

    for (const user of users) {
      const userTx = transactions.find((tx) => tx.userId === user.id);
      if (!userTx) continue;

      // Skip if no email
      if (!user.email) continue;

      // Determine transaction type for message
      const typeText =
        userTx.type === 'DEPOSIT'
          ? 'deposit'
          : userTx.type === 'WITHDRAW'
            ? 'withdrawal'
            : 'yield/interest payment';
      const userName = user.name || 'Valued Customer';

      try {
        await this.mailService.sendRawMail(
          user.email,
          'Blockchain Reorganization Notice - Action Required',
          `Dear ${userName},\n\nWe detected a temporary blockchain reorganization that affected your account.\n\nA ${typeText} of ${userTx.amount} XLM (approx. ${userTx.amount} USDC equivalent) has been reversed from your account. This is a temporary state while we reconcile with the correct blockchain state.\n\nThe correct transaction will be automatically reprocessed shortly. No action is required on your part.\n\nIf you have any questions or if this affects time-sensitive operations, please contact our support team.\n\nThank you for your understanding.\n\nBest regards,\nNestera Team`,
        );
        notifiedCount++;
      } catch (err) {
        this.logger.error(
          `Failed to send reorg notification to ${user.email}: ${(err as Error).message}`,
        );
      }
    }

    this.logger.log(`Notified ${notifiedCount} users of reverted transactions`);
  }

  /**
   * Finalize reorg audit log with completion details
   */
  private async finalizeReorgAuditLog(
    id: string,
    stats: {
      affectedEventsCount: number;
      revertedTransactionsCount: number;
      reprocessedTransactionsCount: number;
    },
  ): Promise<void> {
    await this.reorgAuditLogRepo.save(
      this.reorgAuditLogRepo.create({
        id,
        affectedEventsCount: stats.affectedEventsCount,
        revertedTransactionsCount: stats.revertedTransactionsCount,
        reprocessedTransactionsCount: stats.reprocessedTransactionsCount,
        notifiedUsersCount: stats.revertedTransactionsCount, // Approximate
        status: 'COMPLETED',
        completedAt: new Date(),
      }),
    );
  }

  /**
   * Mark reorg as failed
   */
  private async markReorgFailed(
    id: string,
    errorMessage: string,
  ): Promise<void> {
    await this.reorgAuditLogRepo.save(
      this.reorgAuditLogRepo.create({
        id,
        status: 'COMPLETED', // Still COMPLETED but with error
        completedAt: new Date(),
        errorMessage,
      }),
    );
  }

  private async initializeIndexerState() {
    let state = await this.indexerStateRepo.findOne({ where: {} });

    if (!state) {
      state = await this.indexerStateRepo.save(
        this.indexerStateRepo.create({
          lastProcessedLedger: 0,
          lastProcessedTimestamp: null,
          totalEventsProcessed: 0,
          totalEventsFailed: 0,
        }),
      );
    }

    this.indexerState = state;
  }

  private async loadContractIds() {
    const products = await this.savingsProductRepo.find({
      where: { isActive: true },
    });

    const newSet = new Set<string>();
    for (const p of products) {
      if (p.contractId) newSet.add(p.contractId);
    }

    this.contractIds = newSet;
  }

  private async saveIndexerState() {
    if (this.indexerState) {
      await this.indexerStateRepo.save(this.indexerState);
    }
  }

  private async processEvent(event: SorobanEvent): Promise<boolean> {
    try {
      await this.handleEvent(event);

      // Fetch ledger hash for reorg detection
      const ledgerInfo = await this.stellarService.getLedgers([event.ledger]);
      const ledgerHash = ledgerInfo[event.ledger]?.hash || null;

      // Persist the processed event record
      await this.persistProcessedEvent(event, ledgerHash);

      if (
        this.indexerState &&
        event.ledger > this.indexerState.lastProcessedLedger
      ) {
        this.indexerState.lastProcessedLedger = event.ledger;
        this.indexerState.lastProcessedTimestamp = Date.now();
      }

      return true;
    } catch (err) {
      const msg = (err as Error).message;
      this.logger.error(
        `FAILURE at Ledger ${event.ledger}: Processing of event ${event.id} crashed. JSON: ${JSON.stringify(event)}. Error: ${msg}`,
      );

      await this.dlqRepo.save(
        this.dlqRepo.create({
          ledgerSequence: event.ledger,
          rawEvent: JSON.stringify(event),
          errorMessage: msg,
        }),
      );

      return false;
    }
  }

  /**
   * Persist a ProcessedStellarEvent record for tracking
   */
  private async persistProcessedEvent(
    event: SorobanEvent,
    ledgerHash: string | null,
  ): Promise<void> {
    let eventType: EventType = 'deposit';
    if (this.withdrawHandler['isWithdrawTopic'](event.topic)) {
      eventType = 'withdraw';
    } else if (this.yieldHandler['isYieldTopic'](event.topic)) {
      eventType = 'yield';
    }

    const eventId = this.resolveEventId(event, eventType);

    // Check if already processed
    const existing = await this.processedEventRepo.findOne({
      where: { eventId },
    });

    if (existing) {
      this.logger.debug(`Event ${eventId} already persisted. Skipping.`);
      return;
    }

    await this.processedEventRepo.save(
      this.processedEventRepo.create({
        eventId,
        contractId: this.extractContractId(event),
        transactionHash:
          typeof event.txHash === 'string' ? event.txHash : null,
        ledger: event.ledger,
        ledgerHash,
        eventType,
        eventData: this.sanitizeEventData(event),
        claimId: null,
        ledgerCloseTime: null,
        isReorged: false,
        reorgAuditLogId: null,
      }),
    );
  }

  private async handleEvent(event: SorobanEvent): Promise<void> {
    if (await this.depositHandler.handle(event)) return;
    if (await this.withdrawHandler.handle(event)) return;
    if (await this.yieldHandler.handle(event)) return;

    this.logger.debug(`Unhandled event: ${JSON.stringify(event.topic)}`);
  }

  private async fetchEvents(): Promise<SorobanEvent[]> {
    if (!this.indexerState) return [];

    const rpcEvents = await this.stellarService.getEvents(
      this.indexerState.lastProcessedLedger + 1,
      Array.from(this.contractIds),
    );

    return rpcEvents
      .map((e) => ({
        id: e.id,
        ledger: parseInt(e.ledger, 10),
        topic: e.topic,
        value: e.value,
        txHash: e.txHash,
      }))
      .sort((a, b) => a.ledger - b.ledger);
  }

  /**
   *Resolve event ID consistently
   */
  private resolveEventId(event: SorobanEvent, eventType: EventType): string {
    if (typeof event.id === 'string' && event.id.length > 0) {
      return event.id;
    }

    const txHash =
      typeof event.txHash === 'string' && event.txHash
        ? event.txHash
        : 'unknown';
    const ledger = typeof event.ledger === 'number' ? event.ledger : 0;
    return `${txHash}:${ledger}:${eventType}`;
  }

  /**
   * Extract contract ID from event
   */
  private extractContractId(event: SorobanEvent): string {
    // The event structure from RPC includes contractId in the XDR
    // Try to extract from event metadata or return a placeholder
    return (event as any)?.contractId || 'unknown';
  }

  /**
   * Sanitize event data for storage
   */
  private sanitizeEventData(event: SorobanEvent): Record<string, any> {
    return {
      topic: event.topic,
      value: event.value,
      ...event,
    };
  }

  getIndexerState() {
    return this.indexerState;
  }

  getLastProcessedTimestamp(): number | null {
    return this.indexerState?.lastProcessedTimestamp ?? null;
  }

  async reloadContractIds() {
    await this.loadContractIds();
  }

  getMonitoredContracts(): string[] {
    return Array.from(this.contractIds);
  }
}
