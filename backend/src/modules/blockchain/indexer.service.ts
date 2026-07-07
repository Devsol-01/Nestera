import { Injectable, Logger, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { IndexerState } from './entities/indexer-state.entity';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';
import { StellarService } from './stellar.service';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { ShutdownTrackedTask } from '../../common/decorators/shutdown-task.decorator';
import { IndexerCheckpointService } from './indexer-checkpoint.service';
import { DistributedLockService } from '../../common/distributed-lock/distributed-lock.service';
import { EventStreamBackpressureService } from './event-stream-backpressure.service';
import { JobQueueService } from '../job-queue/job-queue.service';
import { INDEXER_STREAM_SAVINGS } from './indexer-checkpoint.utils';
import { DistributedTracingService } from '../apm/distributed-tracing.service';
import { TraceSpan } from '../../common/decorators/trace-span.decorator';

/** Shape of a raw Soroban event as returned by the RPC. */
export interface SorobanEvent {
  id?: string;
  ledger: number;
  topic?: unknown[];
  value?: unknown;
  txHash?: string;
  contractId?: string;
  [key: string]: unknown;
}

@Injectable()
export class IndexerService implements OnModuleInit {
  private readonly logger = new Logger(IndexerService.name);

  private readonly contractIds: Set<string> = new Set();
  private indexerState: IndexerState | null = null;
  private readonly streamId = INDEXER_STREAM_SAVINGS;
  private readonly lockTtlMs: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly stellarService: StellarService,
    @InjectRepository(DeadLetterEvent)
    private readonly dlqRepo: Repository<DeadLetterEvent>,
    @InjectRepository(IndexerState)
    private readonly indexerStateRepo: Repository<IndexerState>,
    @InjectRepository(SavingsProduct)
    private readonly savingsProductRepo: Repository<SavingsProduct>,
    private readonly depositHandler: DepositHandler,
    private readonly withdrawHandler: WithdrawHandler,
    private readonly yieldHandler: YieldHandler,
    private readonly checkpointService: IndexerCheckpointService,
    private readonly lockService: DistributedLockService,
    private readonly backpressureService: EventStreamBackpressureService,
    private readonly jobQueueService: JobQueueService,
    @Optional() readonly tracingService?: DistributedTracingService,
  ) {
    this.lockTtlMs = this.configService.get<number>(
      'distributedLock.indexerTtlMs',
      25_000,
    );
  }

  async onModuleInit() {
    this.logger.log('Initializing Blockchain Event Indexer...');
    await this.initializeIndexerState();
    await this.loadContractIds();
    this.logger.log(
      `Blockchain indexer initialized. Monitoring ${this.contractIds.size} contract(s).`,
    );
  }

  @ShutdownTrackedTask()
  @Cron(CronExpression.EVERY_5_SECONDS)
  @TraceSpan('indexer.runIndexerCycle')
  async runIndexerCycle(): Promise<void> {
    if (!this.indexerState) return;

    const lock = await this.lockService.acquireLock(
      `indexer:stream:${this.streamId}`,
      { ttlMs: this.lockTtlMs },
    );
    if (!lock) {
      this.logger.debug('Indexer cycle skipped: lock held by another instance');
      return;
    }

    try {
      await this.loadContractIds();
      if (this.contractIds.size === 0) {
        this.logger.debug('No active contracts to monitor');
        return;
      }

      const events = await this.fetchEvents();
      if (events.length === 0) {
        this.logger.debug('No new events found');
        return;
      }

      if (await this.backpressureService.shouldPauseIngestion()) {
        this.logger.warn(
          `Indexer paused due to backpressure (${events.length} events deferred)`,
        );
        return;
      }

      if (!this.backpressureService.canIngestEvents(events.length)) {
        this.logger.warn('Ingestion rate limit reached, deferring events');
        return;
      }

      let processed = 0;
      let failed = 0;
      let queued = 0;

      for (const event of events) {
        const eventId = event.id ?? `${event.ledger}-${event.txHash}`;
        await this.jobQueueService.addBlockchainJob({
          eventId,
          contractId: event.contractId ?? 'unknown',
          eventType: this.resolveEventType(event),
          rawEvent: event,
        });
        queued++;

        const ok = await this.processEvent(event);
        if (ok) {
          processed++;
        } else {
          failed++;
        }
      }

      this.logger.log(
        `Processed ${processed} events (Failed: ${failed}, Queued: ${queued}) from ledger ${events[0].ledger} to ${events[events.length - 1].ledger}`,
      );
    } catch (err) {
      this.logger.error(`Indexer cycle failed: ${(err as Error).message}`);
    } finally {
      await lock.release();
    }
  }

  /**
   * Process events for replay or manual catch-up. Caller must hold replay lock.
   */
  @TraceSpan('indexer.processEventsForReplay')
  async processEventsForReplay(
    events: SorobanEvent[],
    options: { skipCheckpoint?: boolean } = {},
  ): Promise<{ processed: number; failed: number; skipped: number }> {
    let processed = 0;
    let failed = 0;
    let skipped = 0;

    for (const event of events) {
      const contractId = event.contractId ?? 'unknown';
      if (event.id) {
        const alreadyProcessed = await this.checkpointService.isEventProcessed(
          contractId,
          event.id,
        );
        if (alreadyProcessed) {
          skipped++;
          continue;
        }
      }

      const ok = await this.processEvent(event, options.skipCheckpoint);
      if (ok) {
        processed++;
      } else {
        failed++;
      }
    }

    return { processed, failed, skipped };
  }

  @TraceSpan('indexer.fetchEventsFromRange')
  async fetchEventsFromRange(
    startLedger: number,
    endLedger?: number,
    cursor?: string | null,
  ): Promise<SorobanEvent[]> {
    const rpcEvents = await this.stellarService.getEvents(
      startLedger,
      Array.from(this.contractIds),
      { endLedger, cursor: cursor ?? undefined },
    );

    return rpcEvents
      .map((e) => ({
        id: e.id,
        ledger: parseInt(e.ledger, 10),
        topic: e.topic,
        value: e.value,
        txHash: e.txHash,
        contractId: e.contractId,
      }))
      .sort((a, b) => {
        if (a.ledger !== b.ledger) {
          return a.ledger - b.ledger;
        }
        return (a.id ?? '').localeCompare(b.id ?? '');
      });
  }

  private async initializeIndexerState() {
    this.indexerState = await this.checkpointService.loadOrCreateState(
      this.streamId,
    );
  }

  private async loadContractIds() {
    const products = await this.savingsProductRepo.find({
      where: { isActive: true },
    });

    const newSet = new Set<string>();
    for (const p of products) {
      if (p.contractId) newSet.add(p.contractId);
    }

    this.contractIds.clear();
    for (const id of newSet) {
      this.contractIds.add(id);
    }
  }

  private async processEvent(
    event: SorobanEvent,
    skipCheckpoint = false,
  ): Promise<boolean> {
    try {
      await this.handleEvent(event);

      if (!skipCheckpoint && this.indexerState) {
        this.indexerState =
          await this.checkpointService.persistAfterSuccessfulEvent({
            streamId: this.streamId,
            lastProcessedLedger: event.ledger,
            lastProcessedEventCursor: event.id ?? null,
            totalEventsProcessed:
              Number(this.indexerState.totalEventsProcessed) + 1,
            totalEventsFailed: Number(this.indexerState.totalEventsFailed),
            eventId: event.id,
            contractId: event.contractId ?? 'unknown',
            transactionHash: event.txHash,
            eventType: this.resolveEventType(event),
            eventData: {
              topic: event.topic,
              value: event.value,
            },
          });
      }

      return true;
    } catch (err) {
      const msg = (err as Error).message;
      this.logger.error('IndexerService: event processing failed', {
        handlerName: 'IndexerService',
        eventId: event.id ?? `${event.ledger}-${event.txHash}`,
        ledgerSequence: event.ledger,
        contractId: event.contractId ?? 'unknown',
        error: msg,
      });

      await this.dlqRepo.save(
        this.dlqRepo.create({
          ledgerSequence: event.ledger,
          rawEvent: JSON.stringify(event),
          errorMessage: msg,
        }),
      );

      await this.checkpointService.recordFailure(this.streamId);
      if (this.indexerState) {
        this.indexerState.totalEventsFailed =
          Number(this.indexerState.totalEventsFailed) + 1;
      }

      return false;
    }
  }

  private async handleEvent(event: SorobanEvent): Promise<void> {
    if (await this.depositHandler.handle(event)) return;
    if (await this.withdrawHandler.handle(event)) return;
    if (await this.yieldHandler.handle(event)) return;

    this.logger.debug(`Unhandled event: ${JSON.stringify(event.topic)}`);
  }

  private async fetchEvents(): Promise<SorobanEvent[]> {
    if (!this.indexerState) return [];

    return this.fetchEventsFromRange(
      Number(this.indexerState.lastProcessedLedger) + 1,
      undefined,
      this.indexerState.lastProcessedEventCursor,
    );
  }

  private resolveEventType(event: SorobanEvent): string {
    const topic = event.topic?.[0];
    if (typeof topic === 'string') {
      return topic;
    }
    return 'unknown';
  }

  getIndexerState() {
    return this.indexerState;
  }

  getLastProcessedTimestamp(): number | null {
    return this.indexerState?.lastProcessedTimestamp ?? null;
  }

  getBackpressureStatus() {
    return this.backpressureService.getStatus();
  }

  async reloadContractIds() {
    await this.loadContractIds();
  }

  getMonitoredContracts(): string[] {
    return Array.from(this.contractIds);
  }

  async refreshState(): Promise<void> {
    this.indexerState = await this.checkpointService.loadOrCreateState(
      this.streamId,
    );
  }
}
