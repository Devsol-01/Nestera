import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Horizon, rpc } from '@stellar/stellar-sdk';
import { StellarService } from './stellar.service';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { IndexerState } from './entities/indexer-state.entity';
import {
  MedicalClaim,
  ClaimStatus,
} from '../claims/entities/medical-claim.entity';
import { RetryService } from './services/retry.service';

interface ContractEvent {
  id: string;
  type: string;
  ledger: number;
  ledgerClosedAt: string;
  contractId: string;
  pagingToken: string;
  topic: string[];
  value: any;
  inSuccessfulContractCall: boolean;
  txHash: string;
}

@Injectable()
export class StellarEventListenerService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(StellarEventListenerService.name);
  private isRunning = false;
  private pollingInterval: NodeJS.Timeout | null = null;
  private lastProcessedCursor: string | null = null;
  private lastProcessedLedger: number = 0;
  private readonly pollIntervalMs: number;
  private readonly contractId: string;
  private indexerState: IndexerState | null = null;

  constructor(
    private readonly stellarService: StellarService,
    private readonly configService: ConfigService,
    private readonly retryService: RetryService,
    @InjectRepository(ProcessedStellarEvent)
    private readonly processedEventRepository: Repository<ProcessedStellarEvent>,
    @InjectRepository(DeadLetterEvent)
    private readonly deadLetterEventRepository: Repository<DeadLetterEvent>,
    @InjectRepository(IndexerState)
    private readonly indexerStateRepository: Repository<IndexerState>,
    @InjectRepository(MedicalClaim)
    private readonly claimRepository: Repository<MedicalClaim>,
  ) {
    this.contractId =
      this.configService.get<string>('stellar.contractId') || '';
    this.pollIntervalMs = this.configService.get<number>(
      'stellar.eventPollInterval',
      10000,
    );
  }

  async onModuleInit() {
    if (!this.contractId) {
      this.logger.warn(
        'No CONTRACT_ID configured. Event listener will not start.',
      );
      return;
    }

    this.logger.log('Initializing Stellar Event Listener Service');
    await this.loadLastCursor();
    await this.startListening();
  }

  onModuleDestroy() {
    this.stopListening();
  }

  private async loadLastCursor(): Promise<void> {
    try {
      // Load IndexerState for ledger tracking
      this.indexerState = await this.indexerStateRepository.findOne({
        where: {},
      });
      if (!this.indexerState) {
        this.indexerState = this.indexerStateRepository.create({
          lastProcessedLedger: 0,
          lastProcessedTimestamp: null,
          totalEventsProcessed: 0,
          totalEventsFailed: 0,
        });
        this.indexerState = await this.indexerStateRepository.save(
          this.indexerState,
        );
      }

      this.lastProcessedLedger = this.indexerState.lastProcessedLedger;

      // Load last processed event cursor
      const lastEvent = await this.processedEventRepository.findOne({
        where: { contractId: this.contractId },
        order: { processedAt: 'DESC' },
      });

      if (lastEvent) {
        this.lastProcessedCursor = lastEvent.eventId;
        this.logger.log(
          `Resuming from cursor: ${this.lastProcessedCursor} (ledger: ${lastEvent.ledger})`,
        );
      } else {
        this.logger.log(
          'No previous cursor found. Starting from latest events.',
        );
      }
    } catch (error) {
      this.logger.error('Failed to load last cursor', error);
    }
  }

  async startListening(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('Event listener is already running');
      return;
    }

    this.isRunning = true;
    this.logger.log(`Starting event listener for contract: ${this.contractId}`);

    // Start polling immediately
    await this.pollEvents();

    // Set up recurring polling
    this.pollingInterval = setInterval(async () => {
      await this.pollEvents();
    }, this.pollIntervalMs);
  }

  stopListening(): void {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    this.isRunning = false;
    this.logger.log('Event listener stopped');
  }

  private async pollEvents(): Promise<void> {
    if (!this.isRunning) return;

    try {
      // First, attempt to process any failed events from DLQ
      await this.processRetryableEvents();

      const rpcServer = this.stellarService.getRpcServer();

      // Build request to get contract events
      const request: any = {
        filters: [
          {
            type: 'contract',
            contractIds: [this.contractId],
          },
        ],
        limit: 100,
      };

      // If we have a cursor, use it to get only new events
      if (this.lastProcessedCursor) {
        request.cursor = this.lastProcessedCursor;
      }

      const response = await rpcServer.getEvents(request);

      if (response.events && response.events.length > 0) {
        this.logger.log(`Fetched ${response.events.length} new events`);

        let processedInBatch = 0;
        let failedInBatch = 0;

        for (const event of response.events) {
          const success = await this.processEvent(event);
          if (success) {
            processedInBatch++;
          } else {
            failedInBatch++;
          }
        }

        // Update cursor to the last event's ID
        const lastEvent = response.events[response.events.length - 1];
        this.lastProcessedCursor = lastEvent.id;

        // Update indexer state with last processed ledger
        if (this.indexerState) {
          this.indexerState.lastProcessedLedger = lastEvent.ledger;
          this.indexerState.lastProcessedTimestamp = Date.now();
          this.indexerState.totalEventsProcessed += processedInBatch;
          this.indexerState.totalEventsFailed += failedInBatch;
          this.indexerState.updatedAt = new Date();
          await this.saveIndexerState();
        }
      }
    } catch (error) {
      this.logger.error('Error polling events', error);
    }
  }

  private async processEvent(event: rpc.Api.EventResponse): Promise<boolean> {
    const eventId = event.id;

    try {
      // Check if event already processed (idempotency)
      const existing = await this.processedEventRepository.findOne({
        where: { eventId },
      });

      if (existing) {
        this.logger.debug(`Event ${eventId} already processed, skipping`);
        return true;
      }

      // Parse event topics and value
      const topics = event.topic.map((topic) => topic.toXDR('base64'));
      const eventType = this.parseEventType(topics);

      this.logger.log(`Processing event: ${eventType} (${eventId})`);

      // Handle different event types
      if (
        eventType === 'AdjudicationComplete' ||
        eventType === 'ClaimStatusUpdated'
      ) {
        await this.handleClaimStatusUpdate(event, eventType);
      }

      // Record that we processed this event
      await this.recordProcessedEvent(event, eventType);
      return true;
    } catch (error) {
      this.logger.error(`Failed to process event ${eventId}`, error);

      // Save failed event to DLQ
      await this.saveToDLQ(event, error);

      return false;
    }
  }

  private parseEventType(topics: string[]): string {
    // The first topic typically contains the event name
    // This is a simplified parser - adjust based on your contract's event structure
    if (topics.length === 0) return 'Unknown';

    try {
      // Decode the first topic which usually contains the event name
      const firstTopic = Buffer.from(topics[0], 'base64').toString('utf-8');
      return firstTopic.replace(/\0/g, '').trim() || 'Unknown';
    } catch (error) {
      this.logger.warn('Failed to parse event type', error);
      return 'Unknown';
    }
  }

  private async handleClaimStatusUpdate(
    event: rpc.Api.EventResponse,
    eventType: string,
  ): Promise<void> {
    try {
      // Parse event data to extract claim ID and new status
      const eventData = this.parseEventData(event);

      const claimId = eventData.claimId || eventData.claim_id;
      const newStatus = eventData.status || eventData.newStatus;

      if (!claimId) {
        this.logger.warn(`Event ${event.id} missing claimId`);
        return;
      }

      // Find the claim in database
      const claim = await this.claimRepository.findOne({
        where: { id: claimId },
      });

      if (!claim) {
        this.logger.warn(`Claim ${claimId} not found in database`);
        return;
      }

      // Map contract status to our enum
      const mappedStatus = this.mapContractStatusToClaimStatus(newStatus);

      if (claim.status !== mappedStatus) {
        const oldStatus = claim.status;
        claim.status = mappedStatus;
        claim.blockchainTxHash = event.txHash || null;
        claim.notes = `Status updated from ${oldStatus} to ${mappedStatus} via blockchain event ${event.id}`;

        await this.claimRepository.save(claim);

        this.logger.log(
          `Updated claim ${claimId} status from ${oldStatus} to ${mappedStatus}`,
        );
      } else {
        this.logger.debug(
          `Claim ${claimId} already has status ${mappedStatus}`,
        );
      }
    } catch (error) {
      this.logger.error('Failed to handle claim status update', error);
      throw error;
    }
  }

  private parseEventData(event: rpc.Api.EventResponse): Record<string, any> {
    try {
      // Parse the event value which contains the event data
      const value = event.value.toXDR('base64');
      const decoded = Buffer.from(value, 'base64');

      // This is a simplified parser - adjust based on your contract's event structure
      // You may need to use Stellar SDK's XDR parsing utilities
      return {
        claimId: this.extractClaimIdFromEvent(event),
        status: this.extractStatusFromEvent(event),
        rawValue: value,
      };
    } catch (error) {
      this.logger.error('Failed to parse event data', error);
      return {};
    }
  }

  private extractClaimIdFromEvent(event: rpc.Api.EventResponse): string | null {
    try {
      // Extract claim ID from event topics or value
      // This depends on your contract's event structure
      // Example: claim ID might be in the second topic
      if (event.topic.length > 1) {
        const claimIdTopic = event.topic[1].toXDR('base64');
        const decoded = Buffer.from(claimIdTopic, 'base64').toString('utf-8');
        return decoded.replace(/\0/g, '').trim();
      }
      return null;
    } catch (error) {
      this.logger.warn('Failed to extract claim ID', error);
      return null;
    }
  }

  private extractStatusFromEvent(event: rpc.Api.EventResponse): string | null {
    try {
      // Extract status from event topics or value
      // This depends on your contract's event structure
      if (event.topic.length > 2) {
        const statusTopic = event.topic[2].toXDR('base64');
        const decoded = Buffer.from(statusTopic, 'base64').toString('utf-8');
        return decoded.replace(/\0/g, '').trim();
      }
      return null;
    } catch (error) {
      this.logger.warn('Failed to extract status', error);
      return null;
    }
  }

  private mapContractStatusToClaimStatus(
    contractStatus: string | null,
  ): ClaimStatus {
    if (!contractStatus) return ClaimStatus.PROCESSING;

    const statusMap: Record<string, ClaimStatus> = {
      approved: ClaimStatus.APPROVED,
      rejected: ClaimStatus.REJECTED,
      pending: ClaimStatus.PENDING,
      processing: ClaimStatus.PROCESSING,
      APPROVED: ClaimStatus.APPROVED,
      REJECTED: ClaimStatus.REJECTED,
      PENDING: ClaimStatus.PENDING,
      PROCESSING: ClaimStatus.PROCESSING,
    };

    return statusMap[contractStatus] || ClaimStatus.PROCESSING;
  }

  private async recordProcessedEvent(
    event: rpc.Api.EventResponse,
    eventType: string,
  ): Promise<void> {
    const processedEvent = this.processedEventRepository.create({
      eventId: event.id,
      contractId: this.contractId,
      transactionHash: event.txHash || 'unknown',
      ledger: event.ledger,
      eventType,
      eventData: {
        topics: event.topic.map((t) => t.toXDR('base64')),
        value: event.value.toXDR('base64'),
        inSuccessfulContractCall: event.inSuccessfulContractCall,
      },
      claimId: this.extractClaimIdFromEvent(event),
    });

    await this.processedEventRepository.save(processedEvent);
  }

  /**
   * Process events from the Dead Letter Queue that are ready for retry
   */
  private async processRetryableEvents(): Promise<number> {
    const retryableEvents = await this.retryService.getRetryableEvents();
    let retried = 0;

    for (const dlqEvent of retryableEvents) {
      try {
        const event = JSON.parse(dlqEvent.rawEvent) as rpc.Api.EventResponse;

        this.logger.log(
          `Retrying event from DLQ (${dlqEvent.id}, ledger ${dlqEvent.ledgerSequence}, attempt ${dlqEvent.retryCount + 1})`,
        );

        const success = await this.processEvent(event);

        if (success) {
          await this.retryService.markSuccessful(dlqEvent.id);
          this.logger.log(`Successfully reprocessed DLQ event ${dlqEvent.id}`);
          retried++;
        } else {
          // Schedule next retry
          await this.retryService.scheduleRetry(dlqEvent);
        }
      } catch (error) {
        this.logger.error(
          `Error during DLQ retry for event ${dlqEvent.id}`,
          error,
        );
        await this.retryService.scheduleRetry(dlqEvent);
      }
    }

    return retried;
  }

  private async saveIndexerState(): Promise<void> {
    if (this.indexerState) {
      await this.indexerStateRepository.save(this.indexerState);
    }
  }

  /**
   * Save failed event to Dead Letter Queue
   */
  private async saveToDLQ(
    event: rpc.Api.EventResponse,
    error: unknown,
  ): Promise<void> {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Check if event already exists in DLQ
    const existing = await this.deadLetterEventRepository.findOne({
      where: { ledgerSequence: event.ledger },
    });

    if (existing) {
      this.logger.debug(
        `DLQ entry already exists for ledger ${event.ledger}, updating retry info`,
      );
      await this.retryService.scheduleRetry(existing);
      return;
    }

    // Create new DLQ entry
    const dlqEntry = this.deadLetterEventRepository.create({
      ledgerSequence: event.ledger,
      rawEvent: JSON.stringify(event),
      errorMessage,
      retryCount: 0,
      nextRetryAt: null,
    });

    await this.deadLetterEventRepository.save(dlqEntry);
    this.logger.error(
      `Event ${event.id} (ledger ${event.ledger}) failed and saved to DLQ: ${errorMessage}`,
    );
  }

  /**
   * Manually trigger retry processing for all failed events in DLQ
   */
  async triggerDLQRetry(): Promise<{
    processed: number;
    failed: number;
    remaining: number;
  }> {
    this.logger.log('Manual DLQ retry triggered');

    const retryable = await this.retryService.getRetryableEvents();
    let processed = 0;
    let failed = 0;

    for (const dlqEvent of retryable) {
      try {
        const event = JSON.parse(dlqEvent.rawEvent) as rpc.Api.EventResponse;
        const success = await this.processEvent(event);

        if (success) {
          await this.retryService.markSuccessful(dlqEvent.id);
          processed++;
        } else {
          await this.retryService.scheduleRetry(dlqEvent);
          failed++;
        }
      } catch (error) {
        this.logger.error(
          `Error during manual retry for ${dlqEvent.id}`,
          error,
        );
        await this.retryService.scheduleRetry(dlqEvent);
        failed++;
      }
    }

    const remaining =
      (await this.deadLetterEventRepository.count()) - processed;

    return { processed, failed, remaining };
  }

  // Manual trigger for testing/admin purposes
  async triggerManualSync(): Promise<{ processed: number; errors: number }> {
    this.logger.log('Manual sync triggered');

    let processed = 0;
    let errors = 0;

    try {
      await this.pollEvents();
      processed++;
    } catch (error) {
      errors++;
      this.logger.error('Manual sync failed', error);
    }

    return { processed, errors };
  }

  /**
   * Replay events starting from a specific ledger number
   */
  async replayFromLedger(
    fromLedger: number,
    toLedger?: number,
  ): Promise<{ replayed: number; skipped: number }> {
    this.logger.log(
      `Replaying events from ledger ${fromLedger}${toLedger ? ` to ${toLedger}` : ''}`,
    );

    let replayed = 0;
    let skipped = 0;

    try {
      const rpcServer = this.stellarService.getRpcServer();

      // Fetch events from the specified ledger range
      const request: any = {
        filters: [
          {
            type: 'contract',
            contractIds: [this.contractId],
          },
        ],
        limit: 100,
      };

      // Use cursor starting from the fromLedger
      // Since we can't directly filter by ledger in the RPC call,
      // we need to start from the cursor that corresponds to fromLedger
      // For simplicity, we'll fetch events and filter by ledger

      // Start from beginning if we need to go back
      const cursor = this.lastProcessedCursor;
      if (!cursor) {
        this.logger.warn(
          'No cursor available for replay, starting from latest',
        );
        return { replayed: 0, skipped: 0 };
      }

      // Get events from cursor - will need to loop through until we hit fromLedger
      // This is a simplified implementation - in production you'd want pagination
      const response = await rpcServer.getEvents({
        ...request,
        cursor,
      });

      if (!response.events || response.events.length === 0) {
        return { replayed: 0, skipped: 0 };
      }

      // Find the starting index for fromLedger
      let startIdx = response.events.findIndex((e) => e.ledger >= fromLedger);

      if (startIdx === -1) startIdx = 0;

      const eventsToProcess = toLedger
        ? response.events.filter(
            (e) => e.ledger >= fromLedger && e.ledger <= toLedger,
          )
        : response.events.slice(startIdx);

      for (const event of eventsToProcess) {
        // Check if already processed
        const existing = await this.processedEventRepository.findOne({
          where: { eventId: event.id },
        });

        if (existing) {
          skipped++;
          continue;
        }

        const success = await this.processEvent(event);
        if (success) {
          replayed++;
        } else {
          skipped++;
        }
      }

      this.logger.log(
        `Replay complete: ${replayed} replayed, ${skipped} skipped`,
      );
    } catch (error) {
      this.logger.error('Error during replay', error);
      throw error;
    }

    return { replayed, skipped };
  }

  /**
   * Get DLQ statistics
   */
  async getDLQStats(): Promise<{
    total: number;
    retryable: number;
    maxRetriesReached: number;
    avgRetryCount: number;
    recent: Array<{
      id: string;
      ledgerSequence: number;
      errorMessage: string;
      retryCount: number;
      nextRetryAt: Date | null;
      createdAt: Date;
    }>;
  }> {
    const stats = await this.retryService.getRetryStats();
    const recent = await this.deadLetterEventRepository.find({
      order: { createdAt: 'DESC' },
      take: 10,
    });

    return {
      ...stats,
      recent,
    };
  }

  /**
   * Find a specific DLQ entry by ID
   */
  async findDLQEntry(id: string): Promise<any> {
    return this.deadLetterEventRepository.findOne({
      where: { id },
    });
  }

  /**
   * Delete a DLQ entry
   */
  async deleteDLQEntry(id: string): Promise<boolean> {
    const result = await this.deadLetterEventRepository.delete(id);
    return (result.affected ?? 0) > 0;
  }

  /**
   * Get comprehensive metrics
   */
  async getMetrics(): Promise<{
    eventListener: {
      isRunning: boolean;
      contractId: string;
      totalProcessed: number;
      totalFailed: number;
      lastLedger: number;
    };
    dlq: {
      total: number;
      retryable: number;
      avgRetryCount: number;
    };
  }> {
    const status = this.getStatus();
    const dlqStats = await this.retryService.getRetryStats();

    return {
      eventListener: {
        isRunning: status.isRunning,
        contractId: status.contractId,
        totalProcessed: status.totalProcessed,
        totalFailed: status.totalFailed,
        lastLedger: status.lastLedger,
      },
      dlq: {
        total: dlqStats.total,
        retryable: dlqStats.retryable,
        avgRetryCount: dlqStats.avgRetryCount,
      },
    };
  }

  getStatus(): {
    isRunning: boolean;
    contractId: string;
    lastCursor: string | null;
    lastLedger: number;
    pollInterval: number;
    totalProcessed: number;
    totalFailed: number;
  } {
    return {
      isRunning: this.isRunning,
      contractId: this.contractId,
      lastCursor: this.lastProcessedCursor,
      lastLedger: this.lastProcessedLedger,
      pollInterval: this.pollIntervalMs,
      totalProcessed: this.indexerState?.totalEventsProcessed ?? 0,
      totalFailed: this.indexerState?.totalEventsFailed ?? 0,
    };
  }
}
