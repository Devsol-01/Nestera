import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Horizon, rpc } from '@stellar/stellar-sdk';
import { StellarService } from './stellar.service';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { MedicalClaim, ClaimStatus } from '../claims/entities/medical-claim.entity';

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
export class StellarEventListenerService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(StellarEventListenerService.name);
    private isRunning = false;
    private pollingInterval: NodeJS.Timeout | null = null;
    private lastProcessedCursor: string | null = null;
    private readonly pollIntervalMs: number;
    private readonly contractId: string;

    constructor(
        private readonly stellarService: StellarService,
        private readonly configService: ConfigService,
        @InjectRepository(ProcessedStellarEvent)
        private readonly processedEventRepository: Repository<ProcessedStellarEvent>,
        @InjectRepository(MedicalClaim)
        private readonly claimRepository: Repository<MedicalClaim>,
    ) {
        this.contractId = this.configService.get<string>('stellar.contractId') || '';
        this.pollIntervalMs = this.configService.get<number>('stellar.eventPollInterval', 10000);
    }

    async onModuleInit() {
        if (!this.contractId) {
            this.logger.warn('No CONTRACT_ID configured. Event listener will not start.');
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
            const lastEvent = await this.processedEventRepository.findOne({
                where: { contractId: this.contractId },
                order: { processedAt: 'DESC' },
            });

            if (lastEvent) {
                this.lastProcessedCursor = lastEvent.eventId;
                this.logger.log(`Resuming from cursor: ${this.lastProcessedCursor}`);
            } else {
                this.logger.log('No previous cursor found. Starting from latest events.');
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

                for (const event of response.events) {
                    await this.processEvent(event);
                }

                // Update cursor to the last event's ID
                const lastEvent = response.events[response.events.length - 1];
                this.lastProcessedCursor = lastEvent.id;
            }
        } catch (error) {
            this.logger.error('Error polling events', error);
        }
    }

    private async processEvent(event: rpc.Api.EventResponse): Promise<void> {
        const eventId = event.id;

        try {
            // Check if event already processed (idempotency)
            const existing = await this.processedEventRepository.findOne({
                where: { eventId },
            });

            if (existing) {
                this.logger.debug(`Event ${eventId} already processed, skipping`);
                return;
            }

            // Parse event topics and value
            const topics = event.topic.map((topic) => topic.toXDR('base64'));
            const eventType = this.parseEventType(topics);

            this.logger.log(`Processing event: ${eventType} (${eventId})`);

            // Handle different event types
            if (eventType === 'AdjudicationComplete' || eventType === 'ClaimStatusUpdated') {
                await this.handleClaimStatusUpdate(event, eventType);
            }

            // Record that we processed this event
            await this.recordProcessedEvent(event, eventType);
        } catch (error) {
            this.logger.error(`Failed to process event ${eventId}`, error);
            // Don't throw - continue processing other events
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
                this.logger.debug(`Claim ${claimId} already has status ${mappedStatus}`);
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

    private mapContractStatusToClaimStatus(contractStatus: string | null): ClaimStatus {
        if (!contractStatus) return ClaimStatus.PROCESSING;

        const statusMap: Record<string, ClaimStatus> = {
            'approved': ClaimStatus.APPROVED,
            'rejected': ClaimStatus.REJECTED,
            'pending': ClaimStatus.PENDING,
            'processing': ClaimStatus.PROCESSING,
            'APPROVED': ClaimStatus.APPROVED,
            'REJECTED': ClaimStatus.REJECTED,
            'PENDING': ClaimStatus.PENDING,
            'PROCESSING': ClaimStatus.PROCESSING,
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

    getStatus(): {
        isRunning: boolean;
        contractId: string;
        lastCursor: string | null;
        pollInterval: number;
    } {
        return {
            isRunning: this.isRunning,
            contractId: this.contractId,
            lastCursor: this.lastProcessedCursor,
            pollInterval: this.pollIntervalMs,
        };
    }
}
