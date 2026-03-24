import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { StellarEventListenerService } from './stellar-event-listener.service';
import { StellarService } from './stellar.service';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { MedicalClaim, ClaimStatus } from '../claims/entities/medical-claim.entity';

describe('StellarEventListenerService', () => {
    let service: StellarEventListenerService;
    let stellarService: StellarService;
    let processedEventRepository: Repository<ProcessedStellarEvent>;
    let claimRepository: Repository<MedicalClaim>;

    const mockStellarService = {
        getRpcServer: jest.fn(),
        getHorizonServer: jest.fn(),
    };

    const mockProcessedEventRepository = {
        findOne: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
    };

    const mockClaimRepository = {
        findOne: jest.fn(),
        save: jest.fn(),
    };

    const mockConfigService = {
        get: jest.fn((key: string, defaultValue?: any) => {
            const config = {
                'stellar.contractId': 'test-contract-id',
                'stellar.eventPollInterval': 5000,
            };
            return config[key] ?? defaultValue;
        }),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                StellarEventListenerService,
                {
                    provide: StellarService,
                    useValue: mockStellarService,
                },
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: getRepositoryToken(ProcessedStellarEvent),
                    useValue: mockProcessedEventRepository,
                },
                {
                    provide: getRepositoryToken(MedicalClaim),
                    useValue: mockClaimRepository,
                },
            ],
        }).compile();

        service = module.get<StellarEventListenerService>(StellarEventListenerService);
        stellarService = module.get<StellarService>(StellarService);
        processedEventRepository = module.get<Repository<ProcessedStellarEvent>>(
            getRepositoryToken(ProcessedStellarEvent),
        );
        claimRepository = module.get<Repository<MedicalClaim>>(
            getRepositoryToken(MedicalClaim),
        );
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('getStatus', () => {
        it('should return listener status', () => {
            const status = service.getStatus();

            expect(status).toHaveProperty('isRunning');
            expect(status).toHaveProperty('contractId');
            expect(status).toHaveProperty('lastCursor');
            expect(status).toHaveProperty('pollInterval');
            expect(status.contractId).toBe('test-contract-id');
        });
    });

    describe('stopListening', () => {
        it('should stop the event listener', () => {
            service.stopListening();
            const status = service.getStatus();

            expect(status.isRunning).toBe(false);
        });
    });

    describe('idempotency', () => {
        it('should not process the same event twice', async () => {
            const mockEvent = {
                id: 'event-123',
                ledger: 12345,
                txHash: 'tx-hash-123',
                topic: [],
                value: { toXDR: () => 'value' },
                inSuccessfulContractCall: true,
                pagingToken: 'token-123',
            };

            // Simulate event already processed
            mockProcessedEventRepository.findOne.mockResolvedValue({
                eventId: 'event-123',
            });

            // This should not throw and should skip processing
            await service['processEvent'](mockEvent as any);

            // Verify we didn't try to save a new processed event
            expect(mockProcessedEventRepository.save).not.toHaveBeenCalled();
        });
    });
});
