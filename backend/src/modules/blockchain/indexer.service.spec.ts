import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { IndexerService } from './indexer.service';
import { IndexerState } from './entities/indexer-state.entity';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { ReorgAuditLog } from './entities/reorg-audit-log.entity';
import { ReorgAffectedTransaction } from './entities/reorg-affected-transaction.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { StellarService } from './stellar.service';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';
import { MailService } from '../mail/mail.service';
import { User } from '../user/entities/user.entity';
import { LedgerTransaction } from './entities/transaction.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';

describe('IndexerService', () => {
  let service: IndexerService;
  let stellarService: StellarService;
  let indexerStateRepo: any;
  let processedEventRepo: any;
  let reorgAuditLogRepo: any;
  let reorgAffectedTxRepo: any;
  let savingsProductRepo: any;
  let deadLetterRepo: any;
  let userRepo: any;
  let txRepo: any;
  let subscriptionRepo: any;
  let depositHandler: any;
  let withdrawHandler: any;
  let yieldHandler: any;
  let mailService: any;

  const mockIndexerState = {
    id: 'uuid',
    lastProcessedLedger: 100,
    totalEventsProcessed: 0,
    totalEventsFailed: 0,
    updatedAt: new Date(),
  };

  const mockSavingsProducts = [
    { contractId: 'CC1', isActive: true },
    { contractId: 'CC2', isActive: true },
  ];

  beforeEach(async () => {
    indexerStateRepo = {
      findOne: jest.fn().mockResolvedValue(mockIndexerState),
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      create: jest.fn().mockImplementation((val) => val),
    };

    processedEventRepo = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      create: jest.fn().mockImplementation((val) => val),
      createQueryBuilder: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      groupBy: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      getMany: jest.fn().mockResolvedValue([]),
    };

    reorgAuditLogRepo = {
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      create: jest.fn().mockImplementation((val) => val),
    };

    reorgAffectedTxRepo = {
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      create: jest.fn().mockImplementation((val) => val),
    };

    savingsProductRepo = {
      find: jest.fn().mockResolvedValue(mockSavingsProducts),
    };

    deadLetterRepo = {
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      create: jest.fn().mockImplementation((val) => val),
    };

    userRepo = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
    };

    txRepo = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
      delete: jest.fn().mockResolvedValue(undefined),
      createQueryBuilder: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    subscriptionRepo = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
      save: jest.fn().mockImplementation((val) => Promise.resolve(val)),
      createQueryBuilder: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 1 }),
      decrement: jest.fn().mockReturnThis(),
      increment: jest.fn().mockReturnThis(),
    };

    stellarService = {
      getRpcServer: jest.fn().mockReturnValue({
        getEvents: jest.fn(),
      }),
      getEvents: jest.fn(),
      getLedgers: jest.fn(),
    } as any;

    depositHandler = { 
      handle: jest.fn().mockResolvedValue(true),
      isDepositTopic: jest.fn(),
    };
    withdrawHandler = { 
      handle: jest.fn().mockResolvedValue(false),
      isWithdrawTopic: jest.fn(),
    };
    yieldHandler = { 
      handle: jest.fn().mockResolvedValue(false),
      isYieldTopic: jest.fn(),
    };
    mailService = { sendRawMail: jest.fn().mockResolvedValue(undefined) };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IndexerService,
        { provide: ConfigService, useValue: { get: jest.fn() } },
        { provide: StellarService, useValue: stellarService },
        { provide: DataSource, useValue: {} },
        {
          provide: getRepositoryToken(IndexerState),
          useValue: indexerStateRepo,
        },
        {
          provide: getRepositoryToken(ProcessedStellarEvent),
          useValue: processedEventRepo,
        },
        {
          provide: getRepositoryToken(ReorgAuditLog),
          useValue: reorgAuditLogRepo,
        },
        {
          provide: getRepositoryToken(ReorgAffectedTransaction),
          useValue: reorgAffectedTxRepo,
        },
        {
          provide: getRepositoryToken(SavingsProduct),
          useValue: savingsProductRepo,
        },
        {
          provide: getRepositoryToken(DeadLetterEvent),
          useValue: deadLetterRepo,
        },
        {
          provide: getRepositoryToken(User),
          useValue: userRepo,
        },
        {
          provide: getRepositoryToken(LedgerTransaction),
          useValue: txRepo,
        },
        {
          provide: getRepositoryToken(UserSubscription),
          useValue: subscriptionRepo,
        },
        { provide: DepositHandler, useValue: depositHandler },
        { provide: WithdrawHandler, useValue: withdrawHandler },
        { provide: YieldHandler, useValue: yieldHandler },
        { provide: MailService, useValue: mailService },
      ],
    }).compile();

    service = module.get<IndexerService>(IndexerService);
    // Suppress logger output during tests
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => null);
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => null);
    jest.spyOn(Logger.prototype, 'debug').mockImplementation(() => null);
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => null);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('onModuleInit', () => {
    it('should initialize state and load contract IDs', async () => {
      await service.onModuleInit();
      expect(indexerStateRepo.findOne).toHaveBeenCalled();
      expect(savingsProductRepo.find).toHaveBeenCalledWith({
        where: { isActive: true },
      });
      expect(service.getMonitoredContracts()).toContain('CC1');
      expect(service.getMonitoredContracts()).toContain('CC2');
    });
  });

  describe('runIndexerCycle', () => {
    beforeEach(async () => {
      await service.onModuleInit();
    });

    it('should fetch and process events successfully', async () => {
      const mockEvents = [
        {
          id: '1',
          ledger: '101',
          topic: ['deposit'],
          value: '100',
          txHash: 'hash1',
        },
      ];
      (stellarService.getEvents as jest.Mock).mockResolvedValue(mockEvents);
      (stellarService.getLedgers as jest.Mock).mockResolvedValue({});

      await service.runIndexerCycle();

      expect(stellarService.getEvents).toHaveBeenCalledWith(101, [
        'CC1',
        'CC2',
      ]);
      expect(depositHandler.handle).toHaveBeenCalled();
      expect(indexerStateRepo.save).toHaveBeenCalled();
      expect(service.getIndexerState()?.lastProcessedLedger).toBe(101);
    });

    it('should persist processed event after successful handling', async () => {
      const mockEvents = [
        {
          id: 'test-event',
          ledger: '101',
          topic: ['deposit'],
          value: '100',
          txHash: 'hash1',
        },
      ];
      (stellarService.getEvents as jest.Mock).mockResolvedValue(mockEvents);
      (stellarService.getLedgers as jest.Mock).mockResolvedValue({ 101: { hash: 'abc123', previousHash: 'def456' } });
      processedEventRepo.findOne.mockResolvedValue(null);

      await service.runIndexerCycle();

      expect(processedEventRepo.save).toHaveBeenCalled();
    });

    it('should handle failed events by logging to dead letter queue', async () => {
      const mockEvents = [
        {
          id: '1',
          ledger: '101',
          topic: ['deposit'],
          value: 'fail',
          txHash: 'hash1',
        },
      ];
      (stellarService.getEvents as jest.Mock).mockResolvedValue(mockEvents);
      (stellarService.getLedgers as jest.Mock).mockResolvedValue({});
      depositHandler.handle.mockRejectedValue(new Error('Processing failed'));

      await service.runIndexerCycle();

      expect(deadLetterRepo.save).toHaveBeenCalled();
      expect(service.getIndexerState()?.totalEventsFailed).toBe(1);
    });

    it('should skip cycle if no active contracts', async () => {
      savingsProductRepo.find.mockResolvedValue([]);
      await service.runIndexerCycle();
      expect(stellarService.getEvents).not.toHaveBeenCalled();
    });
  });

  describe('detectAndHandleReorgs', () => {
    beforeEach(async () => {
      await service.onModuleInit();
    });

    it('should detect no reorgs when ledger hashes match', async () => {
      processedEventRepo.createQueryBuilder.mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        groupBy: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([
          { ledger: 100, ledgerHash: 'abc123' } as any,
        ]),
      } as any);
      (stellarService.getLedgers as jest.Mock).mockResolvedValue({
        100: { hash: 'abc123', previousHash: 'def456' },
      });

      await (service as any).detectAndHandleReorgs();

      expect(reorgAuditLogRepo.save).not.toHaveBeenCalled();
    });

    it('should detect and handle reorg when ledger hash has changed', async () => {
      processedEventRepo.find.mockResolvedValue([]);
      processedEventRepo.createQueryBuilder.mockReturnValue({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        groupBy: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([
          { ledger: 100, ledgerHash: 'old-hash', isReorged: false } as any,
          { ledger: 101, ledgerHash: 'old-hash-2', isReorged: false } as any,
        ]),
      } as any);
      (stellarService.getLedgers as jest.Mock).mockResolvedValue({
        100: { hash: 'new-hash', previousHash: 'def456' },
        101: { hash: 'new-hash-2', previousHash: 'abc123' },
      });
      processedEventRepo.save.mockImplementation((val: any) => Promise.resolve(val));
      processedEventRepo.delete = jest.fn().mockResolvedValue({} as any);
      subscriptionRepo.find.mockResolvedValue([]);
      userRepo.find.mockResolvedValue([]);
      reorgAffectedTxRepo.save.mockImplementation((val: any) => Promise.resolve(val));
      (stellarService.getEvents as jest.Mock).mockResolvedValue([]);

      await (service as any).detectAndHandleReorgs();

      expect(reorgAuditLogRepo.save).toHaveBeenCalled();
    });
  });
});