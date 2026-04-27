import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { GovernanceService } from './governance.service';
import {
  GovernanceProposal,
  ProposalStatus,
} from './entities/governance-proposal.entity';
import { Vote } from './entities/vote.entity';
import { Delegation } from './entities/delegation.entity';
import { UserService } from '../user/user.service';
import { StellarService } from '../blockchain/stellar.service';
import { SavingsService } from '../blockchain/savings.service';
import { TransactionsService } from '../transactions/transactions.service';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';

const mockRepo = () => ({
  findOneBy: jest.fn(),
  findOne: jest.fn(),
  find: jest.fn(),
  save: jest.fn(),
  delete: jest.fn(),
  upsert: jest.fn(),
  count: jest.fn(),
  create: jest.fn((v) => v),
  createQueryBuilder: jest.fn(),
  findAndCount: jest.fn(),
});

describe('GovernanceService – lifecycle & delegation', () => {
  let service: GovernanceService;
  let proposalRepo: ReturnType<typeof mockRepo>;
  let delegationRepo: ReturnType<typeof mockRepo>;
  let voteRepo: ReturnType<typeof mockRepo>;
  let userService: { findById: jest.Mock };
  let stellarService: {
    getDelegationForUser: jest.Mock;
    getRpcServer: jest.Mock;
  };
  let eventEmitter: { emit: jest.Mock };

  const baseProposal = (overrides = {}): Partial<GovernanceProposal> => ({
    id: 'prop-1',
    onChainId: 1,
    title: 'Test',
    description: 'desc',
    status: ProposalStatus.PASSED,
    createdByUserId: 'user-1',
    timelockEndsAt: null,
    executedAt: null,
    startBlock: 100,
    endBlock: 200,
    attachments: [],
    requiredQuorum: '0',
    quorumBps: 5000,
    proposalThreshold: '100',
    ...overrides,
  });

  beforeEach(async () => {
    proposalRepo = mockRepo();
    delegationRepo = mockRepo();
    voteRepo = mockRepo();
    userService = { findById: jest.fn() };
    stellarService = {
      getDelegationForUser: jest.fn(),
      getRpcServer: jest.fn().mockReturnValue({
        getLatestLedger: jest.fn().mockResolvedValue({ sequence: 1000 }),
      }),
    };
    eventEmitter = { emit: jest.fn() };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GovernanceService,
        { provide: UserService, useValue: userService },
        { provide: StellarService, useValue: stellarService },
        {
          provide: SavingsService,
          useValue: {
            getUserVaultBalance: jest.fn().mockResolvedValue(1_000_000_000),
          },
        },
        { provide: TransactionsService, useValue: {} },
        { provide: EventEmitter2, useValue: eventEmitter },
        {
          provide: getRepositoryToken(GovernanceProposal),
          useValue: proposalRepo,
        },
        { provide: getRepositoryToken(Vote), useValue: voteRepo },
        { provide: getRepositoryToken(Delegation), useValue: delegationRepo },
        {
          provide: getRepositoryToken(LedgerTransaction),
          useValue: mockRepo(),
        },
      ],
    }).compile();

    service = module.get<GovernanceService>(GovernanceService);
  });

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  describe('getProposalStatus', () => {
    it('returns status for existing proposal', async () => {
      proposalRepo.findOneBy.mockResolvedValue(baseProposal());
      const result = await service.getProposalStatus('prop-1');
      expect(result.status).toBe(ProposalStatus.PASSED);
    });

    it('throws NotFoundException for unknown proposal', async () => {
      proposalRepo.findOneBy.mockResolvedValue(null);
      await expect(service.getProposalStatus('bad')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('queueProposal', () => {
    it('queues a passed proposal and sets timelockEndsAt', async () => {
      const proposal = baseProposal({ status: ProposalStatus.PASSED });
      proposalRepo.findOneBy.mockResolvedValue(proposal);
      proposalRepo.save.mockResolvedValue({
        ...proposal,
        status: ProposalStatus.QUEUED,
        timelockEndsAt: new Date(),
      });

      const result = await service.queueProposal('prop-1', 'user-1');
      expect(result.status).toBe(ProposalStatus.QUEUED);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'governance.proposal.queued',
        expect.any(Object),
      );
    });

    it('throws if proposal is not in Passed state', async () => {
      proposalRepo.findOneBy.mockResolvedValue(
        baseProposal({ status: ProposalStatus.ACTIVE }),
      );
      await expect(service.queueProposal('prop-1', 'user-1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('executeProposal', () => {
    it('executes a queued proposal after timelock', async () => {
      const past = new Date(Date.now() - 1000);
      const proposal = baseProposal({
        status: ProposalStatus.QUEUED,
        timelockEndsAt: past,
      });
      proposalRepo.findOneBy.mockResolvedValue(proposal);
      proposalRepo.save.mockResolvedValue({
        ...proposal,
        status: ProposalStatus.EXECUTED,
        executedAt: new Date(),
      });

      const result = await service.executeProposal('prop-1', 'user-1');
      expect(result.status).toBe(ProposalStatus.EXECUTED);
    });

    it('throws if timelock has not elapsed', async () => {
      const future = new Date(Date.now() + 100_000);
      proposalRepo.findOneBy.mockResolvedValue(
        baseProposal({ status: ProposalStatus.QUEUED, timelockEndsAt: future }),
      );
      await expect(service.executeProposal('prop-1', 'user-1')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws if proposal is not queued', async () => {
      proposalRepo.findOneBy.mockResolvedValue(
        baseProposal({ status: ProposalStatus.PASSED }),
      );
      await expect(service.executeProposal('prop-1', 'user-1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('cancelProposal', () => {
    it('cancels a proposal by its creator', async () => {
      const proposal = baseProposal({
        status: ProposalStatus.ACTIVE,
        createdByUserId: 'user-1',
      });
      proposalRepo.findOneBy.mockResolvedValue(proposal);
      proposalRepo.save.mockResolvedValue({
        ...proposal,
        status: ProposalStatus.CANCELLED,
      });

      const result = await service.cancelProposal('prop-1', 'user-1');
      expect(result.status).toBe(ProposalStatus.CANCELLED);
    });

    it('throws ForbiddenException for non-creator', async () => {
      proposalRepo.findOneBy.mockResolvedValue(
        baseProposal({ createdByUserId: 'other-user' }),
      );
      await expect(service.cancelProposal('prop-1', 'user-1')).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('throws if already executed', async () => {
      proposalRepo.findOneBy.mockResolvedValue(
        baseProposal({
          status: ProposalStatus.EXECUTED,
          createdByUserId: 'user-1',
        }),
      );
      await expect(service.cancelProposal('prop-1', 'user-1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // ── Delegation ─────────────────────────────────────────────────────────────

  describe('delegate', () => {
    it('delegates voting power and returns txHash', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      delegationRepo.findOne.mockResolvedValue(null); // no reverse loop
      delegationRepo.upsert.mockResolvedValue(undefined);

      const result = await service.delegate('user-1', 'GXYZ');
      expect(result.transactionHash).toBeDefined();
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'governance.delegation.changed',
        expect.any(Object),
      );
    });

    it('throws if user has no public key', async () => {
      userService.findById.mockResolvedValue({ id: 'user-1', publicKey: null });
      await expect(service.delegate('user-1', 'GXYZ')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws on self-delegation', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      await expect(service.delegate('user-1', 'GABC')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws on delegation loop', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      delegationRepo.findOne.mockResolvedValue({
        delegatorAddress: 'GXYZ',
        delegateAddress: 'GABC',
      });
      await expect(service.delegate('user-1', 'GXYZ')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('revokeDelegate', () => {
    it('deletes the delegation record', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      delegationRepo.delete.mockResolvedValue(undefined);

      await service.revokeDelegate('user-1');
      expect(delegationRepo.delete).toHaveBeenCalledWith({
        delegatorAddress: 'GABC',
      });
    });
  });

  describe('getMyDelegation', () => {
    it('returns delegate address and delegated power count', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      delegationRepo.findOne.mockResolvedValue({ delegateAddress: 'GXYZ' });
      delegationRepo.find.mockResolvedValue([{ delegatorAddress: 'GDEF' }]);

      const result = await service.getMyDelegation('user-1');
      expect(result.delegate).toBe('GXYZ');
      expect(result.totalDelegatedPower).toBe(1);
    });
  });

  describe('getMyDelegators', () => {
    it('returns list of delegators', async () => {
      userService.findById.mockResolvedValue({
        id: 'user-1',
        publicKey: 'GABC',
      });
      delegationRepo.find.mockResolvedValue([
        { delegatorAddress: 'G111' },
        { delegatorAddress: 'G222' },
      ]);

      const result = await service.getMyDelegators('user-1');
      expect(result.delegators).toEqual(['G111', 'G222']);
      expect(result.totalDelegatedPower).toBe(2);
    });
  });
});
