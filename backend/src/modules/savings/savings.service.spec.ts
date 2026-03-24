import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { SavingsService } from './savings.service';
import { SavingsProduct } from './entities/savings-product.entity';
import {
  UserSubscription,
  SubscriptionStatus,
} from './entities/user-subscription.entity';
import { SavingsGoal, SavingsGoalStatus } from './entities/savings-goal.entity';
import { User } from '../user/entities/user.entity';
import { SavingsService as BlockchainSavingsService } from '../blockchain/savings.service';

describe('SavingsService', () => {
  let service: SavingsService;
  let subscriptionRepository: { find: jest.Mock };
  let goalRepository: { find: jest.Mock };
  let userRepository: { findOne: jest.Mock };
  let blockchainSavingsService: { getUserSavingsBalance: jest.Mock };

  beforeEach(async () => {
    subscriptionRepository = {
      find: jest.fn(),
    };

    goalRepository = {
      find: jest.fn(),
    };

    userRepository = {
      findOne: jest.fn(),
    };

    blockchainSavingsService = {
      getUserSavingsBalance: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SavingsService,
        {
          provide: getRepositoryToken(SavingsProduct),
          useValue: {},
        },
        {
          provide: getRepositoryToken(UserSubscription),
          useValue: subscriptionRepository,
        },
        {
          provide: getRepositoryToken(SavingsGoal),
          useValue: goalRepository,
        },
        {
          provide: getRepositoryToken(User),
          useValue: userRepository,
        },
        {
          provide: BlockchainSavingsService,
          useValue: blockchainSavingsService,
        },
      ],
    }).compile();

    service = module.get<SavingsService>(SavingsService);
  });

  describe('findMySubscriptions', () => {
    const SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60;

    it('attaches estimatedYieldPerSecond derived from interestRate and amount', async () => {
      subscriptionRepository.find.mockResolvedValue([
        {
          id: 'sub-1',
          userId: 'user-1',
          amount: 1000,
          status: SubscriptionStatus.ACTIVE,
          product: { interestRate: 10 }, // 10% APY
        },
      ]);

      const result = await service.findMySubscriptions('user-1');

      const expected = parseFloat(
        ((1000 * 0.1) / SECONDS_PER_YEAR).toFixed(10),
      );
      expect(result[0].estimatedYieldPerSecond).toBe(expected);
    });

    it('returns 0 yield for non-ACTIVE subscriptions', async () => {
      subscriptionRepository.find.mockResolvedValue([
        {
          id: 'sub-2',
          userId: 'user-1',
          amount: 5000,
          status: SubscriptionStatus.MATURED,
          product: { interestRate: 8.5 },
        },
        {
          id: 'sub-3',
          userId: 'user-1',
          amount: 2000,
          status: SubscriptionStatus.CANCELLED,
          product: { interestRate: 5 },
        },
      ]);

      const result = await service.findMySubscriptions('user-1');

      expect(result[0].estimatedYieldPerSecond).toBe(0);
      expect(result[1].estimatedYieldPerSecond).toBe(0);
    });
  });

  it('returns goals enriched with percentageComplete from live vault balances', async () => {
    goalRepository.find.mockResolvedValue([
      {
        id: 'goal-1',
        userId: 'user-1',
        goalName: 'Emergency Fund',
        targetAmount: 100,
        targetDate: new Date('2026-12-31'),
        status: SavingsGoalStatus.IN_PROGRESS,
        metadata: null,
        createdAt: new Date('2026-01-01'),
        updatedAt: new Date('2026-01-02'),
      },
    ]);
    userRepository.findOne.mockResolvedValue({
      id: 'user-1',
      publicKey: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    });
    blockchainSavingsService.getUserSavingsBalance.mockResolvedValue({
      flexible: 24_000_000,
      locked: 50_000_000,
      total: 74_000_000,
    });

    await expect(service.findMyGoals('user-1')).resolves.toEqual([
      expect.objectContaining({
        id: 'goal-1',
        goalName: 'Emergency Fund',
        targetAmount: 100,
        currentBalance: 7.4,
        percentageComplete: 7,
      }),
    ]);
  });

  it('returns 0 progress when the user has no linked wallet', async () => {
    goalRepository.find.mockResolvedValue([
      {
        id: 'goal-1',
        userId: 'user-1',
        goalName: 'Vacation',
        targetAmount: 10,
        targetDate: new Date('2026-12-31'),
        status: SavingsGoalStatus.IN_PROGRESS,
        metadata: null,
        createdAt: new Date('2026-01-01'),
        updatedAt: new Date('2026-01-02'),
      },
    ]);
    userRepository.findOne.mockResolvedValue({
      id: 'user-1',
      publicKey: null,
    });

    await expect(service.findMyGoals('user-1')).resolves.toEqual([
      expect.objectContaining({
        currentBalance: 0,
        percentageComplete: 0,
      }),
    ]);
    expect(
      blockchainSavingsService.getUserSavingsBalance,
    ).not.toHaveBeenCalled();
  });

  it('caps progress at 100 percent', async () => {
    goalRepository.find.mockResolvedValue([
      {
        id: 'goal-1',
        userId: 'user-1',
        goalName: 'New Laptop',
        targetAmount: 5,
        targetDate: new Date('2026-12-31'),
        status: SavingsGoalStatus.COMPLETED,
        metadata: null,
        createdAt: new Date('2026-01-01'),
        updatedAt: new Date('2026-01-02'),
      },
    ]);
    userRepository.findOne.mockResolvedValue({
      id: 'user-1',
      publicKey: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    });
    blockchainSavingsService.getUserSavingsBalance.mockResolvedValue({
      flexible: 40_000_000,
      locked: 20_000_000,
      total: 60_000_000,
    });

    await expect(service.findMyGoals('user-1')).resolves.toEqual([
      expect.objectContaining({
        currentBalance: 6,
        percentageComplete: 100,
      }),
    ]);
  });
});
