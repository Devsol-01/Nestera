import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { SavingsService } from './savings.service';
import { SavingsProduct } from './entities/savings-product.entity';
import { UserSubscription } from './entities/user-subscription.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from './entities/savings-goal.entity';
import { User } from '../user/entities/user.entity';
import { SavingsService as BlockchainSavingsService } from '../blockchain/savings.service';

describe('SavingsService', () => {
  let service: SavingsService;
  let goalRepository: { find: jest.Mock };
  let userRepository: { findOne: jest.Mock };
  let blockchainSavingsService: { getUserSavingsBalance: jest.Mock };

  beforeEach(async () => {
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
          useValue: {},
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
    expect(blockchainSavingsService.getUserSavingsBalance).not.toHaveBeenCalled();
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
