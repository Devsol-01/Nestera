import { NotFoundException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ChallengeAchievement } from '../challenges/entities/challenge-achievement.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from '../savings/entities/savings-goal.entity';
import {
  SavingsProduct,
  SavingsProductType,
  RiskLevel,
} from '../savings/entities/savings-product.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { TxStatus, TxType, Transaction } from '../transactions/entities/transaction.entity';
import { User } from '../user/entities/user.entity';
import { RewardsService } from './rewards.service';

describe('RewardsService', () => {
  let service: RewardsService;
  let userRepository: Repository<User>;
  let transactionRepository: Repository<Transaction>;
  let subscriptionRepository: Repository<UserSubscription>;
  let goalRepository: Repository<SavingsGoal>;
  let achievementRepository: Repository<ChallengeAchievement>;

  beforeEach(async () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-03-31T00:00:00.000Z'));

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RewardsService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Transaction),
          useValue: {
            find: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(UserSubscription),
          useValue: {
            find: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(SavingsGoal),
          useValue: {
            find: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(ChallengeAchievement),
          useValue: {
            find: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<RewardsService>(RewardsService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    transactionRepository = module.get<Repository<Transaction>>(getRepositoryToken(Transaction));
    subscriptionRepository = module.get<Repository<UserSubscription>>(
      getRepositoryToken(UserSubscription),
    );
    goalRepository = module.get<Repository<SavingsGoal>>(getRepositoryToken(SavingsGoal));
    achievementRepository = module.get<Repository<ChallengeAchievement>>(
      getRepositoryToken(ChallengeAchievement),
    );
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should throw when the user cannot be found', async () => {
    jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
    jest.spyOn(achievementRepository, 'find').mockResolvedValue([]);
    jest.spyOn(transactionRepository, 'find').mockResolvedValue([]);
    jest.spyOn(subscriptionRepository, 'find').mockResolvedValue([]);
    jest.spyOn(goalRepository, 'find').mockResolvedValue([]);

    await expect(service.getDashboard('missing-user')).rejects.toThrow(
      NotFoundException,
    );
  });

  it('should build a rewards dashboard from existing savings activity', async () => {
    const nowYear = 2026;
    const product = {
      id: 'product-1',
      name: 'Locked Vault',
      type: SavingsProductType.FIXED,
      description: '12 month vault',
      interestRate: 12,
      minAmount: 50,
      maxAmount: 100000,
      tenureMonths: 12,
      contractId: 'contract-1',
      tvlAmount: 0,
      capacity: 1000,
      maxSubscriptionsPerUser: 2,
      version: 1,
      versionGroupId: null,
      previousVersionId: null,
      maxCapacity: null,
      isActive: true,
      riskLevel: RiskLevel.LOW,
      createdAt: new Date(`${nowYear}-01-01T00:00:00.000Z`),
      updatedAt: new Date(`${nowYear}-01-01T00:00:00.000Z`),
      subscriptions: [],
    } as SavingsProduct;

    jest.spyOn(userRepository, 'findOne').mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      name: 'Rewards User',
      createdAt: new Date(`${nowYear - 1}-12-01T00:00:00.000Z`),
      updatedAt: new Date(`${nowYear}-03-01T00:00:00.000Z`),
    } as User);

    jest.spyOn(achievementRepository, 'find').mockResolvedValue([
      {
        id: 'achievement-1',
        userId: 'user-1',
        challengeId: 'challenge-1',
        badgeName: 'Challenge Champion',
        shareCode: 'share-code',
        createdAt: new Date(`${nowYear}-03-15T00:00:00.000Z`),
      } as ChallengeAchievement,
    ]);

    jest.spyOn(transactionRepository, 'find').mockResolvedValue([
      {
        id: 'tx-1',
        userId: 'user-1',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '50',
        createdAt: new Date(`${nowYear}-01-05T00:00:00.000Z`),
      },
      {
        id: 'tx-2',
        userId: 'user-1',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '100',
        createdAt: new Date(`${nowYear}-03-11T00:00:00.000Z`),
      },
      {
        id: 'tx-3',
        userId: 'user-1',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '150',
        createdAt: new Date(`${nowYear}-03-18T00:00:00.000Z`),
      },
      {
        id: 'tx-4',
        userId: 'user-1',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '200',
        createdAt: new Date(`${nowYear}-03-25T00:00:00.000Z`),
      },
      {
        id: 'tx-5',
        userId: 'user-1',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '300',
        createdAt: new Date(`${nowYear}-03-29T00:00:00.000Z`),
      },
      {
        id: 'tx-6',
        userId: 'user-2',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '1200',
        createdAt: new Date(`${nowYear}-03-10T00:00:00.000Z`),
      },
      {
        id: 'tx-7',
        userId: 'user-3',
        type: TxType.DEPOSIT,
        status: TxStatus.COMPLETED,
        amount: '200',
        createdAt: new Date(`${nowYear}-03-12T00:00:00.000Z`),
      },
    ] as Transaction[]);

    jest.spyOn(subscriptionRepository, 'find').mockResolvedValue([
      {
        id: 'subscription-1',
        userId: 'user-1',
        productId: 'product-1',
        amount: 300,
        startDate: new Date(`${nowYear}-03-29T00:00:00.000Z`),
        endDate: new Date(`${nowYear + 1}-03-29T00:00:00.000Z`),
        createdAt: new Date(`${nowYear}-03-29T00:00:00.000Z`),
        updatedAt: new Date(`${nowYear}-03-29T00:00:00.000Z`),
        totalInterestEarned: '0',
        product,
      } as UserSubscription,
    ]);

    jest.spyOn(goalRepository, 'find').mockResolvedValue([
      {
        id: 'goal-1',
        userId: 'user-1',
        goalName: 'Emergency Fund',
        targetAmount: 500,
        targetDate: new Date(`${nowYear}-04-30T00:00:00.000Z`),
        status: SavingsGoalStatus.COMPLETED,
        metadata: null,
        milestonesSent: {},
        createdAt: new Date(`${nowYear}-03-01T00:00:00.000Z`),
        updatedAt: new Date(`${nowYear}-03-30T00:00:00.000Z`),
      } as SavingsGoal,
    ]);

    const dashboard = await service.getDashboard('user-1');

    expect(dashboard.totalPoints).toBe(10300);
    expect(dashboard.currentStreak).toBe(4);
    expect(dashboard.longestStreak).toBe(4);
    expect(dashboard.tier).toBe('Gold');
    expect(dashboard.nextTierPoints).toBe(20000);
    expect(dashboard.pointsToNextTier).toBe(9700);
    expect(dashboard.leaderboardPosition).toBe(2);
    expect(dashboard.totalRankedUsers).toBe(3);
    expect(dashboard.expiringPoints.amount).toBe(500);
    expect(dashboard.expiringPoints.date).toBe(`${nowYear}-04-05`);
    expect(dashboard.badges).toEqual(
      expect.arrayContaining([
        'Challenge Champion',
        'Early Adopter',
        'Goal Crusher',
        'Consistent Saver',
      ]),
    );
    expect(dashboard.availableRedemptionOptions).toHaveLength(3);
    expect(dashboard.availableRedemptionOptions.map((option) => option.id)).toEqual([
      'fee-discount',
      'yield-boost',
      'nst-conversion',
    ]);
    expect(dashboard.earningHistory[0].source).toBe('goal_completion');
  });
});
