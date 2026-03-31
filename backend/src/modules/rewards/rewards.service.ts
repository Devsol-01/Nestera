import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ChallengeAchievement } from '../challenges/entities/challenge-achievement.entity';
import {
  SavingsGoal,
  SavingsGoalStatus,
} from '../savings/entities/savings-goal.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { TxStatus, TxType, Transaction } from '../transactions/entities/transaction.entity';
import { User } from '../user/entities/user.entity';
import {
  RewardHistoryItemDto,
  RewardRedemptionOptionDto,
  RewardsDashboardDto,
} from './dto/rewards-dashboard.dto';

const DAY_MS = 24 * 60 * 60 * 1000;
const POINTS_PER_TOKEN = 10;
const MIN_DEPOSIT_FOR_REWARDS = 10;
const STREAK_WINDOW_MS = 7 * DAY_MS;
const STREAK_BONUS_THRESHOLD = 3;
const STREAK_BONUS_BPS = 2_000;
const LONG_LOCK_BONUS_BPS = 1_000;
const LONG_LOCK_THRESHOLD_MONTHS = 6;
const GOAL_COMPLETION_BONUS = 1_000;
const POINTS_EXPIRY_DAYS = 90;
const EXPIRY_LOOKAHEAD_DAYS = 30;
const PROJECTION_WINDOW_DAYS = 30;
const EARLY_ADOPTER_AGE_DAYS = 90;
const HISTORY_LIMIT = 25;

const REDEMPTION_OPTIONS: RewardRedemptionOptionDto[] = [
  {
    id: 'fee-discount',
    title: 'Fee Discount',
    pointsCost: 500,
    description: 'Reduce protocol fees on your next savings action.',
  },
  {
    id: 'yield-boost',
    title: 'Yield Boost',
    pointsCost: 1_500,
    description: 'Activate a temporary APY boost on an eligible savings plan.',
  },
  {
    id: 'nst-conversion',
    title: 'Convert to NST',
    pointsCost: 5_000,
    description: 'Convert rewards points into claimable NST token rewards.',
  },
  {
    id: 'governance-pass',
    title: 'Governance Pass',
    pointsCost: 12_000,
    description: 'Unlock premium governance and community perks for 30 days.',
  },
];

const TIER_THRESHOLDS = [
  { name: 'Bronze', minPoints: 0 },
  { name: 'Silver', minPoints: 5_000 },
  { name: 'Gold', minPoints: 10_000 },
  { name: 'Platinum', minPoints: 20_000 },
  { name: 'Diamond', minPoints: 50_000 },
] as const;

interface RewardHistoryRecord {
  source: string;
  points: number;
  description: string;
  earnedAt: Date;
  expiresAt: Date;
}

interface RewardSummary {
  totalPoints: number;
  currentStreak: number;
  longestStreak: number;
  recentPoints: number;
  history: RewardHistoryRecord[];
}

@Injectable()
export class RewardsService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Transaction)
    private readonly transactionRepository: Repository<Transaction>,
    @InjectRepository(UserSubscription)
    private readonly subscriptionRepository: Repository<UserSubscription>,
    @InjectRepository(SavingsGoal)
    private readonly savingsGoalRepository: Repository<SavingsGoal>,
    @InjectRepository(ChallengeAchievement)
    private readonly challengeAchievementRepository: Repository<ChallengeAchievement>,
  ) {}

  async getDashboard(userId: string): Promise<RewardsDashboardDto> {
    const [user, achievements, depositTransactions, subscriptions, completedGoals] =
      await Promise.all([
        this.userRepository.findOne({ where: { id: userId } }),
        this.challengeAchievementRepository.find({
          where: { userId },
          order: { createdAt: 'DESC' },
        }),
        this.transactionRepository.find({
          where: { type: TxType.DEPOSIT, status: TxStatus.COMPLETED },
          order: { createdAt: 'ASC' },
        }),
        this.subscriptionRepository.find({
          order: { startDate: 'ASC' },
        }),
        this.savingsGoalRepository.find({
          where: { status: SavingsGoalStatus.COMPLETED },
          order: { updatedAt: 'ASC' },
        }),
      ]);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const now = new Date();
    const transactionsByUser = this.groupByUserId(depositTransactions);
    const subscriptionsByUser = this.groupByUserId(subscriptions);
    const goalsByUser = this.groupByUserId(completedGoals);

    const userSummary = this.buildRewardSummary(
      transactionsByUser.get(userId) ?? [],
      subscriptionsByUser.get(userId) ?? [],
      goalsByUser.get(userId) ?? [],
      now,
    );

    const rankedUsers = this.buildLeaderboard(
      transactionsByUser,
      subscriptionsByUser,
      goalsByUser,
      now,
    );

    const leaderboardIndex = rankedUsers.findIndex((entry) => entry.userId === userId);
    const tierInfo = this.resolveTier(userSummary.totalPoints);
    const projection = this.buildProjection(
      userSummary.totalPoints,
      userSummary.recentPoints,
      now,
      user.createdAt,
      tierInfo.nextTierPoints,
    );

    return {
      totalPoints: userSummary.totalPoints,
      currentStreak: userSummary.currentStreak,
      longestStreak: userSummary.longestStreak,
      badges: this.buildBadges(
        user,
        achievements,
        goalsByUser.get(userId) ?? [],
        userSummary.longestStreak,
        now,
      ),
      tier: tierInfo.name,
      nextTierPoints: tierInfo.nextTierPoints,
      pointsToNextTier: tierInfo.pointsToNextTier,
      expiringPoints: this.buildExpiringPoints(userSummary.history, now),
      availableRedemptionOptions: REDEMPTION_OPTIONS.filter(
        (option) => option.pointsCost <= userSummary.totalPoints,
      ),
      earningHistory: userSummary.history
        .slice(0, HISTORY_LIMIT)
        .map((entry) => this.toHistoryDto(entry)),
      leaderboardPosition: leaderboardIndex >= 0 ? leaderboardIndex + 1 : null,
      totalRankedUsers: rankedUsers.length,
      projectedPointsForNextTier: projection,
    };
  }

  private buildRewardSummary(
    depositTransactions: Transaction[],
    subscriptions: UserSubscription[],
    completedGoals: SavingsGoal[],
    now: Date,
  ): RewardSummary {
    const history: RewardHistoryRecord[] = [];
    const rewardableDeposits = [...depositTransactions]
      .filter((transaction) => this.parseAmount(transaction.amount) >= MIN_DEPOSIT_FOR_REWARDS)
      .sort(
        (left, right) =>
          this.toDate(left.createdAt).getTime() - this.toDate(right.createdAt).getTime(),
      );

    let runningStreak = 0;
    let longestStreak = 0;
    let lastRewardedDepositAt: Date | null = null;

    for (const transaction of rewardableDeposits) {
      const depositDate = this.toDate(transaction.createdAt);
      const basePoints = this.toPoints(this.parseAmount(transaction.amount));
      if (basePoints <= 0) {
        continue;
      }

      runningStreak = this.updateRunningStreak(lastRewardedDepositAt, depositDate, runningStreak);
      longestStreak = Math.max(longestStreak, runningStreak);
      lastRewardedDepositAt = depositDate;

      history.push({
        source: 'deposit',
        points: basePoints,
        description: `Deposit reward for ${this.formatAmount(transaction.amount)} NST.`,
        earnedAt: depositDate,
        expiresAt: this.addDays(depositDate, POINTS_EXPIRY_DAYS),
      });

      if (runningStreak >= STREAK_BONUS_THRESHOLD) {
        const streakBonus = Math.floor((basePoints * STREAK_BONUS_BPS) / 10_000);
        if (streakBonus > 0) {
          history.push({
            source: 'streak_bonus',
            points: streakBonus,
            description: `Consistency bonus for maintaining a ${runningStreak}-deposit streak.`,
            earnedAt: depositDate,
            expiresAt: this.addDays(depositDate, POINTS_EXPIRY_DAYS),
          });
        }
      }
    }

    for (const subscription of subscriptions) {
      if (!this.isLongLockEligible(subscription)) {
        continue;
      }

      const lockBonusPoints = Math.floor(
        (this.toPoints(this.parseAmount(subscription.amount)) * LONG_LOCK_BONUS_BPS) / 10_000,
      );

      if (lockBonusPoints <= 0) {
        continue;
      }

      const earnedAt = this.toDate(subscription.startDate || subscription.createdAt);
      history.push({
        source: 'long_lock_bonus',
        points: lockBonusPoints,
        description: `Long-lock bonus for committing to ${this.getLockDurationMonths(subscription)} months.`,
        earnedAt,
        expiresAt: this.addDays(earnedAt, POINTS_EXPIRY_DAYS),
      });
    }

    for (const goal of completedGoals) {
      const earnedAt = this.toDate(goal.updatedAt || goal.createdAt);
      history.push({
        source: 'goal_completion',
        points: GOAL_COMPLETION_BONUS,
        description: `Goal completion bonus for "${goal.goalName}".`,
        earnedAt,
        expiresAt: this.addDays(earnedAt, POINTS_EXPIRY_DAYS),
      });
    }

    history.sort((left, right) => right.earnedAt.getTime() - left.earnedAt.getTime());

    const totalPoints = history.reduce((sum, entry) => sum + entry.points, 0);
    const recentWindowStart = this.addDays(now, -PROJECTION_WINDOW_DAYS);
    const recentPoints = history
      .filter((entry) => entry.earnedAt >= recentWindowStart)
      .reduce((sum, entry) => sum + entry.points, 0);

    const latestRewardedDeposit = rewardableDeposits.at(-1);
    const currentStreak =
      latestRewardedDeposit &&
      now.getTime() - this.toDate(latestRewardedDeposit.createdAt).getTime() <= STREAK_WINDOW_MS
        ? runningStreak
        : 0;

    return {
      totalPoints,
      currentStreak,
      longestStreak,
      recentPoints,
      history,
    };
  }

  private buildLeaderboard(
    transactionsByUser: Map<string, Transaction[]>,
    subscriptionsByUser: Map<string, UserSubscription[]>,
    goalsByUser: Map<string, SavingsGoal[]>,
    now: Date,
  ) {
    const userIds = new Set<string>([
      ...transactionsByUser.keys(),
      ...subscriptionsByUser.keys(),
      ...goalsByUser.keys(),
    ]);

    return [...userIds]
      .map((candidateUserId) => ({
        userId: candidateUserId,
        totalPoints: this.buildRewardSummary(
          transactionsByUser.get(candidateUserId) ?? [],
          subscriptionsByUser.get(candidateUserId) ?? [],
          goalsByUser.get(candidateUserId) ?? [],
          now,
        ).totalPoints,
      }))
      .filter((entry) => entry.totalPoints > 0)
      .sort(
        (left, right) =>
          right.totalPoints - left.totalPoints || left.userId.localeCompare(right.userId),
      );
  }

  private buildBadges(
    user: User,
    achievements: ChallengeAchievement[],
    completedGoals: SavingsGoal[],
    longestStreak: number,
    now: Date,
  ): string[] {
    const badges = new Set<string>();

    achievements.forEach((achievement) => badges.add(achievement.badgeName));

    if (now.getTime() - this.toDate(user.createdAt).getTime() >= EARLY_ADOPTER_AGE_DAYS * DAY_MS) {
      badges.add('Early Adopter');
    }

    if (completedGoals.length > 0) {
      badges.add('Goal Crusher');
    }

    if (longestStreak >= STREAK_BONUS_THRESHOLD) {
      badges.add('Consistent Saver');
    }

    return [...badges];
  }

  private buildProjection(
    totalPoints: number,
    recentPoints: number,
    now: Date,
    userCreatedAt: Date,
    nextTierPoints: number | null,
  ) {
    const accountAgeDays = Math.max(
      1,
      Math.ceil((now.getTime() - this.toDate(userCreatedAt).getTime()) / DAY_MS),
    );
    const dailyAveragePoints = recentPoints > 0 ? recentPoints / PROJECTION_WINDOW_DAYS : totalPoints / accountAgeDays;
    const pointsToNextTier = nextTierPoints ? Math.max(nextTierPoints - totalPoints, 0) : 0;

    return {
      pointsToNextTier,
      projectedMonthlyPoints: Math.round(dailyAveragePoints * PROJECTION_WINDOW_DAYS),
      estimatedDaysToNextTier:
        nextTierPoints && dailyAveragePoints > 0
          ? Math.ceil(pointsToNextTier / dailyAveragePoints)
          : null,
      dailyAveragePoints: Number(dailyAveragePoints.toFixed(2)),
    };
  }

  private buildExpiringPoints(history: RewardHistoryRecord[], now: Date) {
    const expiryCutoff = this.addDays(now, EXPIRY_LOOKAHEAD_DAYS);
    const expiringEntries = history.filter(
      (entry) => entry.expiresAt >= now && entry.expiresAt <= expiryCutoff,
    );

    if (expiringEntries.length === 0) {
      return {
        amount: 0,
        date: null,
      };
    }

    const earliestExpiry = expiringEntries.reduce((earliest, entry) =>
      entry.expiresAt < earliest ? entry.expiresAt : earliest,
    , expiringEntries[0].expiresAt);

    return {
      amount: expiringEntries.reduce((sum, entry) => sum + entry.points, 0),
      date: this.toDateOnly(earliestExpiry),
    };
  }

  private resolveTier(totalPoints: number) {
    let currentTier = TIER_THRESHOLDS[0];
    for (const tier of TIER_THRESHOLDS) {
      if (totalPoints >= tier.minPoints) {
        currentTier = tier;
      }
    }

    const currentIndex = TIER_THRESHOLDS.findIndex((tier) => tier.name === currentTier.name);
    const nextTier = TIER_THRESHOLDS[currentIndex + 1];

    return {
      name: currentTier.name,
      nextTierPoints: nextTier?.minPoints ?? null,
      pointsToNextTier: nextTier ? Math.max(nextTier.minPoints - totalPoints, 0) : 0,
    };
  }

  private groupByUserId<T extends { userId: string }>(items: T[]): Map<string, T[]> {
    return items.reduce((groups, item) => {
      const group = groups.get(item.userId) ?? [];
      group.push(item);
      groups.set(item.userId, group);
      return groups;
    }, new Map<string, T[]>());
  }

  private isLongLockEligible(subscription: UserSubscription): boolean {
    return this.getLockDurationMonths(subscription) >= LONG_LOCK_THRESHOLD_MONTHS;
  }

  private getLockDurationMonths(subscription: UserSubscription): number {
    if (subscription.product?.tenureMonths) {
      return subscription.product.tenureMonths;
    }

    if (subscription.startDate && subscription.endDate) {
      const durationMs =
        this.toDate(subscription.endDate).getTime() -
        this.toDate(subscription.startDate).getTime();
      return Math.round(durationMs / (30 * DAY_MS));
    }

    return 0;
  }

  private updateRunningStreak(
    previousDepositAt: Date | null,
    currentDepositAt: Date,
    currentStreak: number,
  ): number {
    if (!previousDepositAt) {
      return 1;
    }

    return currentDepositAt.getTime() - previousDepositAt.getTime() <= STREAK_WINDOW_MS
      ? currentStreak + 1
      : 1;
  }

  private toHistoryDto(entry: RewardHistoryRecord): RewardHistoryItemDto {
    return {
      source: entry.source,
      points: entry.points,
      earnedAt: entry.earnedAt.toISOString(),
      expiresAt: entry.expiresAt.toISOString(),
      description: entry.description,
    };
  }

  private toPoints(amount: number): number {
    return Math.floor(amount * POINTS_PER_TOKEN);
  }

  private parseAmount(amount: string | number | null | undefined): number {
    if (amount === null || amount === undefined) {
      return 0;
    }

    const parsed = typeof amount === 'number' ? amount : Number.parseFloat(amount);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  private formatAmount(amount: string | number): string {
    return this.parseAmount(amount).toFixed(2).replace(/\.00$/, '');
  }

  private toDate(value: Date | string): Date {
    return value instanceof Date ? value : new Date(value);
  }

  private addDays(date: Date, days: number): Date {
    return new Date(date.getTime() + days * DAY_MS);
  }

  private toDateOnly(date: Date): string {
    return date.toISOString().slice(0, 10);
  }
}
