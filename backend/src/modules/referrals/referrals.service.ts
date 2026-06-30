import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  Logger,
  Optional,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import { Referral, ReferralStatus } from './entities/referral.entity';
import { ReferralCampaign } from './entities/referral-campaign.entity';
import {
  ProcessedReferralEvent,
  ReferralEventType,
} from './entities/processed-referral-event.entity';
import { User } from '../user/entities/user.entity';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { randomBytes } from 'crypto';
import { ReferralFraudDetectionService } from './referral-fraud-detection.service';
import { ReferralFraudEvaluationContext } from './referral-fraud.types';
import { DistributedTracingService } from '../apm/distributed-tracing.service';
import { TraceSpan } from '../../common/decorators/trace-span.decorator';
import {
  REFERRAL_COMPLETED_EVENT,
  ReferralCompletedEventPayloadV1,
} from './referral-events.types';

@Injectable()
export class ReferralsService {
  private readonly logger = new Logger(ReferralsService.name);

  constructor(
    @InjectRepository(Referral)
    private referralRepository: Repository<Referral>,
    @InjectRepository(ReferralCampaign)
    private campaignRepository: Repository<ReferralCampaign>,
    @InjectRepository(ProcessedReferralEvent)
    private processedEventRepository: Repository<ProcessedReferralEvent>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private eventEmitter: EventEmitter2,
    private readonly fraudDetectionService: ReferralFraudDetectionService,
    @Optional() readonly tracingService?: DistributedTracingService,
  ) {}

  /**
   * Check if an event has already been processed
   */
  private async hasEventBeenProcessed(
    eventType: ReferralEventType,
    userId?: string | null,
    referralId?: string | null,
  ): Promise<boolean> {
    const query: any = { eventType };
    if (userId) query.userId = userId;
    if (referralId) query.referralId = referralId;
    const exists = await this.processedEventRepository.findOne({
      where: query,
    });
    return !!exists;
  }

  /**
   * Mark an event as processed
   */
  private async markEventAsProcessed(
    eventType: ReferralEventType,
    userId?: string | null,
    referralId?: string | null,
    campaignId?: string | null,
    metadata?: Record<string, any>,
  ): Promise<void> {
    const event = this.processedEventRepository.create({
      eventType,
      userId: userId || null,
      referralId: referralId || null,
      campaignId: campaignId || null,
      metadata: metadata || null,
    });
    await this.processedEventRepository.save(event);
  }

  /**
   * Generate a unique referral code for a user
   */
  @TraceSpan('referrals.generateReferralCode')
  async generateReferralCode(
    userId: string,
    campaignId?: string,
  ): Promise<Referral> {
    this.fraudDetectionService.enforceCreationRateLimit(userId);

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user already has an active referral code
    const existing = await this.referralRepository.findOne({
      where: { referrerId: userId, campaignId: campaignId ?? IsNull() },
    });

    if (existing) {
      return existing;
    }

    // Validate campaign if provided
    let campaign: ReferralCampaign | null = null;
    if (campaignId) {
      campaign = await this.campaignRepository.findOne({
        where: { id: campaignId },
      });
      if (!campaign || !campaign.isActive) {
        throw new BadRequestException('Invalid or inactive campaign');
      }
    }

    // Generate unique code
    const code = await this.generateUniqueCode();

    const referral = this.referralRepository.create({
      referrerId: userId,
      referralCode: code,
      campaignId: campaignId || null,
      status: ReferralStatus.PENDING,
    });

    return this.referralRepository.save(referral);
  }

  /**
   * Apply a referral code during user signup
   */
  @TraceSpan('referrals.applyReferralCode')
  async applyReferralCode(
    referralCode: string,
    refereeId: string,
    context: ReferralFraudEvaluationContext = {},
  ): Promise<void> {
    // Check idempotency
    const alreadyProcessed = await this.hasEventBeenProcessed(
      ReferralEventType.SIGNUP,
      refereeId,
    );
    if (alreadyProcessed) {
      this.logger.log(`Referral code already processed for user ${refereeId}`);
      return;
    }

    const referral = await this.referralRepository.findOne({
      where: { referralCode },
      relations: ['referrer', 'campaign'],
    });

    if (!referral) {
      throw new NotFoundException('Invalid referral code');
    }

    if (referral.refereeId) {
      throw new ConflictException('Referral code already used');
    }

    if (referral.referrerId === refereeId) {
      const evaluation = await this.fraudDetectionService.evaluateReferral(
        { ...referral, refereeId },
        context,
      );
      await this.fraudDetectionService.quarantineReferral(referral, evaluation);
      throw new BadRequestException('Cannot use your own referral code');
    }

    // Check if campaign is still valid
    if (referral.campaign) {
      const now = new Date();
      if (
        referral.campaign.endDate &&
        new Date(referral.campaign.endDate) < now
      ) {
        referral.status = ReferralStatus.EXPIRED;
        await this.referralRepository.save(referral);
        throw new BadRequestException('Referral campaign has expired');
      }
    }

    // Fraud detection: Check if referee already referred by someone else
    const existingReferral = await this.referralRepository.findOne({
      where: { refereeId },
    });

    if (existingReferral) {
      throw new ConflictException('User already referred by another user');
    }

    referral.refereeId = refereeId;
    const fingerprint =
      this.fraudDetectionService.buildMetadataFingerprint(context);
    referral.metadata = {
      ...(referral.metadata ?? {}),
      fingerprint: fingerprint ?? undefined,
      appliedAt: new Date().toISOString(),
      ...context,
    };

    const evaluation = await this.fraudDetectionService.evaluateReferral(
      referral,
      context,
    );
    if (evaluation.shouldQuarantine) {
      await this.fraudDetectionService.quarantineReferral(referral, evaluation);
      throw new BadRequestException(
        'Referral flagged for manual review due to suspicious activity',
      );
    }

    await this.referralRepository.save(referral);

    // Mark event as processed
    await this.markEventAsProcessed(
      ReferralEventType.SIGNUP,
      refereeId,
      referral.id,
      referral.campaignId,
      { referralCode },
    );

    this.logger.log(
      `Referral code ${referralCode} applied for user ${refereeId}`,
    );
  }

  /**
   * Check and complete referral when user makes first deposit
   */
  @TraceSpan('referrals.checkAndCompleteReferral')
  async checkAndCompleteReferral(
    userId: string,
    depositAmount: string,
  ): Promise<void> {
    // Check idempotency
    const alreadyProcessed = await this.hasEventBeenProcessed(
      ReferralEventType.FIRST_DEPOSIT,
      userId,
    );
    if (alreadyProcessed) {
      this.logger.log(`First deposit already processed for user ${userId}`);
      return;
    }

    const referral = await this.referralRepository.findOne({
      where: { refereeId: userId, status: ReferralStatus.PENDING },
      relations: ['referrer', 'campaign'],
    });

    if (!referral) {
      // Mark as processed even if no referral to prevent reprocessing
      await this.markEventAsProcessed(
        ReferralEventType.FIRST_DEPOSIT,
        userId,
        null,
        null,
        { depositAmount },
      );
      return; // No pending referral for this user
    }

    // Check minimum deposit requirement
    const campaign = referral.campaign;
    const minDeposit = campaign?.minDepositAmount || '0';

    if (parseFloat(depositAmount) < parseFloat(minDeposit)) {
      this.logger.log(
        `Deposit amount ${depositAmount} below minimum ${minDeposit} for referral ${referral.id}`,
      );
      // Mark as processed even if below min
      await this.markEventAsProcessed(
        ReferralEventType.FIRST_DEPOSIT,
        userId,
        referral.id,
        referral.campaignId,
        { depositAmount, belowMinimum: true },
      );
      return;
    }

    const evaluation =
      await this.fraudDetectionService.evaluateReferral(referral);
    if (evaluation.shouldQuarantine) {
      await this.fraudDetectionService.quarantineReferral(referral, evaluation);
      await this.markEventAsProcessed(
        ReferralEventType.FIRST_DEPOSIT,
        userId,
        referral.id,
        referral.campaignId,
        { depositAmount, quarantined: true },
      );
      return;
    }

    // Mark as completed
    referral.status = ReferralStatus.COMPLETED;
    referral.completedAt = new Date();
    await this.referralRepository.save(referral);

    // Mark event as processed
    await this.markEventAsProcessed(
      ReferralEventType.FIRST_DEPOSIT,
      userId,
      referral.id,
      referral.campaignId,
      { depositAmount },
    );

    // Emit versioned referral.completed event for backward compatible consumers
    const completedEvent: ReferralCompletedEventPayloadV1 = {
      eventType: REFERRAL_COMPLETED_EVENT,
      schemaVersion: 1,
      referralId: referral.id,
      referrerId: referral.referrerId,
      refereeId: referral.refereeId!,
      campaignId: referral.campaignId,
      completedAt: referral.completedAt?.toISOString(),
    };

    this.eventEmitter.emit(REFERRAL_COMPLETED_EVENT, completedEvent);

    this.logger.log(`Referral ${referral.id} completed`);
  }

  /**
   * Distribute rewards for completed referral
   */
  @TraceSpan('referrals.distributeRewards')
  async distributeRewards(referralId: string): Promise<void> {
    // Check idempotency
    const alreadyProcessed = await this.hasEventBeenProcessed(
      ReferralEventType.REFERRAL_COMPLETED,
      null,
      referralId,
    );
    if (alreadyProcessed) {
      this.logger.log(`Rewards already distributed for referral ${referralId}`);
      return;
    }

    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
      relations: ['referrer', 'referee', 'campaign'],
    });

    if (!referral) {
      throw new NotFoundException('Referral not found');
    }

    // If already rewarded, just mark processed
    if (referral.status === ReferralStatus.REWARDED) {
      await this.markEventAsProcessed(
        ReferralEventType.REFERRAL_COMPLETED,
        null,
        referralId,
        referral.campaignId,
      );
      this.logger.log(`Rewards already distributed for referral ${referralId}`);
      return;
    }

    if (referral.status !== ReferralStatus.COMPLETED) {
      throw new BadRequestException('Referral not completed yet');
    }

    const campaign = referral.campaign;
    const defaultReward = '10'; // Default reward if no campaign

    // Check max rewards per user limit
    if (campaign?.maxRewardsPerUser) {
      const rewardedCount = await this.referralRepository.count({
        where: {
          referrerId: referral.referrerId,
          status: ReferralStatus.REWARDED,
          campaignId: campaign.id,
        },
      });

      if (rewardedCount >= campaign.maxRewardsPerUser) {
        this.logger.warn(
          `User ${referral.referrerId} reached max rewards limit for campaign ${campaign.id}`,
        );
        await this.markEventAsProcessed(
          ReferralEventType.REFERRAL_COMPLETED,
          null,
          referralId,
          referral.campaignId,
          { maxRewardsReached: true },
        );
        return;
      }
    }

    const referrerReward = campaign?.rewardAmount || defaultReward;
    const refereeReward = campaign?.refereeRewardAmount;

    // Update referral status
    referral.status = ReferralStatus.REWARDED;
    referral.rewardAmount = referrerReward;
    referral.rewardedAt = new Date();
    await this.referralRepository.save(referral);

    // Mark event as processed
    await this.markEventAsProcessed(
      ReferralEventType.REFERRAL_COMPLETED,
      null,
      referralId,
      referral.campaignId,
    );

    // Emit events for reward transactions
    this.eventEmitter.emit('referral.reward.distribute', {
      userId: referral.referrerId,
      amount: referrerReward,
      referralId: referral.id,
      type: 'referrer',
    });

    if (refereeReward && referral.refereeId) {
      this.eventEmitter.emit('referral.reward.distribute', {
        userId: referral.refereeId,
        amount: refereeReward,
        referralId: referral.id,
        type: 'referee',
      });
    }

    this.logger.log(`Rewards distributed for referral ${referralId}`);
  }

  /**
   * Get referral statistics for a user (dashboard format per issue #528)
   */
  @TraceSpan('referrals.getReferralStats')
  async getReferralStats(userId: string) {
    const referrals = await this.referralRepository.find({
      where: { referrerId: userId },
    });

    const userReferral = referrals[0];

    const successfulReferrals = referrals.filter(
      (r) =>
        r.status === ReferralStatus.COMPLETED ||
        r.status === ReferralStatus.REWARDED,
    );

    const pendingReferrals = referrals.filter(
      (r) => r.status === ReferralStatus.PENDING,
    ).length;

    const completedReferrals = referrals.filter(
      (r) => r.status === ReferralStatus.COMPLETED,
    ).length;

    const rewardedReferrals = referrals.filter(
      (r) => r.status === ReferralStatus.REWARDED,
    ).length;

    const pendingRewards = referrals
      .filter((r) => r.status === ReferralStatus.COMPLETED && r.rewardAmount)
      .reduce((sum, r) => sum + parseFloat(r.rewardAmount!), 0);

    const claimedRewards = referrals
      .filter((r) => r.status === ReferralStatus.REWARDED && r.rewardAmount)
      .reduce((sum, r) => sum + parseFloat(r.rewardAmount!), 0);

    const totalRewardsEarned = referrals
      .filter((r) => r.status === ReferralStatus.REWARDED && r.rewardAmount)
      .reduce((sum, r) => sum + parseFloat(r.rewardAmount!), 0);

    const rank = null; // await this.getReferrerRank(userId);

    return {
      referralCode: userReferral?.referralCode || null,
      totalReferrals: referrals.length,
      successfulReferrals: successfulReferrals.length,
      pendingReferrals,
      completedReferrals,
      rewardedReferrals,
      pendingRewards: parseFloat(pendingRewards.toFixed(2)),
      claimedRewards: parseFloat(claimedRewards.toFixed(2)),
      totalRewardsEarned: totalRewardsEarned.toFixed(7),
      rank,
    };
  }

  /**
   * Get detailed referral list for a user (history with conversion funnel)
   */
  @TraceSpan('referrals.getUserReferrals')
  async getUserReferrals(userId: string) {
    return this.referralRepository.find({
      where: { referrerId: userId },
      relations: ['referee'],
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Generate a custom referral code for a user (issue #528)
   */
  @TraceSpan('referrals.generateCustomCode')
  async generateCustomCode(
    userId: string,
    code?: string,
    campaignId?: string,
  ): Promise<Referral> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    if (code) {
      const taken = await this.referralRepository.findOne({
        where: { referralCode: code },
      });
      if (taken) {
        if (taken.referrerId === userId) return taken; // idempotent
        throw new ConflictException('Referral code already taken');
      }
    } else {
      code = await this.generateUniqueCode();
    }

    if (campaignId) {
      const campaign = await this.campaignRepository.findOne({
        where: { id: campaignId },
      });
      if (!campaign || !campaign.isActive) {
        throw new BadRequestException('Invalid or inactive campaign');
      }
    }

    const referral = this.referralRepository.create({
      referrerId: userId,
      referralCode: code,
      campaignId: campaignId || null,
      status: ReferralStatus.PENDING,
    });
    return this.referralRepository.save(referral);
  }

  /**
   * Get leaderboard of top referrers (issue #528)
   */
  @TraceSpan('referrals.getLeaderboard')
  async getLeaderboard(limit = 10): Promise<
    Array<{
      rank: number;
      userId: string;
      successfulReferrals: number;
      totalRewards: number;
    }>
  > {
    const rows = await this.referralRepository
      .createQueryBuilder('r')
      .select('r.referrerId', 'userId')
      .addSelect(
        `COUNT(*) FILTER (WHERE r.status IN ('${ReferralStatus.COMPLETED}','${ReferralStatus.REWARDED}'))`,
        'successfulReferrals',
      )
      .addSelect(
        `COALESCE(SUM(CASE WHEN r.status = '${ReferralStatus.REWARDED}' THEN CAST(r.rewardAmount AS DECIMAL) ELSE 0 END), 0)`,
        'totalRewards',
      )
      .groupBy('r.referrerId')
      .orderBy('"successfulReferrals"', 'DESC')
      .limit(limit)
      .getRawMany();

    return rows.map((row, index) => ({
      rank: index + 1,
      userId: row.userId,
      successfulReferrals: parseInt(row.successfulReferrals, 10),
      totalRewards: parseFloat(parseFloat(row.totalRewards).toFixed(2)),
    }));
  }

  /**
   * Get the rank of a specific referrer
   */
  private async getReferrerRank(userId: string): Promise<number | null> {
    const leaderboard = await this.getLeaderboard(1000);
    const entry = leaderboard.find((e) => e.userId === userId);
    return entry ? entry.rank : null;
  }

  /**
   * Generate unique referral code
   */
  private async generateUniqueCode(): Promise<string> {
    let code: string;
    let exists = true;

    while (exists) {
      code = randomBytes(6).toString('base64url').substring(0, 8).toUpperCase();
      const existing = await this.referralRepository.findOne({
        where: { referralCode: code },
      });
      exists = !!existing;
    }

    return code!;
  }

  /**
   * Admin: Get all referrals with filters
   */
  async getAllReferrals(status?: ReferralStatus, campaignId?: string) {
    const where: any = {};
    if (status) where.status = status;
    if (campaignId) where.campaignId = campaignId;

    return this.referralRepository.find({
      where,
      relations: ['referrer', 'referee', 'campaign'],
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Admin: Update referral status
   */
  async updateReferralStatus(
    referralId: string,
    status: ReferralStatus,
    rewardAmount?: number,
  ): Promise<Referral> {
    const referral = await this.referralRepository.findOne({
      where: { id: referralId },
    });

    if (!referral) {
      throw new NotFoundException('Referral not found');
    }

    referral.status = status;
    if (rewardAmount !== undefined) {
      referral.rewardAmount = rewardAmount.toString();
    }

    if (status === ReferralStatus.REWARDED && !referral.rewardedAt) {
      referral.rewardedAt = new Date();
    }

    return this.referralRepository.save(referral);
  }
}
