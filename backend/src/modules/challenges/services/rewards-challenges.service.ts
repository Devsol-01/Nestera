import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, LessThanOrEqual, MoreThanOrEqual } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  Challenge,
  ChallengeType,
  ChallengeStatus,
} from '../entities/challenge.entity';
import {
  UserChallenge,
  UserChallengeStatus,
} from '../entities/user-challenge.entity';
import { User } from '../../user/entities/user.entity';
import {
  CreateChallengeDto,
  UpdateChallengeDto,
  GetActiveChallengesQueryDto,
  ChallengeResponseDto,
  UserChallengeResponseDto,
} from '../dto/challenge.dto';

@Injectable()
export class RewardsChallengesService {
  private readonly logger = new Logger(RewardsChallengesService.name);

  constructor(
    @InjectRepository(Challenge)
    private readonly challengeRepository: Repository<Challenge>,
    @InjectRepository(UserChallenge)
    private readonly userChallengeRepository: Repository<UserChallenge>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  /**
   * Get all active challenges
   */
  async getActiveChallenges(
    query: GetActiveChallengesQueryDto,
    userId?: string,
  ): Promise<{ challenges: ChallengeResponseDto[]; total: number }> {
    const { type, category, featured, limit = 20, offset = 0 } = query;

    const now = new Date();
    const queryBuilder = this.challengeRepository
      .createQueryBuilder('challenge')
      .where('challenge.status = :status', {
        status: ChallengeStatus.ACTIVE,
      })
      .andWhere('challenge.isVisible = :isVisible', { isVisible: true })
      .andWhere('challenge.startDate <= :now', { now })
      .andWhere('challenge.endDate >= :now', { now });

    if (type) {
      queryBuilder.andWhere('challenge.type = :type', { type });
    }

    if (category) {
      queryBuilder.andWhere('challenge.category = :category', { category });
    }

    if (featured !== undefined) {
      queryBuilder.andWhere('challenge.isFeatured = :featured', { featured });
    }

    queryBuilder
      .orderBy('challenge.isFeatured', 'DESC')
      .addOrderBy('challenge.startDate', 'DESC')
      .skip(offset)
      .take(limit);

    const [challenges, total] = await queryBuilder.getManyAndCount();

    // If user is authenticated, include their participation status
    let userChallenges: UserChallenge[] = [];
    if (userId) {
      userChallenges = await this.userChallengeRepository.find({
        where: {
          userId,
          challengeId: In(challenges.map((c) => c.id)),
        },
      });
    }

    const challengesWithParticipation = challenges.map((challenge) => {
      const userChallenge = userChallenges.find(
        (uc) => uc.challengeId === challenge.id,
      );

      return {
        ...challenge,
        userParticipation: userChallenge
          ? {
              joined: true,
              status: userChallenge.status,
              progressPercentage: Number(userChallenge.progressPercentage),
              joinedAt: userChallenge.joinedAt,
            }
          : { joined: false },
      };
    });

    return {
      challenges: challengesWithParticipation,
      total,
    };
  }

  /**
   * Get a specific challenge by ID
   */
  async getChallengeById(
    challengeId: string,
    userId?: string,
  ): Promise<ChallengeResponseDto> {
    const challenge = await this.challengeRepository.findOne({
      where: { id: challengeId },
    });

    if (!challenge) {
      throw new NotFoundException('Challenge not found');
    }

    let userParticipation = { joined: false };

    if (userId) {
      const userChallenge = await this.userChallengeRepository.findOne({
        where: { userId, challengeId },
      });

      if (userChallenge) {
        userParticipation = {
          joined: true,
          status: userChallenge.status,
          progressPercentage: Number(userChallenge.progressPercentage),
          joinedAt: userChallenge.joinedAt,
        } as any;
      }
    }

    return {
      ...challenge,
      userParticipation,
    };
  }

  /**
   * Join a challenge
   */
  async joinChallenge(
    userId: string,
    challengeId: string,
  ): Promise<UserChallengeResponseDto> {
    // Verify user exists
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify challenge exists and is active
    const challenge = await this.challengeRepository.findOne({
      where: { id: challengeId },
    });

    if (!challenge) {
      throw new NotFoundException('Challenge not found');
    }

    // Check if challenge is active and within date range
    const now = new Date();
    if (challenge.status !== ChallengeStatus.ACTIVE) {
      throw new BadRequestException('Challenge is not active');
    }

    if (challenge.startDate > now) {
      throw new BadRequestException('Challenge has not started yet');
    }

    if (challenge.endDate < now) {
      throw new BadRequestException('Challenge has already ended');
    }

    // Check if user already joined
    const existingParticipation = await this.userChallengeRepository.findOne({
      where: { userId, challengeId },
    });

    if (existingParticipation) {
      throw new ConflictException('You have already joined this challenge');
    }

    // Check challenge rules
    await this.validateChallengeRules(user, challenge);

    // Check max participants
    if (
      challenge.rules.maxParticipants &&
      challenge.participantCount >= challenge.rules.maxParticipants
    ) {
      throw new BadRequestException(
        'Challenge has reached maximum participants',
      );
    }

    // Create user challenge
    const userChallenge = this.userChallengeRepository.create({
      userId,
      challengeId,
      status: UserChallengeStatus.ACTIVE,
      progressPercentage: 0,
      progressMetadata: this.initializeProgressMetadata(challenge.type),
    });

    const saved = await this.userChallengeRepository.save(userChallenge);

    // Update participant count
    await this.challengeRepository.increment(
      { id: challengeId },
      'participantCount',
      1,
    );

    // Emit event
    this.eventEmitter.emit('challenge.joined', {
      userId,
      challengeId,
      challengeName: challenge.name,
      challengeType: challenge.type,
    });

    this.logger.log(
      `User ${userId} joined challenge ${challengeId} (${challenge.name})`,
    );

    return {
      ...saved,
      challenge: challenge,
    };
  }

  /**
   * Get user's active challenges
   */
  async getUserChallenges(
    userId: string,
    status?: UserChallengeStatus,
  ): Promise<UserChallengeResponseDto[]> {
    const whereClause: any = { userId };
    if (status) {
      whereClause.status = status;
    }

    const userChallenges = await this.userChallengeRepository.find({
      where: whereClause,
      order: { joinedAt: 'DESC' },
    });

    const challengeIds = userChallenges.map((uc) => uc.challengeId);
    const challenges = await this.challengeRepository.find({
      where: { id: In(challengeIds) },
    });

    const challengeMap = new Map(challenges.map((c) => [c.id, c]));

    return userChallenges.map((uc) => ({
      ...uc,
      challenge: challengeMap.get(uc.challengeId) as any,
    }));
  }

  /**
   * Create a new challenge (Admin)
   */
  async createChallenge(
    dto: CreateChallengeDto,
    createdBy: string,
  ): Promise<Challenge> {
    const startDate = new Date(dto.startDate);
    const endDate = new Date(dto.endDate);

    if (startDate >= endDate) {
      throw new BadRequestException('Start date must be before end date');
    }

    const challenge = this.challengeRepository.create({
      ...dto,
      startDate,
      endDate,
      status: ChallengeStatus.SCHEDULED,
      participantCount: 0,
      completionCount: 0,
      isVisible: true,
      createdBy,
    });

    const saved = await this.challengeRepository.save(challenge);

    this.logger.log(`Challenge created: ${saved.id} (${saved.name})`);

    return saved;
  }

  /**
   * Update a challenge (Admin)
   */
  async updateChallenge(
    challengeId: string,
    dto: UpdateChallengeDto,
  ): Promise<Challenge> {
    const challenge = await this.challengeRepository.findOne({
      where: { id: challengeId },
    });

    if (!challenge) {
      throw new NotFoundException('Challenge not found');
    }

    // Prevent updating active challenges with participants
    if (
      challenge.status === ChallengeStatus.ACTIVE &&
      challenge.participantCount > 0
    ) {
      throw new BadRequestException(
        'Cannot update active challenge with participants',
      );
    }

    Object.assign(challenge, dto);

    if (dto.startDate) {
      challenge.startDate = new Date(dto.startDate);
    }

    if (dto.endDate) {
      challenge.endDate = new Date(dto.endDate);
    }

    return this.challengeRepository.save(challenge);
  }

  /**
   * Delete a challenge (Admin)
   */
  async deleteChallenge(challengeId: string): Promise<void> {
    const challenge = await this.challengeRepository.findOne({
      where: { id: challengeId },
    });

    if (!challenge) {
      throw new NotFoundException('Challenge not found');
    }

    if (challenge.participantCount > 0) {
      throw new BadRequestException(
        'Cannot delete challenge with participants',
      );
    }

    await this.challengeRepository.remove(challenge);

    this.logger.log(`Challenge deleted: ${challengeId}`);
  }

  /**
   * Activate scheduled challenges
   */
  async activateScheduledChallenges(): Promise<void> {
    const now = new Date();

    const challenges = await this.challengeRepository.find({
      where: {
        status: ChallengeStatus.SCHEDULED,
        startDate: LessThanOrEqual(now),
      },
    });

    for (const challenge of challenges) {
      challenge.status = ChallengeStatus.ACTIVE;
      await this.challengeRepository.save(challenge);

      this.logger.log(
        `Challenge activated: ${challenge.id} (${challenge.name})`,
      );
    }
  }

  /**
   * Complete expired challenges
   */
  async completeExpiredChallenges(): Promise<void> {
    const now = new Date();

    const challenges = await this.challengeRepository.find({
      where: {
        status: ChallengeStatus.ACTIVE,
        endDate: LessThanOrEqual(now),
      },
    });

    for (const challenge of challenges) {
      challenge.status = ChallengeStatus.COMPLETED;
      await this.challengeRepository.save(challenge);

      // Mark all active user challenges as expired
      await this.userChallengeRepository.update(
        {
          challengeId: challenge.id,
          status: UserChallengeStatus.ACTIVE,
        },
        {
          status: UserChallengeStatus.EXPIRED,
          expiredAt: now,
        },
      );

      this.logger.log(
        `Challenge completed: ${challenge.id} (${challenge.name})`,
      );
    }
  }

  /**
   * Validate challenge rules for a user
   */
  private async validateChallengeRules(
    user: User,
    challenge: Challenge,
  ): Promise<void> {
    const { rules } = challenge;

    // Check KYC requirement
    if (rules.requiresKYC && user.kycStatus !== 'APPROVED') {
      throw new BadRequestException(
        'KYC verification required to join this challenge',
      );
    }

    // Check minimum account age
    if (rules.minimumAccountAge) {
      const accountAge =
        (Date.now() - user.createdAt.getTime()) / (1000 * 60 * 60 * 24);
      if (accountAge < rules.minimumAccountAge) {
        throw new BadRequestException(
          `Account must be at least ${rules.minimumAccountAge} days old`,
        );
      }
    }

    // Check excluded users
    if (rules.excludedUserIds?.includes(user.id)) {
      throw new BadRequestException('You are not eligible for this challenge');
    }
  }

  /**
   * Initialize progress metadata based on challenge type
   */
  private initializeProgressMetadata(type: ChallengeType): any {
    switch (type) {
      case ChallengeType.DEPOSIT_STREAK:
        return {
          currentStreak: 0,
          streakHistory: [],
        };
      case ChallengeType.GOAL_CREATION:
        return {
          goalsCreated: 0,
          goalIds: [],
        };
      case ChallengeType.REFERRAL:
        return {
          referralsCount: 0,
          referralIds: [],
          completedReferrals: 0,
        };
      case ChallengeType.SAVINGS_TARGET:
        return {
          currentAmount: 0,
          deposits: [],
        };
      case ChallengeType.TRANSACTION_COUNT:
        return {
          transactionCount: 0,
          transactionIds: [],
        };
      default:
        return {};
    }
  }
}
