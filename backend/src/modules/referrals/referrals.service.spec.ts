import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ReferralsService } from './referrals.service';
import { ReferralFraudDetectionService } from './referral-fraud-detection.service';
import { Referral, ReferralStatus } from './entities/referral.entity';
import { ReferralCampaign } from './entities/referral-campaign.entity';
import { ProcessedReferralEvent } from './entities/processed-referral-event.entity';
import { User } from '../user/entities/user.entity';
import {
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';

describe('ReferralsService', () => {
  let service: ReferralsService;
  let referralRepository: Repository<Referral>;
  let campaignRepository: Repository<ReferralCampaign>;
  let userRepository: Repository<User>;
  let processedReferralEventRepository: Repository<ProcessedReferralEvent>;
  let eventEmitter: EventEmitter2;
  let fraudDetectionService: jest.Mocked<ReferralFraudDetectionService>;

  const mockUser = {
    id: 'user-1',
    email: 'test@example.com',
    name: 'Test User',
  };

  const mockReferral = {
    id: 'referral-1',
    referrerId: 'user-1',
    refereeId: null,
    referralCode: 'ABC12345',
    status: ReferralStatus.PENDING,
    rewardAmount: null,
    campaignId: null,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    fraudDetectionService = {
      enforceCreationRateLimit: jest.fn(),
      evaluateReferral: jest.fn().mockResolvedValue({
        isSuspicious: false,
        reasons: [],
        metadata: {},
        shouldQuarantine: false,
      }),
      quarantineReferral: jest.fn(),
      buildMetadataFingerprint: jest.fn().mockReturnValue(null),
    } as unknown as jest.Mocked<ReferralFraudDetectionService>;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReferralsService,
        {
          provide: getRepositoryToken(Referral),
          useValue: {
            findOne: jest.fn(),
            find: jest.fn(),
            count: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            createQueryBuilder: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(ReferralCampaign),
          useValue: {
            findOne: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(ProcessedReferralEvent),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
          },
        },
        {
          provide: EventEmitter2,
          useValue: {
            emit: jest.fn(),
          },
        },
        {
          provide: ReferralFraudDetectionService,
          useValue: fraudDetectionService,
        },
      ],
    }).compile();

    service = module.get<ReferralsService>(ReferralsService);
    referralRepository = module.get<Repository<Referral>>(
      getRepositoryToken(Referral),
    );
    campaignRepository = module.get<Repository<ReferralCampaign>>(
      getRepositoryToken(ReferralCampaign),
    );
    processedReferralEventRepository = module.get<
      Repository<ProcessedReferralEvent>
    >(getRepositoryToken(ProcessedReferralEvent));
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateReferralCode', () => {
    it('should generate a new referral code for a user', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser as any);
      jest.spyOn(referralRepository, 'findOne').mockResolvedValue(null);
      jest
        .spyOn(referralRepository, 'create')
        .mockReturnValue(mockReferral as any);
      jest
        .spyOn(referralRepository, 'save')
        .mockResolvedValue(mockReferral as any);

      const result = await service.generateReferralCode('user-1');

      expect(result).toBeDefined();
      expect(result.referralCode).toBeDefined();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-1' },
      });
    });

    it('should return existing referral code if already exists', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser as any);
      jest
        .spyOn(referralRepository, 'findOne')
        .mockResolvedValue(mockReferral as any);

      const result = await service.generateReferralCode('user-1');

      expect(result).toEqual(mockReferral);
      expect(referralRepository.save).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException if user not found', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(
        service.generateReferralCode('invalid-user'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('applyReferralCode', () => {
    it('should apply referral code successfully', async () => {
      const referral = { ...mockReferral, refereeId: null };
      jest
        .spyOn(referralRepository, 'findOne')
        .mockResolvedValueOnce(referral as any)
        .mockResolvedValueOnce(null);
      jest.spyOn(referralRepository, 'save').mockResolvedValue(referral as any);

      await service.applyReferralCode('ABC12345', 'user-2');

      expect(referralRepository.save).toHaveBeenCalled();
    });

    it('should throw NotFoundException for invalid code', async () => {
      jest.spyOn(referralRepository, 'findOne').mockResolvedValue(null);

      await expect(
        service.applyReferralCode('INVALID', 'user-2'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ConflictException if code already used', async () => {
      const usedReferral = { ...mockReferral, refereeId: 'user-3' };
      jest
        .spyOn(referralRepository, 'findOne')
        .mockResolvedValue(usedReferral as any);

      await expect(
        service.applyReferralCode('ABC12345', 'user-2'),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw BadRequestException if user tries to use own code', async () => {
      jest
        .spyOn(referralRepository, 'findOne')
        .mockResolvedValue(mockReferral as any);

      await expect(
        service.applyReferralCode('ABC12345', 'user-1'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('checkAndCompleteReferral', () => {
    it('should emit a versioned referral.completed event when a referral is completed', async () => {
      const referral = {
        ...mockReferral,
        refereeId: 'user-2',
        status: ReferralStatus.PENDING,
        referrerId: 'user-1',
        campaignId: null,
      };

      jest
        .spyOn(processedReferralEventRepository, 'findOne')
        .mockResolvedValue(null);
      jest
        .spyOn(referralRepository, 'findOne')
        .mockResolvedValue(referral as any);
      jest.spyOn(referralRepository, 'save').mockResolvedValue({
        ...referral,
        status: ReferralStatus.COMPLETED,
        completedAt: new Date(),
      } as any);
      const eventSpy = jest.spyOn(eventEmitter, 'emit');

      await service.checkAndCompleteReferral('user-2', '5');

      expect(eventSpy).toHaveBeenCalledWith(
        'referral.completed',
        expect.objectContaining({
          eventType: 'referral.completed',
          schemaVersion: 1,
          referralId: 'referral-1',
          referrerId: 'user-1',
          refereeId: 'user-2',
        }),
      );
    });
  });

  describe('getReferralStats', () => {
    it('should return correct statistics', async () => {
      const referrals = [
        { ...mockReferral, status: ReferralStatus.PENDING },
        { ...mockReferral, status: ReferralStatus.COMPLETED },
        {
          ...mockReferral,
          status: ReferralStatus.REWARDED,
          rewardAmount: '10',
        },
      ];
      jest
        .spyOn(referralRepository, 'find')
        .mockResolvedValue(referrals as any);

      const stats = await service.getReferralStats('user-1');

      expect(stats.totalReferrals).toBe(3);
      expect(stats.pendingReferrals).toBe(1);
      expect(stats.completedReferrals).toBe(1);
      expect(stats.rewardedReferrals).toBe(1);
      expect(stats.totalRewardsEarned).toBe('10.0000000');
    });
  });
});
