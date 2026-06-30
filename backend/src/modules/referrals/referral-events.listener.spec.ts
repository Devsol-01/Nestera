import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Notification } from '../notifications/entities/notification.entity';
import { ReferralEventsListener } from './referral-events.listener';
import { ReferralsService } from './referrals.service';
import {
  REFERRAL_COMPLETED_EVENT,
  ReferralCompletedEventPayloadV1,
} from './referral-events.types';

describe('ReferralEventsListener', () => {
  let listener: ReferralEventsListener;
  let notificationRepository: Repository<Notification>;
  let referralsService: ReferralsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReferralEventsListener,
        {
          provide: getRepositoryToken(Notification),
          useValue: {
            save: jest.fn(),
          },
        },
        {
          provide: ReferralsService,
          useValue: {
            distributeRewards: jest.fn(),
          },
        },
      ],
    }).compile();

    listener = module.get<ReferralEventsListener>(ReferralEventsListener);
    notificationRepository = module.get<Repository<Notification>>(
      getRepositoryToken(Notification),
    );
    referralsService = module.get<ReferralsService>(ReferralsService);
  });

  it('should handle version 1 referral.completed payload', async () => {
    const payload: ReferralCompletedEventPayloadV1 = {
      eventType: REFERRAL_COMPLETED_EVENT,
      schemaVersion: 1,
      referralId: 'referral-1',
      referrerId: 'user-1',
      refereeId: 'user-2',
      campaignId: 'campaign-1',
      completedAt: new Date().toISOString(),
    };

    await listener.handleReferralCompleted(payload);

    expect(notificationRepository.save).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: expect.anything(),
        metadata: { referralId: 'referral-1' },
      }),
    );
    expect(referralsService.distributeRewards).toHaveBeenCalledWith(
      'referral-1',
    );
  });

  it('should handle legacy referral.completed payload without version fields', async () => {
    const legacyPayload = {
      referralId: 'referral-2',
      referrerId: 'user-3',
      refereeId: 'user-4',
      campaignId: null,
    };

    await listener.handleReferralCompleted(legacyPayload);

    expect(notificationRepository.save).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-3',
        metadata: { referralId: 'referral-2' },
      }),
    );
    expect(referralsService.distributeRewards).toHaveBeenCalledWith(
      'referral-2',
    );
  });
});
