import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  Notification,
  NotificationType,
} from '../notifications/entities/notification.entity';
import { ReferralsService } from './referrals.service';
import {
  REFERRAL_COMPLETED_EVENT,
  ReferralCompletedEventPayload,
  normalizeReferralCompletedEvent,
} from './referral-events.types';

@Injectable()
export class ReferralEventsListener {
  private readonly logger = new Logger(ReferralEventsListener.name);

  constructor(
    @InjectRepository(Notification)
    private notificationRepository: Repository<Notification>,
    private referralsService: ReferralsService,
  ) {}

  @OnEvent('user.first-deposit')
  async handleFirstDeposit(payload: { userId: string; amount: string }) {
    this.logger.log(`Checking referral completion for user ${payload.userId}`);
    await this.referralsService.checkAndCompleteReferral(
      payload.userId,
      payload.amount,
    );
  }

  @OnEvent('user.signup-with-referral')
  async handleSignupWithReferral(payload: {
    userId: string;
    referralCode: string;
  }) {
    this.logger.log(
      `Applying referral code ${payload.referralCode} for user ${payload.userId}`,
    );
    try {
      await this.referralsService.applyReferralCode(
        payload.referralCode,
        payload.userId,
      );
    } catch (error) {
      this.logger.error(`Failed to apply referral code: ${error.message}`);
      // Don't throw - we don't want to block user registration
    }
  }

  @OnEvent(REFERRAL_COMPLETED_EVENT)
  async handleReferralCompleted(payload: ReferralCompletedEventPayload) {
    const normalizedPayload = normalizeReferralCompletedEvent(payload);

    this.logger.log(`Referral ${normalizedPayload.referralId} completed`);

    // Notify referrer
    await this.notificationRepository.save({
      userId: normalizedPayload.referrerId,
      type: NotificationType.REFERRAL_COMPLETED,
      title: 'Referral Completed!',
      message:
        'Your referral has completed their first deposit. Rewards will be distributed soon.',
      metadata: { referralId: normalizedPayload.referralId },
    });

    // Automatically distribute rewards
    await this.referralsService.distributeRewards(normalizedPayload.referralId);
  }

  @OnEvent('referral.reward.distribute')
  async handleRewardDistribution(payload: {
    userId: string;
    amount: string;
    referralId: string;
    type: 'referrer' | 'referee';
  }) {
    this.logger.log(
      `Distributing ${payload.amount} reward to ${payload.type} ${payload.userId}`,
    );

    // Create notification
    const message =
      payload.type === 'referrer'
        ? `You earned ${payload.amount} tokens for referring a friend!`
        : `Welcome bonus: You received ${payload.amount} tokens!`;

    await this.notificationRepository.save({
      userId: payload.userId,
      type: NotificationType.REFERRAL_REWARD,
      title: 'Referral Reward',
      message,
      metadata: {
        referralId: payload.referralId,
        amount: payload.amount,
        type: payload.type,
      },
    });

    // Here you would integrate with your transaction/wallet system
    // to actually credit the user's account
    // Example: await this.walletService.credit(payload.userId, payload.amount);
  }
}
