import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { MailService } from '../mail/mail.service';
import { Notification, NotificationType } from './entities/notification.entity';
import { SweepCompletedEvent } from './events/sweep-completed.event';
import { ClaimUpdatedEvent } from './events/claim-updated.event';

@Injectable()
export class NotificationService {
  private readonly logger = new Logger(NotificationService.name);

  constructor(
    @InjectRepository(Notification)
    private readonly notificationRepository: Repository<Notification>,
    private readonly mailService: MailService,
  ) {}

  @OnEvent('sweep.completed', { async: true })
  async handleSweepCompleted(event: SweepCompletedEvent): Promise<void> {
    this.logger.log(`Handling sweep.completed for user ${event.userId}`);

    await Promise.all([
      this.mailService.sendSweepCompleted(
        event.userEmail,
        event.userName,
        event.productName,
        event.amount,
        event.txHash,
      ),
      this.notificationRepository.save(
        this.notificationRepository.create({
          userId: event.userId,
          type: NotificationType.SWEEP_COMPLETED,
          title: 'Account Sweep Successful',
          message: `Your sweep of ${event.amount} from "${event.productName}" has been completed successfully.`,
          referenceId: event.subscriptionId,
        }),
      ),
    ]);
  }

  @OnEvent('claim.updated', { async: true })
  async handleClaimUpdated(event: ClaimUpdatedEvent): Promise<void> {
    this.logger.log(`Handling claim.updated for claim ${event.claimId}`);

    await Promise.all([
      this.mailService.sendClaimUpdated(
        event.patientEmail,
        event.patientName,
        event.claimId,
        event.hospitalName,
        event.claimAmount,
        event.status,
        event.notes,
      ),
      this.notificationRepository.save(
        this.notificationRepository.create({
          userId: event.claimId,
          type: NotificationType.CLAIM_UPDATED,
          title: `Claim ${event.status}`,
          message: `Your medical claim at ${event.hospitalName} for $${event.claimAmount} has been updated to ${event.status}.${event.notes ? ` Notes: ${event.notes}` : ''}`,
          referenceId: event.claimId,
        }),
      ),
    ]);
  }

  async getNotificationsForUser(userId: string): Promise<Notification[]> {
    return this.notificationRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async markAsRead(id: string): Promise<void> {
    await this.notificationRepository.update(id, { isRead: true });
  }
}
