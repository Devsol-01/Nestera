import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ClaimStatus } from '../claims/entities/medical-claim.entity';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly mailerService: MailerService) {}

  async sendWelcomeEmail(userEmail: string, name: string): Promise<void> {
    try {
      await this.mailerService.sendMail({
        to: userEmail,
        subject: 'Welcome to Nestera!',
        template: './welcome',
        context: {
          name: name || 'there',
        },
      });
      this.logger.log(`Welcome email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${userEmail}`, error);
    }
  }

  async sendSweepCompleted(
    userEmail: string,
    userName: string,
    productName: string,
    amount: number,
    txHash?: string,
  ): Promise<void> {
    try {
      await this.mailerService.sendMail({
        to: userEmail,
        subject: 'Your Nestera account sweep was successful',
        template: './sweep-completed',
        context: { userName, productName, amount, txHash },
      });
      this.logger.log(`Sweep-completed email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send sweep-completed email to ${userEmail}`,
        error,
      );
    }
  }

  async sendClaimUpdated(
    patientEmail: string,
    patientName: string,
    claimId: string,
    hospitalName: string,
    claimAmount: number,
    status: ClaimStatus,
    notes?: string,
  ): Promise<void> {
    try {
      await this.mailerService.sendMail({
        to: patientEmail,
        subject: `Your medical claim status has been updated to ${status}`,
        template: './claim-updated',
        context: { patientName, claimId, hospitalName, claimAmount, status, notes },
      });
      this.logger.log(`Claim-updated email sent to ${patientEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send claim-updated email to ${patientEmail}`,
        error,
      );
    }
  }
}
