import { Injectable, Logger, Optional } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { TestModeService } from '../../common/test-mode/test-mode.service';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(
    private readonly mailerService: MailerService,
    @Optional() private readonly testModeService?: TestModeService,
  ) {}

  private async sendMailWithTestMode(
    options: Record<string, unknown>,
  ): Promise<void> {
    if (this.testModeService?.isEnabled) {
      this.testModeService.captureEmail({
        to: options.to as string,
        subject: options.subject as string,
        text: options.text as string | undefined,
        template: options.template as string | undefined,
        context: options.context as Record<string, unknown> | undefined,
        attachments: options.attachments as
          | { filename: string; content: Buffer }[]
          | undefined,
      });
      return;
    }
    await this.mailerService.sendMail(options);
  }

  async sendWelcomeEmail(userEmail: string, name: string): Promise<void> {
    try {
      await this.sendMailWithTestMode({
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

  async sendSweepCompletedEmail(
    userEmail: string,
    name: string,
    amount: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'Account Sweep Completed',
        template: './sweep-completed',
        context: {
          name: name || 'User',
          amount,
        },
      });
      this.logger.log(`Sweep completed email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send sweep completed email to ${userEmail}`,
        error,
      );
    }
  }

  async sendWithdrawalCompletedEmail(
    userEmail: string,
    name: string,
    amount: string,
    penalty: string,
    netAmount: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'Withdrawal Request Completed',
        template: './withdrawal-completed',
        context: {
          name: name || 'User',
          amount,
          penalty,
          netAmount,
        },
      });
      this.logger.log(`Withdrawal completed email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send withdrawal completed email to ${userEmail}`,
        error,
      );
    }
  }

  async sendClaimStatusEmail(
    userEmail: string,
    name: string,
    status: string,
    claimAmount: number,
    notes?: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: `Medical Claim ${status}`,
        template: './claim-status',
        context: {
          name: name || 'User',
          status,
          claimAmount,
          notes: notes || '',
        },
      });
      this.logger.log(`Claim status email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send claim status email to ${userEmail}`,
        error,
      );
    }
  }

  async sendGoalMilestoneEmail(
    userEmail: string,
    name: string,
    goalName: string,
    percentage: number,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: `Congrats — ${percentage}% of your goal achieved!`,
        template: './goal-milestone',
        context: {
          name: name || 'User',
          goalName,
          percentage,
        },
      });
      this.logger.log(
        `Goal milestone email (${percentage}%) sent to ${userEmail}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to send goal milestone email to ${userEmail}`,
        error,
      );
    }
  }

  async sendWaitlistAvailabilityEmail(
    userEmail: string,
    name: string,
    productId: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'A savings product you waited for is available',
        template: './waitlist-available',
        context: {
          name: name || 'User',
          productId,
        },
      });
      this.logger.log(`Waitlist availability email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send waitlist availability email to ${userEmail}`,
        error,
      );
    }
  }

  async sendSavingsAlertEmail(
    userEmail: string,
    name: string,
    message: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'Savings product alert',
        template: './generic-notification',
        context: {
          name: name || 'User',
          message,
        },
      });
      this.logger.log(`Savings alert email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send savings alert email to ${userEmail}`,
        error,
      );
    }
  }

  async sendWithdrawalApprovedEmail(
    userEmail: string,
    name: string,
    amount: string,
    penalty: string,
    netAmount: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'Withdrawal Request Approved',
        template: './withdrawal-approved',
        context: {
          name: name || 'User',
          amount,
          penalty,
          netAmount,
        },
      });
      this.logger.log(`Withdrawal approved email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send withdrawal approved email to ${userEmail}`,
        error,
      );
    }
  }

  async sendWithdrawalRejectedEmail(
    userEmail: string,
    name: string,
    reason: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: 'Withdrawal Request Rejected',
        template: './withdrawal-rejected',
        context: {
          name: name || 'User',
          reason,
        },
      });
      this.logger.log(`Withdrawal rejected email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send withdrawal rejected email to ${userEmail}`,
        error,
      );
    }
  }

  async sendRawMail(to: string, subject: string, text: string): Promise<void> {
    try {
      await this.sendMailWithTestMode({ to, subject, text });
    } catch (error) {
      this.logger.error(`Failed to send raw email to ${to}`, error);
    }
  }

  async sendGovernanceEmail(
    userEmail: string,
    name: string,
    subject: string,
    message: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject,
        template: './generic-notification',
        context: {
          name: name || 'User',
          message,
        },
      });
      this.logger.log(`Governance email (${subject}) sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send governance email to ${userEmail}`,
        error,
      );
    }
  }

  async sendBadgeEarnedEmail(
    userEmail: string,
    name: string,
    badgeName: string,
    points: number,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: `You earned the "${badgeName}" badge!`,
        template: './badge-earned',
        context: {
          name: name || 'User',
          badgeName,
          points,
        },
      });
      this.logger.log(`Badge earned email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(
        `Failed to send badge earned email to ${userEmail}`,
        error,
      );
    }
  }

  async sendReportEmail(
    userEmail: string,
    name: string,
    reportType: string,
    periodLabel: string,
    attachment: Buffer,
    filename: string,
  ): Promise<void> {
    try {
      await this.sendMailWithTestMode({
        to: userEmail,
        subject: `Your ${reportType.replace(/_/g, ' ')} report — ${periodLabel}`,
        template: './savings-alert',
        context: {
          name: name || 'User',
          message: `Your scheduled ${reportType.replace(/_/g, ' ').toLowerCase()} report for ${periodLabel} is attached.`,
        },
        attachments: [
          {
            filename,
            content: attachment,
          },
        ],
      });
      this.logger.log(`Report email sent to ${userEmail}`);
    } catch (error) {
      this.logger.error(`Failed to send report email to ${userEmail}`, error);
    }
  }
}
