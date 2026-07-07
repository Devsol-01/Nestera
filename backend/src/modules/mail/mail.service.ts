import { Injectable, Logger, Optional } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { createTransport } from 'nodemailer';
import { TestModeService } from '../../common/test-mode/test-mode.service';

export interface MailTransport {
  name: string;
  sendMail(options: Record<string, unknown>): Promise<unknown>;
  maxRetries?: number;
  retryDelayMs?: number;
  region?: string;
}

export type MailTransportFactory = () => MailTransport[];

export interface EmailDeliveryStatus {
  messageId: string;
  to: string;
  subject: string;
  status: 'queued' | 'sending' | 'sent' | 'failed';
  attempts: number;
  provider?: string;
  lastAttemptAt: Date;
  error?: string;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly deliveryStatuses = new Map<string, EmailDeliveryStatus>();
  private readonly defaultFrom: string;

  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
    @Optional() private readonly testModeService?: TestModeService,
    private readonly mailTransportFactory?: MailTransportFactory,
  ) {
    this.defaultFrom =
      this.configService.get<string>(
        'mail.from',
        '"Nestera" <noreply@nestera.io>',
      ) ?? '"Nestera" <noreply@nestera.io>';
  }

  async sendWelcomeEmail(userEmail: string, name: string): Promise<void> {
    try {
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({ to, subject, text });
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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
      await this.sendMailWithResilience({
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

  getDeliveryStatusHistory(): EmailDeliveryStatus[] {
    return [...this.deliveryStatuses.values()].sort(
      (left, right) =>
        right.lastAttemptAt.getTime() - left.lastAttemptAt.getTime(),
    );
  }

  getDeliveryStatus(messageId: string): EmailDeliveryStatus | undefined {
    return this.deliveryStatuses.get(messageId);
  }

  private async sendMailWithResilience(
    options: Record<string, unknown>,
  ): Promise<void> {
    // In test mode, capture the email instead of actually sending it,
    // and skip the provider/retry machinery entirely.
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

    const providers = this.mailTransportFactory
      ? this.mailTransportFactory()
      : this.buildDefaultTransports();

    const normalizedProviders = providers.length
      ? providers
      : [
          {
            name: 'default',
            maxRetries: 1,
            retryDelayMs: 0,
            sendMail: (mailOptions: Record<string, unknown>) =>
              this.mailerService.sendMail(mailOptions),
          },
        ];

    const messageId = this.createMessageId(
      String(options.to ?? ''),
      String(options.subject ?? ''),
    );
    const status: EmailDeliveryStatus = {
      messageId,
      to: String(options.to ?? ''),
      subject: String(options.subject ?? ''),
      status: 'queued',
      attempts: 0,
      lastAttemptAt: new Date(),
    };

    this.deliveryStatuses.set(messageId, status);

    let lastError: Error | null = null;

    for (const provider of normalizedProviders) {
      const maxAttempts = (provider.maxRetries ?? 1) + 1;

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        status.status = 'sending';
        status.attempts += 1;
        status.provider = provider.name;
        status.lastAttemptAt = new Date();
        this.deliveryStatuses.set(messageId, { ...status });

        try {
          await provider.sendMail({
            ...options,
            from: options.from ?? this.defaultFrom,
          });

          status.status = 'sent';
          status.error = undefined;
          status.lastAttemptAt = new Date();
          this.deliveryStatuses.set(messageId, { ...status });
          return;
        } catch (error) {
          lastError = error as Error;
          status.error = lastError.message;
          status.lastAttemptAt = new Date();
          this.deliveryStatuses.set(messageId, { ...status });
          this.logger.warn(
            `Provider ${provider.name} attempt ${attempt}/${maxAttempts} failed: ${lastError.message}`,
          );

          if (attempt < maxAttempts) {
            await this.sleep(
              (provider.retryDelayMs ?? 0) * Math.pow(2, attempt - 1),
            );
          }
        }
      }
    }

    status.status = 'failed';
    status.error = lastError?.message ?? 'Unknown mail delivery failure';
    status.lastAttemptAt = new Date();
    this.deliveryStatuses.set(messageId, { ...status });
    throw lastError ?? new Error(`Unable to deliver email to ${status.to}`);
  }

  private buildDefaultTransports(): MailTransport[] {
    const configuredProviders =
      this.configService.get<string>('mail.providers');

    if (configuredProviders) {
      try {
        const parsedProviders = JSON.parse(configuredProviders) as Array<
          Record<string, unknown>
        >;

        if (Array.isArray(parsedProviders)) {
          return parsedProviders.map((providerConfig) =>
            this.buildTransportFromConfig(providerConfig),
          );
        }
      } catch (error) {
        this.logger.warn(
          `Unable to parse mail providers config: ${(error as Error).message}`,
        );
      }
    }

    const host = this.configService.get<string>('mail.host');
    const port = this.configService.get<number>('mail.port');
    const user = this.configService.get<string>('mail.user');
    const pass = this.configService.get<string>('mail.pass');

    if (!host && !user && !pass) {
      return [];
    }

    return [
      this.buildTransportFromConfig({
        name: 'default',
        host,
        port,
        secure: false,
        user,
        pass,
        maxRetries: 1,
        retryDelayMs: 0,
      }),
    ];
  }

  private buildTransportFromConfig(
    providerConfig: Record<string, unknown>,
  ): MailTransport {
    const name = String(providerConfig.name ?? 'default');
    const host = providerConfig.host as string | undefined;
    const port = Number(providerConfig.port ?? 587);
    const secure = Boolean(providerConfig.secure ?? false);
    const user = providerConfig.user as string | undefined;
    const pass = providerConfig.pass as string | undefined;
    const maxRetries = Number(providerConfig.maxRetries ?? 1);
    const retryDelayMs = Number(providerConfig.retryDelayMs ?? 0);

    const transporter = host
      ? createTransport({
          host,
          port,
          secure,
          auth:
            user || pass
              ? {
                  user: user ?? '',
                  pass: pass ?? '',
                }
              : undefined,
        })
      : undefined;

    return {
      name,
      maxRetries: Number.isFinite(maxRetries) ? maxRetries : 1,
      retryDelayMs: Number.isFinite(retryDelayMs) ? retryDelayMs : 0,
      region: providerConfig.region as string | undefined,
      sendMail: (mailOptions: Record<string, unknown>) =>
        transporter?.sendMail(mailOptions) ??
        this.mailerService.sendMail(mailOptions),
    };
  }

  private createMessageId(to: string, subject: string): string {
    return `${to}:${subject}:${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}