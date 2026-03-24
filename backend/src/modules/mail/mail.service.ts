import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

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
}
