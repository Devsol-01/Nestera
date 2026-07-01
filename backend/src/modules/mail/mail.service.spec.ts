import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { MailService, MailTransport } from './mail.service';

describe('MailService', () => {
  let mailerService: { sendMail: jest.Mock };
  let configService: Partial<ConfigService>;
  let service: MailService;

  beforeEach(() => {
    mailerService = { sendMail: jest.fn() };
    configService = {
      get: jest.fn((key: string, defaultValue?: unknown) => {
        const values: Record<string, unknown> = {
          'mail.from': 'noreply@nestera.test',
        };

        return values[key] ?? defaultValue;
      }),
    };

    service = new MailService(
      mailerService as unknown as MailerService,
      configService as ConfigService,
      () => [],
    );
  });

  it('retries the primary provider and falls back to the next provider when it is unavailable', async () => {
    const primaryProvider: MailTransport = {
      name: 'primary',
      maxRetries: 1,
      retryDelayMs: 0,
      sendMail: jest.fn().mockRejectedValue(new Error('primary outage')),
    };

    const secondaryProvider: MailTransport = {
      name: 'secondary',
      maxRetries: 0,
      retryDelayMs: 0,
      sendMail: jest.fn().mockResolvedValue({ messageId: 'secondary-id' }),
    };

    service = new MailService(
      mailerService as unknown as MailerService,
      configService as ConfigService,
      () => [primaryProvider, secondaryProvider],
    );

    await expect(
      service.sendRawMail('user@example.com', 'Test subject', 'hello world'),
    ).resolves.toBeUndefined();

    expect(primaryProvider.sendMail).toHaveBeenCalledTimes(2);
    expect(secondaryProvider.sendMail).toHaveBeenCalledTimes(1);

    const deliveryStatuses = service.getDeliveryStatusHistory();
    expect(deliveryStatuses).toHaveLength(1);
    expect(deliveryStatuses[0].status).toBe('sent');
    expect(deliveryStatuses[0].provider).toBe('secondary');
  });
});
