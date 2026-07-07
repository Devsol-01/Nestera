import { Test, TestingModule } from '@nestjs/testing';
import { StellarWebhookController } from './stellar-webhook.controller';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { WebhookAllowlistService } from './security/webhook-allowlist.service';

const SENDER_ID_HEADER = 'x-stellar-sender-id';

describe('StellarWebhookController', () => {
  let controller: StellarWebhookController;
  let configService: ConfigService;
  let allowlistMock: { verify: jest.Mock };

  const mockSecret = 'test_webhook_secret_key_123456';
  const mockPayload = {
    type: 'payment',
    transaction_hash: '123...',
    from: 'GA...',
    to: 'GB...',
    amount: '10.0',
  };
  const validSignature = crypto
    .createHmac('sha256', mockSecret)
    .update(JSON.stringify(mockPayload))
    .digest('hex');

  beforeEach(async () => {
    allowlistMock = { verify: jest.fn().mockResolvedValue(true) };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [StellarWebhookController],
      providers: [
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue(mockSecret),
          },
        },
        {
          provide: WebhookAllowlistService,
          useValue: allowlistMock,
        },
      ],
    }).compile();

    controller = module.get<StellarWebhookController>(StellarWebhookController);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('handleWebhook', () => {
    function buildReq() {
      return {
        headers: {
          [SENDER_ID_HEADER]:
            'GSENDER00000000000000000000000000000000000000000000',
        },
      } as any;
    }

    it('returns 200 + success on valid signature AND allowlisted sender', async () => {
      const result = await controller.handleWebhook(
        buildReq(),
        mockPayload,
        validSignature,
      );
      expect(result).toEqual({ status: 'success' });
      expect(allowlistMock.verify).toHaveBeenCalledWith(
        expect.objectContaining({
          [SENDER_ID_HEADER]: expect.any(String),
        }),
        expect.objectContaining({ senderIdHeader: SENDER_ID_HEADER }),
      );
    });

    it('throws UnauthorizedException for missing signature', async () => {
      await expect(
        controller.handleWebhook(buildReq(), mockPayload, undefined),
      ).rejects.toThrow(UnauthorizedException);
      expect(allowlistMock.verify).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException for invalid signature', async () => {
      await expect(
        controller.handleWebhook(buildReq(), mockPayload, 'invalid_signature'),
      ).rejects.toThrow(UnauthorizedException);
      expect(allowlistMock.verify).not.toHaveBeenCalled();
    });

    it('throws when allowlist rejects (after signature was valid)', async () => {
      allowlistMock.verify.mockRejectedValue(
        new UnauthorizedException({
          message: 'Sender is not in the allowlist',
          code: 'WEBHOOK_ALLOWLIST_UNKNOWN_SENDER',
        }),
      );
      await expect(
        controller.handleWebhook(buildReq(), mockPayload, validSignature),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
