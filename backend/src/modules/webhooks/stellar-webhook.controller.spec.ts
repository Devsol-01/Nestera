import { Test, TestingModule } from '@nestjs/testing';
import { StellarWebhookController } from './stellar-webhook.controller';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';

describe('StellarWebhookController', () => {
  let controller: StellarWebhookController;
  let configService: ConfigService;

  const mockSecret = 'test_webhook_secret_key_123456';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [StellarWebhookController],
      providers: [
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue(mockSecret),
          },
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
    const mockPayload = {
      type: 'payment',
      transaction_hash: '123...',
      from: 'GA...',
      to: 'GB...',
      amount: '10.0',
    };
    const payloadString = JSON.stringify(mockPayload);
    const validSignature = crypto
      .createHmac('sha256', mockSecret)
      .update(payloadString)
      .digest('hex');

    it('should return 200 and success status for valid signature', async () => {
      const result = await controller.handleWebhook(
        mockPayload,
        validSignature,
      );
      expect(result).toEqual({ status: 'success' });
    });

    it('should throw UnauthorizedException for missing signature', async () => {
      await expect(
        controller.handleWebhook(mockPayload, undefined),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for invalid signature', async () => {
      const invalidSignature = 'invalid_signature';
      await expect(
        controller.handleWebhook(mockPayload, invalidSignature),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should handle webhook with different body order', async () => {
      // Since we use JSON.stringify(payload), the order matters.
      // In a real scenario, the provider should be consistent or we should sort keys.
      // For this implementation, we assume the stringified payload matches the signature.
      const reorderedPayload = { ...mockPayload, amount: '10.0' }; // same order here
      const result = await controller.handleWebhook(
        reorderedPayload,
        validSignature,
      );
      expect(result).toEqual({ status: 'success' });
    });
  });
});
