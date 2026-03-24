import {
  Controller,
  Post,
  Body,
  Headers,
  UnauthorizedException,
  Logger,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Controller('webhooks/stellar')
export class StellarWebhookController {
  private readonly logger = new Logger(StellarWebhookController.name);

  constructor(private configService: ConfigService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  async handleWebhook(
    @Body() payload: any,
    @Headers('x-stellar-signature') signature?: string,
  ) {
    this.logger.log('Received Stellar webhook');

    if (!signature) {
      this.logger.warn('Missing x-stellar-signature header');
      throw new UnauthorizedException('Missing signature');
    }

    const secret =
      this.configService.get<string>('stellar.webhookSecret') || '';
    const payloadString = JSON.stringify(payload);

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payloadString)
      .digest('hex');

    if (!this.verifySignature(signature, expectedSignature)) {
      this.logger.warn('Invalid webhook signature');
      throw new UnauthorizedException('Invalid signature');
    }

    this.logger.log('Webhook signature verified');
    this.processPayment(payload);

    return { status: 'success' };
  }

  private verifySignature(
    signature: string,
    expectedSignature: string,
  ): boolean {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex'),
      );
    } catch (error) {
      return false;
    }
  }

  private processPayment(payload: any) {
    const {
      type,
      from,
      to,
      amount,
      asset_code,
      asset_issuer,
      transaction_hash,
    } = payload;

    this.logger.log(`Processing ${type}:
      Hash: ${transaction_hash}
      From: ${from}
      To: ${to}
      Amount: ${amount} ${asset_code || 'XLM'}
      Issuer: ${asset_issuer || 'native'}
    `);

    // TODO: Add further logic here (e.g., updating database, notifying user)
  }
}
