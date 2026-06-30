import {
  Controller,
  Post,
  Body,
  Headers,
  Req,
  UnauthorizedException,
  Logger,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { Request } from 'express';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { WebhookAllowlistService } from './security/webhook-allowlist.service';

@Controller('webhooks/stellar')
export class StellarWebhookController {
  private readonly logger = new Logger(StellarWebhookController.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly allowlistService: WebhookAllowlistService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @Idempotent({ ttlSeconds: 86400 })
  async handleWebhook(
    @Req() req: Request,
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

    // Defense-in-depth: also enforce the DB-backed sender allowlist here
    // (in addition to the middleware) so the controller cannot be reached
    // without allowlisting, even if the middleware is bypassed in tests or
    // by a future routing change. The middleware path runs first and short-
    // circuits duplicate work in production, but this fallback guarantees
    // the contract under any configuration.
    await this.allowlistService.verify(req.headers, {
      senderIdHeader: 'x-stellar-sender-id',
    });

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

    this.logger.log(
      `Processing ${type}:\n      Hash: ${transaction_hash}\n      From: ${from}\n      To: ${to}\n      Amount: ${amount} ${asset_code || 'XLM'}\n      Issuer: ${asset_issuer || 'native'}\n    `,
    );

    // TODO: Add further logic here (e.g., updating database, notifying user)
  }
}
