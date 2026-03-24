import { Module } from '@nestjs/common';
import { StellarWebhookController } from './stellar-webhook.controller';

@Module({
  controllers: [StellarWebhookController],
})
export class WebhooksModule {}
