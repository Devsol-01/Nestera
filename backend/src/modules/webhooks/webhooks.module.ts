import {
  Module,
  MiddlewareConsumer,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { StellarWebhookController } from './stellar-webhook.controller';
import { WebhooksController } from './webhooks.controller';
import { WebhookService } from './webhook.service';
import { WebhookRetryScheduler } from './webhook-retry.scheduler';
import { WebhookSubscription } from './entities/webhook-subscription.entity';
import { WebhookDelivery } from './entities/webhook-delivery.entity';
import { WebhookSender } from './entities/webhook-sender.entity';
import { WebhookSignatureVerifier } from './security/webhook-signature-verifier';
import { ReplayNonceStore } from './security/replay-nonce-store';
import { WebhookAllowlistService } from './security/webhook-allowlist.service';
import { WebhookVerificationMiddleware } from './middleware/webhook-verification.middleware';
import { WebhookIngestGuard } from './security/webhook-ingest.guard';
import { MetricsService } from '../../common/metrics/metrics.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      WebhookSubscription,
      WebhookDelivery,
      WebhookSender,
    ]),
    HttpModule,
  ],
  controllers: [StellarWebhookController, WebhooksController],
  providers: [
    WebhookService,
    WebhookRetryScheduler,
    WebhookSignatureVerifier,
    ReplayNonceStore,
    WebhookAllowlistService,
    WebhookVerificationMiddleware,
    WebhookIngestGuard,
    MetricsService,
  ],
  exports: [WebhookService, WebhookAllowlistService, WebhookSignatureVerifier],
})
export class WebhooksModule implements NestModule {
  /**
   * Applies the unified webhook verification flow:
   *   1. TenantContextMiddleware (already applied globally in AppModule)
   *      populates `req.tenant` for tenant-scoped processing.
   *   2. WebhookVerificationMiddleware verifies signature + timestamp + nonce
   *      and then enforces the DB-backed sender allowlist (with tenant
   *      scoping when multi-tenant mode is enabled).
   *
   * The middleware is bound only to the `webhooks/stellar` route that
   * carries `{PATH:webhooks/stellar}` constraint. It deliberately does not
   * run on the OUTBOUND webhook management endpoints under `/webhooks/*`,
   * which are JWT-protected and not subject to allowlist enforcement.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(WebhookVerificationMiddleware)
      .forRoutes({ path: 'webhooks/stellar', method: RequestMethod.POST });
  }
}
