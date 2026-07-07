import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Response } from 'express';
import {
  WebhookDelivery,
  DeliveryStatus,
} from '../entities/webhook-delivery.entity';

const DEFAULT_MAX_INGEST_QUEUE_DEPTH = 1000;
const BACKPRESSURE_RETRY_AFTER_SECONDS = 30;

/**
 * Guards the inbound webhook ingest endpoint against queue overload.
 *
 * Before admitting a new inbound request, counts the number of PENDING
 * outbound deliveries.  If that count meets or exceeds the configured
 * maximum, the request is rejected with HTTP 503 and a `Retry-After`
 * header so well-behaved senders back off.
 *
 * This implements the "backpressure when ingest is overloaded" requirement
 * from #1168.  The queue-depth threshold is tunable via
 * `WEBHOOK_MAX_INGEST_QUEUE_DEPTH` (default 1000).
 */
@Injectable()
export class WebhookIngestGuard implements CanActivate {
  private readonly logger = new Logger(WebhookIngestGuard.name);

  constructor(
    @InjectRepository(WebhookDelivery)
    private readonly deliveryRepo: Repository<WebhookDelivery>,
    private readonly configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const maxQueueDepth =
      this.configService.get<number>('webhook.maxIngestQueueDepth') ??
      DEFAULT_MAX_INGEST_QUEUE_DEPTH;

    const pendingCount = await this.deliveryRepo.count({
      where: { status: DeliveryStatus.PENDING },
    });

    if (pendingCount >= maxQueueDepth) {
      const response = context.switchToHttp().getResponse<Response>();
      response.setHeader('Retry-After', BACKPRESSURE_RETRY_AFTER_SECONDS);

      this.logger.warn(
        `Webhook ingest backpressure: ${pendingCount}/${maxQueueDepth} pending deliveries. Rejecting inbound request.`,
      );

      throw new ServiceUnavailableException({
        message:
          'Webhook ingest is at capacity. Please retry after the indicated interval.',
        retryAfterSeconds: BACKPRESSURE_RETRY_AFTER_SECONDS,
      });
    }

    return true;
  }
}
