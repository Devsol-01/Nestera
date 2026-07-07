import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThanOrEqual } from 'typeorm';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { firstValueFrom } from 'rxjs';
import {
  WebhookSubscription,
  WebhookStatus,
} from './entities/webhook-subscription.entity';
import {
  WebhookDelivery,
  DeliveryStatus,
} from './entities/webhook-delivery.entity';
import { CreateWebhookDto } from './dto/create-webhook.dto';
import { UpdateWebhookDto } from './dto/update-webhook.dto';

/** Exponential back-off delays in minutes: 1, 5, 30, 120 */
const RETRY_DELAYS_MINUTES = [1, 5, 30, 120];
const MAX_ATTEMPTS = RETRY_DELAYS_MINUTES.length + 1; // 5 total

/** Maximum pending outbound deliveries before new dispatch calls are shed. */
const DEFAULT_MAX_PENDING_DELIVERIES = 500;

@Injectable()
export class WebhookService {
  private readonly logger = new Logger(WebhookService.name);

  constructor(
    @InjectRepository(WebhookSubscription)
    private readonly subRepo: Repository<WebhookSubscription>,
    @InjectRepository(WebhookDelivery)
    private readonly deliveryRepo: Repository<WebhookDelivery>,
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  // ── Registration ──────────────────────────────────────────────────────────

  async register(
    userId: string,
    dto: CreateWebhookDto,
  ): Promise<WebhookSubscription> {
    const secret = dto.secret ?? crypto.randomBytes(32).toString('hex');
    const sub: WebhookSubscription = this.subRepo.create({
      ...dto,
      userId,
      secret,
    });
    return this.subRepo.save(sub);
  }

  async list(userId: string): Promise<WebhookSubscription[]> {
    return this.subRepo.find({ where: { userId } });
  }

  async findOne(id: string, userId: string): Promise<WebhookSubscription> {
    const sub = await this.subRepo.findOne({ where: { id } });
    if (!sub) throw new NotFoundException('Webhook not found');
    if (sub.userId !== userId) throw new ForbiddenException();
    return sub;
  }

  async remove(id: string, userId: string): Promise<void> {
    const sub = await this.findOne(id, userId);
    await this.subRepo.remove(sub);
  }

  async update(
    id: string,
    userId: string,
    dto: UpdateWebhookDto,
  ): Promise<WebhookSubscription> {
    const sub = await this.findOne(id, userId);
    Object.assign(sub, dto);
    return this.subRepo.save(sub);
  }

  async disable(id: string, userId: string): Promise<WebhookSubscription> {
    const sub = await this.findOne(id, userId);
    sub.status = WebhookStatus.DISABLED;
    return this.subRepo.save(sub);
  }

  async enable(id: string, userId: string): Promise<WebhookSubscription> {
    const sub = await this.findOne(id, userId);
    sub.status = WebhookStatus.ACTIVE;
    return this.subRepo.save(sub);
  }

  // ── Delivery ──────────────────────────────────────────────────────────────

  /**
   * Fan-out an event to all active subscriptions that match the event name.
   * Matching supports exact names and wildcard patterns (e.g. 'savings.*').
   *
   * Applies backpressure: if the number of PENDING outbound deliveries
   * exceeds `WEBHOOK_MAX_PENDING_DELIVERIES`, the dispatch is shed and a
   * warning is logged.  Callers should surface this as a 503 on ingest
   * paths so upstream senders retry later.
   */
  async dispatch(
    eventName: string,
    payload: Record<string, any>,
  ): Promise<void> {
    const maxPending =
      this.configService.get<number>('webhook.maxPendingDeliveries') ??
      DEFAULT_MAX_PENDING_DELIVERIES;
    const pendingCount = await this.deliveryRepo.count({
      where: { status: DeliveryStatus.PENDING },
    });
    if (pendingCount >= maxPending) {
      this.logger.warn(
        `Webhook dispatch shed: queue at capacity (${pendingCount}/${maxPending} pending). Event=${eventName}`,
      );
      return;
    }

    const subs = await this.subRepo.find({
      where: { status: WebhookStatus.ACTIVE },
    });
    const matching = subs.filter((s) => this.matches(s.events, eventName));

    await Promise.all(
      matching.map((sub) => this.createAndDeliver(sub, eventName, payload)),
    );
  }

  private async createAndDeliver(
    sub: WebhookSubscription,
    eventName: string,
    payload: Record<string, any>,
  ): Promise<void> {
    const delivery = await this.deliveryRepo.save(
      this.deliveryRepo.create({ subscriptionId: sub.id, eventName, payload }),
    );
    await this.attempt(delivery, sub);
  }

  async attempt(
    delivery: WebhookDelivery,
    sub?: WebhookSubscription,
  ): Promise<void> {
    if (!sub) {
      const found = await this.subRepo.findOne({
        where: { id: delivery.subscriptionId },
      });
      if (!found) return;
      sub = found;
    }

    delivery.attempts += 1;
    delivery.nextRetryAt = null;

    const body = JSON.stringify({
      event: delivery.eventName,
      data: delivery.payload,
    });
    const sig = this.sign(body, sub.secret);
    const timestamp = Date.now().toString();

    try {
      const deliveryTimeoutMs =
        this.configService.get<number>('timeouts.webhookDeliveryMs') ?? 10_000;
      const response = await firstValueFrom(
        this.httpService.post(sub.url, body, {
          headers: {
            'Content-Type': 'application/json',
            'X-Nestera-Signature': `sha256=${sig}`,
            'X-Nestera-Timestamp': timestamp,
            'X-Nestera-Event': delivery.eventName,
          },
          timeout: deliveryTimeoutMs,
          validateStatus: () => true, // don't throw on 4xx/5xx
        }),
      );

      const success = response.status >= 200 && response.status < 300;
      delivery.responseStatus = response.status;
      delivery.responseBody = String(response.data ?? '').substring(0, 500);
      delivery.status = success
        ? DeliveryStatus.SUCCESS
        : DeliveryStatus.FAILED;

      if (!success) {
        this.scheduleRetry(delivery);
      }
    } catch (err) {
      delivery.status = DeliveryStatus.FAILED;
      delivery.errorMessage = (err as Error).message;
      this.scheduleRetry(delivery);
    }

    await this.deliveryRepo.save(delivery);
  }

  private scheduleRetry(delivery: WebhookDelivery): void {
    const retryIndex = delivery.attempts - 1; // 0-based
    if (retryIndex >= RETRY_DELAYS_MINUTES.length) {
      this.logger.warn(`Webhook delivery ${delivery.id} exhausted retries`);
      return;
    }
    const delayMs = RETRY_DELAYS_MINUTES[retryIndex] * 60_000;
    delivery.nextRetryAt = new Date(Date.now() + delayMs);
    delivery.status = DeliveryStatus.PENDING;
  }

  /** Retry all pending deliveries whose nextRetryAt is in the past */
  async retryDue(): Promise<void> {
    const due = await this.deliveryRepo.find({
      where: {
        status: DeliveryStatus.PENDING,
        nextRetryAt: LessThanOrEqual(new Date()),
      },
      take: 100,
    });
    await Promise.all(due.map((d) => this.attempt(d)));
  }

  // ── Logs ──────────────────────────────────────────────────────────────────

  async getLogs(
    subscriptionId: string,
    userId: string,
  ): Promise<WebhookDelivery[]> {
    await this.findOne(subscriptionId, userId); // ownership check
    return this.deliveryRepo.find({
      where: { subscriptionId },
      order: { createdAt: 'DESC' },
      take: 100,
    });
  }

  // ── Test endpoint ─────────────────────────────────────────────────────────

  async test(id: string, userId: string): Promise<WebhookDelivery> {
    const sub = await this.findOne(id, userId);
    const delivery = await this.deliveryRepo.save(
      this.deliveryRepo.create({
        subscriptionId: sub.id,
        eventName: 'webhook.test',
        payload: {
          message: 'This is a test event from Nestera',
          timestamp: new Date().toISOString(),
        },
      }),
    );
    await this.attempt(delivery, sub);
    return delivery;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  sign(body: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(body).digest('hex');
  }

  verifySignature(body: string, secret: string, signature: string): boolean {
    const expected = `sha256=${this.sign(body, secret)}`;
    try {
      return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected),
      );
    } catch {
      return false;
    }
  }

  private matches(patterns: string[], eventName: string): boolean {
    return patterns.some((p) => {
      if (p === '*') return true;
      if (p.endsWith('.*')) {
        const prefix = p.slice(0, -2);
        return eventName === prefix || eventName.startsWith(`${prefix}.`);
      }
      return p === eventName;
    });
  }
}
