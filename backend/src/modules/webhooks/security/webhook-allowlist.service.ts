import {
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request } from 'express';
import { REQUEST } from '@nestjs/core';
import { WebhookSender } from '../entities/webhook-sender.entity';
import { TenantContextService } from '../../../common/services/tenant-context.service';
import { MetricsService } from '../../../common/metrics/metrics.service';
import {
  WebhookAllowlistErrorCode,
  WebhookAllowlistErrorPayload,
} from './webhook-allowlist.errors';

export interface WebhookAllowlistVerifyOptions {
  /**
   * Header that carries the stable sender id. Defaults to
   * `x-stellar-sender-id` which is the canonical header for the
   * Stellar integration. Other integrations can override this.
   */
  senderIdHeader?: string;
  /**
   * Whether to require a senderId to be present. Defaults to true so
   * callers cannot skip allowlist enforcement by omitting the header.
   */
  requireSenderId?: boolean;
}

export interface WebhookAllowlistContext {
  /** The raw senderId presented in the request (or null if missing) */
  presentedSenderId: string | null;
  /** The tenant context id from the request (or null) */
  requestTenantId: string | null;
  /** Whether multi-tenant mode is enabled in configuration */
  multiTenantEnabled: boolean;
}

const DEFAULT_SENDER_ID_HEADER = 'x-stellar-sender-id';
/**
 * Maximum length for a header-stripped sender id. Inline cap protects the
 * logger and downstream code from oversized attacker-controlled values.
 */
const MAX_SENDER_ID_LENGTH = 256;
/**
 * Length cap applied to the sender id before it is used as a metric tag.
 * Metrics tags are kept under this cap so an attacker cannot blow up the
 * cardinality of the in-memory metrics map (Cardinality DoS).
 */
const METRIC_TAG_SENDER_ID_PREFIX = 12;
/**
 * Like {@link METRIC_TAG_SENDER_ID_PREFIX} but for tenant ids.
 */
const METRIC_TAG_TENANT_ID_PREFIX = 16;

/**
 * Webhook Sender Allowlist Service
 *
 * Verifies that an incoming webhook came from a known sender (DB-backed
 * allowlist) and — when multi-tenant mode is enabled — that the request's
 * tenant context is compatible with the sender's tenant scope.
 *
 * This service MUST be called AFTER signature verification. It is a pure
 * authorization / identity check; it never reads request bodies for
 * validation and therefore never has secrets in its log path.
 *
 * Operational behavior:
 *   - On rejection: increments `webhook_rejections_total` metric with
 *     reason + bounded sender_id (when known) + bounded tenant_id (when known).
 *   - On rejection: emits a structured warn-level log including only
 *     non-sensitive fields (NO signature, body, or HMAC secret).
 *   - On success: increments `webhook_accepted_total` for observability.
 *
 * NOTE: When the allowlist is empty the service rejects ALL requests.
 * Operators must seed the table to enable webhook ingestion. This is the
 * safe default — "fail closed" rather than "fail open" relative to the
 * tenant's security posture.
 */
@Injectable()
export class WebhookAllowlistService {
  private readonly logger = new Logger(WebhookAllowlistService.name);

  constructor(
    @InjectRepository(WebhookSender)
    private readonly senderRepo: Repository<WebhookSender>,
    private readonly configService: ConfigService,
    private readonly metricsService: MetricsService,
    @Inject(REQUEST)
    private readonly request: Request,
    private readonly tenantContextService: TenantContextService,
  ) {}

  /**
   * Verify the sender against the allowlist.
   *
   * Returns true on success. Throws UnauthorizedException with a
   * machine-readable `code` on rejection.
   */
  async verify(
    headers: Record<string, string | string[] | undefined>,
    options?: WebhookAllowlistVerifyOptions,
  ): Promise<true> {
    // If the middleware path already verified this request, short-circuit
    // so we do NOT double-count `webhook_accepted_total` and do NOT make
    // a second DB lookup. Controller-level (or test) callers without the
    // flag continue to enforce the check normally.
    if (this.isRequestAlreadyVerified()) {
      return true;
    }

    const senderIdHeader = options?.senderIdHeader ?? DEFAULT_SENDER_ID_HEADER;
    const requireSenderId = options?.requireSenderId ?? true;

    const raw = headers[senderIdHeader];
    const senderId = Array.isArray(raw) ? raw[0] : raw;

    const context: WebhookAllowlistContext = {
      presentedSenderId: this.normalizeSenderId(senderId),
      requestTenantId: this.resolveRequestTenantId(),
      multiTenantEnabled: this.isMultiTenantEnabled(),
    };

    if (!context.presentedSenderId) {
      if (!requireSenderId) return true;
      this.handleRejection(
        WebhookAllowlistErrorCode.MISSING_SENDER_ID,
        `Missing ${senderIdHeader} header`,
        context,
        { senderIdHeader },
      );
    }

    const row = await this.senderRepo.findOne({
      where: { senderId: context.presentedSenderId },
    });

    if (!row) {
      this.handleRejection(
        WebhookAllowlistErrorCode.UNKNOWN_SENDER,
        'Sender is not in the allowlist',
        context,
      );
    }

    if (row.enabled === false) {
      this.handleRejection(
        WebhookAllowlistErrorCode.SENDER_DISABLED,
        'Sender is disabled in the allowlist',
        context,
        { allowlistId: row.id },
      );
    }

    if (context.multiTenantEnabled) {
      this.enforceTenantScope(row, context);
    }

    this.metricsService.incrementCounter('webhook_accepted_total', 1, {
      sender_id: this.boundedTag(context.presentedSenderId, 'sender'),
      tenant_id: this.boundedTag(context.requestTenantId ?? 'none', 'tenant'),
      multi_tenant: context.multiTenantEnabled ? 'true' : 'false',
    });

    this.logger.log({
      msg: 'Webhook sender allowlisted',
      senderId: context.presentedSenderId,
      tenantId: context.requestTenantId,
      multiTenant: context.multiTenantEnabled,
    });

    return true;
  }

  /**
   * Mark the current request as allowlist-verified. Called by
   * {@link WebhookVerificationMiddleware} after both signature and
   * allowlist checks succeed. The webhooks controller's defense-in-depth
   * call short-circuits on this flag instead of re-running the lookup.
   */
  markRequestVerified(): void {
    const req = this.request as
      | (Request & { [k: string]: unknown })
      | undefined;
    if (req) req['webhookAllowlistVerified'] = true;
  }

  /**
   * Returns true when the current request was already verified by the
   * middleware on the same request object. Used to skip the duplicate
   * controller-level invocation of {@link verify}.
   */
  private isRequestAlreadyVerified(): boolean {
    const req = this.request as
      | (Request & { webhookAllowlistVerified?: boolean })
      | undefined;
    return req?.webhookAllowlistVerified === true;
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  private normalizeSenderId(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim();
    if (trimmed.length === 0) return null;
    // Defensive cap on raw length so a maliciously long header value
    // cannot be stored unredacted in logs.
    if (trimmed.length > MAX_SENDER_ID_LENGTH) {
      return trimmed.slice(0, MAX_SENDER_ID_LENGTH);
    }
    return trimmed;
  }

  /**
   * Bound a tag value to a small, cardinality-safe prefix so an attacker
   * cannot blow up the in-memory metrics map (`MetricsService.metrics`
   * keyed by tag combinations). The original value still flows through to
   * logs — only the metric tag is bounded.
   */
  private boundedTag(value: string, kind: 'sender' | 'tenant'): string {
    const limit =
      kind === 'tenant'
        ? METRIC_TAG_TENANT_ID_PREFIX
        : METRIC_TAG_SENDER_ID_PREFIX;
    return value.length <= limit ? value : value.slice(0, limit);
  }

  /**
   * Multi-tenant detection reads exclusively from typed configuration so
   * tests can assert behavior via the config mock — there is no parallel
   * env-var truth source.
   */
  private isMultiTenantEnabled(): boolean {
    const fromConfig = this.configService.get<boolean>(
      'multiTenant.enabled',
      false,
    );
    return fromConfig === true;
  }

  private resolveRequestTenantId(): string | null {
    // Prefer the request-scoped tenant context service when wired in
    // (CommonModule exports it).
    const fromService = this.tenantContextService.getTenantId();
    if (fromService) return fromService;

    // Fallback to `req.tenant` slotted in by TenantContextMiddleware.
    const req = this.request as
      | (Request & { tenant?: { id?: string } })
      | undefined;
    return req?.tenant?.id ?? null;
  }

  private enforceTenantScope(
    row: WebhookSender,
    context: WebhookAllowlistContext,
  ): void {
    // Wildcard sender (tenantId == null) is allowed for any tenant context,
    // including requests that arrive without tenant context.
    if (row.tenantId == null) {
      return;
    }

    // The row is tenant-scoped, so we require a matching request tenant.
    if (!context.requestTenantId) {
      this.handleRejection(
        WebhookAllowlistErrorCode.MISSING_TENANT_CONTEXT,
        'Sender requires tenant context but request has none',
        context,
        { allowlistId: row.id, expectedTenantId: row.tenantId },
      );
    }

    if (context.requestTenantId !== row.tenantId) {
      this.handleRejection(
        WebhookAllowlistErrorCode.TENANT_MISMATCH,
        'Webhook tenant context does not match allowlist scope',
        context,
        {
          allowlistId: row.id,
          allowlistTenantId: row.tenantId,
          requestTenantId: context.requestTenantId,
        },
      );
    }
  }

  private handleRejection(
    code: WebhookAllowlistErrorCode,
    message: string,
    context: WebhookAllowlistContext,
    details?: Record<string, unknown>,
  ): never {
    // Redact anything that might contain a secret before logging.
    const safeDetails = details ? this.sanitizeDetails(details) : undefined;

    this.metricsService.incrementCounter('webhook_rejections_total', 1, {
      reason: this.reasonTagFor(code),
      sender_id: this.boundedTag(context.presentedSenderId ?? 'none', 'sender'),
      tenant_id: this.boundedTag(context.requestTenantId ?? 'none', 'tenant'),
      multi_tenant: context.multiTenantEnabled ? 'true' : 'false',
    });

    this.logger.warn({
      msg: 'Webhook rejected by allowlist',
      reason: code,
      senderId: context.presentedSenderId,
      requestTenantId: context.requestTenantId,
      multiTenant: context.multiTenantEnabled,
      details: safeDetails,
    });

    const payload: WebhookAllowlistErrorPayload = {
      code,
      message,
      details: safeDetails,
    };
    throw new UnauthorizedException({
      message: payload.message,
      code: payload.code,
      details: payload.details,
    });
  }

  private reasonTagFor(code: WebhookAllowlistErrorCode): string {
    switch (code) {
      case WebhookAllowlistErrorCode.MISSING_SENDER_ID:
        return 'missing_sender_id';
      case WebhookAllowlistErrorCode.UNKNOWN_SENDER:
        return 'unknown_sender';
      case WebhookAllowlistErrorCode.SENDER_DISABLED:
        return 'sender_disabled';
      case WebhookAllowlistErrorCode.TENANT_MISMATCH:
        return 'tenant_mismatch';
      case WebhookAllowlistErrorCode.MISSING_TENANT_CONTEXT:
        return 'missing_tenant_context';
    }
  }

  /**
   * Strips any top-level key that LOOKS sensitive. Defaults to depth-1
   * because the only caller (handleRejection) constructs a flat bag of
   * static, scalar fields. Do NOT pass caller-controlled nested objects
   * through this function.
   */
  private sanitizeDetails(
    details: Record<string, unknown>,
  ): Record<string, unknown> {
    const SENSITIVE_KEYS =
      /(secret|password|token|signature|hmac|key|seed|passphrase|private|mnemonic)/i;
    const safe: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(details)) {
      if (SENSITIVE_KEYS.test(k)) {
        safe[k] = '[REDACTED]';
      } else {
        safe[k] = v;
      }
    }
    return safe;
  }
}
