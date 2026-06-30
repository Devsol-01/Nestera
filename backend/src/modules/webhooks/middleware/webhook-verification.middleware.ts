import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { WebhookSignatureVerifier } from '../security/webhook-signature-verifier';
import { WebhookAllowlistService } from '../security/webhook-allowlist.service';

/**
 * Inbound webhook verification pipeline:
 *
 *   1. Cryptographic verification (signature + timestamp + replay nonce)
 *      via {@link WebhookSignatureVerifier}.
 *   2. Identity verification (DB-backed sender allowlist + tenant scope)
 *      via {@link WebhookAllowlistService}.
 *
 * The middleware is intentionally *fail-closed*: any error short-circuits
 * the response. Callers never get past the middleware if either step
 * fails, and no allowlisting logic ever logs raw signatures or secrets.
 */
@Injectable()
export class WebhookVerificationMiddleware implements NestMiddleware {
  constructor(
    private readonly configService: ConfigService,
    private readonly verifier: WebhookSignatureVerifier,
    private readonly allowlist: WebhookAllowlistService,
  ) {}

  async use(
    req: Request,
    res: Response,
    next: (err?: any) => void,
  ): Promise<void> {
    const secret =
      this.configService.get<string>('stellar.webhookSecret') || '';

    // For Stellar webhooks, we use:
    // - signature header: x-stellar-signature (hex)
    // - timestamp/nonce headers: x-nestera-timestamp, x-nestera-nonce
    // If provider doesn't send timestamp/nonce, verification will fail.
    this.verifier.verifyIncomingWebhook({
      payload: (req as any).body,
      headers: req.headers,
      options: {
        secret,
        signatureHeader: 'x-stellar-signature',
        timestampHeader: 'x-nestera-timestamp',
        nonceHeader: 'x-nestera-nonce',
        maxTimestampSkewMs:
          Number(this.configService.get('WEBHOOK_MAX_SKEW_MS')) ||
          5 * 60 * 1000,
        signaturePrefix: '',
      },
    });

    // Sender allowlist (DB-backed). Runs after signature is verified so we
    // never leak whether a sender exists to unauthenticated callers. The
    // service marks the request as verified on success so that the
    // controller's defense-in-depth re-call does NOT double-count the
    // `webhook_accepted_total` metric and does NOT trigger a second DB
    // lookup.
    await this.allowlist.verify(req.headers, {
      senderIdHeader: 'x-stellar-sender-id',
    });
    this.allowlist.markRequestVerified();

    next();
  }
}
