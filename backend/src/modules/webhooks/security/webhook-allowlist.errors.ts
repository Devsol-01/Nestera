/**
 * Allows webhook sender allowlist & tenant-scoping checks to reject incoming
 * requests with a structured, machine-readable reason.
 *
 * Reasons are intentionally coarse-grained to keep log / metric tags stable.
 */
export enum WebhookAllowlistErrorCode {
  /** Sender ID header was missing on the request */
  MISSING_SENDER_ID = 'WEBHOOK_ALLOWLIST_MISSING_SENDER_ID',
  /** No row in webhook_senders matched the presented senderId */
  UNKNOWN_SENDER = 'WEBHOOK_ALLOWLIST_UNKNOWN_SENDER',
  /** Row exists but enabled = false */
  SENDER_DISABLED = 'WEBHOOK_ALLOWLIST_SENDER_DISABLED',
  /**
   * Row exists but is scoped to a tenantId that does not match the
   * request's current tenant context. Only raised when multi-tenant
   * mode is enabled AND the sender is not a wildcard (tenantId != null).
   */
  TENANT_MISMATCH = 'WEBHOOK_ALLOWLIST_TENANT_MISMATCH',
  /**
   * Multi-tenant mode is enabled and the allowlist row requires tenant
   * scoping, but the request did not supply a tenant context.
   */
  MISSING_TENANT_CONTEXT = 'WEBHOOK_ALLOWLIST_MISSING_TENANT_CONTEXT',
}

export interface WebhookAllowlistErrorPayload {
  code: WebhookAllowlistErrorCode;
  message: string;
  details?: Record<string, unknown>;
}
