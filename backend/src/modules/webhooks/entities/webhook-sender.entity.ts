import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

/**
 * Webhook Sender Allowlist
 *
 * Database-backed allowlist of known webhook senders. After the request
 * signature is verified, the handler MUST look up the stable `senderId`
 * provided by the caller (e.g. a header like `x-stellar-sender-id` or a
 * public account) and confirm it appears here.
 *
 * Each row supports optional tenant scoping:
 *  - tenantId = NULL  → wildcard sender (allowed for any tenant).
 *  - tenantId = X     → only requests scoped to tenant X are allowed.
 *
 * Disabling a row (enabled = false) does not delete the history; it simply
 * causes new requests from that sender to be rejected.
 *
 * NOTE: The HMAC secret used to sign each sender's payloads MUST NEVER be
 * stored on this entity and MUST NEVER be logged. Sensitive values belong
 * in dedicated secret-management infrastructure.
 */
@Entity('webhook_senders')
@Index('idx_webhook_sender_sender_id', ['senderId'], { unique: true })
@Index('idx_webhook_sender_tenant_id', ['tenantId'])
export class WebhookSender {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Stable, opaque identifier for the webhook sender (e.g. a Stellar public
   * account address 'G...' or an issuer-specific id). This is the value the
   * caller MUST present in the request so we can look it up in the allowlist.
   */
  @Column({ type: 'varchar', length: 256 })
  senderId: string;

  /**
   * Optional display label/description for operator visibility
   * (e.g. "Stellar Horizon testnet anchor X").
   */
  @Column({ type: 'varchar', length: 255, nullable: true })
  description: string | null;

  /**
   * When false, the sender is rejected regardless of signature validity.
   * Useful to temporarily revoke a known sender without losing audit trail.
   */
  @Column({ type: 'boolean', default: true })
  enabled: boolean;

  /**
   * Optional tenant scoping. When null, the sender is treated as a wildcard
   * (allowed for any tenant context). When set, only requests whose current
   * tenant matches this value are accepted.
   */
  @Column({ type: 'uuid', nullable: true })
  tenantId: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
