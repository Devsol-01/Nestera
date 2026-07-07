import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Creates the webhook_senders allowlist table.
 *
 * Each row represents a known-good webhook sender. Senders are identified
 * by a stable, opaque `senderId` (e.g. a Stellar public account address).
 *
 * - `enabled=false` flips a sender off without losing the audit trail.
 * - `tenantId NULL` means the sender is allowed for any tenant (wildcard).
 * - `tenantId X` means the sender is only allowed when the current request's
 *   tenant context equals X.
 */
export class CreateWebhookSenderAllowlist1800000000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // FK to tenants(id) with ON DELETE SET NULL preserves referential
    // integrity: if a tenant is deleted, scoped senders degrade to wildcard.
    // The tenants table is created earlier in add-tenant-columns.ts so the
    // FK constraint is safe to add here.
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "webhook_senders" (
        "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "senderId"    varchar(256) NOT NULL,
        "description" varchar(255),
        "enabled"     boolean NOT NULL DEFAULT true,
        "tenantId"    uuid NULL REFERENCES "tenants"("id") ON DELETE SET NULL,
        "createdAt"   timestamp NOT NULL DEFAULT now(),
        "updatedAt"   timestamp NOT NULL DEFAULT now()
      );
    `);

    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "idx_webhook_sender_sender_id"
        ON "webhook_senders"("senderId");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_webhook_sender_tenant_id"
        ON "webhook_senders"("tenantId");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "webhook_senders";`);
  }
}
