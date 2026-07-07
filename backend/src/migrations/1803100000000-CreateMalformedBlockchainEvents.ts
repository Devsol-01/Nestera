import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Creates the `malformed_blockchain_events` quarantine table (#1133).
 *
 * Events that fail schema validation or cannot be safely parsed are persisted
 * here instead of silently discarded, enabling forensic investigation and
 * manual reprocessing.
 */
export class CreateMalformedBlockchainEvents1803100000000
  implements MigrationInterface
{
  name = 'CreateMalformedBlockchainEvents1803100000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TYPE "quarantine_reason_enum" AS ENUM (
        'MISSING_REQUIRED_FIELDS',
        'TYPE_MISMATCH',
        'INVALID_SCHEMA',
        'UNPARSEABLE_AMOUNT',
        'MISSING_PUBLIC_KEY',
        'XDR_DECODE_ERROR',
        'HANDLER_ERROR',
        'UNKNOWN'
      )
    `);

    await queryRunner.query(`
      CREATE TYPE "quarantine_status_enum" AS ENUM (
        'PENDING',
        'UNDER_REVIEW',
        'RESOLVED',
        'DISCARDED'
      )
    `);

    await queryRunner.query(`
      CREATE TABLE "malformed_blockchain_events" (
        "id"              UUID                        NOT NULL DEFAULT uuid_generate_v4(),
        "eventType"       VARCHAR(64),
        "ledgerSequence"  BIGINT,
        "txHash"          VARCHAR(255),
        "eventId"         VARCHAR(255),
        "reason"          "quarantine_reason_enum"    NOT NULL,
        "errorDetails"    TEXT                        NOT NULL,
        "rawEvent"        TEXT                        NOT NULL,
        "status"          "quarantine_status_enum"    NOT NULL DEFAULT 'PENDING',
        "resolutionNotes" TEXT,
        "createdAt"       TIMESTAMP WITH TIME ZONE    NOT NULL DEFAULT now(),
        CONSTRAINT "pk_malformed_blockchain_events" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_mbe_reason"
        ON "malformed_blockchain_events" ("reason")
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_mbe_status"
        ON "malformed_blockchain_events" ("status")
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_mbe_event_type"
        ON "malformed_blockchain_events" ("eventType")
        WHERE "eventType" IS NOT NULL
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_mbe_ledger_sequence"
        ON "malformed_blockchain_events" ("ledgerSequence")
        WHERE "ledgerSequence" IS NOT NULL
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_mbe_created_at"
        ON "malformed_blockchain_events" ("createdAt")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS "malformed_blockchain_events"`,
    );
    await queryRunner.query(`DROP TYPE IF EXISTS "quarantine_reason_enum"`);
    await queryRunner.query(`DROP TYPE IF EXISTS "quarantine_status_enum"`);
  }
}
