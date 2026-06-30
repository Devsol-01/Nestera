import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Creates the `admin_correction_ledger` table.
 *
 * The table is intentionally designed to be append-only:
 *  - No UPDATE or DELETE permissions should be granted to the application role.
 *  - A database-level trigger can optionally enforce this; the application
 *    layer already guards it via AdminLedgerService.
 *
 * Down migration is a simple DROP — this is safe because the table only ever
 * holds audit history and is never a FK dependency for operational tables.
 */
export class CreateAdminCorrectionLedger1803000000000
  implements MigrationInterface
{
  name = 'CreateAdminCorrectionLedger1803000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Enum type for correction category
    await queryRunner.query(`
      CREATE TYPE "admin_correction_type_enum" AS ENUM (
        'BALANCE_CREDIT',
        'BALANCE_DEBIT',
        'FEE_WAIVER',
        'FEE_ADJUSTMENT',
        'INTEREST_CORRECTION',
        'OTHER'
      )
    `);

    await queryRunner.query(`
      CREATE TABLE "admin_correction_ledger" (
        "id"              UUID                            NOT NULL DEFAULT uuid_generate_v4(),
        "targetId"        VARCHAR(255)                    NOT NULL,
        "targetType"      VARCHAR(64)                     NOT NULL,
        "adminId"         UUID                            NOT NULL,
        "correctionType"  "admin_correction_type_enum"    NOT NULL,
        "delta"           VARCHAR(64)                     NOT NULL,
        "previousValue"   TEXT,
        "newValue"        TEXT,
        "reason"          TEXT                            NOT NULL,
        "requestId"       VARCHAR(255),
        "workflowId"      VARCHAR(255),
        "metadata"        JSONB,
        "createdAt"       TIMESTAMP WITH TIME ZONE        NOT NULL DEFAULT now(),
        CONSTRAINT "pk_admin_correction_ledger" PRIMARY KEY ("id")
      )
    `);

    // Indexes for the most common query patterns
    await queryRunner.query(`
      CREATE INDEX "idx_acl_target_id"
        ON "admin_correction_ledger" ("targetId")
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_acl_admin_id"
        ON "admin_correction_ledger" ("adminId")
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_acl_request_id"
        ON "admin_correction_ledger" ("requestId")
        WHERE "requestId" IS NOT NULL
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_acl_workflow_id"
        ON "admin_correction_ledger" ("workflowId")
        WHERE "workflowId" IS NOT NULL
    `);

    await queryRunner.query(`
      CREATE INDEX "idx_acl_created_at"
        ON "admin_correction_ledger" ("createdAt")
    `);

    // Composite index useful for reconciliation queries
    await queryRunner.query(`
      CREATE INDEX "idx_acl_target_type_correction_type"
        ON "admin_correction_ledger" ("targetId", "correctionType")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "admin_correction_ledger"`);
    await queryRunner.query(
      `DROP TYPE IF EXISTS "admin_correction_type_enum"`,
    );
  }
}
