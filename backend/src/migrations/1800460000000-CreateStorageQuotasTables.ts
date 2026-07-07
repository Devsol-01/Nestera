import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateStorageQuotasTables1800460000000 implements MigrationInterface {
  name = 'CreateStorageQuotasTables1800460000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "storage_quotas" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" uuid NOT NULL,
        "tenantId" varchar(64) NOT NULL DEFAULT '',
        "maxTotalBytes" bigint NOT NULL DEFAULT 0,
        "usedBytes" bigint NOT NULL DEFAULT 0,
        "reservedBytes" bigint NOT NULL DEFAULT 0,
        "maxActiveUploads" integer NOT NULL DEFAULT 0,
        "activeUploads" integer NOT NULL DEFAULT 0,
        "maxUploadsPerHour" integer NOT NULL DEFAULT 0,
        "uploadsThisHour" integer NOT NULL DEFAULT 0,
        "uploadWindowStartedAt" timestamptz NULL,
        "tier" varchar(32) NOT NULL DEFAULT 'free',
        "createdAt" timestamptz NOT NULL DEFAULT now(),
        "updatedAt" timestamptz NOT NULL DEFAULT now(),
        "version" integer NOT NULL DEFAULT 0,
        CONSTRAINT "uq_storage_quotas_user_tenant" UNIQUE ("userId", "tenantId"),
        CONSTRAINT "pk_storage_quotas" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_storage_quotas_user" ON "storage_quotas" ("userId")`,
    );

    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "storage_quota_ledger" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "reservationId" varchar(64) NOT NULL,
        "userId" uuid NOT NULL,
        "tenantId" varchar(64) NOT NULL DEFAULT '',
        "uploadKind" varchar(32) NOT NULL DEFAULT 'generic',
        "uploadId" varchar(128) NULL,
        "byteDelta" bigint NOT NULL,
        "status" varchar(16) NOT NULL DEFAULT 'pending',
        "expiresAt" timestamptz NULL,
        "finalBytes" bigint NULL,
        "reason" varchar(256) NULL,
        "createdAt" timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT "uq_storage_quota_ledger_reservation" UNIQUE ("reservationId"),
        CONSTRAINT "pk_storage_quota_ledger" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_storage_quota_ledger_user_created" ON "storage_quota_ledger" ("userId", "createdAt")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_storage_quota_ledger_tenant_created" ON "storage_quota_ledger" ("tenantId", "createdAt")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_storage_quota_ledger_status_expires" ON "storage_quota_ledger" ("status", "expiresAt")`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_storage_quota_ledger_upload" ON "storage_quota_ledger" ("uploadKind", "uploadId")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "storage_quota_ledger"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "storage_quotas"`);
  }
}
