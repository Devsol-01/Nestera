import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Add export artifact integrity fields to data_export_requests.
 *
 * Adds:
 *  - `checksum`  VARCHAR(64)  – SHA-256 hex digest of the ZIP artifact
 *  - `fileSize`  BIGINT       – size of the artifact in bytes
 *
 * Both columns are nullable so existing rows are unaffected.
 */
export class AddExportArtifactIntegrity1800100000000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "data_export_requests"
        ADD COLUMN IF NOT EXISTS "checksum"  VARCHAR(64),
        ADD COLUMN IF NOT EXISTS "fileSize"  BIGINT
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "data_export_requests"
        DROP COLUMN IF EXISTS "checksum",
        DROP COLUMN IF EXISTS "fileSize"
    `);
  }
}
