import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableIndex,
} from 'typeorm';

/**
 * Migration: Add support for background/system audit log entries
 *
 * Changes:
 *  1. Add `job_id` column – stores Bull/BullMQ job.id for background jobs.
 *  2. Extend `action` enum with RECONCILE, CLEANUP, ARCHIVE, EXPORT_JOB.
 *  3. Extend `resource_type` enum with JOB.
 */
export class AddSystemAuditLoggingSupport1804000000000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Add job_id column
    await queryRunner.addColumn(
      'audit_logs',
      new TableColumn({
        name: 'job_id',
        type: 'varchar',
        isNullable: true,
        comment:
          'Bull/BullMQ job ID for background/automated audit entries (null for user-initiated entries)',
      }),
    );

    // Index for fast lookups by job_id
    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_logs_job_id',
        columnNames: ['job_id'],
      }),
    );

    // 2. Extend the action enum (PostgreSQL requires renaming the type)
    await queryRunner.query(
      `ALTER TYPE "audit_logs_action_enum" ADD VALUE IF NOT EXISTS 'RECONCILE'`,
    );
    await queryRunner.query(
      `ALTER TYPE "audit_logs_action_enum" ADD VALUE IF NOT EXISTS 'CLEANUP'`,
    );
    await queryRunner.query(
      `ALTER TYPE "audit_logs_action_enum" ADD VALUE IF NOT EXISTS 'ARCHIVE'`,
    );
    await queryRunner.query(
      `ALTER TYPE "audit_logs_action_enum" ADD VALUE IF NOT EXISTS 'EXPORT_JOB'`,
    );

    // 3. Extend the resource_type enum
    await queryRunner.query(
      `ALTER TYPE "audit_logs_resource_type_enum" ADD VALUE IF NOT EXISTS 'JOB'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove index + column (PostgreSQL enum values cannot be removed without recreating the type,
    // so we leave the enum values as-is on rollback – they are safely ignored by older code)
    await queryRunner.dropIndex('audit_logs', 'idx_audit_logs_job_id');
    await queryRunner.dropColumn('audit_logs', 'job_id');
  }
}
