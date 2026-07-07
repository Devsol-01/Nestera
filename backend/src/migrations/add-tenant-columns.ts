/**
 * Migration: Add Tenant Columns to Multi-Tenant Tables
 *
 * This migration adds tenantId columns to all tables that require tenant isolation.
 * Run this migration after enabling multi-tenancy in your configuration.
 *
 * To run: npm run migration:run
 * To revert: npm run migration:revert
 */

import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class AddTenantColumns1700000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add tenantId column to users table
    await queryRunner.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Add tenantId column to savings_goals table
    await queryRunner.query(`
      ALTER TABLE savings_goals
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Add tenantId column to user_subscriptions table
    await queryRunner.query(`
      ALTER TABLE user_subscriptions
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Add tenantId column to transactions table
    await queryRunner.query(`
      ALTER TABLE transactions
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Add tenantId column to referrals table
    await queryRunner.query(`
      ALTER TABLE referrals
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Add tenantId column to notifications table
    await queryRunner.query(`
      ALTER TABLE notifications
      ADD COLUMN IF NOT EXISTS "tenantId" UUID NULL
    `);

    // Create tenants table
    await queryRunner.createTable(
      new Table({
        name: 'tenants',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'slug',
            type: 'varchar',
            length: '100',
            isUnique: true,
          },
          {
            name: 'name',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'description',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'status',
            type: 'enum',
            enum: ['ACTIVE', 'SUSPENDED', 'PENDING'],
            default: "'PENDING'",
          },
          {
            name: 'settings',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'metadata',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'now()',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'now()',
          },
        ],
        indices: [
          {
            name: 'idx_tenants_slug',
            columnNames: ['slug'],
          },
          {
            name: 'idx_tenants_status',
            columnNames: ['status'],
          },
        ],
      }),
      true,
    );

    // Create indexes for tenant_id columns
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_users_tenant_id" ON users("tenantId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_savings_goals_tenant_id" ON savings_goals("tenantId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_user_subscriptions_tenant_id" ON user_subscriptions("tenantId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_transactions_tenant_id" ON transactions("tenantId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_referrals_tenant_id" ON referrals("tenantId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_notifications_tenant_id" ON notifications("tenantId")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop indexes
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_users_tenant_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_savings_goals_tenant_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_subscriptions_tenant_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_transactions_tenant_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_referrals_tenant_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_notifications_tenant_id"`);

    // Drop tenants table
    await queryRunner.dropTable('tenants');

    // Remove tenantId columns
    await queryRunner.query(`ALTER TABLE users DROP COLUMN IF EXISTS "tenantId"`);
    await queryRunner.query(`ALTER TABLE savings_goals DROP COLUMN IF EXISTS "tenantId"`);
    await queryRunner.query(`ALTER TABLE user_subscriptions DROP COLUMN IF EXISTS "tenantId"`);
    await queryRunner.query(`ALTER TABLE transactions DROP COLUMN IF EXISTS "tenantId"`);
    await queryRunner.query(`ALTER TABLE referrals DROP COLUMN IF EXISTS "tenantId"`);
    await queryRunner.query(`ALTER TABLE notifications DROP COLUMN IF EXISTS "tenantId"`);
  }
}
