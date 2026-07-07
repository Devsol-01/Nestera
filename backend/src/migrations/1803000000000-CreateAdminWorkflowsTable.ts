import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

/**
 * Creates the admin_workflows table for the Admin Workflow Engine.
 *
 * This table stores multi-step approval workflow instances used for high-risk
 * admin actions such as emergency withdrawals, large refunds, and governance
 * overrides.
 */
export class CreateAdminWorkflowsTable1803000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'admin_workflows',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'gen_random_uuid()',
          },
          {
            name: 'action_type',
            type: 'varchar',
            isNullable: false,
            comment: 'Semantic type of the action (e.g. EMERGENCY_WITHDRAWAL)',
          },
          {
            name: 'status',
            type: 'varchar',
            isNullable: false,
            default: "'PENDING_APPROVAL'",
            comment: 'Current workflow lifecycle state',
          },
          {
            name: 'description',
            type: 'text',
            isNullable: false,
            comment: 'Human-readable description of the requested action',
          },
          {
            name: 'required_approver_role',
            type: 'varchar',
            isNullable: false,
            default: "'SUPER_ADMIN'",
            comment: 'Minimum role required to approve this workflow step',
          },
          {
            name: 'initiator_id',
            type: 'uuid',
            isNullable: false,
            comment: 'ID of the user who created this workflow',
          },
          {
            name: 'initiator_email',
            type: 'varchar',
            isNullable: false,
            comment: 'Email of the initiating user (denormalised for audit)',
          },
          {
            name: 'payload',
            type: 'jsonb',
            isNullable: false,
            comment: 'Action-specific payload (e.g. withdrawalId, amount)',
          },
          {
            name: 'previous_state',
            type: 'jsonb',
            isNullable: true,
            comment: 'Snapshot of resource state before the action (for diff)',
          },
          {
            name: 'executed_state',
            type: 'jsonb',
            isNullable: true,
            comment: 'Snapshot of resource state after execution (for diff)',
          },
          {
            name: 'idempotency_key',
            type: 'varchar',
            isNullable: true,
            isUnique: true,
            comment: 'Optional key to prevent duplicate workflow creation',
          },
          // Approval fields
          {
            name: 'approved_by_id',
            type: 'uuid',
            isNullable: true,
          },
          {
            name: 'approved_by_email',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'approved_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'approver_notes',
            type: 'text',
            isNullable: true,
          },
          // Rejection fields
          {
            name: 'rejected_by_id',
            type: 'uuid',
            isNullable: true,
          },
          {
            name: 'rejected_by_email',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'rejection_reason',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'rejected_at',
            type: 'timestamp',
            isNullable: true,
          },
          // Cancellation fields
          {
            name: 'canceled_by_id',
            type: 'uuid',
            isNullable: true,
          },
          {
            name: 'canceled_by_email',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'cancellation_reason',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'canceled_at',
            type: 'timestamp',
            isNullable: true,
          },
          // Execution fields
          {
            name: 'executed_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'execution_error',
            type: 'text',
            isNullable: true,
          },
          // Expiry
          {
            name: 'expires_at',
            type: 'timestamp',
            isNullable: true,
            comment: 'Auto-transition to TIMED_OUT after this timestamp',
          },
          // Timestamps
          {
            name: 'created_at',
            type: 'timestamp',
            isNullable: false,
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            isNullable: false,
            default: 'now()',
          },
        ],
      }),
      true,
    );

    // Indexes for common query patterns
    await queryRunner.createIndex(
      'admin_workflows',
      new TableIndex({
        name: 'IDX_admin_workflows_status',
        columnNames: ['status'],
      }),
    );

    await queryRunner.createIndex(
      'admin_workflows',
      new TableIndex({
        name: 'IDX_admin_workflows_action_type',
        columnNames: ['action_type'],
      }),
    );

    await queryRunner.createIndex(
      'admin_workflows',
      new TableIndex({
        name: 'IDX_admin_workflows_initiator_id',
        columnNames: ['initiator_id'],
      }),
    );

    await queryRunner.createIndex(
      'admin_workflows',
      new TableIndex({
        name: 'IDX_admin_workflows_expires_at',
        columnNames: ['expires_at'],
      }),
    );

    await queryRunner.createIndex(
      'admin_workflows',
      new TableIndex({
        name: 'IDX_admin_workflows_created_at',
        columnNames: ['created_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('admin_workflows');
  }
}
