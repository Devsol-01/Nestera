import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateReorgHistory1800000000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'reorg_history',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'detectedAtLedger',
            type: 'bigint',
          },
          {
            name: 'rollbackToLedger',
            type: 'bigint',
          },
          {
            name: 'affectedAccounts',
            type: 'json',
            isNullable: true,
          },
          {
            name: 'rolledBackSnapshots',
            type: 'integer',
            default: 0,
          },
          {
            name: 'reappliedSnapshots',
            type: 'integer',
            default: 0,
          },
          {
            name: 'status',
            type: 'varchar',
            length: '20',
            default: 'detected',
          },
          {
            name: 'description',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'detectedAt',
            type: 'timestamp',
          },
          {
            name: 'resolvedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'reorg_history',
      new TableIndex({
        name: 'IDX_REORG_HISTORY_DETECTED',
        columnNames: ['detectedAtLedger'],
      }),
    );

    await queryRunner.createIndex(
      'reorg_history',
      new TableIndex({
        name: 'IDX_REORG_HISTORY_STATUS',
        columnNames: ['status'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('reorg_history');
  }
}
