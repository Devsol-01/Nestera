import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateBalanceSnapshots1800000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'balance_snapshots',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'accountId',
            type: 'varchar',
            length: '56',
          },
          {
            name: 'assetCode',
            type: 'varchar',
            length: '20',
          },
          {
            name: 'balance',
            type: 'varchar',
          },
          {
            name: 'ledgerSequence',
            type: 'bigint',
          },
          {
            name: 'transactionHash',
            type: 'varchar',
            length: '64',
            isNullable: true,
          },
          {
            name: 'operationId',
            type: 'varchar',
            length: '64',
            isNullable: true,
          },
          {
            name: 'isConfirmed',
            type: 'boolean',
            default: false,
          },
          {
            name: 'snapshotTime',
            type: 'timestamp',
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
      }),
      true,
    );

    await queryRunner.createIndex(
      'balance_snapshots',
      new TableIndex({
        name: 'IDX_BALANCE_SNAPSHOTS_ACCOUNT_ASSET',
        columnNames: ['accountId', 'assetCode'],
      }),
    );

    await queryRunner.createIndex(
      'balance_snapshots',
      new TableIndex({
        name: 'IDX_BALANCE_SNAPSHOTS_LEDGER',
        columnNames: ['ledgerSequence'],
      }),
    );

    await queryRunner.createIndex(
      'balance_snapshots',
      new TableIndex({
        name: 'IDX_BALANCE_SNAPSHOTS_CONFIRMED',
        columnNames: ['isConfirmed'],
      }),
    );

    // Unique constraint: one account/asset per ledger
    await queryRunner.createIndex(
      'balance_snapshots',
      new TableIndex({
        name: 'UQ_BALANCE_SNAPSHOT_ACCOUNT_ASSET_LEDGER',
        columnNames: ['accountId', 'assetCode', 'ledgerSequence'],
        isUnique: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('balance_snapshots');
  }
}
