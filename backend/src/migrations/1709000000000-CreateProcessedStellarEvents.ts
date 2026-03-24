import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateProcessedStellarEvents1709000000000 implements MigrationInterface {
    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.createTable(
            new Table({
                name: 'processed_stellar_events',
                columns: [
                    {
                        name: 'eventId',
                        type: 'varchar',
                        isPrimary: true,
                    },
                    {
                        name: 'contractId',
                        type: 'varchar',
                        isNullable: false,
                    },
                    {
                        name: 'transactionHash',
                        type: 'varchar',
                        isNullable: false,
                    },
                    {
                        name: 'ledger',
                        type: 'integer',
                        isNullable: false,
                    },
                    {
                        name: 'eventType',
                        type: 'varchar',
                        isNullable: false,
                    },
                    {
                        name: 'eventData',
                        type: 'jsonb',
                        isNullable: false,
                    },
                    {
                        name: 'claimId',
                        type: 'varchar',
                        isNullable: true,
                    },
                    {
                        name: 'processedAt',
                        type: 'timestamp',
                        default: 'now()',
                    },
                ],
            }),
            true,
        );

        // Create unique index on contractId and eventId
        await queryRunner.createIndex(
            'processed_stellar_events',
            new TableIndex({
                name: 'IDX_CONTRACT_EVENT',
                columnNames: ['contractId', 'eventId'],
                isUnique: true,
            }),
        );

        // Create index on claimId for faster lookups
        await queryRunner.createIndex(
            'processed_stellar_events',
            new TableIndex({
                name: 'IDX_CLAIM_ID',
                columnNames: ['claimId'],
            }),
        );

        // Create index on processedAt for time-based queries
        await queryRunner.createIndex(
            'processed_stellar_events',
            new TableIndex({
                name: 'IDX_PROCESSED_AT',
                columnNames: ['processedAt'],
            }),
        );
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropTable('processed_stellar_events');
    }
}
