import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateSavingsGoalMilestones1774445030 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'savings_goal_milestones',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'goalId', type: 'uuid', isNullable: false },
          { name: 'userId', type: 'uuid', isNullable: false },
          { name: 'percentage', type: 'int', isNullable: false },
          { name: 'label', type: 'varchar', length: '255', isNullable: false },
          {
            name: 'type',
            type: 'enum',
            enum: ['AUTOMATIC', 'CUSTOM'],
            default: "'AUTOMATIC'",
            isNullable: false,
          },
          {
            name: 'achieved',
            type: 'boolean',
            default: false,
            isNullable: false,
          },
          { name: 'achievedAt', type: 'timestamp', isNullable: true },
          { name: 'bonusPoints', type: 'int', default: 0, isNullable: false },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'now()',
            isNullable: false,
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'now()',
            isNullable: false,
          },
        ],
        foreignKeys: [
          {
            columnNames: ['goalId'],
            referencedTableName: 'savings_goals',
            referencedColumnNames: ['id'],
            onDelete: 'CASCADE',
          },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'savings_goal_milestones',
      new TableIndex({
        name: 'IDX_MILESTONES_GOAL_PERCENTAGE',
        columnNames: ['goalId', 'percentage'],
      }),
    );

    await queryRunner.createIndex(
      'savings_goal_milestones',
      new TableIndex({
        name: 'IDX_MILESTONES_USER_ACHIEVED',
        columnNames: ['userId', 'achieved'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('savings_goal_milestones');
  }
}
