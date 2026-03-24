import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddSavingsProductEnhancements1711289600000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create the risk_level enum type
    await queryRunner.query(`
      CREATE TYPE "public"."savings_products_risklevel_enum"
      AS ENUM ('LOW', 'MEDIUM', 'HIGH')
    `);

    // contractId — nullable varchar, maps to Soroban contract address
    await queryRunner.query(`
      ALTER TABLE "savings_products"
      ADD COLUMN "contractId" character varying
    `);

    // tvlAmount — decimal cache of Total Value Locked, defaults to 0
    await queryRunner.query(`
      ALTER TABLE "savings_products"
      ADD COLUMN "tvlAmount" numeric(28,7) NOT NULL DEFAULT 0
    `);

    // riskLevel — enum column, defaults to LOW
    await queryRunner.query(`
      ALTER TABLE "savings_products"
      ADD COLUMN "riskLevel" "public"."savings_products_risklevel_enum" NOT NULL DEFAULT 'LOW'
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "savings_products" DROP COLUMN "riskLevel"`,
    );
    await queryRunner.query(
      `ALTER TABLE "savings_products" DROP COLUMN "tvlAmount"`,
    );
    await queryRunner.query(
      `ALTER TABLE "savings_products" DROP COLUMN "contractId"`,
    );
    await queryRunner.query(
      `DROP TYPE "public"."savings_products_risklevel_enum"`,
    );
  }
}
