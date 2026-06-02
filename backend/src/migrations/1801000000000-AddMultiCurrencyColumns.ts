import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMultiCurrencyColumns1801000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "transactions"
      ADD COLUMN IF NOT EXISTS "currencyCode" varchar(12) NOT NULL DEFAULT 'USDC',
      ADD COLUMN IF NOT EXISTS "assetCode" varchar(12),
      ADD COLUMN IF NOT EXISTS "assetIssuer" varchar(128),
      ADD COLUMN IF NOT EXISTS "assetContractId" varchar(128),
      ADD COLUMN IF NOT EXISTS "amountBaseCurrency" decimal(18,7),
      ADD COLUMN IF NOT EXISTS "conversionRateToBase" decimal(18,7);
    `);

    await queryRunner.query(`
      UPDATE "transactions"
      SET
        "currencyCode" = COALESCE("currencyCode", 'USDC'),
        "assetCode" = COALESCE("assetCode", 'USDC'),
        "assetContractId" = COALESCE(
          "assetContractId",
          NULLIF(("metadata"->>'assetId'), ''),
          NULLIF(("metadata"->>'contractId'), '')
        ),
        "conversionRateToBase" = COALESCE("conversionRateToBase", 1),
        "amountBaseCurrency" = COALESCE("amountBaseCurrency", "amount")
      WHERE "currencyCode" IS NULL OR "amountBaseCurrency" IS NULL;
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_transactions_currency_code"
      ON "transactions" ("currencyCode");
    `);

    await queryRunner.query(`
      ALTER TABLE "savings_products"
      ADD COLUMN IF NOT EXISTS "currencyCode" varchar(12) NOT NULL DEFAULT 'USDC';
    `);

    await queryRunner.query(`
      ALTER TABLE "user_subscriptions"
      ADD COLUMN IF NOT EXISTS "currencyCode" varchar(12) NOT NULL DEFAULT 'USDC';
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "user_subscriptions"
      DROP COLUMN IF EXISTS "currencyCode";
    `);

    await queryRunner.query(`
      ALTER TABLE "savings_products"
      DROP COLUMN IF EXISTS "currencyCode";
    `);

    await queryRunner.query(`
      DROP INDEX IF EXISTS "idx_transactions_currency_code";
    `);

    await queryRunner.query(`
      ALTER TABLE "transactions"
      DROP COLUMN IF EXISTS "conversionRateToBase",
      DROP COLUMN IF EXISTS "amountBaseCurrency",
      DROP COLUMN IF EXISTS "assetContractId",
      DROP COLUMN IF EXISTS "assetIssuer",
      DROP COLUMN IF EXISTS "assetCode",
      DROP COLUMN IF EXISTS "currencyCode";
    `);
  }
}
