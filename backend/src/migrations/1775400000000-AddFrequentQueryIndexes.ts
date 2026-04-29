import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Adds btree indexes for hot filters and joins (#660).
 *
 * For `users`, single-column indexes are created only when no btree index
 * already references that column (UNIQUE constraints already provide one).
 */
export class AddFrequentQueryIndexes1775400000000 implements MigrationInterface {
  name = 'AddFrequentQueryIndexes1775400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION _nestera_column_has_btree_index(
        p_table regclass,
        p_attname name
      ) RETURNS boolean
      LANGUAGE sql
      STABLE
      AS $fn$
        SELECT EXISTS (
          SELECT 1
          FROM pg_index idx
          JOIN pg_class tbl ON tbl.oid = idx.indrelid
          CROSS JOIN LATERAL unnest(idx.indkey::smallint[]) AS attnums(attnum)
          JOIN pg_attribute a ON a.attrelid = tbl.oid AND a.attnum = attnums.attnum
          WHERE tbl.oid = p_table
            AND idx.indisvalid
            AND a.attnum > 0
            AND NOT a.attisdropped
            AND a.attname = p_attname
        );
      $fn$;
    `);

    await queryRunner.query(`
      DO $body$
      BEGIN
        IF NOT _nestera_column_has_btree_index('public.users'::regclass, 'email') THEN
          EXECUTE 'CREATE INDEX idx_users_email ON public.users (email)';
        END IF;
        IF NOT _nestera_column_has_btree_index('public.users'::regclass, 'publicKey') THEN
          EXECUTE 'CREATE INDEX idx_users_public_key ON public.users ("publicKey")';
        END IF;
        IF NOT _nestera_column_has_btree_index('public.users'::regclass, 'walletAddress') THEN
          EXECUTE 'CREATE INDEX idx_users_wallet_address ON public.users ("walletAddress")';
        END IF;
      END
      $body$;
    `);

    await queryRunner.query(`
      DROP FUNCTION IF EXISTS _nestera_column_has_btree_index(regclass, name);
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id_status
        ON user_subscriptions ("userId", status);
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_user_subscriptions_product_id_status
        ON user_subscriptions ("productId", status);
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id_product_id
        ON user_subscriptions ("userId", "productId");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_savings_goals_user_id_status
        ON savings_goals ("userId", status);
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_user_id_status
        ON transactions ("userId", status);
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_user_id_tx_hash
        ON transactions ("userId", "txHash");
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_transactions_status
        ON transactions (status);
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_governance_proposals_status
        ON governance_proposals (status);
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_governance_proposals_status_on_chain_id
        ON governance_proposals (status, "onChainId");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_votes_proposal_id_wallet_address
        ON votes ("proposalId", "walletAddress");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS idx_votes_proposal_id_wallet_address;`);

    await queryRunner.query(
      `DROP INDEX IF EXISTS idx_governance_proposals_status_on_chain_id;`,
    );
    await queryRunner.query(`DROP INDEX IF EXISTS idx_governance_proposals_status;`);

    await queryRunner.query(`DROP INDEX IF EXISTS idx_transactions_status;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_transactions_user_id_tx_hash;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_transactions_user_id_status;`);

    await queryRunner.query(`DROP INDEX IF EXISTS idx_savings_goals_user_id_status;`);

    await queryRunner.query(`DROP INDEX IF EXISTS idx_user_subscriptions_user_id_product_id;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_user_subscriptions_product_id_status;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_user_subscriptions_user_id_status;`);

    await queryRunner.query(`DROP INDEX IF EXISTS idx_users_wallet_address;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_users_public_key;`);
    await queryRunner.query(`DROP INDEX IF EXISTS idx_users_email;`);
  }
}
