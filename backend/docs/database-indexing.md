# Database indexing strategy

This backend uses PostgreSQL with TypeORM. Migrations under `src/migrations/` are the source of truth for production schema; entity `@Index()` decorators keep the ORM model aligned with the database.

## Principles

1. **Foreign keys and ownership** — Index columns used in `WHERE` / `JOIN` for parent keys (for example `userId`, `proposalId`).
2. **Filters and sorts** — Add composite indexes that match common predicates together (for example `(userId, status)` for “this user’s active subscriptions”).
3. **Uniqueness** — Prefer `UNIQUE` constraints where appropriate; PostgreSQL builds a btree index for each constraint, so avoid duplicating a second index on the same column unless you have a measured need.
4. **New entities** — When adding a table, add explicit indexes in the same migration that creates the table (or follow up immediately with a migration). Declare matching `@Index()` on the entity.
5. **Naming** — Use lowercase `idx_<table>_<columns>` for non-unique indexes so migrations stay grep-friendly.

## Issue #660 indexes

| Area | Indexes |
|------|---------|
| `users` | `email`, `publicKey`, `walletAddress` — created only if no btree index already covers the column (unique constraints count). |
| `user_subscriptions` | `(userId, status)`, `(productId, status)`, `(userId, productId)` |
| `savings_goals` | `(userId, status)` in addition to existing single-column indexes from earlier migrations |
| `transactions` | `(userId, status)`, `(userId, txHash)`, `(status)` |
| `governance_proposals` | `(status)`, `(status, onChainId)` |
| `votes` | `(proposalId, walletAddress)` for proposal-scoped queries; unique `(walletAddress, proposalId)` unchanged |

## Verifying performance

On a staging database with representative row counts:

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM user_subscriptions
WHERE "userId" = $1 AND status = 'ACTIVE';
```

Compare plans before and after applying migration `AddFrequentQueryIndexes1775400000000`. Prefer index scans over sequential scans on large tables for these predicates.

For production-sized tables, consider running heavy `CREATE INDEX` operations during a maintenance window; optionally use `CREATE INDEX CONCURRENTLY` outside a transaction (TypeORM’s default migration transaction must be disabled for that statement).
