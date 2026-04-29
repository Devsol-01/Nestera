import { ConfigService } from '@nestjs/config';

/**
 * Sensible defaults for a single NestJS API instance talking to PostgreSQL via `pg`.
 * Tune `DB_POOL_*` after load testing (connections × replicas × pods vs. `max_connections` on the server).
 */
export const DB_POOL_DEFAULT_MAX = 20;
export const DB_POOL_DEFAULT_MIN = 2;
export const DB_POOL_DEFAULT_CONNECTION_TIMEOUT_MS = 10_000;
export const DB_POOL_DEFAULT_IDLE_TIMEOUT_MS = 30_000;

export interface DbPoolSettings {
  max: number;
  min: number;
  connectionTimeoutMillis: number;
  idleTimeoutMillis: number;
}

export function resolveDbPoolSettingsFromEnv(
  env: NodeJS.ProcessEnv,
): DbPoolSettings {
  const num = (key: string, fallback: number) => {
    const raw = env[key];
    if (raw === undefined || raw === '') {
      return fallback;
    }
    const v = parseInt(raw, 10);
    return Number.isFinite(v) ? v : fallback;
  };
  return {
    max: num('DB_POOL_MAX', DB_POOL_DEFAULT_MAX),
    min: num('DB_POOL_MIN', DB_POOL_DEFAULT_MIN),
    connectionTimeoutMillis: num(
      'DB_POOL_CONNECTION_TIMEOUT_MS',
      DB_POOL_DEFAULT_CONNECTION_TIMEOUT_MS,
    ),
    idleTimeoutMillis: num(
      'DB_POOL_IDLE_TIMEOUT_MS',
      DB_POOL_DEFAULT_IDLE_TIMEOUT_MS,
    ),
  };
}

export function resolveDbPoolSettingsFromConfig(
  config: ConfigService,
): DbPoolSettings {
  return {
    max: config.get<number>('database.pool.max') ?? DB_POOL_DEFAULT_MAX,
    min: config.get<number>('database.pool.min') ?? DB_POOL_DEFAULT_MIN,
    connectionTimeoutMillis:
      config.get<number>('database.pool.connectionTimeoutMs') ??
      DB_POOL_DEFAULT_CONNECTION_TIMEOUT_MS,
    idleTimeoutMillis:
      config.get<number>('database.pool.idleTimeoutMs') ??
      DB_POOL_DEFAULT_IDLE_TIMEOUT_MS,
  };
}

/**
 * Passed to node-postgres Pool via TypeORM `extra` (merged in {@link PostgresDriver.createPool}).
 */
export function buildTypeOrmPgExtra(
  settings: DbPoolSettings,
): Record<string, unknown> {
  return {
    max: settings.max,
    min: settings.min,
    connectionTimeoutMillis: settings.connectionTimeoutMillis,
    idleTimeoutMillis: settings.idleTimeoutMillis,
    allowExitOnIdle: false,
  };
}

export interface PgPoolMetricsSnapshot {
  totalCount: number;
  idleCount: number;
  waitingCount: number;
}

export function snapshotPgPool(pool: {
  totalCount: number;
  idleCount: number;
  waitingCount: number;
}): PgPoolMetricsSnapshot {
  return {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount,
  };
}
