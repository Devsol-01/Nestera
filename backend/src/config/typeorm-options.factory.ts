import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import {
  buildTypeOrmPgExtra,
  resolveDbPoolSettingsFromConfig,
} from './connection-pool.config';

/**
 * Builds Nest `TypeOrmModule` options including pg pool sizing, timeouts, and optional read replica routing.
 *
 * When `database.readUrl` (`DATABASE_READ_URL`) is set, TypeORM replication is enabled: writes use the primary,
 * SELECT-heavy workloads use the replica pool (separate `pg.Pool` instances in the driver).
 */
export function createTypeOrmModuleOptions(
  configService: ConfigService,
): TypeOrmModuleOptions {
  const logger = new Logger('TypeOrmPool');
  const nodeEnv = configService.get<string>('NODE_ENV');
  const dbUrl = configService.get<string>('database.url');
  const readUrl = configService.get<string | undefined>('database.readUrl');
  const poolSettings = resolveDbPoolSettingsFromConfig(configService);
  const extra = buildTypeOrmPgExtra(poolSettings);

  const base: TypeOrmModuleOptions = {
    type: 'postgres',
    autoLoadEntities: true,
    synchronize: nodeEnv !== 'production',
    connectTimeoutMS: poolSettings.connectionTimeoutMillis,
    extra,
    poolErrorHandler: (err: Error) => {
      logger.error(err.message, err.stack);
    },
  };

  if (dbUrl) {
    if (readUrl) {
      return {
        ...base,
        replication: {
          master: { url: dbUrl },
          slaves: [{ url: readUrl }],
        },
      };
    }
    return { ...base, url: dbUrl };
  }

  const dbHost = configService.get<string>('database.host');
  if (!dbHost) {
    throw new Error(
      'Database configuration error: set either DATABASE_URL or DB_HOST in your environment.',
    );
  }

  const hostOptions = {
    host: dbHost,
    port: configService.get<number>('database.port') ?? 5432,
    database: configService.get<string>('database.name'),
    username: configService.get<string>('database.user'),
    password: configService.get<string>('database.pass'),
  };

  if (readUrl) {
    return {
      ...base,
      replication: {
        master: hostOptions,
        slaves: [{ url: readUrl }],
      },
    };
  }

  return { ...base, ...hostOptions };
}
