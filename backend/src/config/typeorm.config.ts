import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';
import {
  buildTypeOrmPgExtra,
  resolveDbPoolSettingsFromEnv,
} from './connection-pool.config';

dotenv.config();

const pool = resolveDbPoolSettingsFromEnv(process.env);

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME,
  username: process.env.DB_USER,
  password: process.env.DB_PASS,
  connectTimeoutMS: pool.connectionTimeoutMillis,
  extra: buildTypeOrmPgExtra(pool),
  entities: ['src/modules/**/entities/*.entity.ts'],
  migrations: ['src/migrations/*.ts'],
  synchronize: false,
  logging: false,
});
