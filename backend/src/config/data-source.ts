import 'reflect-metadata';
import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';

dotenv.config();

const AppDataSource = new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  host: process.env.DATABASE_URL
    ? undefined
    : (process.env.DB_HOST ?? 'localhost'),
  port: process.env.DATABASE_URL
    ? undefined
    : parseInt(process.env.DB_PORT ?? '5432', 10),
  database: process.env.DATABASE_URL ? undefined : process.env.DB_NAME,
  username: process.env.DATABASE_URL ? undefined : process.env.DB_USER,
  password: process.env.DATABASE_URL ? undefined : process.env.DB_PASS,
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  migrations: [__dirname + '/../migrations/*{.ts,.js}'],
  synchronize: false,
});

export default AppDataSource;
