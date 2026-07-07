import { INestApplication, BadRequestException } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { ValidationPipe } from '@nestjs/common';
import { flattenValidationErrors } from '../../src/common/validators/validation-error.utils';

export async function createTestApp(): Promise<INestApplication> {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();
  app.setGlobalPrefix('api');
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) =>
        new BadRequestException({
          message: 'Validation failed',
          errors: flattenValidationErrors(errors as never),
        }),
    }),
  );
  await app.init();
  return app;
}

export function getDataSource(app: INestApplication): DataSource {
  return app.get<DataSource>(DataSource);
}

export async function clearTable(dataSource: DataSource, tableName: string): Promise<void> {
  try {
    await dataSource.query(`TRUNCATE TABLE "${tableName}" CASCADE`);
  } catch {
    // Table may not exist in test; ignore
  }
}

export async function clearTestUsers(dataSource: DataSource): Promise<void> {
  await clearTable(dataSource, 'users');
}

export async function closeTestApp(app: INestApplication): Promise<void> {
  if (app) {
    await app.close();
  }
}
