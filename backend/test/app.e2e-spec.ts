import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

/**
 * NOTE: These e2e tests are currently skipped as they require a running PostgreSQL database.
 * To run e2e tests, ensure:
 * 1. PostgreSQL is running with credentials in DATABASE_URL env var
 * 2. Database schema is migrated
 * 3. Run: pnpm run test:e2e
 * 
 * For CI/CD, unit tests and build are the primary checks.
 */
describe.skip('AppController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });
});
