import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, UnauthorizedException } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

/**
 * NOTE: These e2e tests are currently skipped as they require a running PostgreSQL database.
 * To run e2e tests, ensure:
 * 1. PostgreSQL is running with credentials in DATABASE_URL env var
 * 2. Database schema is migrated
 * 3. Run: pnpm run test:e2e
 * 
 * For CI/CD, unit tests and build are the primary checks.
 */
describe.skip('Webhooks (e2e)', () => {
  let app: INestApplication;
  const mockSecret = 'test_webhook_secret_key_123456';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ConfigService)
      .useValue({
        get: jest.fn((key: string) => {
          if (key === 'stellar.webhookSecret') return mockSecret;
          if (key === 'stellar.network') return 'testnet';
          return 'mock_value';
        }),
      })
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('/webhooks/stellar (POST) - Valid Signature', () => {
    const payload = {
      type: 'payment',
      transaction_hash: '123...',
      from: 'GA...',
      to: 'GB...',
      amount: '10.0',
    };
    const signature = crypto
      .createHmac('sha256', mockSecret)
      .update(JSON.stringify(payload))
      .digest('hex');

    return request(app.getHttpServer())
      .post('/webhooks/stellar')
      .set('x-stellar-signature', signature)
      .send(payload)
      .expect(200)
      .expect({ status: 'success' });
  });

  it('/webhooks/stellar (POST) - Invalid Signature', () => {
    const payload = { type: 'payment' };
    return request(app.getHttpServer())
      .post('/webhooks/stellar')
      .set('x-stellar-signature', 'wrong')
      .send(payload)
      .expect(401);
  });

  it('/webhooks/stellar (POST) - Missing Signature', () => {
    const payload = { type: 'payment' };
    return request(app.getHttpServer())
      .post('/webhooks/stellar')
      .send(payload)
      .expect(401);
  });
});
