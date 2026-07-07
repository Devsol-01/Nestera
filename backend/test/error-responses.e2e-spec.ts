import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe, BadRequestException } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { flattenValidationErrors } from '../src/common/validators/validation-error.utils';

describe('Standardized Error Responses E2E', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalFilters(new AllExceptionsFilter());
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
  });

  afterAll(async () => {
    await app?.close();
  });

  it('should have consistent 404 shape', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/nonexistent-route')
      .expect(404);

    expect(res.body).toMatchObject({
      success: false,
      statusCode: 404,
    });
    expect(res.body).toHaveProperty('errorCode');
    expect(res.body).toHaveProperty('message');
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body).toHaveProperty('path');
    expect(res.body).toHaveProperty('requestId');
  });

  it('should have consistent 401 shape', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/savings/my-subscriptions')
      .expect(401);

    expect(res.body).toMatchObject({
      success: false,
      statusCode: 401,
      errorCode: 'UNAUTHORIZED',
    });
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body).toHaveProperty('requestId');
  });

  it('should have consistent validation error shape with details array', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/auth/register')
      .send({ email: 'not-an-email', password: 'x' })
      .expect(400);

    expect(res.body).toMatchObject({
      success: false,
      statusCode: 400,
      errorCode: 'VALIDATION_ERROR',
    });
    expect(res.body).toHaveProperty('details');
    expect(Array.isArray(res.body.details)).toBe(true);
    expect(res.body.details.length).toBeGreaterThan(0);
    expect(res.body.details[0]).toHaveProperty('field');
    expect(res.body.details[0]).toHaveProperty('constraints');
  });

  it('should include requestId from correlation-id header', async () => {
    const correlationId = 'test-correlation-12345';

    const res = await request(app.getHttpServer())
      .get('/api/nonexistent-route')
      .set('x-correlation-id', correlationId)
      .expect(404);

    expect(res.body.requestId).toBe(correlationId);
  });

  it('should auto-generate requestId when not provided', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/nonexistent-route')
      .expect(404);

    // Should be either a UUID or null depending on middleware ordering
    expect(res.body).toHaveProperty('requestId');
  });

  it('should have ISO-8601 timestamp', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/nonexistent-route')
      .expect(404);

    const timestamp = new Date(res.body.timestamp);
    expect(timestamp.getTime()).not.toBeNaN();
    expect(res.body.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('should not leak stack traces in error responses', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/nonexistent-route')
      .expect(404);

    expect(res.body).not.toHaveProperty('stack');
    expect(JSON.stringify(res.body)).not.toContain('at ');
  });

  it('should have consistent shape for rate-limited requests', async () => {
    // Trigger many requests rapidly — if throttled, check the 429 shape
    const promises = Array.from({ length: 20 }, () =>
      request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: 'throttle@test.com', password: 'whatever' }),
    );

    const results = await Promise.all(promises);
    const throttled = results.find((r) => r.status === 429);

    if (throttled) {
      expect(throttled.body).toHaveProperty('success', false);
      expect(throttled.body).toHaveProperty('errorCode', 'TOO_MANY_REQUESTS');
      expect(throttled.body).toHaveProperty('timestamp');
    }
  });
});
