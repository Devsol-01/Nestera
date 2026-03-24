import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe, ExecutionContext } from '@nestjs/common';
import request from 'supertest';
import { join } from 'path';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { UserModule } from '../src/modules/user/user.module';
import { UserService } from '../src/modules/user/user.service';
import { ConfigModule } from '@nestjs/config';
import { JwtAuthGuard } from '../src/auth/guards/jwt-auth.guard';

/**
 * NOTE: These e2e tests are currently skipped as they require a running PostgreSQL database.
 * To run e2e tests, ensure:
 * 1. PostgreSQL is running with credentials in DATABASE_URL env var
 * 2. Database schema is migrated
 * 3. Run: pnpm run test:e2e
 * 
 * For CI/CD, unit tests and build are the primary checks.
 */
describe.skip('User Avatar (e2e)', () => {
  let app: INestApplication;
  const token = 'mock-token';

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    avatarUrl: null,
    bio: null,
    kycStatus: 'NOT_SUBMITTED',
    kycDocumentUrl: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockUserService = {
    findById: jest.fn().mockResolvedValue(mockUser),
    updateAvatar: jest
      .fn()
      .mockImplementation((userId, avatarUrl) =>
        Promise.resolve({ ...mockUser, avatarUrl }),
      ),
  };

  const testFilePath = join(__dirname, 'test-avatar.png');

  beforeAll(async () => {
    // Create a dummy image file for testing
    writeFileSync(testFilePath, Buffer.from('fake-image-content-png-mock'));

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [() => ({ jwt: { secret: 'secret' } })],
        }),
        UserModule,
      ],
    })
      .overrideProvider(UserService)
      .useValue(mockUserService)
      .overrideGuard(JwtAuthGuard)
      .useValue({
        canActivate: (context: ExecutionContext) => {
          const req = context.switchToHttp().getRequest();
          req.user = { id: mockUser.id, email: mockUser.email };
          return true;
        },
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
  });

  afterAll(async () => {
    if (existsSync(testFilePath)) {
      unlinkSync(testFilePath);
    }
    if (app) {
      await app.close();
    }
  });

  it('/users/avatar (POST) - should upload avatar successfully', async () => {
    const res = await request(app.getHttpServer())
      .post('/users/avatar')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', testFilePath);

    if (res.status !== 201) {
      console.log('Failing response body:', res.body);
    }

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('avatarUrl');
    expect(res.body.avatarUrl).toContain('/uploads/');
  });

  it('/users/avatar (POST) - should fail if file is missing', () => {
    return request(app.getHttpServer())
      .post('/users/avatar')
      .set('Authorization', `Bearer ${token}`)
      .expect(400);
  });

  it('/users/avatar (POST) - should fail if file is not an image', () => {
    const textFilePath = join(__dirname, 'test.txt');
    writeFileSync(textFilePath, 'not an image');

    return request(app.getHttpServer())
      .post('/users/avatar')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', textFilePath)
      .expect(400)
      .then(() => {
        if (existsSync(textFilePath)) unlinkSync(textFilePath);
      });
  });
});
