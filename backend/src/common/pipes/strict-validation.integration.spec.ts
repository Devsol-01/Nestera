import { Test, TestingModule } from '@nestjs/testing';
import {
  INestApplication,
  Controller,
  Post,
  Body,
  BadRequestException,
} from '@nestjs/common';
import { IsString, IsEmail, MinLength } from 'class-validator';
import request from 'supertest';
import { StrictValidationPipe } from './strict-validation.pipe';
import { ContractValidationService } from '../services/contract-validation.service';
import { AllowBackwardCompatibility } from '../decorators/allow-backward-compatibility.decorator';
import { DisableStrictValidation } from '../decorators/disable-strict-validation.decorator';

// Test DTOs
class CreateUserDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  username?: string;
}

class LegacyUpdateUserDto {
  @IsString()
  fullName?: string;
}

// Test Controller
@Controller('test')
class TestController {
  @Post('users')
  createUser(@Body() dto: CreateUserDto) {
    return { success: true, data: dto };
  }

  @Post('users-legacy')
  @AllowBackwardCompatibility({ fullName: 'name' })
  legacyUpdateUser(@Body() dto: LegacyUpdateUserDto) {
    return { success: true, data: dto };
  }

  @Post('upload')
  @DisableStrictValidation()
  uploadFile(@Body() dto: any) {
    return { success: true, data: dto };
  }
}

describe('Strict Validation Integration Tests', () => {
  let app: INestApplication;
  let contractValidationService: ContractValidationService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestController],
      providers: [
        StrictValidationPipe,
        ContractValidationService,
      ],
    }).compile();

    app = module.createNestApplication();
    
    // Register the validation pipe globally
    app.useGlobalPipes(new StrictValidationPipe(undefined, module.get(ContractValidationService)));

    contractValidationService = module.get<ContractValidationService>(
      ContractValidationService,
    );

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Valid requests', () => {
    it('should accept valid user creation request', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'test@example.com',
          password: 'SecurePassword123',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.data).toHaveProperty('email');
          expect(res.body.data).toHaveProperty('password');
        });
    });

    it('should accept request with optional fields', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'test@example.com',
          password: 'SecurePassword123',
          username: 'testuser',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.data.username).toBe('testuser');
        });
    });

    it('should trim whitespace from request body', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: '  test@example.com  ',
          password: '  SecurePassword123  ',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.data.email).toBe('test@example.com');
          expect(res.body.data.password).toBe('SecurePassword123');
        });
    });
  });

  describe('Invalid requests - validation failures', () => {
    it('should reject missing required field', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'test@example.com',
          // password missing
        })
        .expect(400)
        .expect((res) => {
          expect(res.body.message).toBe('Validation failed');
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should reject invalid email format', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'not-an-email',
          password: 'SecurePassword123',
        })
        .expect(400);
    });

    it('should reject password that is too short', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'test@example.com',
          password: 'short',
        })
        .expect(400);
    });

    it('should include correlationId in error response', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .set('X-Correlation-ID', 'test-corr-123')
        .send({
          email: 'invalid',
          password: 'short',
        })
        .expect(400)
        .expect((res) => {
          expect(res.body).toHaveProperty('correlationId');
        });
    });
  });

  describe('Unknown fields rejection', () => {
    it('should reject request with unknown fields', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'test@example.com',
          password: 'SecurePassword123',
          unknownField: 'should-not-exist',
          anotherUnknown: 123,
        })
        .expect(400)
        .expect((res) => {
          expect(res.body.message).toContain('Validation failed');
        });
    });

    it('should be able to bypass strict validation with decorator', () => {
      // This test demonstrates that @DisableStrictValidation can allow more flexible payloads
      return request(app.getHttpServer())
        .post('/test/upload')
        .send({
          randomField1: 'value',
          randomField2: 123,
          randomField3: { nested: 'object' },
        })
        .expect(201); // Should succeed despite unknown fields
    });
  });

  describe('Backward compatibility', () => {
    it('should map deprecated field names to current ones', () => {
      return request(app.getHttpServer())
        .post('/test/users-legacy')
        .send({
          fullName: 'John Doe',
        })
        .expect(201);
        // fullName should be mapped to name via decorator
    });
  });

  describe('Error logging and tracking', () => {
    it('should track validation failures', () => {
      return request(app.getHttpServer())
        .post('/test/users')
        .send({
          email: 'invalid',
          // password missing
        })
        .expect(400)
        .then(() => {
          const stats = contractValidationService.getFailureStatistics();
          expect(stats.totalFailures).toBeGreaterThan(0);
        });
    });

    it('should track multiple validation failures', () => {
      const promises = [];

      for (let i = 0; i < 5; i++) {
        promises.push(
          request(app.getHttpServer())
            .post('/test/users')
            .send({
              email: `invalid-${i}`,
              password: 'short',
            })
            .expect(400),
        );
      }

      return Promise.all(promises).then(() => {
        const stats = contractValidationService.getFailureStatistics();
        expect(stats.totalFailures).toBeGreaterThanOrEqual(5);
        expect(stats.failuresByReason['validation_failed']).toBeGreaterThan(0);
      });
    });
  });
});
