import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, Logger } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { StrictValidationPipe } from './strict-validation.pipe';
import { ContractValidationService } from '../services/contract-validation.service';
import {
  IsString,
  IsEmail,
  IsOptional,
  MinLength,
  MaxLength,
  IsNumber,
  Min,
  Max,
} from 'class-validator';

// Test DTOs
class UpdateUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  bio?: string;
}

class CreateUserDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsOptional()
  @IsString()
  name?: string;
}

class CreateOrderDto {
  @IsNumber()
  @Min(0)
  @Max(1000000)
  amount: number;

  @IsString()
  orderId: string;
}

describe('StrictValidationPipe', () => {
  let pipe: StrictValidationPipe;
  let contractValidationService: ContractValidationService;
  let module: TestingModule;

  beforeEach(async () => {
    module = await Test.createTestingModule({
      providers: [
        StrictValidationPipe,
        {
          provide: ContractValidationService,
          useValue: {
            recordValidationFailure: jest.fn(),
          },
        },
      ],
    }).compile();

    contractValidationService =
      module.get<ContractValidationService>(ContractValidationService);
    pipe = module.get<StrictValidationPipe>(StrictValidationPipe);
  });

  afterEach(async () => {
    await module.close();
  });

  describe('Valid payloads', () => {
    it('should accept valid DTO with all required fields', async () => {
      const validPayload = {
        email: 'test@example.com',
        password: 'SecurePassword123',
      };

      const result = await pipe.transform(validPayload, {
        type: 'body',
        metatype: CreateUserDto,
      });

      expect(result).toBeDefined();
      expect(result).toHaveProperty('email', 'test@example.com');
      expect(result).toHaveProperty('password', 'SecurePassword123');
    });

    it('should accept valid DTO with optional fields', async () => {
      const validPayload = {
        email: 'test@example.com',
        password: 'SecurePassword123',
        name: 'John Doe',
      };

      const result = await pipe.transform(validPayload, {
        type: 'body',
        metatype: CreateUserDto,
      });

      expect(result).toBeDefined();
      expect(result).toHaveProperty('name', 'John Doe');
    });

    it('should trim whitespace from string fields', async () => {
      const payloadWithWhitespace = {
        email: '  test@example.com  ',
        password: '  SecurePassword123  ',
        name: '  John Doe  ',
      };

      const result = await pipe.transform(payloadWithWhitespace, {
        type: 'body',
        metatype: CreateUserDto,
      });

      expect(result.email).toBe('test@example.com');
      expect(result.password).toBe('SecurePassword123');
      expect(result.name).toBe('John Doe');
    });

    it('should accept numeric values for number fields', async () => {
      const validPayload = {
        amount: 500,
        orderId: 'order-123',
      };

      const result = await pipe.transform(validPayload, {
        type: 'body',
        metatype: CreateOrderDto,
      });

      expect(result).toBeDefined();
      expect(result.amount).toBe(500);
    });
  });

  describe('Invalid payloads - Required fields', () => {
    it('should reject missing required field', async () => {
      const invalidPayload = {
        email: 'test@example.com',
        // password missing
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should include correlationId in error response', async () => {
      const invalidPayload = {
        email: 'test@example.com',
      };

      try {
        await pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        });
      } catch (error) {
        expect(error.getResponse()).toHaveProperty('correlationId');
      }
    });
  });

  describe('Invalid payloads - Type validation', () => {
    it('should reject invalid email format', async () => {
      const invalidPayload = {
        email: 'not-an-email',
        password: 'SecurePassword123',
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject string when number expected', async () => {
      const invalidPayload = {
        amount: 'not-a-number',
        orderId: 'order-123',
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateOrderDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject too-short password', async () => {
      const invalidPayload = {
        email: 'test@example.com',
        password: 'short',
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject too-long string field', async () => {
      const invalidPayload = {
        email: 'test@example.com',
        password: 'SecurePassword123',
        name: 'A'.repeat(101), // Exceeds MaxLength(100)
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('Invalid payloads - Boundary values', () => {
    it('should reject negative amount', async () => {
      const invalidPayload = {
        amount: -100,
        orderId: 'order-123',
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateOrderDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject amount exceeding max value', async () => {
      const invalidPayload = {
        amount: 1000001,
        orderId: 'order-123',
      };

      await expect(
        pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateOrderDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should accept amount at min boundary', async () => {
      const validPayload = {
        amount: 0,
        orderId: 'order-123',
      };

      const result = await pipe.transform(validPayload, {
        type: 'body',
        metatype: CreateOrderDto,
      });

      expect(result.amount).toBe(0);
    });

    it('should accept amount at max boundary', async () => {
      const validPayload = {
        amount: 1000000,
        orderId: 'order-123',
      };

      const result = await pipe.transform(validPayload, {
        type: 'body',
        metatype: CreateOrderDto,
      });

      expect(result.amount).toBe(1000000);
    });
  });

  describe('Unknown fields handling', () => {
    it('should reject unknown fields by default', async () => {
      const payloadWithUnknownFields = {
        email: 'test@example.com',
        password: 'SecurePassword123',
        unknownField: 'should-not-exist',
      };

      await expect(
        pipe.transform(payloadWithUnknownFields, {
          type: 'body',
          metatype: CreateUserDto,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should include unknown field names in error', async () => {
      const payloadWithUnknownFields = {
        email: 'test@example.com',
        password: 'SecurePassword123',
        unknownField: 'should-not-exist',
      };

      try {
        await pipe.transform(payloadWithUnknownFields, {
          type: 'body',
          metatype: CreateUserDto,
        });
      } catch (error) {
        const response = error.getResponse();
        expect(response).toHaveProperty('message');
      }
    });
  });

  describe('Non-body parameters', () => {
    it('should skip validation for query parameters', async () => {
      const payload = { anyField: 'any-value' };

      const result = await pipe.transform(payload, {
        type: 'query',
        metatype: CreateUserDto,
      });

      expect(result).toEqual(payload);
    });

    it('should skip validation for path parameters', async () => {
      const payload = { anyField: 'any-value' };

      const result = await pipe.transform(payload, {
        type: 'param',
        metatype: CreateUserDto,
      });

      expect(result).toEqual(payload);
    });

    it('should skip validation when no metatype provided', async () => {
      const payload = { anyField: 'any-value' };

      const result = await pipe.transform(payload, {
        type: 'body',
        metatype: undefined,
      });

      expect(result).toEqual(payload);
    });
  });

  describe('Error logging', () => {
    it('should log validation failures', async () => {
      const invalidPayload = {
        email: 'invalid-email',
        password: 'short',
      };

      try {
        await pipe.transform(invalidPayload, {
          type: 'body',
          metatype: CreateUserDto,
        });
      } catch (error) {
        // Validation should have been logged via ContractValidationService
        expect(contractValidationService.recordValidationFailure).toHaveBeenCalled();
      }
    });
  });

  describe('Optional field handling', () => {
    it('should allow optional fields to be undefined', async () => {
      const payload = {
        email: 'test@example.com',
        password: 'SecurePassword123',
        // name is optional and not provided
      };

      const result = await pipe.transform(payload, {
        type: 'body',
        metatype: CreateUserDto,
      });

      expect(result).toBeDefined();
      expect(result.name).toBeUndefined();
    });

    it('should convert empty string to undefined for optional fields', async () => {
      const payload = {
        name: '',
        bio: '',
      };

      const result = await pipe.transform(payload, {
        type: 'body',
        metatype: UpdateUserDto,
      });

      expect(result.name).toBeUndefined();
      expect(result.bio).toBeUndefined();
    });
  });
});
