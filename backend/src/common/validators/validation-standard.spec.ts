import { ValidationPipe, BadRequestException } from '@nestjs/common';
import { IsString, IsNotEmpty } from 'class-validator';
import { Trim } from '../decorators/trim.decorator';
import { flattenValidationErrors } from './validation-error.utils';

class TestDto {
  @IsString()
  @IsNotEmpty()
  @Trim()
  name: string;
}

describe('Validation Standardization and Sanitization', () => {
  let validationPipe: ValidationPipe;

  beforeEach(() => {
    validationPipe = new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const result = flattenValidationErrors(errors as never);
        return new BadRequestException({
          message: 'Validation failed',
          errors: result,
        });
      },
    });
  });

  it('should trim string inputs', async () => {
    const input = { name: '  John Doe  ' };
    const result = await validationPipe.transform(input, {
      type: 'body',
      metatype: TestDto,
    });

    expect(result.name).toBe('John Doe');
  });

  it('should return standardized error response on validation failure', async () => {
    const input = { name: '' };
    try {
      await validationPipe.transform(input, {
        type: 'body',
        metatype: TestDto,
      });
      fail('Should have thrown BadRequestException');
    } catch (error) {
      expect(error).toBeInstanceOf(BadRequestException);
      const response = error.getResponse();
      expect(response.message).toBe('Validation failed');
      expect(response.errors).toBeDefined();
      expect(response.errors).toHaveLength(1);
      expect(response.errors[0].field).toBe('name');
      expect(response.errors[0].constraints).toBeDefined();
      expect(Object.values(response.errors[0].constraints)).toContain(
        'name should not be empty',
      );
    }
  });

  it('should preserve nested field paths', async () => {
    const result = flattenValidationErrors([
      {
        property: 'profile',
        children: [
          {
            property: 'street',
            constraints: { isNotEmpty: 'street should not be empty' },
          },
        ],
      },
    ]);

    expect(result).toEqual([
      {
        field: 'profile.street',
        constraints: { isNotEmpty: 'street should not be empty' },
        value: undefined,
      },
    ]);
  });
});
