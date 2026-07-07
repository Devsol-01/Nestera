# Integration Guide - Runtime Contract Validation

## Overview

This guide provides step-by-step instructions for integrating the runtime contract validation layer into existing endpoints and DTOs.

## Phase 1: Audit Current DTOs

### Step 1.1: Find all DTOs

```bash
# List all DTOs in the backend
find backend/src -name "*.dto.ts" | wc -l

# List DTOs by module
find backend/src/modules -name "*.dto.ts" | head -20
```

### Step 1.2: Audit validation coverage

Check existing DTOs for validation decorators:

```bash
# Find DTOs without decorators
grep -L "@Is" backend/src/**/*.dto.ts | head -20

# Find classes with potential missing validation
grep -B5 "?" backend/src/**/*.dto.ts | grep -v "IsOptional"
```

### Step 1.3: Document gaps

Create a checklist of DTOs needing updates:
- [ ] Missing @IsOptional() on optional fields
- [ ] Missing min/max constraints
- [ ] Missing type validators
- [ ] Missing length constraints
- [ ] Inconsistent error messages

## Phase 2: Update DTOs

### Step 2.1: Add basic validation

**Before:**
```typescript
export class UpdateUserDto {
  name?: string;
  email?: string;
  bio?: string;
}
```

**After:**
```typescript
import { IsOptional, IsString, IsEmail, MaxLength } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  bio?: string;
}
```

### Step 2.2: Add boundary constraints

**Example with constraints:**
```typescript
import {
  IsOptional,
  IsString,
  IsNumber,
  MinLength,
  MaxLength,
  Min,
  Max,
  IsArray,
  ArrayMinSize,
  ArrayMaxSize,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateOrderDto {
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  orderId: string;

  @IsNumber()
  @Min(0.01)
  @Max(1000000)
  @Type(() => Number)
  amount: number;

  @IsOptional()
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}
```

### Step 2.3: Use custom validators

```typescript
import { IsCustom, IsISO8601, IsUUID } from 'class-validator';
import { IsPositiveAmount, IsStellarKey } from '../validators';

export class CreateWalletDto {
  @IsUUID()
  userId: string;

  @IsStellarKey()
  publicKey: string;

  @IsPositiveAmount()
  initialBalance: number;
}
```

## Phase 3: Configure Controllers

### Step 3.1: Basic endpoint

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @Post()
  async createUser(@Body() dto: CreateUserDto) {
    // dto is automatically validated
    // Unknown fields are rejected
    // Validation errors include correlationId
    return this.userService.create(dto);
  }
}
```

### Step 3.2: Backward compatibility

```typescript
import { AllowBackwardCompatibility } from '../decorators/allow-backward-compatibility.decorator';

@Controller('users')
export class UserController {
  @Put(':id')
  @AllowBackwardCompatibility({
    'fullName': 'name',
    'emailAddress': 'email',
    'userBio': 'bio',
  })
  async updateUser(
    @Param('id') id: string,
    @Body() dto: UpdateUserDto,
  ) {
    // Old field names (fullName, emailAddress, userBio)
    // are automatically mapped to new names (name, email, bio)
    return this.userService.update(id, dto);
  }
}
```

### Step 3.3: Special payload handling

```typescript
import { DisableStrictValidation } from '../decorators/disable-strict-validation.decorator';

@Controller('uploads')
export class UploadController {
  @Post('avatar')
  @DisableStrictValidation()
  async uploadAvatar(
    @Param('userId') userId: string,
    @Body() dto: AvatarUploadDto,
  ) {
    // Strict validation disabled
    // Allows flexibility with file metadata
    return this.uploadService.uploadAvatar(userId, dto);
  }
}
```

## Phase 4: Error Handling

### Step 4.1: Understand error responses

```typescript
// Validation error response structure
{
  "statusCode": 400,
  "message": "Validation failed",
  "errors": [
    {
      "field": "email",
      "constraints": {
        "isEmail": "email must be an email"
      },
      "value": "not-an-email"
    }
  ],
  "correlationId": "req_1234567890_abc123",
  "timestamp": "2026-06-30T12:34:56.789Z"
}
```

### Step 4.2: Client-side error handling

```typescript
// Example client code
async createUser(userData: any) {
  try {
    const response = await fetch('/api/v2/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-ID': generateCorrelationId(),
      },
      body: JSON.stringify(userData),
    });

    if (!response.ok) {
      const error = await response.json();
      console.error('Validation failed:', {
        correlationId: error.correlationId,
        errors: error.errors,
      });
      // Display errors to user
      this.displayErrors(error.errors);
    }

    return response.json();
  } catch (error) {
    console.error('Request failed:', error);
  }
}
```

### Step 4.3: Logging correlationId

```typescript
// In your service
@Injectable()
export class UserService {
  constructor(
    private logger: Logger,
    private contractValidationService: ContractValidationService,
  ) {}

  async create(dto: CreateUserDto) {
    try {
      // Create user logic
      return user;
    } catch (error) {
      // Log with correlationId for tracing
      const failures = this.contractValidationService.getFailureByCorrelationId(
        this.getCorrelationIdFromContext(),
      );
      this.logger.error('User creation failed', {
        errors: failures,
        dto,
      });
      throw error;
    }
  }
}
```

## Phase 5: Testing

### Step 5.1: Unit test examples

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { StrictValidationPipe } from '../pipes/strict-validation.pipe';
import { CreateUserDto } from './dto/create-user.dto';

describe('CreateUserDto Validation', () => {
  let pipe: StrictValidationPipe;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [StrictValidationPipe],
    }).compile();

    pipe = module.get(StrictValidationPipe);
  });

  it('should accept valid user data', async () => {
    const validPayload = {
      email: 'test@example.com',
      password: 'SecurePassword123',
    };

    const result = await pipe.transform(validPayload, {
      type: 'body',
      metatype: CreateUserDto,
    });

    expect(result).toBeDefined();
    expect(result.email).toBe('test@example.com');
  });

  it('should reject invalid email', async () => {
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

  it('should reject unknown fields', async () => {
    const payloadWithExtraFields = {
      email: 'test@example.com',
      password: 'SecurePassword123',
      unknownField: 'should-fail',
    };

    await expect(
      pipe.transform(payloadWithExtraFields, {
        type: 'body',
        metatype: CreateUserDto,
      }),
    ).rejects.toThrow(BadRequestException);
  });
});
```

### Step 5.2: Integration test examples

```typescript
describe('UserController POST /users', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [UserService],
    }).compile();

    app = module.createNestApplication();
    app.useGlobalPipes(new StrictValidationPipe());
    await app.init();
  });

  it('should create user with valid data', () => {
    return request(app.getHttpServer())
      .post('/users')
      .send({
        email: 'test@example.com',
        password: 'SecurePassword123',
      })
      .expect(201);
  });

  it('should return 400 with validation error', () => {
    return request(app.getHttpServer())
      .post('/users')
      .send({
        email: 'invalid',
        password: 'short',
      })
      .expect(400)
      .expect((res) => {
        expect(res.body.message).toBe('Validation failed');
        expect(res.body.errors).toBeDefined();
        expect(res.body.correlationId).toBeDefined();
      });
  });

  it('should reject unknown fields', () => {
    return request(app.getHttpServer())
      .post('/users')
      .send({
        email: 'test@example.com',
        password: 'SecurePassword123',
        unknownField: 'value',
      })
      .expect(400);
  });
});
```

## Phase 6: Deployment

### Step 6.1: Pre-deployment checklist

```markdown
## Pre-Deployment Validation Checklist

- [ ] All DTOs reviewed for validation decorators
- [ ] All required fields properly decorated with type validators
- [ ] All optional fields decorated with @IsOptional()
- [ ] All boundary constraints added (min/max/length)
- [ ] Unit tests updated for validation behavior
- [ ] Integration tests verify error responses
- [ ] Backward compatibility decorators applied where needed
- [ ] Error response format verified in Swagger/Postman
- [ ] Client examples updated
- [ ] Team trained on new validation system
- [ ] Monitoring dashboard configured
- [ ] Rollback plan documented
```

### Step 6.2: Monitoring setup

```typescript
// Create monitoring endpoint to track validation metrics
@Injectable()
@Controller('admin/monitoring')
export class MonitoringController {
  constructor(
    private contractValidationService: ContractValidationService,
  ) {}

  @Get('validation-stats')
  getValidationStats() {
    const stats = this.contractValidationService.getFailureStatistics();
    return {
      timestamp: new Date(),
      ...stats,
    };
  }

  @Get('validation-failures')
  getRecentFailures(@Query('limit') limit: number = 100) {
    return this.contractValidationService.getFailureRecords({ limit });
  }

  @Get('validation-failures/:correlationId')
  getFailuresByCorrelationId(@Param('correlationId') correlationId: string) {
    return this.contractValidationService.getFailureByCorrelationId(correlationId);
  }
}
```

### Step 6.3: Gradual rollout

1. **Stage 1**: Deploy with StrictValidationPipe in test environment
2. **Stage 2**: Deploy to staging with monitoring
3. **Stage 3**: Deploy to production with reduced traffic
4. **Stage 4**: Monitor metrics and roll out to 100%

## Phase 7: Maintenance

### Step 7.1: Monitor validation failures

```bash
# Daily validation report
curl http://localhost:3001/admin/monitoring/validation-stats

# Investigate specific failures
curl http://localhost:3001/admin/monitoring/validation-failures?limit=50

# Debug specific request
curl http://localhost:3001/admin/monitoring/validation-failures/req_1234567890
```

### Step 7.2: Handle new requirements

When adding new fields:
1. Add to DTO with proper validators
2. If breaking change: use @AllowBackwardCompatibility
3. Document in changelog
4. Add tests
5. Deploy
6. Monitor

### Step 7.3: Deprecation process

When deprecating fields:
1. Add @AllowBackwardCompatibility decorator
2. Document sunset date
3. Log deprecation warnings
4. Monitor backward compatibility usage
5. Remove after grace period (typically 3-6 months)

## Rollback Plan

If validation issues arise:

```bash
# Option 1: Disable strict validation temporarily
# In main.ts, revert to basic ValidationPipe:
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: false, // Temporarily disable
    transform: true,
  }),
);

# Option 2: Disable specific endpoints
@DisableStrictValidation()
@Post('endpoint')
```

## Success Metrics

After deployment, track:

| Metric | Target | Method |
|--------|--------|--------|
| Validation error rate | < 5% | Monitor /validation-stats |
| Unknown field rejections | Track trend | Check failuresByReason |
| Backward compatibility usage | Declining | Monitor deprecated fields |
| Mean response time | < 1ms added | Performance testing |
| Test coverage | > 90% | npm test --coverage |

---

**Integration Guide Complete** ✅
