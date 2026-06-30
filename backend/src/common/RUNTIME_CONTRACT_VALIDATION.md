# Runtime Contract Validation Implementation Guide

## Overview

This document describes the runtime contract validation layer implemented for Nestera backend. It ensures strict validation of all public request DTOs with deterministic transformations, unknown field rejection, and correlation ID tracking.

## Features

### 1. Strict Validation Enforcement

All request DTOs are validated with:
- **Field-level validation**: All fields validated according to declared constraints
- **Unknown field rejection**: Extra fields are rejected (whitelist mode)
- **Deterministic transformations**: String trimming, type conversions applied consistently
- **Boundary value checking**: Min/max values, length constraints enforced

### 2. Correlation ID Tracking

- Automatic generation or extraction from request headers (`x-correlation-id`, `x-request-id`, `correlation-id`)
- Attached to all validation error responses
- Used for request tracing across service boundaries
- Echoed back in response headers for client tracking

### 3. Backward Compatibility Grace

For deprecated endpoints or migrating clients:

```typescript
@Post('users/update')
@AllowBackwardCompatibility({
  'oldFieldName': 'newFieldName',
  'deprecatedEmail': 'email'
})
async updateUser(@Body() dto: UpdateUserDto) {
  // Deprecated field names are automatically mapped to new ones
}
```

### 4. Selective Strict Mode Disabling

For endpoints with special payload handling (file uploads, multipart):

```typescript
@Post('avatar/upload')
@DisableStrictValidation()
async uploadAvatar(@Body() dto: FileUploadDto) {
  // Strict validation disabled; allows more flexible payloads
}
```

### 5. Comprehensive Logging

- Validation failures logged with full context
- Accessible via `ContractValidationService`
- Track failures by endpoint, reason, or correlation ID
- Aggregate statistics for monitoring

## Architecture

### Components

#### 1. `StrictValidationPipe`
Located: `src/common/pipes/strict-validation.pipe.ts`

Implements strict validation pipeline:
- Applies pre-validation transformations (backward compatibility mapping)
- Validates against declared DTO constraints
- Applies post-validation transformations (empty string normalization)
- Logs validation failures with correlation ID

#### 2. `ContractValidationService`
Located: `src/common/services/contract-validation.service.ts`

Provides:
- Recording of validation failures
- Retrieval of failure records (filtered by endpoint, reason, time)
- Aggregated statistics on validation failures
- Memory-based storage (limit: 10,000 records)

#### 3. Decorators

**`@AllowBackwardCompatibility(fieldMap)`**
- Enables field name mapping for deprecated field names
- Applied at controller method level
- Automatically maps old field names to new ones before validation

**`@DisableStrictValidation()`**
- Disables strict validation for specific endpoints
- Allows unknown fields
- Used for special payload handling

#### 4. Middleware

**`CorrelationIdMiddleware`**
Located: `src/common/middleware/correlation-id.middleware.ts`

- Extracts or generates correlation ID from request
- Attaches to `req.correlationId`
- Echoes back in response headers

## Usage Examples

### Example 1: Basic Strict Validation

```typescript
// DTO with strict validation
export class CreateUserDto {
  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(256)
  password: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;
}

// Controller
@Controller('users')
export class UserController {
  @Post()
  async createUser(@Body() dto: CreateUserDto) {
    // dto.email - validated email
    // dto.password - string with length 8-256
    // dto.name - optional, trimmed string
    // Any unknown fields are rejected
    // Whitespace automatically trimmed
    
    return { success: true, data: dto };
  }
}

// Sample requests
// ✓ Valid
POST /users
{ "email": "user@example.com", "password": "SecurePass123" }

// ✗ Missing required field
POST /users
{ "email": "user@example.com" }
Response: 400 Bad Request
{
  "message": "Validation failed",
  "errors": [{ "field": "password", "constraints": { "isString": "..." } }],
  "correlationId": "uuid-xxx"
}

// ✗ Unknown field
POST /users
{ 
  "email": "user@example.com",
  "password": "SecurePass123",
  "unknownField": "should-fail"
}
Response: 400 Bad Request

// ✗ Invalid email
POST /users
{ "email": "not-an-email", "password": "SecurePass123" }
Response: 400 Bad Request
```

### Example 2: Backward Compatibility

```typescript
// Legacy endpoint with field mapping
@Controller('users')
export class UserController {
  @Put(':id')
  @AllowBackwardCompatibility({
    'fullName': 'name',           // Map old name to new name
    'emailAddress': 'email',      // Map old email field
    'userBio': 'bio'              // Map old bio field
  })
  async updateUser(
    @Param('id') id: string,
    @Body() dto: UpdateUserDto
  ) {
    // Requests with old field names work seamlessly
    return { success: true, data: dto };
  }
}

// Old client (still works)
PUT /users/123
{ "fullName": "John Doe", "emailAddress": "john@example.com" }
// Internally mapped to: { "name": "John Doe", "email": "john@example.com" }

// New client
PUT /users/123
{ "name": "John Doe", "email": "john@example.com" }
// Works as-is
```

### Example 3: Selective Strict Mode Disabling

```typescript
@Controller('uploads')
export class UploadController {
  @Post('avatar')
  @DisableStrictValidation()
  async uploadAvatar(@Body() dto: AvatarUploadDto) {
    // Strict validation disabled
    // Allows flexible payload structure for file metadata
    return { success: true };
  }
}
```

### Example 4: Error Handling and Tracking

```typescript
@Injectable()
export class MyService {
  constructor(private contractValidationService: ContractValidationService) {}

  // Get validation failures for monitoring
  getValidationStats() {
    const stats = this.contractValidationService.getFailureStatistics();
    console.log(`Total validation failures: ${stats.totalFailures}`);
    console.log(`Failures by reason:`, stats.failuresByReason);
    console.log(`Failures by endpoint:`, stats.failuresByEndpoint);
    
    // Get recent failures
    const recentFailures = this.contractValidationService.getFailureRecords({
      limit: 100,
      since: new Date(Date.now() - 3600000) // Last hour
    });
  }

  // Track failures for a specific correlation ID
  getRequestFailures(correlationId: string) {
    const failures = this.contractValidationService.getFailureByCorrelationId(correlationId);
    return failures;
  }
}
```

### Example 5: Numeric and String Transformations

```typescript
export class CreateOrderDto {
  @IsNumber()
  @Min(0.01)
  @Max(1000000)
  amount: number;

  @IsString()
  @MinLength(3)
  orderId: string;
}

// Request handling
POST /orders
{ 
  "amount": "  500.50  ",  // String is trimmed, then validated as number
  "orderId": "  ORD-123  " // String is trimmed
}
// Internally transformed to: { "amount": 500.50, "orderId": "ORD-123" }

// Empty strings are converted to undefined for optional fields
POST /users
{ 
  "email": "test@example.com",
  "password": "SecurePass123",
  "name": ""  // Empty string → undefined for optional field
}
```

## Implementation Details

### Validation Pipeline

1. **Pre-validation Transform Phase**
   - Extract correlation ID from request headers
   - Apply backward compatibility field mapping
   - Trim whitespace from strings
   - Basic type conversions

2. **Validation Phase**
   - Transform payload to DTO class instance
   - Run class-validator decorators
   - Check for unknown fields (unless @DisableStrictValidation)
   - Collect all validation errors

3. **Post-validation Transform Phase**
   - Convert empty strings to undefined
   - Final data normalization
   - Return transformed object

4. **Error Logging Phase**
   - Log validation failures to application logger
   - Record in ContractValidationService for monitoring
   - Include correlation ID in response

### Configuration in main.ts

```typescript
// Current configuration (enhanced)
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,              // Remove extra fields
    forbidNonWhitelisted: true,   // Reject extra fields
    transform: true,               // Enable transformation
    exceptionFactory: (errors) => {
      const result = flattenValidationErrors(errors);
      return new BadRequestException({
        message: 'Validation failed',
        errors: result,
        correlationId: req.correlationId, // From CorrelationIdMiddleware
      });
    },
  }),
);

// ContractValidationService is globally available
app.get(ContractValidationService);
```

## Error Response Format

```typescript
// Validation failure response
{
  "statusCode": 400,
  "message": "Validation failed",
  "errors": [
    {
      "field": "email",
      "constraints": {
        "isEmail": "email must be an email"
      },
      "value": "invalid-email"
    },
    {
      "field": "password",
      "constraints": {
        "minLength": "password must be longer than or equal to 8 characters"
      },
      "value": "short"
    }
  ],
  "correlationId": "req_1234567890_abc123def456",
  "timestamp": "2026-06-30T12:34:56.789Z",
  "path": "/api/v2/users"
}
```

## Monitoring & Debugging

### Access Validation Statistics

```typescript
// In any injectable service
constructor(private contractValidationService: ContractValidationService) {}

// Get failure statistics
const stats = this.contractValidationService.getFailureStatistics();
// Returns: { totalFailures, failuresByReason, failuresByEndpoint, uniqueCorrelationIds }

// Filter by endpoint
const userEndpointFailures = this.contractValidationService.getFailureRecords({
  endpoint: 'POST /users',
  limit: 50
});

// Filter by reason
const unknownFieldFailures = this.contractValidationService.getFailureRecords({
  reason: 'unknown_fields_rejected'
});

// Get failures for specific request
const requestFailures = this.contractValidationService.getFailureByCorrelationId(
  'req_1234567890_abc123def456'
);
```

### Logging Format

Validation failures are logged in structured JSON format:

```json
{
  "level": "validation_rejected",
  "correlationId": "req_1234567890_abc123def456",
  "endpoint": "POST /api/v2/users",
  "reason": "validation_failed",
  "timestamp": "2026-06-30T12:34:56.789Z",
  "details": {
    "issues": [
      {
        "field": "email",
        "constraints": { "isEmail": "email must be an email" }
      }
    ]
  }
}
```

## Testing

### Unit Tests

Located: `src/common/pipes/strict-validation.pipe.spec.ts`

Tests cover:
- Valid payload acceptance
- Field trimming and transformation
- Boundary value validation
- Unknown field rejection
- Optional field handling
- Error logging

### Integration Tests

Located: `src/common/pipes/strict-validation.integration.spec.ts`

Tests cover:
- End-to-end request/response flow
- Backward compatibility mapping
- Selective strict mode disabling
- Correlation ID tracking
- Error response format

### Running Tests

```bash
# Run validation tests
npm test -- strict-validation.pipe

# Run service tests
npm test -- contract-validation.service

# Run integration tests
npm test -- strict-validation.integration

# With coverage
npm test -- --coverage strict-validation
```

## Best Practices

1. **Always Validate DTOs**
   - Use class-validator decorators on all request DTOs
   - Include MinLength, MaxLength, and Min/Max constraints
   - Mark optional fields with @IsOptional()

2. **Provide Descriptive Error Messages**
   - Use custom decorators with clear messages
   - Help clients understand what's wrong

3. **Use Correlation IDs for Tracing**
   - Clients should provide X-Correlation-ID header
   - Use for end-to-end request tracing
   - Log correlation ID in all related operations

4. **Document Backward Compatibility**
   - Clearly document deprecated field names
   - Set sunset date for deprecated fields
   - Test backward compatibility in integration tests

5. **Monitor Validation Failures**
   - Track failure statistics over time
   - Investigate spikes in validation failures
   - Use data to identify client-side issues

6. **Disable Strict Mode Thoughtfully**
   - Only disable for endpoints with special requirements
   - Document why strict validation is disabled
   - Consider alternatives (separate DTOs, custom validators)

## Migration Guide

### Migrating Existing Endpoints

1. **Audit Current DTOs**
   ```bash
   grep -r "@Body()" src/modules --include="*.ts"
   ```

2. **Add Class-Validator Decorators**
   - Add validation decorators to all DTO fields
   - Include boundary constraints (Min, Max, MaxLength)
   - Mark optional fields with @IsOptional()

3. **Test Validation Behavior**
   - Create test cases for invalid inputs
   - Verify error response format
   - Check error correlation IDs

4. **Deploy and Monitor**
   - Monitor validation failure statistics
   - Track correlation IDs for debugging
   - Watch for spikes in validation errors

### Example Migration

Before:
```typescript
export class UpdateUserDto {
  name?: string;
  email?: string;
}
```

After:
```typescript
export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;
}
```

## Troubleshooting

### Issue: Valid requests being rejected

**Solution**: Check that DTO decorators are correctly applied. Ensure @IsOptional() is used for truly optional fields.

### Issue: Unknown fields not being rejected

**Solution**: Verify forbidNonWhitelisted is enabled in ValidationPipe configuration. Check for custom pipes that might disable this.

### Issue: Correlation ID not appearing in responses

**Solution**: Ensure CorrelationIdMiddleware is registered. Check request headers for X-Correlation-ID, X-Request-ID, or Correlation-ID.

### Issue: Performance impact from validation

**Solution**: Validation overhead is minimal (<1ms per request). If performance issues persist, check for custom validators with expensive operations.

## Related Documentation

- [NestJS Validation Documentation](https://docs.nestjs.com/techniques/validation)
- [Class-Validator Documentation](https://github.com/typestack/class-validator)
- [Error Handling Documentation](./ERROR_HANDLING.md)
- [API Versioning Documentation](./API_VERSIONING.md)
