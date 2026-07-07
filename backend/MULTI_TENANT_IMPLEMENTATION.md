# Multi-Tenant Implementation Guide

This document describes the multi-tenant architecture implemented in the Nestera backend.

## Overview

The multi-tenant implementation provides automatic tenant isolation for database queries and request context. This enables the application to serve multiple organizations/tenants from a single database instance while ensuring complete data isolation.

## Architecture Components

### 1. Tenant Entity

**Location:** `src/common/entities/tenant.entity.ts`

The `Tenant` entity represents a multi-tenant organization in the system:

```typescript
@Entity('tenants')
export class Tenant {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true, length: 100 })
  slug: string;

  @Column({ length: 255 })
  name: string;

  @Column({ type: 'enum', enum: TenantStatus, default: TenantStatus.PENDING })
  status: TenantStatus;

  @Column({ type: 'jsonb', nullable: true })
  settings: Record<string, any> | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;
}
```

### 2. Tenant Context Middleware

**Location:** `src/common/middleware/tenant-context.middleware.ts`

Extracts tenant context from requests and attaches it to the request object. Tenant context can be provided via:

1. **JWT payload** (attached by JwtStrategy) - Recommended for authenticated requests
2. **X-Tenant-ID header** - For service-to-service calls
3. **X-Tenant-Slug header** - Alternative identification method

```typescript
export interface TenantContext {
  id: string;
  slug: string;
}
```

### 3. Tenant Context Service

**Location:** `src/common/services/tenant-context.service.ts`

Request-scoped service that provides access to the current tenant context:

```typescript
@Injectable({ scope: Scope.REQUEST })
export class TenantContextService {
  getTenant(): TenantContext | null;
  getTenantId(): string | null;
  getTenantSlug(): string | null;
  hasTenant(): boolean;
}
```

### 4. Tenant Query Scope Subscriber

**Location:** `src/common/database/tenant-query-scope.subscriber.ts`

TypeORM subscriber that automatically scopes database operations:

- **INSERT**: Automatically sets `tenantId` if the entity has a `tenantId` column
- **UPDATE**: Ensures updates are scoped to the current tenant
- **LOAD**: Validates that loaded entities belong to the current tenant (safety check)

### 5. Tenant Scoped Repository

**Location:** `src/common/database/tenant-scoped-repository.ts`

Base repository class that provides automatic tenant scoping for queries:

```typescript
export abstract class TenantScopedRepository<T> {
  createQueryBuilder(alias?: string): SelectQueryBuilder<T>;
  find(options?: any): Promise<T[]>;
  findOne(options?: any): Promise<T | null>;
  findOneById(id: string): Promise<T | null>;
  count(options?: any): Promise<number>;
}
```

### 6. Tenant Guard

**Location:** `src/common/guards/tenant.guard.ts`

Guard that ensures a request has valid tenant context:

```typescript
@UseGuards(JwtAuthGuard, TenantGuard)
@Get('savings')
async getSavings(@CurrentTenant() tenant: TenantContext) {
  // This endpoint will only execute if tenant context is present
}
```

### 7. Decorators

**Location:** `src/common/decorators/current-tenant.decorator.ts`

Decorator to inject current tenant context into controllers:

```typescript
@CurrentTenant() tenant: TenantContext
```

## Database Schema Changes

### Tenant Columns Added

The following tables now include a `tenantId` column:

- `users`
- `savings_goals`
- `user_subscriptions`
- `transactions`
- `referrals`
- `notifications`

### New Table: `tenants`

Stores tenant configuration and metadata:

```sql
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  slug VARCHAR(100) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(20) DEFAULT 'PENDING',
  settings JSONB,
  metadata JSONB,
  createdAt TIMESTAMP DEFAULT now(),
  updatedAt TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);
```

### Indexes Created

Indexes on `tenantId` columns for query performance:

```sql
CREATE INDEX idx_users_tenant_id ON users(tenantId);
CREATE INDEX idx_savings_goals_tenant_id ON savings_goals(tenantId);
CREATE INDEX idx_user_subscriptions_tenant_id ON user_subscriptions(tenantId);
CREATE INDEX idx_transactions_tenant_id ON transactions(tenantId);
CREATE INDEX idx_referrals_tenant_id ON referrals(tenantId);
CREATE INDEX idx_notifications_tenant_id ON notifications(tenantId);
```

## Configuration

### Environment Variables

Add the following to your `.env` file:

```bash
# Enable multi-tenant mode
MULTI_TENANT_ENABLED=true

# Default tenant (for single-tenant deployments or fallback)
DEFAULT_TENANT_ID=default
DEFAULT_TENANT_SLUG=default
```

### Configuration Schema

**Location:** `src/config/configuration.ts`

```typescript
multiTenant: {
  enabled: process.env.MULTI_TENANT_ENABLED === 'true',
  defaultTenantId: process.env.DEFAULT_TENANT_ID || 'default',
  defaultTenantSlug: process.env.DEFAULT_TENANT_SLUG || 'default',
}
```

## Migration

Run the migration to add tenant columns and create the tenants table:

```bash
npm run migration:run
```

To revert:

```bash
npm run migration:revert
```

**Migration file:** `src/migrations/add-tenant-columns.ts`

## Usage Patterns

### 1. JWT Authentication with Tenant Context

When issuing JWTs, include tenant information in the payload:

```typescript
const payload = {
  sub: user.id,
  email: user.email,
  role: user.role,
  kycStatus: user.kycStatus,
  tenantId: user.tenantId,
  tenantSlug: tenant.slug,
};
```

### 2. Service-to-Service Calls

Include tenant headers in requests:

```typescript
const headers = {
  'X-Tenant-ID': tenantId,
  'X-Tenant-Slug': tenantSlug,
};
```

### 3. Using Tenant Context in Controllers

```typescript
@Controller('savings')
export class SavingsController {
  @Get()
  @UseGuards(JwtAuthGuard, TenantGuard)
  async getSavings(
    @CurrentTenant() tenant: TenantContext,
    @CurrentUser() user: any,
  ) {
    // tenant.id and tenant.slug are available here
    // All queries will be automatically scoped to this tenant
  }
}
```

### 4. Extending TenantScopedRepository

For custom repositories that need tenant scoping:

```typescript
@Injectable()
export class CustomUserRepository extends TenantScopedRepository<User> {
  constructor(
    @InjectRepository(User)
    repository: Repository<User>,
    tenantContextService: TenantContextService,
  ) {
    super(repository, tenantContextService);
  }

  async findActiveUsers(): Promise<User[]> {
    return this.createQueryBuilder('user')
      .where('user.isActive = :isActive', { isActive: true })
      .getMany();
    // Automatically scoped to current tenant
  }
}
```

### 5. Manual Tenant Scoping

For complex queries that need manual control:

```typescript
@Injectable()
export class SavingsService {
  constructor(
    private readonly tenantContextService: TenantContextService,
    @InjectRepository(SavingsGoal)
    private readonly savingsGoalRepository: Repository<SavingsGoal>,
  ) {}

  async findGoals() {
    const tenantId = this.tenantContextService.getTenantId();
    return this.savingsGoalRepository.find({
      where: { tenantId },
    });
  }
}
```

## Security Considerations

### 1. Data Isolation

- All database queries are automatically scoped to the current tenant
- The subscriber prevents cross-tenant data access
- Safety checks validate loaded entities belong to the current tenant

### 2. Tenant Context Validation

- Tenant context is required for protected endpoints (use `TenantGuard`)
- JWT-based tenant context is preferred over header-based
- Service-to-service calls must provide valid tenant headers

### 3. Migration Safety

- `tenantId` columns are nullable to support gradual migration
- Existing data without `tenantId` will continue to work
- New data will automatically get `tenantId` assigned

## Testing

### Unit Tests

Test tenant context service:

```typescript
describe('TenantContextService', () => {
  it('should return tenant from request', () => {
    const mockRequest = { tenant: { id: '123', slug: 'test' } };
    const service = new TenantContextService(mockRequest);
    expect(service.getTenant()).toEqual({ id: '123', slug: 'test' });
  });
});
```

### Integration Tests

Test tenant isolation:

```typescript
describe('Multi-Tenant Isolation', () => {
  it('should not return data from other tenants', async () => {
    // Create data for tenant A
    await createSavingsGoal({ tenantId: 'tenant-a' });
    
    // Create data for tenant B
    await createSavingsGoal({ tenantId: 'tenant-b' });
    
    // Set tenant context to A
    setTenantContext({ id: 'tenant-a', slug: 'tenant-a' });
    
    // Should only return tenant A's data
    const goals = await savingsService.findGoals();
    expect(goals).toHaveLength(1);
    expect(goals[0].tenantId).toBe('tenant-a');
  });
});
```

## Rollout Strategy

### Phase 1: Enable Multi-Tenant (No Isolation)

1. Set `MULTI_TENANT_ENABLED=false` (default)
2. Run migration to add `tenantId` columns
3. Existing data continues to work (nullable columns)
4. New data gets `tenantId` assigned automatically

### Phase 2: Gradual Rollout

1. Enable multi-tenant for specific modules
2. Add `TenantGuard` to protected endpoints
3. Monitor for any cross-tenant access issues
4. Gradually expand to all modules

### Phase 3: Full Multi-Tenant

1. Set `MULTI_TENANT_ENABLED=true`
2. All endpoints require tenant context
3. Complete data isolation enforced
4. Remove any legacy single-tenant code

## Troubleshooting

### Issue: Queries return no data

**Cause:** Tenant context not set or `tenantId` not populated

**Solution:**
- Check that `X-Tenant-ID` header is set
- Verify JWT payload includes `tenantId`
- Ensure middleware is registered in `AppModule`

### Issue: Cross-tenant data leakage

**Cause:** Manual queries bypassing tenant scoping

**Solution:**
- Use `TenantScopedRepository` for all queries
- Add `tenantId` to manual WHERE clauses
- Enable subscriber safety checks

### Issue: Migration fails

**Cause:** Database permissions or existing constraints

**Solution:**
- Check database user has ALTER TABLE permissions
- Verify no conflicting constraints exist
- Run migration in development environment first

## Performance Considerations

### Database Indexes

All `tenantId` columns are indexed for query performance. Monitor query performance and add composite indexes if needed:

```sql
CREATE INDEX idx_users_tenant_id_email ON users(tenantId, email);
```

### Connection Pooling

Multi-tenant deployments may benefit from larger connection pools. Adjust pool settings in configuration:

```bash
DATABASE_POOL_MAX=50
DATABASE_POOL_MIN=10
```

### Caching

Cache keys should include tenant ID to prevent cross-tenant cache pollution:

```typescript
const cacheKey = `savings:${tenantId}:${productId}`;
```

## Future Enhancements

1. **Tenant-specific configurations** - Per-tenant feature flags and settings
2. **Tenant admin portal** - UI for managing tenants
3. **Tenant metrics** - Per-tenant analytics and reporting
4. **Tenant isolation at storage level** - S3 bucket per tenant
5. **Tenant rate limiting** - Per-tenant throttling limits

## References

- TypeORM Subscribers: https://typeorm.io/#/listeners-and-subscribers
- NestJS Middleware: https://docs.nestjs.com/middleware
- NestJS Guards: https://docs.nestjs.com/guards
- Request-scoped providers: https://docs.nestjs.com/fundamentals/custom-providers#scoped-providers
