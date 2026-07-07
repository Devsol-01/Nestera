import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { TenantContextService } from '../services/tenant-context.service';

/**
 * Tenant Guard
 *
 * Ensures that a request has a valid tenant context.
 * Use this guard on endpoints that require tenant isolation.
 *
 * Usage:
 * @UseGuards(JwtAuthGuard, TenantGuard)
 * @Get('savings')
 * async getSavings(@CurrentTenant() tenant: TenantContext) {
 *   // This endpoint will only execute if tenant context is present
 * }
 */
@Injectable()
export class TenantGuard implements CanActivate {
  constructor(private readonly tenantContextService: TenantContextService) {}

  canActivate(context: ExecutionContext): boolean {
    const tenant = this.tenantContextService.getTenant();

    if (!tenant) {
      throw new ForbiddenException(
        'Tenant context is required for this operation. Please provide X-Tenant-ID header or authenticate with a tenant-scoped JWT.',
      );
    }

    return true;
  }
}
