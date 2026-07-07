import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface TenantContext {
  id: string;
  slug: string;
}

export type RequestWithTenant = Request & {
  tenant?: TenantContext;
};

/**
 * Tenant Context Middleware
 *
 * Extracts tenant context from the request and attaches it to the request object.
 * Tenant context can be provided via:
 * 1. JWT payload (attached by JwtStrategy)
 * 2. X-Tenant-ID header (for service-to-service calls)
 * 3. X-Tenant-Slug header (alternative identification)
 *
 * This middleware runs after authentication to ensure tenant context is available
 * for all subsequent handlers, guards, and interceptors.
 */
@Injectable()
export class TenantContextMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const reqWithTenant = req as RequestWithTenant;

    // Priority 1: Extract from JWT payload (already attached by JwtStrategy)
    if ((req as any).user?.tenantId) {
      reqWithTenant.tenant = {
        id: (req as any).user.tenantId,
        slug: (req as any).user.tenantSlug || 'default',
      };
    }
    // Priority 2: Extract from X-Tenant-ID header (service-to-service)
    else if (req.headers['x-tenant-id']) {
      reqWithTenant.tenant = {
        id: req.headers['x-tenant-id'] as string,
        slug: (req.headers['x-tenant-slug'] as string) || 'default',
      };
    }
    // Priority 3: Extract from X-Tenant-Slug header (alternative)
    else if (req.headers['x-tenant-slug']) {
      reqWithTenant.tenant = {
        id: (req.headers['x-tenant-id'] as string) || 'unknown',
        slug: req.headers['x-tenant-slug'] as string,
      };
    }

    // Echo tenant context in response headers for debugging
    if (reqWithTenant.tenant) {
      res.setHeader('x-tenant-id', reqWithTenant.tenant.id);
      res.setHeader('x-tenant-slug', reqWithTenant.tenant.slug);
    }

    next();
  }
}
