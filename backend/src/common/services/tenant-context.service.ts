import { Injectable, Scope, Inject } from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import { Request } from 'express';

export interface TenantContext {
  id: string;
  slug: string;
}

/**
 * Tenant Context Service
 *
 * Provides request-scoped access to the current tenant context.
 * This service is request-scoped to ensure each request gets its own instance
 * with the correct tenant context from the request object.
 */
@Injectable({ scope: Scope.REQUEST })
export class TenantContextService {
  constructor(@Inject(REQUEST) private request: Request) {}

  /**
   * Get the current tenant context from the request
   */
  getTenant(): TenantContext | null {
    const req = this.request as any;
    return req.tenant || null;
  }

  /**
   * Get the current tenant ID
   */
  getTenantId(): string | null {
    const tenant = this.getTenant();
    return tenant?.id || null;
  }

  /**
   * Get the current tenant slug
   */
  getTenantSlug(): string | null {
    const tenant = this.getTenant();
    return tenant?.slug || null;
  }

  /**
   * Check if a tenant context exists for the current request
   */
  hasTenant(): boolean {
    return this.getTenant() !== null;
  }
}
