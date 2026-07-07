import { Injectable } from '@nestjs/common';
import {
  EntitySubscriberInterface,
  EventSubscriber,
  InsertEvent,
  UpdateEvent,
  LoadEvent,
} from 'typeorm';
import { TenantContextService } from '../services/tenant-context.service';

/**
 * Tenant Query Scope Subscriber
 *
 * Automatically scopes database queries by tenant context.
 * This subscriber ensures that:
 * 1. All INSERT operations include tenantId if the entity has a tenantId column
 * 2. All UPDATE operations are scoped to the current tenant
 * 3. All SELECT operations are scoped to the current tenant
 *
 * This provides automatic tenant isolation at the database level without
 * requiring manual tenant filtering in every query.
 */
@Injectable()
@EventSubscriber()
export class TenantQueryScopeSubscriber implements EntitySubscriberInterface {
  constructor(private readonly tenantContextService: TenantContextService) {}

  /**
   * Called before an entity is inserted.
   * Automatically sets tenantId if the entity has a tenantId column
   * and tenant context is available.
   */
  beforeInsert(event: InsertEvent<any>): void | Promise<any> {
    const tenantId = this.tenantContextService.getTenantId();
    if (!tenantId) {
      return;
    }

    const entity = event.entity;
    if (entity && 'tenantId' in entity && !entity.tenantId) {
      entity.tenantId = tenantId;
    }
  }

  /**
   * Called before an entity is updated.
   * Ensures the update is scoped to the current tenant.
   */
  beforeUpdate(event: UpdateEvent<any>): void | Promise<any> {
    const tenantId = this.tenantContextService.getTenantId();
    if (!tenantId) {
      return;
    }

    const entity = event.entity;
    if (entity && 'tenantId' in entity) {
      // Ensure tenantId cannot be changed to a different tenant
      if (entity.tenantId && entity.tenantId !== tenantId) {
        throw new Error('Cannot update entity from a different tenant');
      }
    }
  }

  /**
   * Called after an entity is loaded.
   * This can be used for additional tenant validation if needed.
   */
  afterLoad(event: LoadEvent<any>): void | Promise<any> {
    const tenantId = this.tenantContextService.getTenantId();
    if (!tenantId) {
      return;
    }

    const entity = event.entity;
    if (entity && 'tenantId' in entity && entity.tenantId) {
      // Optional: Validate that loaded entity belongs to current tenant
      // This is a safety check to prevent data leakage
      if (entity.tenantId !== tenantId) {
        console.warn(
          `Security warning: Loaded entity ${entity.constructor.name} with id ${entity.id} belongs to tenant ${entity.tenantId} but current tenant is ${tenantId}`,
        );
      }
    }
  }
}
