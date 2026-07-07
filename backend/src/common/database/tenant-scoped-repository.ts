import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, SelectQueryBuilder } from 'typeorm';
import { TenantContextService } from '../services/tenant-context.service';

/**
 * Tenant Scoped Repository Base Class
 *
 * Provides automatic tenant scoping for database queries.
 * Extending this class ensures all queries are automatically filtered
 * by the current tenant context.
 *
 * Usage:
 * @Injectable()
 * export class UserRepository extends TenantScopedRepository<User> {
 *   constructor(
 *     @InjectRepository(User)
 *     repository: Repository<User>,
 *     tenantContextService: TenantContextService,
 *   ) {
 *     super(repository, tenantContextService);
 *   }
 * }
 */
@Injectable()
export abstract class TenantScopedRepository<T> {
  constructor(
    protected readonly repository: Repository<T>,
    protected readonly tenantContextService: TenantContextService,
  ) {}

  /**
   * Create a query builder with automatic tenant scoping
   */
  createQueryBuilder(alias?: string): SelectQueryBuilder<T> {
    const tenantId = this.tenantContextService.getTenantId();
    const qb = this.repository.createQueryBuilder(alias);

    // If tenant context exists and entity has tenantId column, add WHERE clause
    if (tenantId && this.hasTenantColumn()) {
      const aliasName = alias || this.repository.metadata.tableName;
      qb.andWhere(`${aliasName}.tenantId = :tenantId`, { tenantId });
    }

    return qb;
  }

  /**
   * Find all with automatic tenant scoping
   */
  async find(options?: any): Promise<T[]> {
    const tenantId = this.tenantContextService.getTenantId();
    if (tenantId && this.hasTenantColumn()) {
      return this.repository.find({
        ...options,
        where: {
          ...options?.where,
          tenantId,
        },
      });
    }
    return this.repository.find(options);
  }

  /**
   * Find one with automatic tenant scoping
   */
  async findOne(options?: any): Promise<T | null> {
    const tenantId = this.tenantContextService.getTenantId();
    if (tenantId && this.hasTenantColumn()) {
      return this.repository.findOne({
        ...options,
        where: {
          ...options?.where,
          tenantId,
        },
      });
    }
    return this.repository.findOne(options);
  }

  /**
   * Find by ID with automatic tenant scoping
   */
  async findOneById(id: string): Promise<T | null> {
    const tenantId = this.tenantContextService.getTenantId();
    if (tenantId && this.hasTenantColumn()) {
      return this.repository.findOne({
        where: { id: id as any, tenantId } as any,
      });
    }
    return this.repository.findOne({
      where: { id: id as any } as any,
    });
  }

  /**
   * Count with automatic tenant scoping
   */
  async count(options?: any): Promise<number> {
    const tenantId = this.tenantContextService.getTenantId();
    if (tenantId && this.hasTenantColumn()) {
      return this.repository.count({
        ...options,
        where: {
          ...options?.where,
          tenantId,
        },
      });
    }
    return this.repository.count(options);
  }

  /**
   * Check if the entity has a tenantId column
   */
  private hasTenantColumn(): boolean {
    const columns = this.repository.metadata.columns;
    return columns.some((col) => col.propertyName === 'tenantId');
  }

  /**
   * Get the base repository for operations that don't need tenant scoping
   * Use with caution - only for system-level operations
   */
  getUnscopedRepository(): Repository<T> {
    return this.repository;
  }
}
