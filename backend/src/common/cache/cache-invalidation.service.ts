import { Injectable, Logger, Inject, Optional } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CacheStrategyService } from '../../modules/cache/cache-strategy.service';
import {
  CacheInvalidationEvent,
  CacheInvalidationByTagEvent,
  CacheInvalidationByPatternEvent,
} from './cache-invalidation.events';
import { AuditLogService } from '../services/audit-log.service';
import { ClsService } from 'nestjs-cls';

@Injectable()
export class CacheInvalidationService {
  private readonly logger = new Logger(CacheInvalidationService.name);

  constructor(
    private readonly eventEmitter: EventEmitter2,
    @Optional()
    @Inject(CacheStrategyService)
    private readonly cacheStrategy?: CacheStrategyService,
    @Optional()
    private readonly auditLogService?: AuditLogService,
    @Optional()
    private readonly clsService?: ClsService,
  ) {
    this.setupEventListeners();
  }

  private setupEventListeners() {
    this.eventEmitter.on(
      CacheInvalidationEvent.name,
      async (event: CacheInvalidationEvent) => {
        await this.handleInvalidation(event);
      },
    );

    this.eventEmitter.on(
      CacheInvalidationByTagEvent.name,
      async (event: CacheInvalidationByTagEvent) => {
        await this.handleInvalidationByTag(event);
      },
    );

    this.eventEmitter.on(
      CacheInvalidationByPatternEvent.name,
      async (event: CacheInvalidationByPatternEvent) => {
        await this.handleInvalidationByPattern(event);
      },
    );
  }

  async invalidateKey(key: string, triggerEvent: string = 'Manual Request') {
    this.eventEmitter.emit(
      CacheInvalidationEvent.name,
      new CacheInvalidationEvent(key, undefined, undefined, triggerEvent),
    );
  }

  async invalidateTag(tag: string, triggerEvent: string = 'Manual Request') {
    this.eventEmitter.emit(
      CacheInvalidationByTagEvent.name,
      new CacheInvalidationByTagEvent(tag, triggerEvent),
    );
  }

  async invalidatePattern(
    pattern: string,
    triggerEvent: string = 'Manual Request',
  ) {
    this.eventEmitter.emit(
      CacheInvalidationByPatternEvent.name,
      new CacheInvalidationByPatternEvent(pattern, triggerEvent),
    );
  }

  private async handleInvalidation(event: CacheInvalidationEvent) {
    try {
      if (!this.cacheStrategy) {
        this.logger.warn('CacheStrategy not available, skipping invalidation');
        return;
      }
      await this.cacheStrategy.del(event.key);
      this.logger.debug(`Cache invalidated: ${event.key}`);

      await this.recordAudit(event.key, 'KEY', (event as any).triggerEvent);
    } catch (error) {
      this.logger.error(`Failed to invalidate cache key ${event.key}:`, error);
    }
  }

  private async handleInvalidationByTag(event: CacheInvalidationByTagEvent) {
    try {
      if (!this.cacheStrategy) {
        this.logger.warn('CacheStrategy not available, skipping invalidation');
        return;
      }
      await this.cacheStrategy.invalidateByTag(event.tag);
      this.logger.debug(`Cache invalidated by tag: ${event.tag}`);

      await this.recordAudit(event.tag, 'TAG', (event as any).triggerEvent);
    } catch (error) {
      this.logger.error(
        `Failed to invalidate cache by tag ${event.tag}:`,
        error,
      );
    }
  }

  private async handleInvalidationByPattern(
    event: CacheInvalidationByPatternEvent,
  ) {
    try {
      if (!this.cacheStrategy) {
        this.logger.warn('CacheStrategy not available, skipping invalidation');
        return;
      }
      const keys = Array.from(
        (this.cacheStrategy as any).cacheManager.stores.keys(),
      );
      const keysToDelete = keys.filter((k: unknown) =>
        String(k).match(new RegExp(event.pattern)),
      );

      for (const key of keysToDelete) {
        await this.cacheStrategy.del(String(key));
      }

      this.logger.debug(
        `Cache invalidated by pattern ${event.pattern}: ${keysToDelete.length} keys`,
      );

      await this.recordAudit(
        event.pattern,
        'PATTERN',
        (event as any).triggerEvent,
      );
    } catch (error) {
      this.logger.error(
        `Failed to invalidate cache by pattern ${event.pattern}:`,
        error,
      );
    }
  }

  private async recordAudit(
    target: string,
    type: 'KEY' | 'TAG' | 'PATTERN',
    triggerEvent?: string,
  ) {
    if (!this.auditLogService) return;

    const correlationId = this.clsService?.getId() || 'N/A';
    const userId = this.clsService?.get('userId') || 'system';

    try {
      await this.auditLogService.create({
        action: 'CACHE_INVALIDATION',
        entity: 'Cache',
        entityId: target,
        userId: userId,
        details: {
          invalidationType: type,
          target,
          triggerEvent: triggerEvent || 'Unknown Trigger',
          correlationId,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      this.logger.error(
        `Failed to record audit for cache invalidation: ${target}`,
        error,
      );
    }
  }
}
