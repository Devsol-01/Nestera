import { Test, TestingModule } from '@nestjs/testing';
import { CacheInvalidationService } from './cache-invalidation.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CacheStrategyService } from '../../modules/cache/cache-strategy.service';
import { AuditLogService } from '../services/audit-log.service';
import { ClsService } from 'nestjs-cls';

describe('CacheInvalidationService', () => {
  let service: CacheInvalidationService;
  let eventEmitter: EventEmitter2;
  let cacheStrategy: CacheStrategyService;
  let auditLogService: AuditLogService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CacheInvalidationService,
        {
          provide: EventEmitter2,
          useValue: {
            on: jest.fn(),
            emit: jest.fn(),
          },
        },
        {
          provide: CacheStrategyService,
          useValue: {
            del: jest.fn(),
            invalidateByTag: jest.fn(),
            cacheManager: {
              stores: {
                keys: jest.fn().mockReturnValue(['user:123', 'product:456']),
              },
            },
          },
        },
        {
          provide: AuditLogService,
          useValue: {
            create: jest.fn().mockResolvedValue(undefined),
          },
        },
        {
          provide: ClsService,
          useValue: {
            getId: jest.fn().mockReturnValue('req-corr-id-123'),
            get: jest.fn().mockReturnValue('user-uuid-456'),
          },
        },
      ],
    }).compile();

    service = module.get<CacheInvalidationService>(CacheInvalidationService);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
    cacheStrategy = module.get<CacheStrategyService>(CacheStrategyService);
    auditLogService = module.get<AuditLogService>(AuditLogService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Event Emission', () => {
    it('should emit cache invalidation event for key with trigger', async () => {
      await service.invalidateKey('test-key', 'UserProfileUpdate');
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'CacheInvalidationEvent',
        expect.objectContaining({
          key: 'test-key',
          triggerEvent: 'UserProfileUpdate',
        }),
      );
    });

    it('should emit cache invalidation event for tag with trigger', async () => {
      await service.invalidateTag('user', 'UserBulkUpdate');
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'CacheInvalidationByTagEvent',
        expect.objectContaining({
          tag: 'user',
          triggerEvent: 'UserBulkUpdate',
        }),
      );
    });

    it('should emit cache invalidation event for pattern with trigger', async () => {
      await service.invalidatePattern('user:*', 'UserCleanupJob');
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'CacheInvalidationByPatternEvent',
        expect.objectContaining({
          pattern: 'user:*',
          triggerEvent: 'UserCleanupJob',
        }),
      );
    });
  });

  describe('Event Handling & Audit Trail', () => {
    it('should handle key invalidation and record an audit log', async () => {
      const mockEvent = { key: 'test-key', triggerEvent: 'UserAction' } as any;

      await (service as any).handleInvalidation(mockEvent);

      expect(cacheStrategy.del).toHaveBeenCalledWith('test-key');
      expect(auditLogService.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'CACHE_INVALIDATION',
          entityId: 'test-key',
          userId: 'user-uuid-456',
          details: expect.objectContaining({
            invalidationType: 'KEY',
            triggerEvent: 'UserAction',
            correlationId: 'req-corr-id-123',
          }),
        }),
      );
    });

    it('should handle tag invalidation and record an audit log', async () => {
      const mockEvent = {
        tag: 'user-tag',
        triggerEvent: 'SystemAction',
      } as any;

      await (service as any).handleInvalidationByTag(mockEvent);

      expect(cacheStrategy.invalidateByTag).toHaveBeenCalledWith('user-tag');
      expect(auditLogService.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'CACHE_INVALIDATION',
          entityId: 'user-tag',
          details: expect.objectContaining({
            invalidationType: 'TAG',
            triggerEvent: 'SystemAction',
          }),
        }),
      );
    });

    it('should handle pattern invalidation and record an audit log', async () => {
      const mockEvent = { pattern: 'user:.*', triggerEvent: 'CronJob' } as any;

      await (service as any).handleInvalidationByPattern(mockEvent);

      expect(cacheStrategy.del).toHaveBeenCalledWith('user:123');
      expect(auditLogService.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'CACHE_INVALIDATION',
          entityId: 'user:.*',
          details: expect.objectContaining({
            invalidationType: 'PATTERN',
            triggerEvent: 'CronJob',
          }),
        }),
      );
    });
  });
});
