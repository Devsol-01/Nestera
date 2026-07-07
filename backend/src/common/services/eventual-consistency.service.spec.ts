import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EventualConsistencyService } from './eventual-consistency.service';

describe('EventualConsistencyService', () => {
  let service: EventualConsistencyService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EventualConsistencyService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              if (key === 'eventualConsistency.defaultRetryAfterSeconds') {
                return 30;
              }
              if (key === 'stellar.eventPollInterval') {
                return 10000;
              }
              return defaultValue;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<EventualConsistencyService>(EventualConsistencyService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('calculateRetryAfter', () => {
    it('should calculate retry-after based on indexer poll interval', () => {
      const result = service.calculateRetryAfter();
      expect(result).toBe(30); // 10s poll interval * 3 multiplier
    });

    it('should apply custom multiplier', () => {
      const result = service.calculateRetryAfter(5);
      expect(result).toBe(50); // 10s poll interval * 5 multiplier
    });

    it('should return integer value', () => {
      const result = service.calculateRetryAfter(2.5);
      expect(Number.isInteger(result)).toBe(true);
    });
  });

  describe('getDefaultRetryAfter', () => {
    it('should return default retry-after seconds', () => {
      const result = service.getDefaultRetryAfter();
      expect(result).toBe(30);
    });
  });

  describe('isLikelyPendingIndexing', () => {
    it('should return true for recently created resources', () => {
      const recentDate = new Date(Date.now() - 1000); // 1 second ago
      const result = service.isLikelyPendingIndexing(recentDate);
      expect(result).toBe(true);
    });

    it('should return false for old resources', () => {
      const oldDate = new Date(Date.now() - 120000); // 2 minutes ago
      const result = service.isLikelyPendingIndexing(oldDate);
      expect(result).toBe(false);
    });

    it('should use custom max age threshold', () => {
      const recentDate = new Date(Date.now() - 30000); // 30 seconds ago
      const result = service.isLikelyPendingIndexing(recentDate, 60);
      expect(result).toBe(true);
    });
  });

  describe('getRetryAfterForRecentCreation', () => {
    it('should calculate retry-after for recent creation', () => {
      const recentDate = new Date(Date.now() - 1000); // 1 second ago
      const result = service.getRetryAfterForRecentCreation(recentDate);
      expect(result).toBeGreaterThan(0);
      expect(result).toBeLessThanOrEqual(70); // 60s window + 10s poll interval
    });

    it('should return minimum poll interval for old resources', () => {
      const oldDate = new Date(Date.now() - 120000); // 2 minutes ago
      const result = service.getRetryAfterForRecentCreation(oldDate);
      expect(result).toBe(10); // Just the poll interval
    });

    it('should return integer value', () => {
      const recentDate = new Date(Date.now() - 5000); // 5 seconds ago
      const result = service.getRetryAfterForRecentCreation(recentDate);
      expect(Number.isInteger(result)).toBe(true);
    });
  });
});
