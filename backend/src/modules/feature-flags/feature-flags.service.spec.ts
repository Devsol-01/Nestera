import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { NotFoundException } from '@nestjs/common';
import { FeatureFlagsService } from './feature-flags.service';
import { FeatureFlag } from './entities/feature-flag.entity';

describe('FeatureFlagsService', () => {
  let service: FeatureFlagsService;

  const mockFlagRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    remove: jest.fn(),
  };

  const mockCacheManager = {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  };

  const enabledFlag: FeatureFlag = {
    id: 'flag-1',
    key: 'new-dashboard',
    name: 'New Dashboard',
    description: 'Rollout dashboard',
    defaultValue: false,
    type: 'boolean',
    enabled: true,
    forceDisabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
import { Cache } from 'cache-manager';
import { FeatureFlagsService } from './feature-flags.service';
import { FeatureFlag } from './entities/feature-flag.entity';
import { CreateFlagDto } from './dto/create-flag.dto';
import { UpdateFlagDto } from './dto/update-flag.dto';

describe('FeatureFlagsService', () => {
  let service: FeatureFlagsService;
  let mockCache: jest.Mocked<Cache>;
  let mockRepository: any;

  beforeEach(async () => {
    mockCache = {
      get: jest.fn(),
      set: jest.fn(),
      del: jest.fn(),
    } as any;

    mockRepository = {
      find: jest.fn(),
      findOne: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      remove: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FeatureFlagsService,
        {
          provide: getRepositoryToken(FeatureFlag),
          useValue: mockFlagRepository,
        },
        {
          provide: CACHE_MANAGER,
          useValue: mockCacheManager,
          useValue: mockRepository,
        },
        {
          provide: CACHE_MANAGER,
          useValue: mockCache,
        },
      ],
    }).compile();

    service = module.get<FeatureFlagsService>(FeatureFlagsService);
  });

  describe('findOne', () => {
    it('returns cached flag when present', async () => {
      mockCacheManager.get.mockResolvedValue(enabledFlag);

      const result = await service.findOne('new-dashboard');

      expect(result).toEqual(enabledFlag);
      expect(mockFlagRepository.findOne).not.toHaveBeenCalled();
    });

    it('loads from database and caches on miss', async () => {
      mockCacheManager.get.mockResolvedValue(undefined);
      mockFlagRepository.findOne.mockResolvedValue(enabledFlag);

      const result = await service.findOne('new-dashboard');

      expect(result).toEqual(enabledFlag);
      expect(mockCacheManager.set).toHaveBeenCalledWith(
        'feature-flag:new-dashboard',
        enabledFlag,
        60_000,
      );
    });

    it('throws when flag is missing', async () => {
      mockCacheManager.get.mockResolvedValue(undefined);
      mockFlagRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne('missing')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('evaluate', () => {
    it('returns false when force disabled', async () => {
      mockCacheManager.get.mockResolvedValue({
        ...enabledFlag,
        forceDisabled: true,
      });

      const result = await service.evaluate('new-dashboard', {
        address: 'user-1',
      });

      expect(result).toEqual({ value: false, reason: 'force_disabled' });
    });

    it('returns enabled value for default boolean flag', async () => {
      mockCacheManager.get.mockResolvedValue(enabledFlag);

      const result = await service.evaluate('new-dashboard', {
        address: 'user-1',
      });

      expect(result).toEqual({ value: true, reason: 'default' });
    });

    it('matches segment targeting', async () => {
      mockCacheManager.get.mockResolvedValue({
        ...enabledFlag,
        enabled: false,
        targetSegments: ['ADMIN'],
      });

      const result = await service.evaluate('new-dashboard', {
        address: 'user-1',
        segments: ['ADMIN'],
      });

      expect(result.reason).toBe('segment_matched');
      expect(result.value).toBe(false);
    });
  });

  describe('isEnabled', () => {
    it('returns true for enabled boolean flag', async () => {
      mockCacheManager.get.mockResolvedValue(enabledFlag);

      await expect(
        service.isEnabled('new-dashboard', { address: 'user-1' }),
      ).resolves.toBe(true);
    });

    it('returns false for disabled boolean flag', async () => {
      mockCacheManager.get.mockResolvedValue({
        ...enabledFlag,
        enabled: false,
      });

      await expect(
        service.isEnabled('new-dashboard', { address: 'user-1' }),
      ).resolves.toBe(false);
    });
  });
});
  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('caching', () => {
    it('should return cached value when available', async () => {
      const cachedResult = { value: true, reason: 'default' };
      mockCache.get.mockResolvedValue(cachedResult);

      const result = await service.evaluate('test-flag', { address: 'G123' });

      expect(mockCache.get).toHaveBeenCalled();
      expect(result).toEqual(cachedResult);
    });

    it('should fetch from repository and cache when no cached value', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: true,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: [],
        targetNetworks: [],
        targetSegments: [],
      } as unknown as FeatureFlag;

      mockCache.get.mockResolvedValue(null);
      mockRepository.findOne.mockResolvedValue(flag);

      const result = await service.evaluate('test-flag', {});

      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { key: 'test-flag' },
      });
      expect(mockCache.set).toHaveBeenCalled();
      expect(result.value).toBe(true);
    });
  });

  describe('cache invalidation', () => {
    it('should invalidate cache on update', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: true,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: ['G1234567890', 'GABCDEFGHIJ'],
        targetNetworks: ['testnet'],
        targetSegments: ['beta-users'],
      } as unknown as FeatureFlag;

      mockRepository.findOne.mockResolvedValue(flag);
      mockRepository.save.mockResolvedValue(flag);

      await service.update('test-flag', { enabled: false });

      expect(mockCache.del).toHaveBeenCalledTimes(4);
    });

    it('should invalidate cache on toggle', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: false,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: ['G1234567890'],
        targetNetworks: [],
        targetSegments: [],
      } as unknown as FeatureFlag;

      mockRepository.findOne.mockResolvedValue(flag);
      mockRepository.save.mockResolvedValue({ ...flag, enabled: true });

      await service.toggle('test-flag');

      expect(mockCache.del).toHaveBeenCalledWith(
        'flag:test-flag|addr:G123456789',
      );
    });

    it('should invalidate cache on remove', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: false,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: ['G1234567890'],
        targetNetworks: [],
        targetSegments: [],
      } as unknown as FeatureFlag;

      mockRepository.findOne.mockResolvedValue(flag);
      mockRepository.remove.mockResolvedValue(undefined);

      await service.remove('test-flag');

      expect(mockCache.del).toHaveBeenCalledWith(
        'flag:test-flag|addr:G123456789',
      );
    });
  });

  describe('evaluate', () => {
    it('should return false when flag is force disabled', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: true,
        forceDisabled: true,
        defaultValue: false,
        targetUsers: [],
        targetNetworks: [],
        targetSegments: [],
      } as unknown as FeatureFlag;

      mockCache.get.mockResolvedValue(null);
      mockRepository.findOne.mockResolvedValue(flag);

      const result = await service.evaluate('test-flag', {});

      expect(result).toEqual({ value: false, reason: 'force_disabled' });
    });

    it('should apply user targeting when address matches', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: true,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: ['G1234567890'],
        targetNetworks: [],
        targetSegments: [],
      } as unknown as FeatureFlag;

      mockCache.get.mockResolvedValue(null);
      mockRepository.findOne.mockResolvedValue(flag);

      const result = await service.evaluate('test-flag', {
        address: 'G1234567890',
      });

      expect(result.value).toBe(true);
      expect(result.reason).toBe('user_targeted');
    });

    it('should apply segment targeting when segment matches', async () => {
      const flag = {
        id: '1',
        key: 'test-flag',
        name: 'Test Flag',
        description: 'Test',
        type: 'boolean',
        enabled: true,
        forceDisabled: false,
        defaultValue: false,
        targetUsers: [],
        targetNetworks: [],
        targetSegments: ['beta-users'],
      } as unknown as FeatureFlag;

      mockCache.get.mockResolvedValue(null);
      mockRepository.findOne.mockResolvedValue(flag);

      const result = await service.evaluate('test-flag', {
        segments: ['beta-users'],
      });

      expect(result.value).toBe(true);
      expect(result.reason).toBe('segment_matched');
    });
  });
});
