import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject } from '@nestjs/common';
import { Cache } from 'cache-manager';
import { FeatureFlag } from './entities/feature-flag.entity';
import { CreateFlagDto } from './dto/create-flag.dto';
import { UpdateFlagDto } from './dto/update-flag.dto';

const FEATURE_FLAG_CACHE_PREFIX = 'feature-flag:';
const FEATURE_FLAG_CACHE_TTL_MS = 60_000;
export interface FeatureEvaluationContext {
  address?: string;
  network?: string;
  segments?: string[];
}

export interface FeatureEvaluationResult {
  value: boolean | string | number;
  reason: string;
}

const FEATURE_FLAG_CACHE_TTL = 60_000; // 1 minute cache TTL

@Injectable()
export class FeatureFlagsService {
  private readonly logger = new Logger(FeatureFlagsService.name);

  constructor(
    @InjectRepository(FeatureFlag)
    private readonly flagRepository: Repository<FeatureFlag>,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async findAll(): Promise<FeatureFlag[]> {
    return this.flagRepository.find({ order: { key: 'ASC' } });
  }

  async findOne(key: string): Promise<FeatureFlag> {
    const cached = await this.cacheManager.get<FeatureFlag>(this.cacheKey(key));
    if (cached) {
      return cached;
    }

    const flag = await this.flagRepository.findOne({ where: { key } });
    if (!flag) throw new NotFoundException(`Feature flag "${key}" not found`);

    await this.cacheManager.set(
      this.cacheKey(key),
      flag,
      FEATURE_FLAG_CACHE_TTL_MS,
    );
    return flag;
  }

  async create(dto: CreateFlagDto): Promise<FeatureFlag> {
    const existing = await this.flagRepository.findOne({
      where: { key: dto.key },
    });
    if (existing) {
      throw new ConflictException(`Feature flag "${dto.key}" already exists`);
    }

    const flag = this.flagRepository.create({
      ...dto,
      enabled: dto.enabled ?? false,
      forceDisabled: dto.forceDisabled ?? false,
    });
    const saved = await this.flagRepository.save(flag);
    await this.invalidateCache(saved.key);
    this.logger.log(`Feature flag created: ${saved.key}`);
    return saved;
  }

  async update(key: string, dto: UpdateFlagDto): Promise<FeatureFlag> {
    const flag = await this.findOne(key);
    Object.assign(flag, dto);
    const saved = await this.flagRepository.save(flag);
    await this.invalidateCache(key);
    this.logger.log(`Feature flag updated: ${key}`, {
      changes: Object.keys(dto),
    });

    await this.invalidateCache(key);

    return saved;
  }

  async toggle(key: string): Promise<FeatureFlag> {
    const flag = await this.findOne(key);
    flag.enabled = !flag.enabled;
    flag.forceDisabled = false;
    const saved = await this.flagRepository.save(flag);
    await this.invalidateCache(key);
    this.logger.log(`Feature flag toggled: ${key} → ${saved.enabled}`);

    await this.invalidateCache(key);

    return saved;
  }

  async remove(key: string): Promise<void> {
    const flag = await this.findOne(key);
    await this.flagRepository.remove(flag);
    await this.invalidateCache(key);
    this.logger.log(`Feature flag deleted: ${key}`);

    await this.invalidateCache(key);
  }

  async isEnabled(
    key: string,
    context: { address?: string; network?: string; segments?: string[] },
  ): Promise<boolean> {
    const result = await this.evaluate(key, context);
    if (typeof result.value === 'boolean') {
      return result.value;
    }
    if (typeof result.value === 'number') {
      return result.value > 0;
    }
    if (typeof result.value === 'string') {
      return result.value.length > 0 && result.value !== 'false';
    }
    return Boolean(result.value);
  }

  /**
   * Evaluate a flag for a given user context.
   * Useful for server-side rendering and API-based evaluation.
   */
  async evaluate(
    key: string,
    context: FeatureEvaluationContext,
  ): Promise<FeatureEvaluationResult> {
    const cacheKey = this.getCacheKey(key, context);
    const cached =
      await this.cacheManager.get<FeatureEvaluationResult>(cacheKey);

    if (cached !== undefined && cached !== null) {
      this.logger.debug(`Cache HIT for feature flag: ${key}`);
      return cached;
    }

    this.logger.debug(`Cache MISS for feature flag: ${key}`);

    const flag = await this.findOne(key);
    const result = this.evaluateFlag(flag, context);

    await this.cacheManager.set(cacheKey, result, FEATURE_FLAG_CACHE_TTL);
    this.logger.debug(
      `Cache SET for feature flag: ${key} ttl=${FEATURE_FLAG_CACHE_TTL}ms`,
    );

    return result;
  }

  private getCacheKey(key: string, context: FeatureEvaluationContext): string {
    const parts = [`flag:${key}`];
    if (context.address) parts.push(`addr:${context.address.slice(0, 10)}`);
    if (context.network) parts.push(`net:${context.network}`);
    if (context.segments?.length)
      parts.push(`seg:${context.segments.sort().join(',')}`);
    return parts.join('|');
  }

  private async invalidateCache(key: string): Promise<void> {
    try {
      const allKeys = await this.findAllKeysForFlag(key);
      for (const cacheKey of allKeys) {
        await this.cacheManager.del(cacheKey);
      }
      this.logger.debug(`Cache invalidated for feature flag: ${key}`);
    } catch (error) {
      this.logger.error(`Cache invalidation error for "${key}":`, error);
    }
  }

  private async findAllKeysForFlag(key: string): Promise<string[]> {
    const keys: string[] = [];
    const featureFlag = await this.findOne(key);

    for (const user of featureFlag.targetUsers || []) {
      keys.push(`flag:${key}|addr:${user.slice(0, 10)}`);
    }
    for (const network of featureFlag.targetNetworks || []) {
      keys.push(`flag:${key}|net:${network}`);
    }
    for (const segment of featureFlag.targetSegments || []) {
      keys.push(`flag:${key}|seg:${segment}`);
    }

    return keys;
  }

  private evaluateFlag(
    flag: FeatureFlag,
    context: FeatureEvaluationContext,
  ): FeatureEvaluationResult {
    if (flag.forceDisabled) {
      return { value: false, reason: 'force_disabled' };
    }

    if (flag.targetUsers?.length && context.address) {
      const truncated = context.address.slice(0, 10).toLowerCase();
      const isTargeted = flag.targetUsers.some((addr) =>
        addr.toLowerCase().startsWith(truncated),
      );
      if (isTargeted) {
        return {
          value:
            flag.type === 'boolean'
              ? flag.enabled
              : (flag.value ?? flag.defaultValue),
          reason: 'user_targeted',
        };
      }
    }

    if (flag.targetNetworks?.length && context.network) {
      if (!flag.targetNetworks.includes(context.network)) {
        return { value: flag.defaultValue, reason: 'network_not_targeted' };
      }
    }

    if (flag.targetSegments?.length && context.segments?.length) {
      const hasSegment = flag.targetSegments.some((seg) =>
        context.segments?.includes(seg),
      );
      if (hasSegment) {
        return {
          value:
            flag.type === 'boolean'
              ? flag.enabled
              : (flag.value ?? flag.defaultValue),
          reason: 'segment_matched',
        };
      }
    }

    if (flag.type === 'rollout' && flag.rolloutPercentage !== undefined) {
      const userId = context.address || 'anonymous';
      const bucket = this.hashBucket(`${flag.key}:${userId}`);
      const inRollout = bucket < flag.rolloutPercentage;
      return {
        value: inRollout,
        reason: `rollout_${inRollout ? 'included' : 'excluded'}_${bucket}`,
      };
    }

    return {
      value:
        flag.type === 'boolean'
          ? flag.enabled
          : (flag.value ?? flag.defaultValue),
      reason: 'default',
    };
  }

  private hashBucket(input: string): number {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash) % 100;
  }

  private cacheKey(key: string): string {
    return `${FEATURE_FLAG_CACHE_PREFIX}${key}`;
  }

  private async invalidateCache(key: string): Promise<void> {
    await this.cacheManager.del(this.cacheKey(key));
  }
}
