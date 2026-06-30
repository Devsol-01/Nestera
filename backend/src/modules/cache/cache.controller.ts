import {
  Controller,
  Get,
  Post,
  Delete,
  UseGuards,
  Param,
  Body,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
} from '@nestjs/swagger';
import { CacheStrategyService } from './cache-strategy.service';
import { CacheWarmingService } from './cache-warming.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { ApiProperty } from '@nestjs/swagger';

class CacheMetricsResponseDto {
  @ApiProperty({ example: 124 })
  hits: number;

  @ApiProperty({ example: 31 })
  misses: number;

  @ApiProperty({ example: 12 })
  sets: number;

  @ApiProperty({ example: 8 })
  deletes: number;

  @ApiProperty({ example: 8, description: 'Total eviction-style deletes observed' })
  evictions: number;

  @ApiProperty({ example: 0.8, description: 'Hit ratio as a decimal' })
  hitRatio: number;

  @ApiProperty({ example: 0.2, description: 'Miss ratio as a decimal' })
  missRatio: number;

  @ApiProperty({ example: '80.00%' })
  hitRate: string;

  @ApiProperty({ example: '20.00%' })
  missRate: string;
}

@ApiTags('Cache')
@Controller('cache')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class CacheController {
  constructor(
    private readonly cacheStrategy: CacheStrategyService,
    private readonly cacheWarming: CacheWarmingService,
  ) {}

  @Get('metrics')
  @ApiOperation({
    summary: 'Get cache hit/miss ratios and per-operation latency (avg/p95/p99)',
  })
  @ApiOkResponse({ type: CacheMetricsResponseDto })
  getMetrics() {
    return this.cacheStrategy.getMetrics();
  }

  @Get('dashboard')
  @ApiOperation({
    summary: 'Get cache dashboard summary including hit ratio, misses, and evictions',
  })
  @ApiOkResponse({ type: CacheMetricsResponseDto })
  getDashboard() {
    return this.cacheStrategy.getMetrics();
  }

  @Delete('metrics')
  @ApiOperation({ summary: 'Reset cache metrics counters and latency buckets' })
  resetMetrics() {
    this.cacheStrategy.resetMetrics();
    return { message: 'Cache metrics reset' };
  }

  @Get('warming-metrics')
  @ApiOperation({ summary: 'Get cache warming metrics' })
  getWarmingMetrics() {
    return this.cacheWarming.getWarmingMetrics();
  }

  @Get('registered-endpoints')
  @ApiOperation({ summary: 'Get registered cacheable endpoints' })
  getRegisteredEndpoints() {
    return this.cacheWarming.getRegisteredEndpoints();
  }

  @Post('warm-all')
  @ApiOperation({ summary: 'Warm all cacheable endpoints manually' })
  async warmAllEndpoints() {
    await this.cacheWarming.warmAllEndpoints();
    return { message: 'Cache warming initiated' };
  }

  @Delete('invalidate/tag/:tag')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: '[Admin] Invalidate all cache entries tagged with the given tag',
    description:
      'Merges both the in-process tag index and the Redis-backed tag set ' +
      'before deleting, so it is safe across restarts and multiple instances. ' +
      'Requires ADMIN role.',
  })
  @ApiUnauthorizedResponse({ description: 'Missing or invalid JWT.' })
  @ApiForbiddenResponse({ description: 'Caller does not have the ADMIN role.' })
  async invalidateByTag(@Param('tag') tag: string) {
    await this.cacheStrategy.invalidateByTag(tag);
    return { message: `Invalidated all keys with tag: ${tag}` };
  }

  @Delete('invalidate/pattern/:pattern')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary:
      '[Admin] Invalidate all tagged cache entries whose key contains the given pattern',
    description: 'Requires ADMIN role.',
  })
  @ApiUnauthorizedResponse({ description: 'Missing or invalid JWT.' })
  @ApiForbiddenResponse({ description: 'Caller does not have the ADMIN role.' })
  async invalidateByPattern(@Param('pattern') pattern: string) {
    await this.cacheStrategy.invalidateByPattern(pattern);
    return { message: `Invalidated all keys matching pattern: ${pattern}` };
  }

  @Post('invalidate/keys')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: '[Admin] Invalidate a specific set of cache keys',
    description:
      'Use this to invalidate exactly the keys affected by a mutation, without ' +
      'needing a tag. Requires ADMIN role.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        keys: { type: 'array', items: { type: 'string' } },
      },
      required: ['keys'],
    },
  })
  @ApiUnauthorizedResponse({ description: 'Missing or invalid JWT.' })
  @ApiForbiddenResponse({ description: 'Caller does not have the ADMIN role.' })
  async invalidateKeys(@Body('keys') keys: string[]) {
    if (!Array.isArray(keys) || keys.length === 0) {
      return { message: 'No keys provided', invalidated: 0 };
    }
    await this.cacheStrategy.invalidateKeys(keys);
    return { message: `Invalidated ${keys.length} key(s)`, invalidated: keys.length };
  }

  /**
   * Admin-only unified invalidation endpoint.
   * Accepts any combination of specific keys, tag names, and key patterns
   * in a single request.  All three fields are optional but at least one
   * must be provided.
   */
  @Post('admin/invalidate')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: '[Admin] Unified cache invalidation — keys, tags, and patterns',
    description:
      'Admin-only endpoint to invalidate any combination of specific cache ' +
      'keys, tag-based sets, and key patterns in a single request. ' +
      'Requires ADMIN role.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        keys:     { type: 'array', items: { type: 'string' }, description: 'Exact cache keys to invalidate' },
        tags:     { type: 'array', items: { type: 'string' }, description: 'Tag names — all keys under each tag are invalidated' },
        patterns: { type: 'array', items: { type: 'string' }, description: 'Substring patterns — all tracked keys containing a pattern are invalidated' },
      },
    },
  })
  @ApiOkResponse({
    schema: {
      type: 'object',
      properties: {
        message:           { type: 'string' },
        invalidatedKeys:   { type: 'number' },
        invalidatedTags:   { type: 'number' },
        invalidatedPatterns: { type: 'number' },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Missing or invalid JWT.' })
  @ApiForbiddenResponse({ description: 'Caller does not have the ADMIN role.' })
  async adminInvalidate(
    @Body('keys')     keys:     string[] | undefined,
    @Body('tags')     tags:     string[] | undefined,
    @Body('patterns') patterns: string[] | undefined,
  ) {
    let invalidatedKeys     = 0;
    let invalidatedTags     = 0;
    let invalidatedPatterns = 0;

    if (Array.isArray(keys) && keys.length > 0) {
      await this.cacheStrategy.invalidateKeys(keys);
      invalidatedKeys = keys.length;
    }

    if (Array.isArray(tags) && tags.length > 0) {
      await Promise.all(tags.map((t) => this.cacheStrategy.invalidateByTag(t)));
      invalidatedTags = tags.length;
    }

    if (Array.isArray(patterns) && patterns.length > 0) {
      await Promise.all(patterns.map((p) => this.cacheStrategy.invalidateByPattern(p)));
      invalidatedPatterns = patterns.length;
    }

    return {
      message: 'Admin cache invalidation complete',
      invalidatedKeys,
      invalidatedTags,
      invalidatedPatterns,
    };
  }
}
