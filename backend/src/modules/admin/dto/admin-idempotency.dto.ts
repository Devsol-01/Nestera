import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

// ─────────────────────────────────────────────────────────
// Query DTOs
// ─────────────────────────────────────────────────────────

export class IdempotencyConflictQueryDto {
  @ApiPropertyOptional({
    description: 'Maximum number of results to return',
    default: 50,
    minimum: 1,
    maximum: 200,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 50;

  @ApiPropertyOptional({
    description: 'Filter by conflict type',
    enum: ['payload_mismatch', 'concurrent_processing'],
  })
  @IsOptional()
  @IsEnum(['payload_mismatch', 'concurrent_processing'])
  conflictType?: 'payload_mismatch' | 'concurrent_processing';

  @ApiPropertyOptional({
    description: 'Filter by route path (partial match)',
  })
  @IsOptional()
  @IsString()
  path?: string;
}

export class IdempotencyUsageQueryDto {
  @ApiPropertyOptional({
    description: 'Maximum number of results to return',
    default: 50,
    minimum: 1,
    maximum: 200,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 50;

  @ApiPropertyOptional({
    description: 'Filter by route path (partial match)',
  })
  @IsOptional()
  @IsString()
  path?: string;
}

// ─────────────────────────────────────────────────────────
// Response DTOs
// ─────────────────────────────────────────────────────────

export class IdempotencyConflictDto {
  @ApiProperty({
    description: 'The idempotency key submitted by the client',
    example: 'req-abc-123',
  })
  idempotencyKey: string;

  @ApiProperty({
    description:
      'SHA-256 fingerprint of the incoming request body — no sensitive payload data',
    example: 'e3b0c44298fc1c149afbf4c8996fb924...',
  })
  requestFingerprintHash: string;

  @ApiProperty({ example: 'POST' })
  method: string;

  @ApiProperty({ example: '/savings/deposit' })
  path: string;

  @ApiProperty({
    enum: ['payload_mismatch', 'concurrent_processing'],
    description:
      'payload_mismatch: same key, different body hash. ' +
      'concurrent_processing: same key already in-flight.',
  })
  conflictType: 'payload_mismatch' | 'concurrent_processing';

  @ApiProperty({
    description: 'ISO 8601 timestamp of the conflict',
    example: '2026-06-30T02:00:00.000Z',
  })
  timestamp: string;

  @ApiPropertyOptional({
    description: 'Related entity type inferred from the route, if determinable',
    example: 'savings',
  })
  relatedEntityType?: string;
}

export class IdempotencyConflictSummaryDto {
  @ApiProperty({ description: 'Total conflicts in the in-memory buffer' })
  total: number;

  @ApiProperty({ description: 'Conflicts in the last 24 hours' })
  last24h: number;

  @ApiProperty({ description: 'Conflicts in the last hour' })
  last1h: number;

  @ApiProperty({
    description: 'Breakdown by conflict type',
    example: { payload_mismatch: 12, concurrent_processing: 3 },
  })
  byConflictType: Record<string, number>;

  @ApiProperty({
    description: 'Breakdown by route (method + path)',
    example: { 'POST /savings/deposit': 7 },
  })
  byRoute: Record<string, number>;

  @ApiProperty({
    description: 'Top 10 most conflicting idempotency keys in the last 24 h',
    type: 'array',
    items: {
      type: 'object',
      properties: {
        idempotencyKey: { type: 'string' },
        count: { type: 'number' },
      },
    },
  })
  topConflictingKeys: { idempotencyKey: string; count: number }[];
}

export class IdempotencyUsageRecordDto {
  @ApiProperty({ description: 'The idempotency key submitted by the client' })
  idempotencyKey: string;

  @ApiProperty({ example: 'POST' })
  method: string;

  @ApiProperty({ example: '/savings/deposit' })
  path: string;

  @ApiProperty({ description: 'ISO 8601 timestamp of first use' })
  firstSeenAt: string;

  @ApiProperty({ description: 'ISO 8601 timestamp of last use or replay' })
  lastSeenAt: string;

  @ApiProperty({ description: 'Number of cache-hit replays for this key' })
  replayCount: number;
}
