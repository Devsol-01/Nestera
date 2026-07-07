import { IsEnum, IsOptional, IsDateString, IsBoolean, IsObject } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  AggregationType,
  AggregationPeriod,
  AggregationJobStatus,
  BackfillStatus,
} from '../entities/analytics-aggregation-job.entity';

export class CreateAggregationJobDto {
  @ApiProperty({
    enum: AggregationType,
    example: AggregationType.DAILY_TRANSACTIONS,
    description: 'Type of aggregation to perform',
  })
  @IsEnum(AggregationType)
  aggregationType: AggregationType;

  @ApiProperty({
    enum: AggregationPeriod,
    example: AggregationPeriod.DAILY,
    description: 'Time period for aggregation',
  })
  @IsEnum(AggregationPeriod)
  period: AggregationPeriod;

  @ApiPropertyOptional({
    description: 'Start date for aggregation (ISO string)',
    example: '2026-06-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'End date for aggregation (ISO string)',
    example: '2026-06-30T23:59:59.999Z',
  })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({
    description: 'Whether this is a backfill operation',
    default: false,
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  isBackfill?: boolean;

  @ApiPropertyOptional({
    description: 'Backfill start date (ISO string)',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  backfillStartDate?: string;

  @ApiPropertyOptional({
    description: 'Backfill end date (ISO string)',
    example: '2026-06-30T23:59:59.999Z',
  })
  @IsOptional()
  @IsDateString()
  backfillEndDate?: string;

  @ApiPropertyOptional({
    description: 'Additional metadata for the job',
    example: { source: 'api', triggeredBy: 'user-123' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class BackfillAggregationJobDto {
  @ApiProperty({
    enum: AggregationType,
    example: AggregationType.DAILY_TRANSACTIONS,
    description: 'Type of aggregation to backfill',
  })
  @IsEnum(AggregationType)
  aggregationType: AggregationType;

  @ApiProperty({
    enum: AggregationPeriod,
    example: AggregationPeriod.DAILY,
    description: 'Time period for aggregation',
  })
  @IsEnum(AggregationPeriod)
  period: AggregationPeriod;

  @ApiProperty({
    description: 'Backfill start date (ISO string)',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsDateString()
  backfillStartDate: string;

  @ApiProperty({
    description: 'Backfill end date (ISO string)',
    example: '2026-06-30T23:59:59.999Z',
  })
  @IsDateString()
  backfillEndDate: string;

  @ApiPropertyOptional({
    description: 'Additional metadata for the backfill',
    example: { source: 'backfill-script', triggeredBy: 'system' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class AggregationJobResponseDto {
  @ApiProperty({ example: 'agg_550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ enum: AggregationType, example: AggregationType.DAILY_TRANSACTIONS })
  aggregationType: AggregationType;

  @ApiProperty({ enum: AggregationPeriod, example: AggregationPeriod.DAILY })
  period: AggregationPeriod;

  @ApiProperty({ enum: AggregationJobStatus, example: AggregationJobStatus.COMPLETED })
  status: AggregationJobStatus;

  @ApiPropertyOptional({ example: '2026-06-01T00:00:00.000Z' })
  startDate?: Date;

  @ApiPropertyOptional({ example: '2026-06-30T23:59:59.999Z' })
  endDate?: Date;

  @ApiProperty({ example: false })
  isBackfill: boolean;

  @ApiPropertyOptional({ enum: BackfillStatus, example: BackfillStatus.NOT_STARTED })
  backfillStatus?: BackfillStatus;

  @ApiPropertyOptional({ example: '2026-01-01T00:00:00.000Z' })
  backfillStartDate?: Date;

  @ApiPropertyOptional({ example: '2026-06-30T23:59:59.999Z' })
  backfillEndDate?: Date;

  @ApiPropertyOptional({ example: 180 })
  totalBackfillPeriods?: number;

  @ApiPropertyOptional({ example: 90 })
  processedBackfillPeriods?: number;

  @ApiPropertyOptional({ example: { '2026-01': 'completed', '2026-02': 'completed' } })
  backfillProgress?: Record<string, unknown>;

  @ApiPropertyOptional({ example: 'Failed to process period 2026-03' })
  errorMessage?: string;

  @ApiPropertyOptional({ example: { source: 'api', triggeredBy: 'admin' } })
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional({ example: { totalRecords: 50000, avgValue: 250 } })
  result?: Record<string, unknown>;

  @ApiPropertyOptional({ example: '2026-06-29T10:00:00.000Z' })
  startedAt?: Date;

  @ApiPropertyOptional({ example: '2026-06-29T10:05:00.000Z' })
  completedAt?: Date;

  @ApiPropertyOptional({ example: 50000 })
  recordsProcessed?: number;

  @ApiPropertyOptional({ example: 0 })
  recordsFailed?: number;

  @ApiProperty({ example: 0 })
  retryCount: number;

  @ApiProperty({ example: '2026-06-29T10:00:00.000Z' })
  createdAt: Date;

  @ApiProperty({ example: '2026-06-29T10:05:00.000Z' })
  updatedAt: Date;
}

export class AggregationJobListQueryDto {
  @ApiPropertyOptional({ enum: AggregationType, example: AggregationType.DAILY_TRANSACTIONS })
  @IsOptional()
  @IsEnum(AggregationType)
  aggregationType?: AggregationType;

  @ApiPropertyOptional({ enum: AggregationJobStatus, example: AggregationJobStatus.COMPLETED })
  @IsOptional()
  @IsEnum(AggregationJobStatus)
  status?: AggregationJobStatus;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  isBackfill?: boolean;

  @ApiPropertyOptional({ default: 1, example: 1 })
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 20, example: 20 })
  @IsOptional()
  limit?: number;
}
