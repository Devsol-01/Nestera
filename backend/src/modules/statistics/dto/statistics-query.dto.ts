import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsOptional,
  IsDateString,
  IsString,
  IsNumber,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';

export enum TimeRange {
  LAST_7_DAYS = '7d',
  LAST_30_DAYS = '30d',
  LAST_90_DAYS = '90d',
  LAST_365_DAYS = '365d',
  CUSTOM = 'custom',
}

export enum MetricPeriod {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  YEARLY = 'yearly',
}

export enum ComparisonPeriod {
  PREVIOUS_PERIOD = 'previous_period',
  SAME_PERIOD_LAST_YEAR = 'same_period_last_year',
  SAME_PERIOD_LAST_MONTH = 'same_period_last_month',
}

export class StatisticsQueryDto {
  @ApiPropertyOptional({
    enum: TimeRange,
    default: TimeRange.LAST_30_DAYS,
    example: TimeRange.LAST_30_DAYS,
    description: 'Time range for statistics',
  })
  @IsEnum(TimeRange)
  @IsOptional()
  range: TimeRange = TimeRange.LAST_30_DAYS;

  @ApiPropertyOptional({
    type: String,
    format: 'date',
    example: '2026-06-01',
    description: 'Start date for custom range (YYYY-MM-DD)',
  })
  @IsDateString()
  @IsOptional()
  fromDate?: string;

  @ApiPropertyOptional({
    type: String,
    format: 'date',
    example: '2026-06-30',
    description: 'End date for custom range (YYYY-MM-DD)',
  })
  @IsDateString()
  @IsOptional()
  toDate?: string;

  @ApiPropertyOptional({
    enum: MetricPeriod,
    default: MetricPeriod.DAILY,
    example: MetricPeriod.DAILY,
    description: 'Granularity of metrics',
  })
  @IsEnum(MetricPeriod)
  @IsOptional()
  period: MetricPeriod = MetricPeriod.DAILY;

  @ApiPropertyOptional({
    enum: ComparisonPeriod,
    example: ComparisonPeriod.PREVIOUS_PERIOD,
    description: 'Compare with a previous period',
  })
  @IsEnum(ComparisonPeriod)
  @IsOptional()
  compareWith?: ComparisonPeriod;

  @ApiPropertyOptional({
    type: String,
    example: 'savings',
    description: 'Filter by specific category/segment',
  })
  @IsString()
  @IsOptional()
  filter?: string;

  @ApiPropertyOptional({
    type: Number,
    default: 1,
    example: 1,
    description: 'Page number for pagination',
  })
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @IsOptional()
  page: number = 1;

  @ApiPropertyOptional({
    type: Number,
    default: 50,
    example: 50,
    description: 'Items per page',
  })
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(500)
  @IsOptional()
  limit: number = 50;
}
