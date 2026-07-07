import { IsOptional, IsDateString, IsNumber, IsEnum, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export enum DateRange {
  LAST_7_DAYS = '7d',
  LAST_30_DAYS = '30d',
  LAST_90_DAYS = '90d',
  LAST_365_DAYS = '365d',
  CUSTOM = 'custom',
}

export enum ComparisonPeriod {
  PREVIOUS_PERIOD = 'previous_period',
  SAME_PERIOD_LAST_YEAR = 'same_period_last_year',
}

export class DateRangeFilterDto {
  @ApiPropertyOptional({ enum: DateRange, example: '30d' })
  @IsOptional()
  @IsEnum(DateRange)
  range?: DateRange;

  @ApiPropertyOptional({ example: '2024-01-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiPropertyOptional({ example: '2024-01-31T23:59:59.999Z' })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiPropertyOptional({ enum: ComparisonPeriod, example: 'previous_period' })
  @IsOptional()
  @IsEnum(ComparisonPeriod)
  compareTo?: ComparisonPeriod;
}

export class UserAnalyticsFilterDto extends DateRangeFilterDto {
  @ApiPropertyOptional({ description: 'Page number', example: 1 })
  @IsOptional()
  @IsNumber()
  page?: number;

  @ApiPropertyOptional({ description: 'Items per page', example: 20 })
  @IsOptional()
  @IsNumber()
  limit?: number;
}

export class TransactionAnalyticsFilterDto extends DateRangeFilterDto {
  @ApiPropertyOptional({ description: 'Minimum transaction amount', example: 100 })
  @IsOptional()
  @IsNumber()
  minAmount?: number;

  @ApiPropertyOptional({ description: 'Maximum transaction amount', example: 10000 })
  @IsOptional()
  @IsNumber()
  maxAmount?: number;

  @ApiPropertyOptional({ description: 'Transaction type filter', example: 'deposit' })
  @IsOptional()
  @IsString()
  transactionType?: string;
}
