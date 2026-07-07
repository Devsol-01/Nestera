import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsOptional } from 'class-validator';

export enum MetricsGranularity {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
}

export class ProductMetricsQueryDto {
  @ApiPropertyOptional({
    enum: MetricsGranularity,
    default: MetricsGranularity.DAILY,
    description: 'Granularity of historical chart data',
  })
  @IsEnum(MetricsGranularity)
  @IsOptional()
  granularity?: MetricsGranularity = MetricsGranularity.DAILY;
}

export class ApyDataPointDto {
  @ApiProperty({ example: '2026-03-01', description: 'Date of the data point' })
  date: string;

  @ApiProperty({ example: 4.5, description: 'APY at this point (%)' })
  apy: number;
}

export class TvlDataPointDto {
  @ApiProperty({ example: '2026-03-01', description: 'Date of the data point' })
  date: string;

  @ApiProperty({ example: 125000, description: 'TVL at this point' })
  tvl: number;
}

export class RiskMetricsDto {
  @ApiProperty({
    example: 1.42,
    description: 'Sharpe ratio (risk-adjusted return)',
  })
  sharpeRatio: number;

  @ApiProperty({
    example: 0.85,
    description: 'Standard deviation of APY over the period (%)',
  })
  apyVolatility: number;

  @ApiProperty({ example: 4.5, description: 'Maximum APY observed (%)' })
  maxApy: number;

  @ApiProperty({ example: 3.8, description: 'Minimum APY observed (%)' })
  minApy: number;

  @ApiProperty({ example: 4.2, description: 'Average APY over the period (%)' })
  avgApy: number;
}

export class SimilarProductDto {
  @ApiProperty({ description: 'Product UUID', example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' })
  id: string;

  @ApiProperty({ description: 'Product name', example: 'Flexible Saver' })
  name: string;

  @ApiProperty({ description: 'Current APY (%)', example: 6.0 })
  apy: number;

  @ApiProperty({ description: 'Current TVL', example: 1250000 })
  tvl: number;

  @ApiProperty({ description: 'Risk level', example: 'low' })
  riskLevel: string;
}

export class ProductMetricsDto {
  @ApiProperty({ description: 'Product UUID', example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' })
  productId: string;

  @ApiProperty({ description: 'Product name', example: 'Flexible Saver' })
  productName: string;

  @ApiProperty({ description: 'Current APY (%)', example: 6.0 })
  currentApy: number;

  @ApiProperty({ description: 'Current TVL', example: 1250000 })
  currentTvl: number;

  @ApiProperty({ description: 'Total active subscribers', example: 250 })
  totalSubscribers: number;

  @ApiProperty({
    description: 'User retention rate (active / total ever subscribed, 0-100)',
    example: 78.5,
  })
  retentionRate: number;

  @ApiProperty({
    type: [ApyDataPointDto],
    description: 'Historical APY chart data',
  })
  apyHistory: ApyDataPointDto[];

  @ApiProperty({
    type: [TvlDataPointDto],
    description: 'TVL growth over time',
  })
  tvlHistory: TvlDataPointDto[];

  @ApiProperty({ type: RiskMetricsDto, description: 'Risk-adjusted metrics' })
  riskMetrics: RiskMetricsDto;

  @ApiProperty({
    type: [SimilarProductDto],
    description: 'Similar products for comparison',
  })
  similarProducts: SimilarProductDto[];

  @ApiPropertyOptional({
    description: 'ISO timestamp when this response was cached',
    example: '2026-03-29T14:00:00.000Z',
  })
  cachedAt?: string;
}
