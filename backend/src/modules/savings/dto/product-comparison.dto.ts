import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SavingsProductType } from '../entities/savings-product.entity';

export class HistoricalPerformanceDto {
  @ApiProperty({ example: 2023, description: 'Year of the performance record' })
  year: number;

  @ApiProperty({
    example: 10.5,
    description: 'Annual return percentage for that year',
  })
  return: number;
}

export class ProductComparisonItemDto {
  @ApiProperty({ description: 'Product UUID' })
  id: string;

  @ApiProperty({ description: 'Product name' })
  name: string;

  @ApiProperty({ enum: SavingsProductType, description: 'Product type' })
  type: SavingsProductType;

  @ApiPropertyOptional({ description: 'Product description' })
  description: string | null;

  @ApiProperty({ description: 'Annual Percentage Yield (%)' })
  apy: number;

  @ApiPropertyOptional({ description: 'Tenure in months (null for flexible)' })
  tenure: number | null;

  @ApiProperty({
    description: 'Risk level derived from product type',
    enum: ['low', 'medium', 'high'],
  })
  riskLevel: 'low' | 'medium' | 'high';

  @ApiProperty({ description: 'Minimum subscription amount' })
  minAmount: number;

  @ApiProperty({ description: 'Maximum subscription amount' })
  maxAmount: number;

  @ApiProperty({ description: 'Whether the product is currently active' })
  isActive: boolean;

  @ApiPropertyOptional({ description: 'Soroban vault contract ID' })
  contractId: string | null;

  @ApiProperty({
    type: [HistoricalPerformanceDto],
    description: 'Historical annual performance data',
  })
  historicalPerformance: HistoricalPerformanceDto[];

  @ApiProperty({
    description: 'Estimated earnings based on provided amount and duration',
  })
  projectedEarnings: number;
}

export class ProductComparisonResponseDto {
  @ApiProperty({ type: [ProductComparisonItemDto] })
  products: ProductComparisonItemDto[];

  @ApiProperty({ description: 'Whether this response was served from cache' })
  cached: boolean;

  @ApiPropertyOptional({
    description: 'The recommended product based on earnings and risk',
    example: { productId: 'uuid', reason: 'Highest projected returns' },
  })
  recommendation?: {
    productId: string;
    reason: string;
  };
}
