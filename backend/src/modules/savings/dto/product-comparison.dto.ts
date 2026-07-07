import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SavingsProductType } from '../entities/savings-product.entity';

export class HistoricalPerformanceDto {
  @ApiProperty({ example: 2023, description: 'Year of the performance record' })
  year: number;

  @ApiProperty({ example: 10.5, description: 'Annual return percentage for that year' })
  return: number;
}

export class ProductComparisonItemDto {
  @ApiProperty({ description: 'Product UUID', example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' })
  id: string;

  @ApiProperty({ description: 'Product name', example: 'Flexible Saver' })
  name: string;

  @ApiProperty({ enum: SavingsProductType, description: 'Product type', example: SavingsProductType.FLEXIBLE })
  type: SavingsProductType;

  @ApiPropertyOptional({ description: 'Product description', example: 'Earn 6% APY with no lock-up period.' })
  description: string | null;

  @ApiProperty({ description: 'Annual Percentage Yield (%)', example: 6.0 })
  apy: number;

  @ApiPropertyOptional({ description: 'Tenure in months (null for flexible)', example: 12 })
  tenure: number | null;

  @ApiProperty({
    description: 'Risk level derived from product type',
    enum: ['low', 'medium', 'high'],
    example: 'low',
  })
  riskLevel: 'low' | 'medium' | 'high';

  @ApiProperty({ description: 'Minimum subscription amount', example: 10 })
  minAmount: number;

  @ApiProperty({ description: 'Maximum subscription amount', example: 100000 })
  maxAmount: number;

  @ApiProperty({ description: 'Whether the product is currently active', example: true })
  isActive: boolean;

  @ApiPropertyOptional({ description: 'Soroban vault contract ID', example: 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA' })
  contractId: string | null;

  @ApiProperty({
    type: [HistoricalPerformanceDto],
    description: 'Historical annual performance data',
    example: [{ year: 2023, return: 10.5 }],
  })
  historicalPerformance: HistoricalPerformanceDto[];
}

export class ProductComparisonResponseDto {
  @ApiProperty({
    type: [ProductComparisonItemDto],
    example: [{
      id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      name: 'Flexible Saver',
      type: 'flexible',
      description: 'Earn 6% APY with no lock-up period.',
      apy: 6.0,
      riskLevel: 'low',
      minAmount: 10,
      maxAmount: 100000,
      isActive: true,
      contractId: null,
      historicalPerformance: [{ year: 2023, return: 10.5 }],
    }],
  })
  products: ProductComparisonItemDto[];

  @ApiProperty({ description: 'Whether this response was served from cache', example: false })
  cached: boolean;
}
