import {
  IsArray,
  IsUUID,
  ArrayMinSize,
  ArrayMaxSize,
  IsNumber,
  IsOptional,
  Min,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CompareProductsDto {
  @ApiProperty({
    description: 'Array of savings product IDs to compare (max 5)',
    example: ['prod-uuid-1', 'prod-uuid-2'],
    type: [String],
  })
  @IsArray()
  @ArrayMinSize(2, {
    message: 'At least 2 products are required for comparison',
  })
  @ArrayMaxSize(5, { message: 'Cannot compare more than 5 products at once' })
  @IsUUID('all', { each: true, message: 'Each productId must be a valid UUID' })
  productIds: string[];

  @ApiProperty({
    description: 'Investment amount to calculate projected earnings',
    example: 100000,
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiPropertyOptional({
    description:
      'Projected duration in months. If omitted, uses the product tenure.',
    example: 12,
    minimum: 1,
  })
  @IsOptional()
  @IsNumber()
  @Min(1)
  duration?: number;
}
