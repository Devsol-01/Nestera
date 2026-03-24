import {
  IsString,
  IsNotEmpty,
  IsEnum,
  IsNumber,
  IsOptional,
  Min,
  Max,
  MinLength,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  RiskLevel,
  SavingsProductType,
} from '../entities/savings-product.entity';

export class CreateProductDto {
  @ApiProperty({ example: 'Fixed 12-Month Plan', description: 'Product name' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(200)
  name: string;

  @ApiProperty({ enum: SavingsProductType, description: 'Product type' })
  @IsEnum(SavingsProductType)
  type: SavingsProductType;

  @ApiPropertyOptional({ description: 'Product description' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiProperty({ example: 8.5, description: 'Annual interest rate (%)' })
  @IsNumber()
  @Min(0)
  @Max(100)
  interestRate: number;

  @ApiProperty({ example: 1000, description: 'Minimum subscription amount' })
  @IsNumber()
  @Min(0)
  minAmount: number;

  @ApiProperty({ example: 1000000, description: 'Maximum subscription amount' })
  @IsNumber()
  @Min(0)
  maxAmount: number;

  @ApiPropertyOptional({
    example: 12,
    description: 'Tenure in months (e.g. for fixed)',
  })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(360)
  tenureMonths?: number;

  @ApiPropertyOptional({
    description: 'Soroban contract ID on testnet/mainnet',
    example: 'CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
  })
  @IsOptional()
  @IsString()
  contractId?: string;

  @ApiPropertyOptional({
    description: 'Total value locked (TVL) cache',
    example: 250000.5,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  tvlAmount?: number;

  @ApiProperty({
    enum: RiskLevel,
    description: 'Risk level of the savings pool',
    default: RiskLevel.LOW,
  })
  @IsEnum(RiskLevel)
  @IsOptional()
  riskLevel?: RiskLevel;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  isActive?: boolean;
}
