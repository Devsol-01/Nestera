import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';

export class RebalancingQueryDto {
  @ApiPropertyOptional({
    enum: ['conservative', 'balanced', 'growth'],
    default: 'balanced',
    example: 'balanced',
  })
  @IsOptional()
  @IsIn(['conservative', 'balanced', 'growth'])
  riskProfile?: 'conservative' | 'balanced' | 'growth';
}
