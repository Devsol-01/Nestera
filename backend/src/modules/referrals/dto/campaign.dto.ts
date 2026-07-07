import {
  IsString,
  IsOptional,
  IsNumber,
  IsBoolean,
  IsDateString,
  Min,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateCampaignDto {
  @ApiProperty({ description: 'Campaign name', example: 'Summer Referral Bonus' })
  @IsString()
  name: string;

  @ApiPropertyOptional({ description: 'Campaign description', example: 'Earn rewards for referring friends this summer' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({ description: 'Reward amount for referrer', example: 10 })
  @IsNumber()
  @Min(0)
  rewardAmount: number;

  @ApiPropertyOptional({ description: 'Reward amount for referee', example: 5 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  refereeRewardAmount?: number;

  @ApiPropertyOptional({
    description: 'Minimum deposit amount to qualify',
    default: 0,
    example: 0,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  minDepositAmount?: number;

  @ApiPropertyOptional({ description: 'Maximum rewards per user', example: 10 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  maxRewardsPerUser?: number;

  @ApiPropertyOptional({ description: 'Campaign start date', example: '2026-06-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({ description: 'Campaign end date', example: '2026-09-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  endDate?: string;
}

export class UpdateCampaignDto {
  @ApiPropertyOptional({ example: 'Summer Referral Bonus' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'Earn rewards for referring friends this summer' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ example: 10 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  rewardAmount?: number;

  @ApiPropertyOptional({ example: 5 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  refereeRewardAmount?: number;

  @ApiPropertyOptional({ example: 0 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  minDepositAmount?: number;

  @ApiPropertyOptional({ example: 10 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  maxRewardsPerUser?: number;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ example: '2026-06-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({ example: '2026-09-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  endDate?: string;
}
