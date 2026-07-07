import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsDateString,
  IsNumber,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class CreateChallengeDto {
  @ApiProperty({ example: '7-Day Savings Streak' })
  @IsString()
  title: string;

  @ApiProperty({ example: 'Deposit at least $10 every day for 7 consecutive days' })
  @IsString()
  description: string;

  @ApiProperty({ minimum: 1, example: 10 })
  @IsNumber()
  @Min(1)
  targetAmount: number;

  @ApiProperty()
  @IsDateString()
  startsAt: string;

  @ApiProperty({ example: '2026-07-07T00:00:00.000Z' })
  @IsDateString()
  endsAt: string;

  @ApiPropertyOptional({ default: 'Challenger', example: 'Challenger' })
  @IsOptional()
  @IsString()
  badgeName?: string;
}
