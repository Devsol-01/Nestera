import {
  IsString,
  IsEnum,
  IsDateString,
  IsObject,
  IsOptional,
  IsBoolean,
  IsArray,
  IsNumber,
  IsUUID,
  ValidateNested,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ChallengeType,
  ChallengeStatus,
  RewardConfiguration,
  ChallengeRules,
} from '../entities/challenge.entity';

export class CreateChallengeDto {
  @ApiProperty({ example: '7-Day Savings Streak' })
  @IsString()
  name!: string;

  @ApiProperty({
    example: 'Make a deposit every day for 7 consecutive days',
  })
  @IsString()
  description!: string;

  @ApiProperty({ enum: ChallengeType, example: ChallengeType.DEPOSIT_STREAK })
  @IsEnum(ChallengeType)
  type!: ChallengeType;

  @ApiProperty({ example: '2026-04-25T00:00:00Z' })
  @IsDateString()
  startDate!: string;

  @ApiProperty({ example: '2026-05-01T00:00:00Z' })
  @IsDateString()
  endDate!: string;

  @ApiProperty({
    example: {
      type: 'badge',
      value: 'Streak Master',
      metadata: { points: 100 },
    },
  })
  @IsObject()
  rewardConfiguration!: RewardConfiguration;

  @ApiProperty({
    example: {
      requiredStreakDays: 7,
      minimumDepositAmount: 10,
    },
  })
  @IsObject()
  rules!: ChallengeRules;

  @ApiPropertyOptional({ example: 'https://example.com/badge.png' })
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @ApiPropertyOptional({ example: 'Streak Master' })
  @IsOptional()
  @IsString()
  badgeName?: string;

  @ApiPropertyOptional({ example: 'savings' })
  @IsOptional()
  @IsString()
  category?: string;

  @ApiPropertyOptional({ example: ['streak', 'deposit', 'beginner'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  isFeatured?: boolean;
}

export class UpdateChallengeDto {
  @ApiPropertyOptional({ example: 'Updated Savings Streak' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'Deposit at least $10 every day for 7 consecutive days' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ enum: ChallengeStatus, example: ChallengeStatus.ACTIVE })
  @IsOptional()
  @IsEnum(ChallengeStatus)
  status?: ChallengeStatus;

  @ApiPropertyOptional({ example: '2026-07-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({ example: '2026-07-08T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({ example: { type: 'badge', value: 'Streak Master', metadata: { points: 100 } } })
  @IsOptional()
  @IsObject()
  rewardConfiguration?: RewardConfiguration;

  @ApiPropertyOptional({ example: { requiredStreakDays: 7, minimumDepositAmount: 10 } })
  @IsOptional()
  @IsObject()
  rules?: ChallengeRules;

  @ApiPropertyOptional({ example: 'https://example.com/badge.png' })
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  isVisible?: boolean;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  isFeatured?: boolean;
}

export class JoinChallengeDto {
  @ApiPropertyOptional({
    description: 'Optional metadata for joining the challenge',
    example: { motivation: 'Improve saving habits' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}

export class GetActiveChallengesQueryDto {
  @ApiPropertyOptional({ enum: ChallengeType, example: ChallengeType.DEPOSIT_STREAK })
  @IsOptional()
  @IsEnum(ChallengeType)
  type?: ChallengeType;

  @ApiPropertyOptional({ example: 'savings' })
  @IsOptional()
  @IsString()
  category?: string;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  @Type(() => Boolean)
  featured?: boolean;

  @ApiPropertyOptional({ example: 10, minimum: 1, maximum: 100 })
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  @Min(1)
  @Max(100)
  limit?: number;

  @ApiPropertyOptional({ example: 0, minimum: 0 })
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  @Min(0)
  offset?: number;
}

export class ChallengeResponseDto {
  @ApiProperty({ example: 'challenge-550e8400-e29b-41d4-a716-446655440000' })
  id!: string;

  @ApiProperty({ example: '7-Day Savings Streak' })
  name!: string;

  @ApiProperty({ example: 'Deposit at least $10 every day for 7 consecutive days' })
  description!: string;

  @ApiProperty({ enum: ChallengeType, example: ChallengeType.DEPOSIT_STREAK })
  type!: ChallengeType;

  @ApiProperty({ enum: ChallengeStatus, example: ChallengeStatus.ACTIVE })
  status!: ChallengeStatus;

  @ApiProperty({ example: '2026-07-01T00:00:00.000Z' })
  startDate!: Date;

  @ApiProperty({ example: '2026-07-08T00:00:00.000Z' })
  endDate!: Date;

  @ApiProperty({ example: { type: 'badge', value: 'Streak Master', metadata: { points: 100 } } })
  rewardConfiguration!: RewardConfiguration;

  @ApiProperty({ example: { requiredStreakDays: 7, minimumDepositAmount: 10 } })
  rules!: ChallengeRules;

  @ApiPropertyOptional({ example: 'https://example.com/badge.png' })
  imageUrl?: string;

  @ApiPropertyOptional({ example: 'Streak Master' })
  badgeName?: string;

  @ApiProperty({ example: 150 })
  participantCount!: number;

  @ApiProperty({ example: 80 })
  completionCount!: number;

  @ApiPropertyOptional({ example: 'savings' })
  category?: string;

  @ApiProperty({ example: ['streak', 'deposit', 'beginner'] })
  tags!: string[];

  @ApiProperty({ example: true })
  isFeatured!: boolean;

  @ApiProperty({ example: '2026-06-29T10:00:00.000Z' })
  createdAt!: Date;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z' })
  updatedAt!: Date;

  @ApiPropertyOptional({
    description: 'User participation status (only if authenticated)',
    example: { joined: true, status: 'in_progress', progressPercentage: 57, joinedAt: '2026-07-03T10:00:00.000Z' },
  })
  userParticipation?: {
    joined: boolean;
    status?: string;
    progressPercentage?: number;
    joinedAt?: Date;
  };
}

export class UserChallengeResponseDto {
  @ApiProperty({ example: 'uc-550e8400-e29b-41d4-a716-446655440000' })
  id!: string;

  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440001' })
  userId!: string;

  @ApiProperty({ example: 'challenge-550e8400-e29b-41d4-a716-446655440000' })
  challengeId!: string;

  @ApiProperty({ example: 'in_progress' })
  status!: string;

  @ApiProperty({ example: 57 })
  progressPercentage!: number;

  @ApiProperty({ example: { streakDays: 4, totalDeposits: 4 } })
  progressMetadata!: Record<string, any>;

  @ApiPropertyOptional({ example: '2026-07-07T12:00:00.000Z' })
  completedAt?: Date;

  @ApiProperty({ example: '2026-07-01T10:00:00.000Z' })
  joinedAt!: Date;

  @ApiProperty({ type: ChallengeResponseDto, example: { id: 'challenge-550e8400-e29b-41d4-a716-446655440000', name: '7-Day Savings Streak', description: 'Deposit at least $10 every day for 7 consecutive days', type: 'deposit_streak', status: 'active', startDate: '2026-07-01T00:00:00.000Z', endDate: '2026-07-08T00:00:00.000Z', participantCount: 150, completionCount: 80, tags: ['streak', 'deposit', 'beginner'], isFeatured: true, createdAt: '2026-06-29T10:00:00.000Z', updatedAt: '2026-06-29T12:00:00.000Z' } })
  challenge!: ChallengeResponseDto;
}
