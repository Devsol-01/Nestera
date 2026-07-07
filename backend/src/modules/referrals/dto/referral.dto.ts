import {
  IsString,
  IsOptional,
  IsUUID,
  IsEnum,
  IsNumber,
  Min,
  Matches,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ReferralStatus } from '../entities/referral.entity';

export class CreateReferralDto {
  @ApiPropertyOptional({
    description: 'Campaign ID to associate with this referral',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsOptional()
  @IsUUID()
  campaignId?: string;
}

export class GenerateCustomCodeDto {
  @ApiPropertyOptional({
    description:
      'Custom referral code (alphanumeric, 4-12 chars). Auto-generated if omitted.',
    example: 'BUY-A-CAR',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Z0-9]{4,12}$/, {
    message: 'Code must be 4-12 uppercase alphanumeric characters',
  })
  @MaxLength(12)
  code?: string;

  @ApiPropertyOptional({
    description: 'Campaign ID to associate with this referral',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsOptional()
  @IsUUID()
  campaignId?: string;
}

export class ApplyReferralCodeDto {
  @ApiProperty({ description: 'Referral code to apply during signup', example: 'BUY-A-CAR' })
  @IsString()
  referralCode!: string;
}

export class ReferralStatsDto {
  @ApiProperty({ example: 'BUY-A-CAR' })
  referralCode!: string | null;

  @ApiProperty({ example: 150 })
  totalReferrals!: number;

  @ApiProperty({ example: 80 })
  successfulReferrals!: number;

  @ApiProperty({ example: 50 })
  pendingRewards!: number;

  @ApiProperty({ example: 30 })
  claimedRewards!: number;

  @ApiProperty({ example: 5 })
  rank!: number | null;
}

export class ReferralResponseDto {
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' })
  id!: string;

  @ApiProperty({ example: 'BUY-A-CAR' })
  referralCode!: string;

  @ApiProperty({ enum: ReferralStatus, example: ReferralStatus.PENDING })
  status!: ReferralStatus;

  @ApiProperty({ example: '10.00' })
  rewardAmount?: string;

  @ApiProperty({ example: 'referee@example.com' })
  refereeEmail?: string;

  @ApiProperty({ example: '2026-06-29T10:00:00.000Z' })
  createdAt!: Date;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z' })
  completedAt?: Date;

  @ApiProperty({ example: '2026-06-29T12:30:00.000Z' })
  rewardedAt?: Date;
}

export class UpdateReferralStatusDto {
  @ApiProperty({ enum: ReferralStatus, example: ReferralStatus.COMPLETED })
  @IsEnum(ReferralStatus)
  status!: ReferralStatus;

  @ApiPropertyOptional({ example: 10 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  rewardAmount?: number;
}
