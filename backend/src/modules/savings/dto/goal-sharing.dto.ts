import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsDateString,
  IsEnum,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SavingsGoalShareVisibility } from '../entities/savings-goal-share.entity';

export class UpdateGoalSharingDto {
  @ApiProperty({ enum: SavingsGoalShareVisibility, example: SavingsGoalShareVisibility.PRIVATE })
  @IsEnum(SavingsGoalShareVisibility)
  visibility: SavingsGoalShareVisibility;

  @ApiPropertyOptional({ default: false, example: false })
  @IsOptional()
  @IsBoolean()
  isDirectoryListed?: boolean;

  @ApiPropertyOptional({ default: true, example: true })
  @IsOptional()
  @IsBoolean()
  showProgress?: boolean;

  @ApiPropertyOptional({ default: false, example: false })
  @IsOptional()
  @IsBoolean()
  showTargetAmount?: boolean;

  @ApiPropertyOptional({ default: true, example: true })
  @IsOptional()
  @IsBoolean()
  showOwnerName?: boolean;

  @ApiPropertyOptional({ default: true, example: true })
  @IsOptional()
  @IsBoolean()
  allowSocialSharing?: boolean;

  @ApiPropertyOptional({ default: true, example: true })
  @IsOptional()
  @IsBoolean()
  allowProgressUpdates?: boolean;

  @ApiPropertyOptional({
    type: [String],
    example: ['123e4567-e89b-12d3-a456-426614174000'],
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @IsUUID('4', { each: true })
  allowedUserIds?: string[];
}

export class CreateShareLinkDto {
  @ApiPropertyOptional({ example: '2027-01-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;
}

export class PublicGoalDirectoryQueryDto {
  @ApiPropertyOptional({ default: 1, example: 1 })
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 20, example: 20 })
  @IsOptional()
  limit?: number;
}

export class SocialShareDto {
  @ApiProperty({ enum: ['x', 'facebook', 'linkedin', 'whatsapp', 'copy'], example: 'x' })
  @IsIn(['x', 'facebook', 'linkedin', 'whatsapp', 'copy'])
  platform: 'x' | 'facebook' | 'linkedin' | 'whatsapp' | 'copy';

  @ApiPropertyOptional({ example: 'Come check out my savings goal!' })
  @IsOptional()
  @IsString()
  @MaxLength(280)
  message?: string;
}
