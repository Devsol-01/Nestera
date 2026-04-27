import {
  IsInt,
  IsString,
  Min,
  Max,
  MaxLength,
  IsNotEmpty,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { MilestoneType } from '../entities/savings-goal-milestone.entity';

export class CreateCustomMilestoneDto {
  @ApiProperty({
    example: 33,
    description: 'Percentage threshold for this milestone (1–99)',
    minimum: 1,
    maximum: 99,
  })
  @IsInt()
  @Min(1)
  @Max(99)
  percentage: number;

  @ApiProperty({
    example: 'One-third of the way there!',
    description: 'Human-readable label for this milestone',
    maxLength: 255,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  label: string;
}

export class MilestoneResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  goalId: string;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  percentage: number;

  @ApiProperty()
  label: string;

  @ApiProperty({ enum: MilestoneType })
  type: MilestoneType;

  @ApiProperty()
  achieved: boolean;

  @ApiProperty({ nullable: true })
  achievedAt: Date | null;

  @ApiProperty()
  bonusPoints: number;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}
