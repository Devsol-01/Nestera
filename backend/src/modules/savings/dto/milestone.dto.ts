import { IsInt, IsString, Min, Max, MaxLength, IsNotEmpty } from 'class-validator';
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
  @ApiProperty({ example: 'a1b2c3d4-1234-5678-90ab-cdef01234567' }) id: string;

  @ApiProperty({ example: 'b2c3d4e5-1234-5678-90ab-cdef01234568' }) goalId: string;

  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' }) userId: string;

  @ApiProperty({ example: 33 }) percentage: number;

  @ApiProperty({ example: 'One-third of the way there!' }) label: string;

  @ApiProperty({ enum: MilestoneType, example: MilestoneType.CUSTOM }) type: MilestoneType;

  @ApiProperty({ example: false }) achieved: boolean;

  @ApiProperty({ nullable: true, example: '2026-06-15T10:00:00.000Z' }) achievedAt: Date | null;

  @ApiProperty({ example: 100 }) bonusPoints: number;

  @ApiProperty({ example: '2026-03-15T10:00:00.000Z' }) createdAt: Date;

  @ApiProperty({ example: '2026-03-29T14:00:00.000Z' }) updatedAt: Date;
}
