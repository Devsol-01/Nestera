import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNumber,
  IsOptional,
  IsUUID,
  Min,
  IsArray,
  ArrayMinSize,
  ValidateNested,
  IsIn,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  GoalTransferFrequency,
  GoalTransferStatus,
} from '../entities/goal-transfer-schedule.entity';
import { IsPositiveAmount } from '../../../common/validators/is-positive-amount.validator';

export class CreateGoalTransferScheduleDto {
  @ApiProperty({ example: 'uuid-goal-id' })
  @IsUUID()
  goalId: string;

  @ApiPropertyOptional({ example: 'uuid-product-id' })
  @IsOptional()
  @IsUUID()
  productId?: string;

  @ApiProperty({ example: 50, minimum: 0.01 })
  @IsNumber()
  @IsPositiveAmount()
  @Min(0.01)
  amount: number;

  @ApiProperty({ enum: GoalTransferFrequency })
  @IsEnum(GoalTransferFrequency)
  frequency: GoalTransferFrequency;
}

export class BatchCreateGoalTransferScheduleDto {
  @ApiProperty({
    type: [CreateGoalTransferScheduleDto],
    description: 'Array of transfer schedules to create',
  })
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => CreateGoalTransferScheduleDto)
  schedules: CreateGoalTransferScheduleDto[];
}

export class UpdateGoalTransferScheduleDto {
  @ApiPropertyOptional({ example: 100, minimum: 0.01 })
  @IsOptional()
  @IsNumber()
  @IsPositiveAmount()
  @Min(0.01)
  amount?: number;

  @ApiPropertyOptional({ enum: GoalTransferFrequency })
  @IsOptional()
  @IsEnum(GoalTransferFrequency)
  frequency?: GoalTransferFrequency;
}

export class GoalTransferScheduleResponseDto {
  @ApiProperty({ example: 'a3d4c2b1-4567-8901-cdef-234567890123' }) id: string;
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' }) userId: string;
  @ApiProperty({ example: 'b2c3d4e5-1234-5678-90ab-cdef01234568' }) goalId: string;
  @ApiPropertyOptional({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }) productId: string | null;
  @ApiProperty({ example: 50 }) amount: number;
  @ApiProperty({ enum: GoalTransferFrequency, example: GoalTransferFrequency.MONTHLY }) frequency: GoalTransferFrequency;
  @ApiProperty({ enum: GoalTransferStatus, example: GoalTransferStatus.ACTIVE }) status: GoalTransferStatus;
  @ApiProperty({ example: '2026-04-15T10:00:00.000Z' }) nextRunAt: Date;
  @ApiProperty({ example: '2026-03-15T10:00:00.000Z' }) createdAt: Date;
  @ApiProperty({ example: '2026-03-29T14:00:00.000Z' }) updatedAt: Date;
}
