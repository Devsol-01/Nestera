import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNumber, IsUUID, Min } from 'class-validator';
import {
  AutoDepositFrequency,
  AutoDepositStatus,
} from '../entities/auto-deposit-schedule.entity';
import { IsPositiveAmount } from '../../../common/validators/is-positive-amount.validator';

export class CreateAutoDepositDto {
  @ApiProperty({
    example: 'uuid-product-id',
    description: 'Savings product UUID',
  })
  @IsUUID()
  productId: string;

  @ApiProperty({
    example: 100,
    description: 'Amount to deposit per cycle (in XLM)',
    minimum: 0.01,
  })
  @IsNumber()
  @IsPositiveAmount()
  @Min(0.01)
  amount: number;

  @ApiProperty({
    enum: AutoDepositFrequency,
    example: AutoDepositFrequency.MONTHLY,
  })
  @IsEnum(AutoDepositFrequency)
  frequency: AutoDepositFrequency;
}

export class AutoDepositResponseDto {
  @ApiProperty({ example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890' }) id: string;
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' }) userId: string;
  @ApiProperty({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }) productId: string;
  @ApiProperty({ example: 100 }) amount: number;
  @ApiProperty({ enum: AutoDepositFrequency, example: AutoDepositFrequency.MONTHLY }) frequency: AutoDepositFrequency;
  @ApiProperty({ enum: AutoDepositStatus, example: AutoDepositStatus.ACTIVE }) status: AutoDepositStatus;
  @ApiProperty({ example: '2026-04-15T10:00:00.000Z' }) nextRunAt: Date;
  @ApiProperty({ example: '2026-03-15T10:00:00.000Z' }) createdAt: Date;
  @ApiProperty({ example: '2026-03-29T14:00:00.000Z' }) updatedAt: Date;
}
