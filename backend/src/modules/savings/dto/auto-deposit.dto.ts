import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNumber, IsUUID, Min } from 'class-validator';
import {
  AutoDepositFrequency,
  AutoDepositStatus,
} from '../entities/auto-deposit-schedule.entity';

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
  @ApiProperty() id: string;
  @ApiProperty() userId: string;
  @ApiProperty() productId: string;
  @ApiProperty() amount: number;
  @ApiProperty({ enum: AutoDepositFrequency }) frequency: AutoDepositFrequency;
  @ApiProperty({ enum: AutoDepositStatus }) status: AutoDepositStatus;
  @ApiProperty() nextRunAt: Date;
  @ApiProperty() createdAt: Date;
  @ApiProperty() updatedAt: Date;
}
