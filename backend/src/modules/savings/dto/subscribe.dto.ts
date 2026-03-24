import { IsUUID, IsNumber, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SubscribeDto {
  @ApiProperty({ description: 'Savings product ID to subscribe to' })
  @IsUUID()
  productId: string;

  @ApiProperty({ example: 5000, description: 'Amount to subscribe' })
  @IsNumber()
  @Min(0.01)
  amount: number;
}
