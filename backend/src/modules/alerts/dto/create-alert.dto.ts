import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsObject, IsOptional } from 'class-validator';
import { AlertType } from '../entities/product-alert.entity';

export class CreateAlertDto {
  @ApiProperty({ enum: AlertType, example: AlertType.PRICE_THRESHOLD })
  @IsEnum(AlertType)
  type!: AlertType;

  @ApiProperty({ description: 'Alert conditions object', example: { asset: 'USDC', condition: 'greater_than', threshold: 50000 } })
  @IsObject()
  conditions!: Record<string, unknown>;

  @ApiPropertyOptional({ description: 'Optional template key', example: 'price-alert-template' })
  @IsOptional()
  template?: string;
}
