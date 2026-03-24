import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsNumber, IsOptional, IsUUID, Min } from 'class-validator';

export class UpdateSweepSettingsDto {
  @ApiProperty({
    description: 'Enable or disable automatic account sweeping',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  autoSweepEnabled?: boolean;

  @ApiProperty({
    description: 'Minimum balance threshold in XLM before sweeping excess funds',
    example: 100.0,
    minimum: 0,
  })
  @IsNumber()
  @Min(0)
  @IsOptional()
  sweepThreshold?: number;

  @ApiProperty({
    description: 'Default savings product ID to sweep funds into',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsUUID()
  @IsOptional()
  defaultSavingsProductId?: string;
}
