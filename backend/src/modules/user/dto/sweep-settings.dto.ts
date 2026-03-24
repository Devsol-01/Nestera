import { ApiProperty } from '@nestjs/swagger';

export class SweepSettingsDto {
  @ApiProperty({
    description: 'Whether automatic account sweeping is enabled',
    example: true,
  })
  autoSweepEnabled: boolean;

  @ApiProperty({
    description: 'Minimum balance threshold in XLM before sweeping excess funds',
    example: 100.0,
    nullable: true,
  })
  sweepThreshold: number | null;

  @ApiProperty({
    description: 'Default savings product ID to sweep funds into',
    example: '123e4567-e89b-12d3-a456-426614174000',
    nullable: true,
  })
  defaultSavingsProductId: string | null;
}
