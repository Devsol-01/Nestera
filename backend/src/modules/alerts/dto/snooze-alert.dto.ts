import { ApiProperty } from '@nestjs/swagger';
import { IsInt, Min } from 'class-validator';

export class SnoozeAlertDto {
  @ApiProperty({ minimum: 1, description: 'Number of hours to snooze alert', example: 24 })
  @IsInt()
  @Min(1)
  hours!: number;
}
