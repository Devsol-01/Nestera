import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsDateString,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class HealthHistoryQueryDto {
  @ApiPropertyOptional({ description: 'Filter by service name', example: 'database' })
  @IsOptional()
  @IsString()
  service?: string;

  @ApiPropertyOptional({ description: 'Max records to return', default: 100, example: 100 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1000)
  limit?: number = 100;

  @ApiPropertyOptional({ description: 'Start of time range (ISO 8601)', example: '2026-06-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  from?: string;

  @ApiPropertyOptional({ description: 'End of time range (ISO 8601)', example: '2026-06-30T23:59:59.999Z' })
  @IsOptional()
  @IsDateString()
  to?: string;
}
