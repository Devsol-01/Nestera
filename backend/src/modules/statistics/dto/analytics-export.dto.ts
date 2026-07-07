import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsOptional } from 'class-validator';
import { StatisticsQueryDto } from './statistics-query.dto';
import {
  AnalyticsExportDataType,
  AnalyticsExportFormat,
  AnalyticsExportStatus,
} from '../entities/analytics-export-job.entity';

export class AnalyticsExportQueryDto extends StatisticsQueryDto {
  @ApiPropertyOptional({
    enum: AnalyticsExportFormat,
    default: AnalyticsExportFormat.JSON,
    example: AnalyticsExportFormat.JSON,
    description: 'Export format',
  })
  @IsEnum(AnalyticsExportFormat)
  @IsOptional()
  format?: AnalyticsExportFormat = AnalyticsExportFormat.JSON;
}

export class AnalyticsExportJobRequestDto extends AnalyticsExportQueryDto {}

export class AnalyticsExportJobResponseDto {
  @ApiPropertyOptional({ enum: AnalyticsExportStatus, example: AnalyticsExportStatus.COMPLETED })
  status!: AnalyticsExportStatus;

  @ApiPropertyOptional({ enum: AnalyticsExportDataType, example: AnalyticsExportDataType.ALL })
  dataType!: AnalyticsExportDataType;

  @ApiPropertyOptional({ enum: AnalyticsExportFormat, example: AnalyticsExportFormat.JSON })
  format!: AnalyticsExportFormat;

  @ApiPropertyOptional({ example: 'req_550e8400-e29b-41d4-a716-446655440000' })
  requestId!: string;

  @ApiPropertyOptional({ example: 'analytics-export-2026-06-29.json' })
  fileName?: string;

  @ApiPropertyOptional({ example: '/tmp/exports/analytics-export-2026-06-29.json' })
  filePath?: string;

  @ApiPropertyOptional({ example: 'Export failed due to insufficient data' })
  errorMessage?: string;

  @ApiPropertyOptional({ example: '2026-06-29T10:00:00.000Z' })
  createdAt?: Date;

  @ApiPropertyOptional({ example: '2026-06-29T10:05:00.000Z' })
  completedAt?: Date | null;

  @ApiPropertyOptional({ example: '2026-07-06T10:00:00.000Z' })
  expiresAt?: Date | null;
}

export class AnalyticsExportArtifactDto {
  @ApiPropertyOptional({ enum: AnalyticsExportFormat, example: AnalyticsExportFormat.JSON })
  format!: AnalyticsExportFormat;

  @ApiPropertyOptional({ example: 'export-data.json' })
  fileName!: string;

  @ApiPropertyOptional({ example: 'application/json' })
  contentType!: string;

  @ApiPropertyOptional({ example: Buffer.from('export-data') })
  buffer!: Buffer;

  @ApiPropertyOptional({ example: { headers: { 'Content-Disposition': 'attachment' } }, type: Object })
  body?: unknown;
}
