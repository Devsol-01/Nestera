import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsEnum, IsOptional } from 'class-validator';
import {
  ReportType,
  ReportFormat,
  ReportScheduleFrequency,
} from '../entities/report-schedule.entity';

export class CreateReportScheduleDto {
  @ApiProperty({ enum: ReportType, example: ReportType.TRANSACTION_SUMMARY })
  @IsEnum(ReportType)
  reportType: ReportType;

  @ApiProperty({
    enum: ReportFormat,
    default: ReportFormat.PDF,
    example: ReportFormat.PDF,
  })
  @IsEnum(ReportFormat)
  format: ReportFormat;

  @ApiProperty({
    enum: ReportScheduleFrequency,
    example: ReportScheduleFrequency.WEEKLY,
  })
  @IsEnum(ReportScheduleFrequency)
  frequency: ReportScheduleFrequency;

  @ApiPropertyOptional({ default: true, example: true })
  @IsOptional()
  @IsBoolean()
  emailDelivery?: boolean;
}
