import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  Res,
  BadRequestException,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ReportsService } from './reports.service';
import { ScheduledReportService } from './scheduled-report.service';
import { CreateReportScheduleDto } from './dto/report-schedule.dto';
import {
  ReportSchedule,
  ReportArchive,
} from './entities/report-schedule.entity';
import { Response } from 'express';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { CorrelationId } from '../../common/decorators/correlation-id.decorator';
import { JobQueueService } from '../job-queue/job-queue.service';
import { AsyncResponseBuilder } from '../../common/dto';

@ApiTags('reports')
@Controller('reports')
export class ReportsController {
  constructor(
    private readonly reportsService: ReportsService,
    private readonly scheduledReportService: ScheduledReportService,
    private readonly jobQueueService: JobQueueService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get('tax/:year')
  async getTaxReport(
    @Param('year') yearParam: string,
    @Query('format') format = 'csv',
    @Query('irs1099') irs1099 = 'false',
    @CurrentUser() user: any,
    @Res() res: Response,
  ) {
    const year = Number(yearParam);
    if (!user || !user.id)
      throw new BadRequestException('authenticated user required');
    if (Number.isNaN(year)) throw new BadRequestException('invalid year');
    const irsFlag = irs1099 === 'true';

    const result = await this.reportsService.buildAndStoreTaxReport(
      user.id,
      year,
      { format, irs1099: irsFlag },
    );

    return res.json({ storedPath: result.path, filename: result.filename });
  }

  @UseGuards(JwtAuthGuard)
  @Post('tax/:year/async')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Queue a tax report for async generation' })
  async queueTaxReport(
    @Param('year') yearParam: string,
    @Query('format') format = 'csv',
    @Query('irs1099') irs1099 = 'false',
    @CurrentUser() user: any,
    @CorrelationId() correlationId?: string,
  ) {
    const year = Number(yearParam);
    if (!user || !user.id)
      throw new BadRequestException('authenticated user required');
    if (Number.isNaN(year)) throw new BadRequestException('invalid year');

    const job = await this.jobQueueService.addReportJob(
      {
        reportType: 'tax',
        userId: user.id,
        params: { year, format, irs1099: irs1099 === 'true' },
      },
      undefined,
      correlationId,
    );

    return new AsyncResponseBuilder(
      job.id,
      `/reports/jobs/${job.id}/status`,
    )
      .setMessage('Tax report generation queued successfully')
      .setRetryAfterSeconds(10)
      .setOperationType('report-generation')
      .setStatus('pending')
      .setMetadata({ reportType: 'tax', year, format })
      .build();
  }

  @Post('schedules')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a scheduled report configuration' })
  async createSchedule(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateReportScheduleDto,
  ): Promise<ReportSchedule> {
    return this.scheduledReportService.createSchedule(user.id, dto);
  }

  @Get('schedules')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List report schedules for current user' })
  async listSchedules(
    @CurrentUser() user: { id: string },
  ): Promise<ReportSchedule[]> {
    return this.scheduledReportService.listSchedules(user.id);
  }

  @Patch('schedules/:id/pause')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Pause a report schedule' })
  async pauseSchedule(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ): Promise<ReportSchedule> {
    return this.scheduledReportService.pauseSchedule(id, user.id);
  }

  @Delete('schedules/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Cancel a report schedule' })
  async cancelSchedule(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ): Promise<void> {
    return this.scheduledReportService.cancelSchedule(id, user.id);
  }

  @Get('archives')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List generated report archives for current user' })
  async listArchives(
    @CurrentUser() user: { id: string },
  ): Promise<ReportArchive[]> {
    return this.scheduledReportService.listArchives(user.id);
  }
}
