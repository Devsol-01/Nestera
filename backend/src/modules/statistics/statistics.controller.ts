import {
  Controller,
  Get,
  Post,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Param,
  Delete,
  BadRequestException,
  Body,
  Res,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
  ApiBody,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { StatisticsService } from './services/statistics.service';
import { StatisticsQueryDto } from './dto/statistics-query.dto';
import {
  UserGrowthDto,
  TransactionVolumeDto,
  SavingsMetricsDto,
  SystemHealthDto,
  StatisticsOverviewDto,
} from './dto/statistics-response.dto';
import {
  AnalyticsExportJobRequestDto,
  AnalyticsExportJobResponseDto,
} from './dto/analytics-export.dto';
import { AnalyticsExportFormat } from './entities/analytics-export-job.entity';
import { AnalyticsExportService } from './services/analytics-export.service';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { AsyncResponseBuilder } from '../../common/dto';

@ApiTags('admin/statistics')
@Controller('admin/statistics')
@UseGuards(RolesGuard)
@ApiBearerAuth()
export class StatisticsController {
  constructor(
    private readonly statisticsService: StatisticsService,
    private readonly analyticsExportService: AnalyticsExportService,
  ) {}

  private resolveExportUserId(user?: { id?: string }): string {
    return user?.id || 'admin-test-user';
  }

  /**
   * Get comprehensive statistics overview
   * Includes user growth, transactions, savings, and system health
   */
  @Get('overview')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get comprehensive statistics overview' })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiQuery({
    name: 'period',
    required: false,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    description: 'Granularity of metrics',
  })
  @ApiQuery({
    name: 'compareWith',
    required: false,
    enum: [
      'previous_period',
      'same_period_last_year',
      'same_period_last_month',
    ],
    description: 'Compare with a previous period',
  })
  @ApiQuery({
    name: 'fromDate',
    required: false,
    type: String,
    description: 'Start date for custom range (YYYY-MM-DD)',
  })
  @ApiQuery({
    name: 'toDate',
    required: false,
    type: String,
    description: 'End date for custom range (YYYY-MM-DD)',
  })
  @ApiResponse({
    status: 200,
    description: 'Statistics overview',
    type: StatisticsOverviewDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getOverview(
    @Query() query: StatisticsQueryDto,
  ): Promise<StatisticsOverviewDto> {
    return this.statisticsService.getStatisticsOverview(query);
  }

  /**
   * Get user growth metrics
   * Includes new users, active users, retention, churn, and growth rates
   */
  @Get('users/growth')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get user growth statistics' })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiQuery({
    name: 'period',
    required: false,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    description: 'Granularity of metrics',
  })
  @ApiQuery({
    name: 'compareWith',
    required: false,
    enum: [
      'previous_period',
      'same_period_last_year',
      'same_period_last_month',
    ],
    description: 'Compare with a previous period',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number for pagination',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page',
  })
  @ApiResponse({
    status: 200,
    description: 'User growth statistics',
    type: UserGrowthDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({ status: 404, description: 'No data found for the period' })
  async getUserGrowth(
    @Query() query: StatisticsQueryDto,
  ): Promise<UserGrowthDto> {
    return this.statisticsService.getUserGrowthStatistics(query);
  }

  /**
   * Get transaction volume metrics
   * Includes transaction counts, volumes, success rates, and gas usage
   */
  @Get('transactions/volume')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get transaction volume statistics' })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiQuery({
    name: 'period',
    required: false,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    description: 'Granularity of metrics',
  })
  @ApiQuery({
    name: 'compareWith',
    required: false,
    enum: [
      'previous_period',
      'same_period_last_year',
      'same_period_last_month',
    ],
    description: 'Compare with a previous period',
  })
  @ApiQuery({
    name: 'filter',
    required: false,
    type: String,
    description: 'Filter by transaction type for drill-down',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number for pagination',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page',
  })
  @ApiResponse({
    status: 200,
    description: 'Transaction volume statistics',
    type: TransactionVolumeDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({ status: 404, description: 'No data found for the period' })
  async getTransactionVolume(
    @Query() query: StatisticsQueryDto,
  ): Promise<TransactionVolumeDto> {
    return this.statisticsService.getTransactionVolumeStatistics(query);
  }

  /**
   * Get savings metrics
   * Includes accounts, TVL, APY distribution, inflows/outflows, and growth rates
   */
  @Get('savings/metrics')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get savings statistics' })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiQuery({
    name: 'period',
    required: false,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    description: 'Granularity of metrics',
  })
  @ApiQuery({
    name: 'compareWith',
    required: false,
    enum: [
      'previous_period',
      'same_period_last_year',
      'same_period_last_month',
    ],
    description: 'Compare with a previous period',
  })
  @ApiQuery({
    name: 'filter',
    required: false,
    type: String,
    description: 'Filter by product for drill-down',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number for pagination',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page',
  })
  @ApiResponse({
    status: 200,
    description: 'Savings statistics',
    type: SavingsMetricsDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({ status: 404, description: 'No data found for the period' })
  async getSavingsMetrics(
    @Query() query: StatisticsQueryDto,
  ): Promise<SavingsMetricsDto> {
    return this.statisticsService.getSavingsStatistics(query);
  }

  /**
   * Get system health metrics
   * Includes uptime, response times, resource usage, and alerts
   */
  @Get('system/health')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get system health statistics' })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiResponse({
    status: 200,
    description: 'System health statistics',
    type: SystemHealthDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({ status: 404, description: 'No data found for the period' })
  async getSystemHealth(
    @Query() query: StatisticsQueryDto,
  ): Promise<SystemHealthDto> {
    return this.statisticsService.getSystemHealthStatistics(query);
  }

  /**
   * Clear statistics cache
   * Useful for forcing regeneration of cached statistics
   */
  @Delete('cache')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Clear statistics cache' })
  @ApiQuery({
    name: 'pattern',
    required: false,
    type: String,
    description: 'Pattern to match cache keys (optional)',
  })
  @ApiResponse({ status: 204, description: 'Cache cleared successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async clearCache(@Query('pattern') pattern?: string): Promise<void> {
    if (pattern && pattern.length > 100) {
      throw new BadRequestException('Pattern is too long');
    }
    await this.statisticsService.clearCache(pattern);
  }

  @Get('export/jobs/:jobId/download')
  @Roles(Role.ADMIN)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Download a completed analytics export job' })
  @ApiParam({ name: 'jobId', description: 'Export job UUID' })
  @ApiResponse({ status: 200, description: 'Export file download' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async downloadExportJob(
    @Param('jobId') jobId: string,
    @Res() res: Response,
    @CurrentUser() user?: { id?: string },
  ): Promise<void> {
    const download = await this.analyticsExportService.getExportJobDownload(
      this.resolveExportUserId(user),
      jobId,
    );

    res.setHeader('Content-Type', download.contentType);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${download.fileName}"`,
    );
    res.sendFile(download.filePath);
  }

  @Get('export/jobs/:jobId')
  @Roles(Role.ADMIN)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Get analytics export job status' })
  @ApiParam({ name: 'jobId', description: 'Export job UUID' })
  @ApiResponse({
    status: 200,
    description: 'Analytics export job status',
    type: AnalyticsExportJobResponseDto,
  })
  async getExportJobStatus(
    @Param('jobId') jobId: string,
    @CurrentUser() user?: { id?: string },
  ): Promise<AnalyticsExportJobResponseDto> {
    return this.analyticsExportService.getExportJobStatus(
      this.resolveExportUserId(user),
      jobId,
    );
  }

  @Delete('export/jobs/:jobId')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Cancel an analytics export job' })
  @ApiParam({ name: 'jobId', description: 'Export job UUID' })
  @ApiResponse({
    status: 202,
    description: 'Analytics export job cancelled',
    type: AnalyticsExportJobResponseDto,
  })
  async cancelExportJob(
    @Param('jobId') jobId: string,
    @CurrentUser() user?: { id?: string },
  ): Promise<AnalyticsExportJobResponseDto> {
    return this.analyticsExportService.cancelExportJob(
      this.resolveExportUserId(user),
      jobId,
    );
  }

  @Post('export/:dataType/jobs')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Queue an analytics export job' })
  @ApiParam({
    name: 'dataType',
    enum: ['all', 'users', 'transactions', 'savings', 'health'],
    description: 'Type of data to export',
  })
  @ApiBody({ type: AnalyticsExportJobRequestDto })
  @ApiResponse({
    status: 202,
    description: 'Export job accepted for processing',
    type: AnalyticsExportJobResponseDto,
  })
  async createExportJob(
    @Param('dataType') dataType: string,
    @Body() body: AnalyticsExportJobRequestDto,
    @CurrentUser() user?: { id?: string },
  ) {
    const job = await this.analyticsExportService.requestExportJob(
      this.resolveExportUserId(user),
      dataType,
      body,
    );
    return new AsyncResponseBuilder(
      job.requestId,
      `/admin/statistics/export/jobs/${job.requestId}`,
    )
      .setMessage('Analytics export job queued successfully')
      .setRetryAfterSeconds(15)
      .setOperationType('analytics-export')
      .setStatus(job.status)
      .setMetadata({ dataType: job.dataType, format: job.format })
      .build();
  }

  /**
   * Queue analytics export and retrieve the result asynchronously.
   */
  @Get('export/:dataType')
  @Roles(Role.ADMIN)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Queue analytics export job (legacy route)' })
  @ApiParam({
    name: 'dataType',
    enum: ['all', 'users', 'transactions', 'savings', 'health'],
    description: 'Type of data to export',
  })
  @ApiQuery({
    name: 'format',
    enum: ['json', 'csv', 'xlsx'],
    description: 'Export format for generated artifact',
  })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiQuery({ name: 'fromDate', required: false, type: String })
  @ApiQuery({ name: 'toDate', required: false, type: String })
  @ApiResponse({
    status: 202,
    description: 'Export job accepted for asynchronous processing',
    type: AnalyticsExportJobResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({ status: 400, description: 'Invalid export format' })
  async exportStatistics(
    @Param('dataType') dataType: string,
    @Query('format') format: string = AnalyticsExportFormat.JSON,
    @Query() query: StatisticsQueryDto,
    @CurrentUser() user?: { id?: string },
  ) {
    const job = await this.analyticsExportService.requestExportJob(
      this.resolveExportUserId(user),
      dataType,
      {
        ...query,
        format: format as AnalyticsExportFormat,
      },
    );
    return new AsyncResponseBuilder(
      job.requestId,
      `/admin/statistics/export/jobs/${job.requestId}`,
    )
      .setMessage('Analytics export job queued successfully')
      .setRetryAfterSeconds(15)
      .setOperationType('analytics-export')
      .setStatus(job.status)
      .setMetadata({ dataType: job.dataType, format: job.format })
      .build();
  }

  /**
   * Get drill-down data for a specific metric
   * Allows exploring statistics by subcategories
   */
  @Get('drilldown/:metricType/:category')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get drill-down statistics' })
  @ApiParam({
    name: 'metricType',
    enum: ['users', 'transactions', 'savings'],
    description: 'Type of metric to drill down',
  })
  @ApiParam({
    name: 'category',
    description: 'Category to drill down into',
  })
  @ApiQuery({
    name: 'range',
    required: false,
    enum: ['7d', '30d', '90d', '365d', 'custom'],
    description: 'Time range for statistics',
  })
  @ApiResponse({
    status: 200,
    description: 'Drill-down statistics',
    schema: {
      type: 'object',
      properties: {
        category: { type: 'string' },
        breakdown: { type: 'object' },
        total: { type: 'number' },
        percentage: { type: 'number' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getDrillDownData(
    @Param('metricType') metricType: string,
    @Param('category') category: string,
    @Query() query: StatisticsQueryDto,
  ): Promise<any> {
    const validMetricTypes = ['users', 'transactions', 'savings'];

    if (!validMetricTypes.includes(metricType)) {
      throw new BadRequestException('Invalid metric type');
    }

    // Return drill-down data
    return {
      category,
      breakdown: {},
      total: 0,
      percentage: 0,
    };
  }
}
