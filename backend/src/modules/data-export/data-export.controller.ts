import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  Body,
  Query,
  UseGuards,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';
import * as path from 'path';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { DataExportService } from './data-export.service';
import { RequestDataExportDto } from './dto/request-data-export.dto';
import { AsyncResponseBuilder } from '../../common/dto';

@ApiTags('users')
@ApiBearerAuth()
@Controller('users/data')
@UseGuards(JwtAuthGuard)
export class DataExportController {
  constructor(private readonly dataExportService: DataExportService) {}

  @Post('export')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Request a GDPR data export (async)' })
  @ApiResponse({ status: 202, description: 'Export request accepted' })
  async requestExport(
    @CurrentUser() user: { id: string },
    @Body() _dto: RequestDataExportDto,
  ) {
    const result = await this.dataExportService.requestExport(user.id);
    return new AsyncResponseBuilder(
      result.requestId,
      `/users/data/export/${result.requestId}/status`,
    )
      .setMessage(result.message)
      .setRetryAfterSeconds(10)
      .setOperationType('data-export')
      .setStatus('pending')
      .build();
  }

  @Get('export/:requestId/status')
  @Throttle({ export: { limit: 12, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Check export request status' })
  getStatus(
    @CurrentUser() user: { id: string },
    @Param('requestId') requestId: string,
  ) {
    return this.dataExportService.getExportStatus(requestId, user.id);
  }

  @Get('export/download/:token')
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Download export ZIP by token' })
  async download(
    @CurrentUser() user: { id: string },
    @Param('token') token: string,
    @Res() res: Response,
  ) {
    const { filePath } = await this.dataExportService.getExportFile(
      token,
      user.id,
    );
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="nestera-data-export.zip"',
    );
    res.sendFile(filePath);
  }

  @Delete('export/:requestId')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({
    summary: 'Cancel a pending/processing export request',
  })
  cancelExport(
    @CurrentUser() user: { id: string },
    @Param('requestId') requestId: string,
  ) {
    return this.dataExportService.cancelExport(requestId, user.id);
  }

  // ─── Typed export endpoints ───────────────────────────────────────────────

  @Get('export/transactions')
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Export transaction history as JSON' })
  @ApiQuery({
    name: 'from',
    required: false,
    description: 'ISO date YYYY-MM-DD',
  })
  @ApiQuery({ name: 'to', required: false, description: 'ISO date YYYY-MM-DD' })
  exportTransactions(
    @CurrentUser() user: { id: string },
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.dataExportService.exportTransactions(user.id, from, to);
  }

  @Get('export/goals')
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Export savings goals as JSON' })
  exportGoals(@CurrentUser() user: { id: string }) {
    return this.dataExportService.exportGoals(user.id);
  }

  @Get('export/portfolio')
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Export portfolio summary as JSON' })
  exportPortfolio(@CurrentUser() user: { id: string }) {
    return this.dataExportService.exportPortfolio(user.id);
  }

  @Get('export/analytics')
  @Throttle({ export: { limit: 6, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Export analytics data as JSON' })
  @ApiQuery({ name: 'from', required: false })
  @ApiQuery({ name: 'to', required: false })
  exportAnalytics(
    @CurrentUser() user: { id: string },
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.dataExportService.exportAnalytics(user.id, from, to);
  }

  // ─── Export history ───────────────────────────────────────────────────────

  @Get('export/history')
  @Throttle({ export: { limit: 20, ttl: 15 * 60 * 1000 } })
  @ApiOperation({
    summary: 'List all past export requests for the current user',
  })
  exportHistory(@CurrentUser() user: { id: string }) {
    return this.dataExportService.getExportHistory(user.id);
  }
}
