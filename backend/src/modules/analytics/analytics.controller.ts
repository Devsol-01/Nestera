import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  UseGuards,
  NotFoundException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AnalyticsService } from './analytics.service';
import { PortfolioTimelineQueryDto } from './dto/portfolio-timeline-query.dto';
import { AssetAllocationDto } from './dto/asset-allocation.dto';
import { YieldBreakdownDto } from './dto/yield-breakdown.dto';
import { RebalancingQueryDto } from './dto/rebalancing-query.dto';
import { ExecuteRebalancingDto } from './dto/execute-rebalancing.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

@ApiTags('analytics')
@Controller('analytics')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get('portfolio')
  @ApiOperation({
    summary: 'Generate portfolio net worth timeline',
    description:
      'Returns a time-series dataset of user balances for chart visualization.',
  })
  @ApiResponse({
    status: 200,
    description: 'Chronological array of portfolio value over time',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          date: { type: 'string', example: 'Oct 25, 2023' },
          value: { type: 'number', example: 124500.0 },
        },
      },
    },
  })
  async getPortfolioTimeline(
    @CurrentUser() user: { id: string },
    @Query() query: PortfolioTimelineQueryDto,
  ) {
    return this.analyticsService.getPortfolioTimeline(user.id, query.timeframe);
  }

  @Get('allocation')
  @ApiOperation({
    summary: 'Get asset allocation breakdown for doughnut chart',
    description:
      'Returns each token held by the authenticated user as a percentage of their total portfolio, sorted highest allocation first.',
  })
  @ApiResponse({
    status: 200,
    description: 'Asset allocation data',
    type: AssetAllocationDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 404,
    description: 'No Stellar public key linked to account',
  })
  async getAllocation(
    @CurrentUser() user: { id: string; publicKey?: string },
  ): Promise<AssetAllocationDto> {
    if (!user.publicKey) {
      throw new NotFoundException(
        'No Stellar public key linked to this account',
      );
    }
    return this.analyticsService.getAssetAllocation(user.publicKey);
  }

  @Get('yield-breakdown')
  @ApiOperation({
    summary: 'Get yield breakdown by savings pool',
    description:
      'Returns exact dollar amounts mapped to individual savings pools showing where the user is making money from yield.',
  })
  @ApiResponse({
    status: 200,
    description: 'Yield breakdown data by pool',
    type: YieldBreakdownDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getYieldBreakdown(
    @CurrentUser() user: { id: string },
  ): Promise<YieldBreakdownDto> {
    return this.analyticsService.getYieldBreakdown(user.id);
  }

  @Get('rebalancing-suggestions')
  @ApiOperation({
    summary: 'Get risk-adjusted portfolio rebalancing suggestions',
    description:
      'Returns recommendations for rebalancing based on the selected risk profile (conservative, balanced, aggressive).',
  })
  @ApiResponse({
    status: 200,
    description: 'Rebalancing recommendation payload',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getRebalancingSuggestions(
    @CurrentUser() user: { id: string },
    @Query() query: RebalancingQueryDto,
  ) {
    return this.analyticsService.getRebalancingSuggestions(
      user.id,
      query.riskProfile || 'balanced',
    );
  }

  @Post('rebalancing-suggestions/execute')
  @ApiOperation({
    summary: 'Execute one-click portfolio rebalancing',
  })
  @ApiResponse({ status: 201, description: 'Rebalancing execution recorded' })
  async executeRebalancing(
    @CurrentUser() user: { id: string },
    @Body() body: ExecuteRebalancingDto,
  ) {
    return this.analyticsService.executeRebalancing(
      user.id,
      body.riskProfile || 'balanced',
    );
  }
}
