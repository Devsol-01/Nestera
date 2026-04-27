import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Delete,
  HttpCode,
  HttpStatus,
  UseGuards,
  UseInterceptors,
  Param,
  Query,
} from '@nestjs/common';

import { CacheInterceptor, CacheKey, CacheTTL } from '@nestjs/cache-manager';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { SavingsService } from './savings.service';
import { MilestoneService } from './services/milestone.service';
import { SavingsProduct, RiskLevel } from './entities/savings-product.entity';
import { UserSubscription } from './entities/user-subscription.entity';
import { SavingsGoal } from './entities/savings-goal.entity';
import { SavingsGoalMilestone } from './entities/savings-goal-milestone.entity';
import { SubscribeDto } from './dto/subscribe.dto';
import { WithdrawDto } from './dto/withdraw.dto';
import { WithdrawalResponseDto } from './dto/withdrawal-response.dto';
import { CreateGoalDto } from './dto/create-goal.dto';
import { UpdateGoalDto } from './dto/update-goal.dto';
import { SavingsProductDto } from './dto/savings-product.dto';
import { ProductDetailsDto } from './dto/product-details.dto';
import { CompareProductsDto } from './dto/compare-products.dto';
import { ProductComparisonResponseDto } from './dto/product-comparison.dto';
import {
  CreateCustomMilestoneDto,
  MilestoneResponseDto,
} from './dto/milestone.dto';
import {
  MetricsGranularity,
  ProductMetricsDto,
  ProductMetricsQueryDto,
} from './dto/product-metrics.dto';
import { RecommendationResponseDto } from './dto/recommendation-response.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RpcThrottleGuard } from '../../common/guards/rpc-throttle.guard';
import { RecommendationService } from './services/recommendation.service';
import { AutoDepositService } from './services/auto-deposit.service';
import {
  CreateAutoDepositDto,
  AutoDepositResponseDto,
} from './dto/auto-deposit.dto';
import { AutoDepositSchedule } from './entities/auto-deposit-schedule.entity';
import {
  SavingsGoalProgress,
  UserSubscriptionWithLiveBalance,
} from './savings.service';

@ApiTags('savings')
@Controller('savings')
export class SavingsController {
  constructor(
    private readonly savingsService: SavingsService,
    private readonly milestoneService: MilestoneService,
    private readonly recommendationService: RecommendationService,
    private readonly autoDepositService: AutoDepositService,
  ) {}

  @Get('products')
  @UseInterceptors(CacheInterceptor)
  @CacheKey('pools_all')
  @CacheTTL(60000)
  @ApiOperation({ summary: 'List all savings products' })
  @ApiQuery({ name: 'sort', required: false, enum: ['apy', 'tvl'] })
  @ApiResponse({
    status: 200,
    description: 'List of savings products',
    type: [SavingsProductDto],
  })
  async getProducts(
    @Query('sort') sort?: 'apy' | 'tvl',
  ): Promise<SavingsProductDto[]> {
    return await this.savingsService.findAllProducts(true, sort);
  }

  @Get('products/:id')
  @Throttle({ rpc: { limit: 30, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get detailed product information with live contract data',
    description:
      'Retrieve a single savings product by ID with live total_assets from the Soroban vault contract',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Product UUID',
  })
  @ApiResponse({
    status: 200,
    description: 'Product details with live contract data',
    type: ProductDetailsDto,
  })
  @ApiResponse({ status: 404, description: 'Product not found' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  @ApiResponse({
    status: 503,
    description: 'Soroban RPC service unavailable',
  })
  @ApiResponse({
    status: 504,
    description: 'Soroban RPC request timeout',
  })
  async getProductDetails(@Param('id') id: string): Promise<ProductDetailsDto> {
    const { product, totalAssets, capacity } =
      await this.savingsService.findProductWithLiveData(id);

    const totalAssetsXlm = totalAssets / 10_000_000;

    return {
      id: product.id,
      name: product.name,
      type: product.type,
      description: product.description,
      interestRate: product.interestRate,
      minAmount: product.minAmount,
      maxAmount: product.maxAmount,
      tenureMonths: product.tenureMonths,
      maxSubscriptionsPerUser: product.maxSubscriptionsPerUser,
      version: product.version ?? 1,
      isActive: product.isActive,
      contractId: product.contractId,
      totalAssets,
      totalAssetsXlm,
      maxCapacity: capacity.maxCapacity,
      utilizedCapacity: capacity.utilizedCapacity,
      availableCapacity: capacity.availableCapacity,
      utilizationPercentage: capacity.utilizationPercentage,
      isFull: capacity.isFull,
      riskLevel: product.riskLevel || RiskLevel.LOW,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    };
  }

  @Post('products/compare')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Compare multiple savings products side-by-side',
    description:
      'Submit 2–5 product IDs to receive a structured comparison including APY, tenure, risk level, fees, and historical performance. Results are cached for 10 minutes.',
  })
  @ApiBody({ type: CompareProductsDto })
  @ApiResponse({
    status: 200,
    description: 'Comparison result',
    type: ProductComparisonResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid request (< 2 or > 5 IDs)' })
  @ApiResponse({ status: 404, description: 'One or more products not found' })
  async compareProducts(
    @Body() dto: CompareProductsDto,
  ): Promise<ProductComparisonResponseDto> {
    return this.savingsService.compareProducts(
      dto.productIds,
      dto.amount,
      dto.duration,
    );
  }

  @Get('products/:id/metrics')
  @UseInterceptors(CacheInterceptor)
  @CacheTTL(3600000)
  @ApiOperation({
    summary: 'Get performance metrics for a savings product',
    description:
      'Returns historical APY, TVL trends, user retention, risk-adjusted returns (Sharpe ratio), and similar product comparisons. Cached for 1 hour.',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Product UUID',
  })
  @ApiQuery({
    name: 'granularity',
    required: false,
    enum: MetricsGranularity,
    description: 'Chart data granularity (daily, weekly, monthly)',
  })
  @ApiResponse({
    status: 200,
    description: 'Product performance metrics',
    type: ProductMetricsDto,
  })
  @ApiResponse({ status: 404, description: 'Product not found' })
  async getProductMetrics(
    @Param('id') id: string,
    @Query() query: ProductMetricsQueryDto,
  ): Promise<ProductMetricsDto> {
    return this.savingsService.getProductMetrics(id, query.granularity);
  }

  @Post('subscribe')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Subscribe to a savings product' })
  @ApiBody({ type: SubscribeDto })
  @ApiResponse({
    status: 201,
    description: 'Subscription created',
    type: UserSubscription,
  })
  @ApiResponse({ status: 400, description: 'Invalid product or amount' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async subscribe(
    @Body() dto: SubscribeDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<UserSubscription> {
    return await this.savingsService.subscribe(
      user.id,
      dto.productId,
      dto.amount,
    );
  }

  @Post('withdraw')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Request withdrawal from a savings subscription',
    description:
      'Creates a withdrawal request with penalty calculation for early withdrawal from locked products',
  })
  @ApiBody({ type: WithdrawDto })
  @ApiResponse({
    status: 201,
    description: 'Withdrawal request created',
    type: WithdrawalResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request or insufficient balance',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Subscription not found' })
  async withdraw(
    @Body() dto: WithdrawDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<WithdrawalResponseDto> {
    const withdrawal = await this.savingsService.createWithdrawalRequest(
      user.id,
      dto.subscriptionId,
      dto.amount,
      dto.reason,
    );

    return {
      withdrawalId: withdrawal.id,
      amount: Number(withdrawal.amount),
      penalty: Number(withdrawal.penalty),
      netAmount: Number(withdrawal.netAmount),
      status: withdrawal.status.toLowerCase(),
      estimatedCompletionTime:
        withdrawal.estimatedCompletionTime?.toISOString() || '',
    };
  }

  @Get('my-subscriptions')
  @Throttle({ rpc: { limit: 10, ttl: 60000 } })
  @UseGuards(JwtAuthGuard, RpcThrottleGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user subscriptions' })
  @ApiResponse({ status: 200, description: 'List of user subscriptions' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async getMySubscriptions(
    @CurrentUser() user: { id: string; email: string },
  ): Promise<UserSubscriptionWithLiveBalance[]> {
    return await this.savingsService.findMySubscriptions(user.id);
  }

  @Get('my-goals')
  @Throttle({ rpc: { limit: 10, ttl: 60000 } })
  @UseGuards(JwtAuthGuard, RpcThrottleGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary:
      'Get current user savings goals enriched with live Soroban balance progress',
  })
  @ApiResponse({
    status: 200,
    description:
      'List of savings goals with current balance and percentage completion',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async getMyGoals(
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoalProgress[]> {
    return await this.savingsService.findMyGoals(user.id);
  }

  @Post('goals')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Create a new savings goal' })
  @ApiBody({ type: CreateGoalDto })
  @ApiResponse({
    status: 201,
    description: 'Savings goal created',
    type: SavingsGoal,
  })
  @ApiResponse({ status: 400, description: 'Invalid goal data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createGoal(
    @Body() dto: CreateGoalDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoal> {
    return await this.savingsService.createGoal(
      user.id,
      dto.goalName,
      dto.targetAmount,
      dto.targetDate,
      dto.metadata,
    );
  }

  @Patch('goals/:id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update a savings goal (user-scoped via JwtAuthGuard)',
    description:
      'Update goal details. Prevents IDOR by validating goal ownership via userId from JWT token.',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Goal UUID',
  })
  @ApiBody({ type: UpdateGoalDto })
  @ApiResponse({
    status: 200,
    description: 'Goal updated',
    type: SavingsGoal,
  })
  @ApiResponse({ status: 400, description: 'Invalid goal data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Goal not found' })
  async updateGoal(
    @Param('id') id: string,
    @Body() dto: UpdateGoalDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoal> {
    return await this.savingsService.updateGoal(id, user.id, dto);
  }

  @Delete('goals/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Delete a savings goal (user-scoped via JwtAuthGuard)',
    description:
      'Delete a goal. Prevents IDOR by validating goal ownership via userId from JWT token.',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Goal UUID',
  })
  @ApiResponse({ status: 204, description: 'Goal deleted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Goal not found' })
  async deleteGoal(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<void> {
    return await this.savingsService.deleteGoal(id, user.id);
  }

  // ── Milestone endpoints (#532) ───────────────────────────────────────────────

  @Get('goals/:id/milestones')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get milestone history for a savings goal' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Goal UUID',
  })
  @ApiResponse({
    status: 200,
    description: 'List of milestones ordered by percentage',
    type: [MilestoneResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Goal not found' })
  async getMilestones(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoalMilestone[]> {
    return this.milestoneService.getMilestones(id, user.id);
  }

  @Post('goals/:id/milestones/custom')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Add a custom milestone to a savings goal' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Goal UUID',
  })
  @ApiBody({ type: CreateCustomMilestoneDto })
  @ApiResponse({
    status: 201,
    description: 'Custom milestone created',
    type: MilestoneResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Milestone at this percentage already exists',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Goal not found' })
  async addCustomMilestone(
    @Param('id') id: string,
    @Body() dto: CreateCustomMilestoneDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoalMilestone> {
    return this.milestoneService.addCustomMilestone(
      id,
      user.id,
      dto.percentage,
      dto.label,
    );
  }

  // ── Auto-Deposit (#534) ────────────────────────────────────────────────────

  @Post('auto-deposit/create')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Create a recurring auto-deposit schedule' })
  @ApiBody({ type: CreateAutoDepositDto })
  @ApiResponse({
    status: 201,
    description: 'Schedule created',
    type: AutoDepositResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid schedule data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createAutoDeposit(
    @Body() dto: CreateAutoDepositDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<AutoDepositSchedule> {
    return this.autoDepositService.create(user.id, dto);
  }

  @Get('auto-deposit')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'List all auto-deposit schedules for the current user',
  })
  @ApiResponse({
    status: 200,
    description: 'List of schedules',
    type: [AutoDepositResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getAutoDeposits(
    @CurrentUser() user: { id: string; email: string },
  ): Promise<AutoDepositSchedule[]> {
    return this.autoDepositService.findAllForUser(user.id);
  }

  @Patch('auto-deposit/:id/pause')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Pause an auto-deposit schedule' })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({
    status: 200,
    description: 'Schedule paused',
    type: AutoDepositResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Schedule not found' })
  async pauseAutoDeposit(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<AutoDepositSchedule> {
    return this.autoDepositService.pause(id, user.id);
  }

  @Delete('auto-deposit/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Cancel an auto-deposit schedule' })
  @ApiParam({ name: 'id', type: 'string', format: 'uuid' })
  @ApiResponse({ status: 204, description: 'Schedule cancelled' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Schedule not found' })
  async cancelAutoDeposit(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<void> {
    return this.autoDepositService.cancel(id, user.id);
  }
}
