import {
  Controller,
  Get,
  Body,
  Delete,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { ExperimentsService } from '../savings/experiments.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import {
  ProductCapacitySnapshot,
  SavingsService,
} from '../savings/savings.service';
import { PageOptionsDto } from '../../common/dto/page-options.dto';
import { CreateProductDto } from '../savings/dto/create-product.dto';
import { UpdateProductDto } from '../savings/dto/update-product.dto';
import { AdminSavingsService } from './admin-savings.service';

@ApiTags('admin/savings')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller({ path: 'admin/savings/products', version: '1' })
export class AdminSavingsController {
  constructor(
    private readonly savingsService: SavingsService,
    private readonly experimentsService: ExperimentsService,
    private readonly adminSavingsService: AdminSavingsService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Create a savings product' })
  createProduct(@Body() dto: CreateProductDto) {
    return this.adminSavingsService.createProduct(dto);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a savings product' })
  updateProduct(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateProductDto,
  ) {
    return this.adminSavingsService.updateProduct(id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Soft-delete (archive) a savings product' })
  archiveProduct(@Param('id', ParseUUIDPipe) id: string) {
    return this.adminSavingsService.archiveProduct(id);
  }

  @Patch(':id/activate')
  @ApiOperation({ summary: 'Enable or disable a savings product' })
  setActive(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: { isActive: boolean },
  ) {
    return this.adminSavingsService.setActive(id, body.isActive);
  }

  @Get(':id/subscribers')
  @ApiOperation({ summary: 'List all subscribers for a savings product' })
  @ApiQuery({ name: 'page', required: false })
  @ApiQuery({ name: 'limit', required: false })
  getSubscribers(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() opts: PageOptionsDto,
  ) {
    return this.adminSavingsService.getSubscribers(id, opts);
  }

  @Post('products/:id/subscriptions/override')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Create a subscription with admin override for limit checks',
  })
  @ApiResponse({
    status: 201,
    description: 'Subscription created with admin override',
  })
  async createSubscriptionOverride(
    @Param('id') id: string,
    @Body() body: { userId: string; amount: number },
    @CurrentUser() _admin: { id: string; email: string },
  ) {
    return await this.savingsService.subscribe(
      body.userId,
      id,
      body.amount,
      true,
    );
  }

  @Post('experiments')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Create a savings product experiment (admin)' })
  @ApiResponse({ status: 201, description: 'Experiment created' })
  async createExperiment(
    @Body()
    body: {
      key: string;
      name: string;
      description?: string;
      productId?: string;
      variants: Array<{
        key: string;
        weight: number;
        config: Record<string, any>;
      }>;
      configuration?: Record<string, any>;
      minSampleSize?: number;
      confidenceLevel?: number;
      status?: 'DRAFT' | 'ACTIVE' | 'PAUSED' | 'COMPLETED';
    },
  ) {
    return await this.experimentsService.createExperiment(body);
  }

  @Post('experiments/:id/assignments')
  @ApiOperation({ summary: 'Assign a user to an experiment variant (admin)' })
  @ApiResponse({ status: 200, description: 'User assigned to a variant' })
  async assignExperimentUser(
    @Param('id') id: string,
    @Body() body: { userId: string },
  ) {
    return await this.experimentsService.assignUser(id, body.userId);
  }

  @Post('experiments/:id/conversions')
  @ApiOperation({ summary: 'Track an experiment conversion event (admin)' })
  @ApiResponse({ status: 200, description: 'Conversion tracked' })
  async trackExperimentConversion(
    @Param('id') id: string,
    @Body()
    body: {
      userId: string;
      value?: number;
      metadata?: Record<string, any>;
    },
  ) {
    return await this.experimentsService.trackConversion(
      id,
      body.userId,
      body.value ?? 1,
      body.metadata,
    );
  }

  @Post('experiments/:id/dashboard')
  @ApiOperation({ summary: 'Get experiment dashboard statistics (admin)' })
  @ApiResponse({ status: 200, description: 'Experiment dashboard' })
  async getExperimentDashboard(
    @Param('id') id: string,
  ): Promise<Record<string, unknown>> {
    return await this.experimentsService.getDashboard(id);
  }

  @Post('products/:id/migrations')
  @ApiOperation({
    summary: 'Migrate active subscriptions to another product version (admin)',
  })
  @ApiResponse({
    status: 200,
    description: 'Subscriptions migrated to the target product version',
  })
  async migrateProductSubscriptions(
    @Param('id') id: string,
    @Body() body: { targetProductId: string; subscriptionIds?: string[] },
    @CurrentUser() user: { id: string; email: string },
  ): Promise<{ migratedCount: number; targetProductId: string }> {
    const result = await this.savingsService.migrateSubscriptionsToVersion(
      id,
      body.targetProductId,
      user.id,
      body.subscriptionIds,
    );

    return {
      migratedCount: result.migratedCount,
      targetProductId: result.targetProduct.id,
    };
  }

  @Get('products/:id/capacity-metrics')
  @ApiOperation({ summary: 'Get live capacity utilization metrics (admin)' })
  @ApiResponse({
    status: 200,
    description: 'Live capacity metrics',
  })
  async getCapacityMetrics(
    @Param('id') id: string,
  ): Promise<ProductCapacitySnapshot> {
    return await this.savingsService.getProductCapacitySnapshot(id);
  }
}
