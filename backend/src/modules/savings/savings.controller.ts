import {
  Controller,
  Get,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { SavingsService } from './savings.service';
import { SavingsProduct } from './entities/savings-product.entity';
import { UserSubscription } from './entities/user-subscription.entity';
import { SubscribeDto } from './dto/subscribe.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { SavingsGoalProgress } from './savings.service';

@ApiTags('savings')
@Controller('savings')
export class SavingsController {
  constructor(private readonly savingsService: SavingsService) {}

  @Get('products')
  @ApiOperation({ summary: 'List all savings products' })
  @ApiResponse({ status: 200, description: 'List of savings products' })
  async getProducts(): Promise<SavingsProduct[]> {
    return await this.savingsService.findAllProducts(true);
  }

  @Post('subscribe')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Subscribe to a savings product' })
  @ApiBody({ type: SubscribeDto })
  @ApiResponse({ status: 201, description: 'Subscription created', type: UserSubscription })
  @ApiResponse({ status: 400, description: 'Invalid product or amount' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async subscribe(
    @Body() dto: SubscribeDto,
    @CurrentUser() user: { id: string; email: string },
  ): Promise<UserSubscription> {
    return await this.savingsService.subscribe(user.id, dto.productId, dto.amount);
  }

  @Get('my-subscriptions')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user subscriptions' })
  @ApiResponse({ status: 200, description: 'List of user subscriptions' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getMySubscriptions(
    @CurrentUser() user: { id: string; email: string },
  ): Promise<UserSubscription[]> {
    return await this.savingsService.findMySubscriptions(user.id);
  }

  @Get('my-goals')
  @UseGuards(JwtAuthGuard)
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
  async getMyGoals(
    @CurrentUser() user: { id: string; email: string },
  ): Promise<SavingsGoalProgress[]> {
    return await this.savingsService.findMyGoals(user.id);
  }
}
