import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RewardsDashboardDto } from './dto/rewards-dashboard.dto';
import { RewardsService } from './rewards.service';

@ApiTags('rewards')
@Controller('rewards')
export class RewardsController {
  constructor(private readonly rewardsService: RewardsService) {}

  @Get('dashboard')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get the rewards dashboard for the current user' })
  @ApiOkResponse({ type: RewardsDashboardDto })
  getDashboard(@CurrentUser() user: { id: string }) {
    return this.rewardsService.getDashboard(user.id);
  }
}
