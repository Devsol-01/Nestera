import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { ReferralsService } from './referrals.service';
import {
  CreateReferralDto,
  GenerateCustomCodeDto,
  ReferralStatsDto,
  ReferralResponseDto,
} from './dto/referral.dto';

@ApiTags('referrals')
@Controller('users/referrals')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class UserReferralsController {
  constructor(private readonly referralsService: ReferralsService) {}

  @Get('stats')
  @ApiOperation({ summary: 'Get referral metrics for the current user' })
  @ApiResponse({ status: 200, type: ReferralStatsDto })
  getReferralStats(@Request() req): Promise<ReferralStatsDto> {
    return this.referralsService.getReferralStats(req.user.userId);
  }

  @Post('code/generate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Generate a custom referral code' })
  @ApiResponse({ status: 201, description: 'Referral code created' })
  async generateCode(@Request() req, @Body() dto: GenerateCustomCodeDto) {
    const referral = await this.referralsService.generateCustomCode(
      req.user.userId,
      dto.code,
      dto.campaignId,
    );
    return {
      referralCode: referral.referralCode,
      id: referral.id,
      createdAt: referral.createdAt,
    };
  }

  @Get('history')
  @ApiOperation({
    summary: 'View referred users and rewards (conversion funnel)',
  })
  @ApiResponse({ status: 200, type: [ReferralResponseDto] })
  async getReferralHistory(@Request() req) {
    const referrals = await this.referralsService.getUserReferrals(
      req.user.userId,
    );
    return referrals.map((r) => ({
      id: r.id,
      referralCode: r.referralCode,
      status: r.status,
      rewardAmount: r.rewardAmount,
      refereeEmail: r.referee?.email,
      createdAt: r.createdAt,
      completedAt: r.completedAt,
      rewardedAt: r.rewardedAt,
    }));
  }

  @Get('leaderboard')
  @ApiOperation({ summary: 'Get top referrers leaderboard' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  getLeaderboard(@Query('limit') limit?: number) {
    return this.referralsService.getLeaderboard(limit ? Number(limit) : 10);
  }
}
