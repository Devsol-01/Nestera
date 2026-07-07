import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { ReferralsService } from './referrals.service';
import {
  CreateReferralDto,
  ReferralStatsDto,
  ReferralResponseDto,
} from './dto/referral.dto';

@ApiTags('referrals')
@Controller('referrals')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class ReferralsController {
  constructor(private readonly referralsService: ReferralsService) {}

  @Post('generate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Generate a referral code for the current user' })
  @ApiResponse({
    status: 201,
    description: 'Referral code generated successfully',
  })
  async generateReferralCode(@Request() req, @Body() dto: CreateReferralDto) {
    const referral = await this.referralsService.generateReferralCode(
      req.user.userId,
      dto.campaignId,
    );
    return {
      referralCode: referral.referralCode,
      id: referral.id,
      createdAt: referral.createdAt,
    };
  }

  @Get('stats')
  @ApiOperation({ summary: "Get current user's referral statistics" })
  @ApiResponse({ status: 200, type: ReferralStatsDto })
  async getReferralStats(@Request() req): Promise<ReferralStatsDto> {
    return this.referralsService.getReferralStats(req.user.userId);
  }

  @Get('my-referrals')
  @ApiOperation({ summary: 'Get list of users referred by current user' })
  @ApiResponse({ status: 200, type: [ReferralResponseDto] })
  async getMyReferrals(@Request() req) {
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

  @Post('check-completion')
  @HttpCode(HttpStatus.OK)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Internal: Check if referral should be completed after deposit',
  })
  async checkReferralCompletion(
    @Body() body: { userId: string; depositAmount: string },
  ) {
    await this.referralsService.checkAndCompleteReferral(
      body.userId,
      body.depositAmount,
    );
    return { message: 'Referral check completed' };
  }
}
