import { Controller, Get, Patch, Query, Body, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from '../../auth/guards/optional-jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RewardsService } from './rewards.service';
import { LeaderboardQueryDto } from './dto/leaderboard-query.dto';
import { UpdateVisibilityDto } from './dto/update-visibility.dto';

@ApiTags('rewards')
@Controller('rewards')
export class RewardsController {
  constructor(private readonly rewardsService: RewardsService) {}

  @Get('leaderboard/points')
  @UseGuards(OptionalJwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Top users ranked by total accumulated points' })
  @ApiResponse({
    status: 200,
    description:
      'Points leaderboard. Authenticated users also receive their own rank.',
  })
  getPointsLeaderboard(
    @Query() query: LeaderboardQueryDto,
    @CurrentUser() user?: { id: string },
  ) {
    return this.rewardsService.getPointsLeaderboard(query, user?.id);
  }

  @Get('leaderboard/streaks')
  @UseGuards(OptionalJwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Top users ranked by longest streak' })
  @ApiResponse({
    status: 200,
    description:
      'Streaks leaderboard. Authenticated users also receive their own rank.',
  })
  getStreaksLeaderboard(
    @Query() query: LeaderboardQueryDto,
    @CurrentUser() user?: { id: string },
  ) {
    return this.rewardsService.getStreaksLeaderboard(query, user?.id);
  }

  @Get('leaderboard/savings')
  @UseGuards(OptionalJwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Top users ranked by total saved amount' })
  @ApiResponse({
    status: 200,
    description:
      'Savings leaderboard. Authenticated users also receive their own rank.',
  })
  getSavingsLeaderboard(
    @Query() query: LeaderboardQueryDto,
    @CurrentUser() user?: { id: string },
  ) {
    return this.rewardsService.getSavingsLeaderboard(query, user?.id);
  }

  @Patch('leaderboard/visibility')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update leaderboard visibility (privacy setting)' })
  @ApiResponse({ status: 200, description: 'Visibility updated' })
  updateVisibility(
    @CurrentUser() user: { id: string },
    @Body() dto: UpdateVisibilityDto,
  ) {
    return this.rewardsService.updateVisibility(
      user.id,
      dto.isLeaderboardVisible,
    );
  }
}
