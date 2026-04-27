import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../../common/guards/roles.guard';
import { CurrentUser } from '../../../common/decorators/current-user.decorator';
import { Roles } from '../../../common/decorators/roles.decorator';
import { Role } from '../../../common/enums/role.enum';
import { RewardsChallengesService } from '../services/rewards-challenges.service';
import {
  CreateChallengeDto,
  UpdateChallengeDto,
  GetActiveChallengesQueryDto,
  ChallengeResponseDto,
  UserChallengeResponseDto,
  JoinChallengeDto,
} from '../dto/challenge.dto';
import { UserChallengeStatus } from '../entities/user-challenge.entity';

@ApiTags('rewards/challenges')
@Controller('rewards/challenges')
export class RewardsChallengesController {
  constructor(
    private readonly rewardsChallengesService: RewardsChallengesService,
  ) {}

  /**
   * GET /rewards/challenges/active
   * Get all active challenges (public or authenticated)
   */
  @Get('active')
  @ApiOperation({
    summary: 'Get all active challenges',
    description:
      'Retrieve all currently active challenges. If authenticated, includes user participation status.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of active challenges',
    type: [ChallengeResponseDto],
  })
  @ApiQuery({
    name: 'type',
    required: false,
    enum: [
      'deposit_streak',
      'goal_creation',
      'referral',
      'savings_target',
      'transaction_count',
    ],
  })
  @ApiQuery({ name: 'category', required: false, type: String })
  @ApiQuery({ name: 'featured', required: false, type: Boolean })
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 20 })
  @ApiQuery({ name: 'offset', required: false, type: Number, example: 0 })
  async getActiveChallenges(
    @Query() query: GetActiveChallengesQueryDto,
    @CurrentUser() user?: { id: string },
  ) {
    return this.rewardsChallengesService.getActiveChallenges(query, user?.id);
  }

  /**
   * GET /rewards/challenges/:id
   * Get a specific challenge by ID
   */
  @Get(':id')
  @ApiOperation({
    summary: 'Get challenge by ID',
    description: 'Retrieve details of a specific challenge',
  })
  @ApiResponse({
    status: 200,
    description: 'Challenge details',
    type: ChallengeResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Challenge not found' })
  async getChallengeById(
    @Param('id') challengeId: string,
    @CurrentUser() user?: { id: string },
  ) {
    return this.rewardsChallengesService.getChallengeById(
      challengeId,
      user?.id,
    );
  }

  /**
   * POST /rewards/challenges/:id/join
   * Join a challenge (requires authentication)
   */
  @Post(':id/join')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Join a challenge',
    description: 'Opt into an active challenge',
  })
  @ApiResponse({
    status: 201,
    description: 'Successfully joined challenge',
    type: UserChallengeResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request (challenge not active, already joined, etc.)',
  })
  @ApiResponse({ status: 404, description: 'Challenge not found' })
  @ApiResponse({ status: 409, description: 'Already joined this challenge' })
  async joinChallenge(
    @Param('id') challengeId: string,
    @CurrentUser() user: { id: string },
    @Body() dto: JoinChallengeDto,
  ) {
    return this.rewardsChallengesService.joinChallenge(user.id, challengeId);
  }

  /**
   * GET /rewards/challenges/my/active
   * Get user's active challenges
   */
  @Get('my/active')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get my active challenges',
    description: 'Retrieve all challenges the authenticated user has joined',
  })
  @ApiResponse({
    status: 200,
    description: 'List of user challenges',
    type: [UserChallengeResponseDto],
  })
  async getMyActiveChallenges(@CurrentUser() user: { id: string }) {
    return this.rewardsChallengesService.getUserChallenges(
      user.id,
      UserChallengeStatus.ACTIVE,
    );
  }

  /**
   * GET /rewards/challenges/my/all
   * Get all user's challenges (active, completed, expired)
   */
  @Get('my/all')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get all my challenges',
    description:
      'Retrieve all challenges the authenticated user has participated in',
  })
  @ApiResponse({
    status: 200,
    description: 'List of all user challenges',
    type: [UserChallengeResponseDto],
  })
  async getAllMyChallenges(@CurrentUser() user: { id: string }) {
    return this.rewardsChallengesService.getUserChallenges(user.id);
  }

  // ==================== ADMIN ENDPOINTS ====================

  /**
   * POST /rewards/challenges/admin/create
   * Create a new challenge (Admin only)
   */
  @Post('admin/create')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[Admin] Create a new challenge',
    description: 'Create a new time-bound challenge',
  })
  @ApiResponse({
    status: 201,
    description: 'Challenge created successfully',
  })
  async createChallenge(
    @Body() dto: CreateChallengeDto,
    @CurrentUser() user: { id: string },
  ) {
    return this.rewardsChallengesService.createChallenge(dto, user.id);
  }

  /**
   * PUT /rewards/challenges/admin/:id
   * Update a challenge (Admin only)
   */
  @Put('admin/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '[Admin] Update a challenge',
    description: 'Update challenge details',
  })
  @ApiResponse({
    status: 200,
    description: 'Challenge updated successfully',
  })
  async updateChallenge(
    @Param('id') challengeId: string,
    @Body() dto: UpdateChallengeDto,
  ) {
    return this.rewardsChallengesService.updateChallenge(challengeId, dto);
  }

  /**
   * DELETE /rewards/challenges/admin/:id
   * Delete a challenge (Admin only)
   */
  @Delete('admin/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: '[Admin] Delete a challenge',
    description: 'Delete a challenge (only if no participants)',
  })
  @ApiResponse({
    status: 204,
    description: 'Challenge deleted successfully',
  })
  async deleteChallenge(@Param('id') challengeId: string) {
    await this.rewardsChallengesService.deleteChallenge(challengeId);
  }

  /**
   * POST /rewards/challenges/admin/activate-scheduled
   * Activate scheduled challenges (Admin only)
   */
  @Post('admin/activate-scheduled')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Admin] Activate scheduled challenges',
    description: 'Activate all challenges that have reached their start date',
  })
  async activateScheduledChallenges() {
    await this.rewardsChallengesService.activateScheduledChallenges();
    return { message: 'Scheduled challenges activated' };
  }

  /**
   * POST /rewards/challenges/admin/complete-expired
   * Complete expired challenges (Admin only)
   */
  @Post('admin/complete-expired')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '[Admin] Complete expired challenges',
    description: 'Mark all challenges past their end date as completed',
  })
  async completeExpiredChallenges() {
    await this.rewardsChallengesService.completeExpiredChallenges();
    return { message: 'Expired challenges completed' };
  }
}
