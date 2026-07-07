import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  Query,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
} from '@nestjs/swagger';
import { UserService } from '../user/user.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AdminHighRisk } from '../../common/decorators/admin-high-risk.decorator';
import { Role } from '../../common/enums/role.enum';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { RateLimitMonitorService } from '../../common/services/rate-limit-monitor.service';
import { ApproveKycDto, RejectKycDto } from '../user/dto/update-user.dto';

@ApiTags('admin')
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminController {
  constructor(
    private readonly userService: UserService,
    private readonly rateLimitMonitor: RateLimitMonitorService,
  ) {}

  @Patch('users/:id/kyc/approve')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Approve KYC for a user',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 200, description: 'KYC approved' })
  @ApiResponse({ status: 400, description: 'User ID is required' })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  @ApiParam({ name: 'id', description: 'User UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async approveKyc(@Param('id') userId: string) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    return this.userService.approveKyc(userId);
  }

  @Patch('users/:id/kyc/reject')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Reject KYC for a user',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 200, description: 'KYC rejected' })
  @ApiResponse({
    status: 400,
    description: 'User ID or rejection reason missing',
  })
  @ApiParam({ name: 'id', description: 'User UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async rejectKyc(@Param('id') userId: string, @Body() dto: RejectKycDto) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    if (!dto.reason) {
      throw new BadRequestException('Rejection reason is required');
    }
    return this.userService.rejectKyc(userId, dto.reason);
  }

  @Patch('users/:id/kyc')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Update KYC status (approve or reject)',
    description:
      'High-risk operation. Requires confirmation on first attempt. Set `action` to `"approve"` or `"reject"`. Reason is required for rejection.',
  })
  @ApiResponse({ status: 200, description: 'KYC status updated' })
  @ApiResponse({
    status: 400,
    description: 'Invalid action or missing parameters',
  })
  @ApiParam({ name: 'id', description: 'User UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async updateKycStatus(
    @Param('id') userId: string,
    @Body() body: { action: 'approve' | 'reject'; reason?: string },
  ) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }

    if (body.action === 'approve') {
      return this.userService.approveKyc(userId);
    } else if (body.action === 'reject') {
      if (!body.reason) {
        throw new BadRequestException('Rejection reason is required');
      }
      return this.userService.rejectKyc(userId, body.reason);
    } else {
      throw new BadRequestException(
        'Action must be either "approve" or "reject"',
      );
    }
  }

  @Get('rate-limits/summary')
  @ApiOperation({ summary: 'Get rate limit violation summary' })
  @ApiResponse({ status: 200, description: 'Rate limit violation summary' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getRateLimitSummary() {
    return this.rateLimitMonitor.getViolationSummary();
  }

  @Get('rate-limits/violations')
  @ApiOperation({ summary: 'Get recent rate limit violations' })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Max results (default 50)',
    type: Number,
  })
  @ApiResponse({ status: 200, description: 'Recent rate limit violations' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getRecentViolations(@Query('limit') limit?: string) {
    return this.rateLimitMonitor.getRecentViolations(
      limit ? parseInt(limit, 10) : 50,
    );
  }

  @Get('rate-limits/violations/:userId')
  @ApiOperation({ summary: 'Get rate limit violations for a specific user' })
  @ApiParam({ name: 'userId', description: 'User UUID' })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Max results (default 50)',
    type: Number,
  })
  @ApiResponse({ status: 200, description: 'User rate limit violations' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getUserViolations(
    @Param('userId') userId: string,
    @Query('limit') limit?: string,
  ) {
    return this.rateLimitMonitor.getViolationsByUser(
      userId,
      limit ? parseInt(limit, 10) : 50,
    );
  }
}
