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
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { UserService } from '../user/user.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
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
  @ApiOperation({ summary: 'Approve KYC for a user (admin only)' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'User ID',
  })
  @ApiResponse({ status: 200, description: 'KYC approved' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden — admin role required' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async approveKyc(@Param('id') userId: string) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    return this.userService.approveKyc(userId);
  }

  @Patch('users/:id/kyc/reject')
  @ApiOperation({ summary: 'Reject KYC for a user with a reason (admin only)' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'User ID',
  })
  @ApiBody({ type: RejectKycDto })
  @ApiResponse({ status: 200, description: 'KYC rejected' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden — admin role required' })
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
  @ApiOperation({
    summary: 'Approve or reject KYC in a single call (admin only)',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'User ID',
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['action'],
      properties: {
        action: {
          type: 'string',
          enum: ['approve', 'reject'],
          example: 'approve',
        },
        reason: {
          type: 'string',
          example: 'Document mismatch',
          description: 'Required when action is reject',
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'KYC status updated' })
  @ApiResponse({ status: 400, description: 'Invalid action or missing reason' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden — admin role required' })
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
  getRateLimitSummary() {
    return this.rateLimitMonitor.getViolationSummary();
  }

  @Get('rate-limits/violations')
  @ApiOperation({ summary: 'Get recent rate limit violations' })
  @ApiResponse({ status: 200, description: 'Recent rate limit violations' })
  getRecentViolations(@Query('limit') limit?: string) {
    return this.rateLimitMonitor.getRecentViolations(
      limit ? parseInt(limit, 10) : 50,
    );
  }

  @Get('rate-limits/violations/:userId')
  @ApiOperation({ summary: 'Get rate limit violations for a specific user' })
  @ApiResponse({ status: 200, description: 'User rate limit violations' })
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
