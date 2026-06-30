import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  UseGuards,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AdminHighRisk } from '../../common/decorators/admin-high-risk.decorator';
import { Role } from '../../common/enums/role.enum';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { User } from '../user/entities/user.entity';
import { AdminWithdrawalService } from './admin-withdrawal.service';
import { PageOptionsDto } from '../../common/dto/page-options.dto';
import { RejectWithdrawalDto } from './dto/reject-withdrawal.dto';
import { WithdrawalStatsResponseDto } from './dto/withdrawal-stats.dto';

@ApiTags('admin-withdrawals')
@ApiBearerAuth()
@Controller({ path: 'admin/withdrawals', version: '1' })
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
export class AdminWithdrawalController {
  constructor(
    private readonly adminWithdrawalService: AdminWithdrawalService,
  ) {}

  @Get('stats')
  @ApiOperation({ summary: 'Get withdrawal statistics' })
  @ApiResponse({
    status: 200,
    description: 'Withdrawal statistics',
    type: WithdrawalStatsResponseDto,
  })
  async getStats() {
    return this.adminWithdrawalService.getStats();
  }

  @Get('pending')
  @ApiOperation({ summary: 'List pending withdrawal requests' })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of pending withdrawals',
  })
  async listPending(@Query() opts: PageOptionsDto) {
    return this.adminWithdrawalService.listPending(opts);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get withdrawal request detail' })
  @ApiResponse({ status: 200, description: 'Withdrawal request detail' })
  @ApiResponse({ status: 404, description: 'Withdrawal request not found' })
  async getDetail(@Param('id', ParseUUIDPipe) id: string) {
    return this.adminWithdrawalService.getDetail(id);
  }

  @Post(':id/approve')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Approve a pending withdrawal request',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 200, description: 'Withdrawal request approved' })
  @ApiResponse({
    status: 400,
    description: 'Withdrawal request is not in PENDING status',
  })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  @ApiResponse({ status: 404, description: 'Withdrawal request not found' })
  async approve(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() actor: User,
  ) {
    return this.adminWithdrawalService.approve(id, actor);
  }

  @Post(':id/reject')
  @AdminHighRisk()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({
    summary: 'Reject a pending withdrawal request',
    description: 'High-risk operation. Requires confirmation on first attempt.',
  })
  @ApiResponse({ status: 200, description: 'Withdrawal request rejected' })
  @ApiResponse({
    status: 400,
    description:
      'Withdrawal request is not in PENDING status or invalid reason',
  })
  @ApiResponse({ status: 403, description: 'Confirmation required' })
  @ApiResponse({ status: 404, description: 'Withdrawal request not found' })
  async reject(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: RejectWithdrawalDto,
    @CurrentUser() actor: User,
  ) {
    return this.adminWithdrawalService.reject(id, body.reason, actor);
  }
}
