import {
  Controller,
  Patch,
  Param,
  Body,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { ApproveKycDto, RejectKycDto } from '../user/dto/update-user.dto';

@Controller('admin')
@UseGuards(JwtAuthGuard)
export class AdminController {
  constructor(private readonly userService: UserService) {}

  @Patch('users/:id/kyc/approve')
  async approveKyc(@Param('id') userId: string) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    return this.userService.approveKyc(userId);
  }

  @Patch('users/:id/kyc/reject')
  async rejectKyc(
    @Param('id') userId: string,
    @Body() dto: RejectKycDto,
  ) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }
    if (!dto.reason) {
      throw new BadRequestException('Rejection reason is required');
    }
    return this.userService.rejectKyc(userId, dto.reason);
  }

  @Patch('users/:id/kyc')
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
}
