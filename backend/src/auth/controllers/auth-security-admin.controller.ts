import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Role } from '../../common/enums/role.enum';
import { AuthRateLimitService } from '../services/auth-rate-limit.service';

@ApiTags('auth-security-admin')
@Controller('auth/admin/security')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AuthSecurityAdminController {
  constructor(private readonly authRateLimitService: AuthRateLimitService) {}

  @Get('metrics')
  @ApiOperation({ summary: 'Get authentication security metrics' })
  @ApiResponse({
    status: 200,
    description: 'Security metrics retrieved successfully',
  })
  async getSecurityMetrics() {
    return this.authRateLimitService.getSecurityMetrics();
  }

  @Get('ip/:ip/status')
  @ApiOperation({ summary: 'Check if an IP is banned' })
  @ApiParam({ name: 'ip', description: 'IP address to check' })
  @ApiResponse({ status: 200, description: 'IP status retrieved' })
  async getIpStatus(@Param('ip') ip: string) {
    const isBanned = await this.authRateLimitService.isIpBanned(ip);
    const banInfo = await this.authRateLimitService.getIpBanInfo(ip);
    const attemptCount = await this.authRateLimitService.getIpAttemptCount(ip);

    return {
      ip,
      isBanned,
      banInfo,
      attemptCount,
    };
  }

  @Delete('ip/:ip/ban')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Unban an IP address' })
  @ApiParam({ name: 'ip', description: 'IP address to unban' })
  @ApiResponse({ status: 200, description: 'IP unbanned successfully' })
  async unbanIp(@Param('ip') ip: string) {
    await this.authRateLimitService.unbanIp(ip);
    return {
      message: `IP ${ip} has been unbanned`,
      ip,
    };
  }

  @Get('account/:identifier/status')
  @ApiOperation({ summary: 'Check if an account is locked' })
  @ApiParam({
    name: 'identifier',
    description: 'Email or public key to check',
  })
  @ApiResponse({ status: 200, description: 'Account status retrieved' })
  async getAccountStatus(@Param('identifier') identifier: string) {
    const isLocked =
      await this.authRateLimitService.isAccountLocked(identifier);
    const lockInfo =
      await this.authRateLimitService.getAccountLockInfo(identifier);
    const failedAttempts =
      await this.authRateLimitService.getFailedAttemptCount(identifier);

    return {
      identifier,
      isLocked,
      lockInfo,
      failedAttempts,
    };
  }

  @Delete('account/:identifier/lock')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Unlock an account' })
  @ApiParam({
    name: 'identifier',
    description: 'Email or public key to unlock',
  })
  @ApiResponse({ status: 200, description: 'Account unlocked successfully' })
  async unlockAccount(@Param('identifier') identifier: string) {
    await this.authRateLimitService.unlockAccount(identifier);
    return {
      message: `Account ${identifier} has been unlocked`,
      identifier,
    };
  }

  @Get('failed-attempts/:identifier')
  @ApiOperation({ summary: 'Get failed attempt count for an identifier' })
  @ApiParam({
    name: 'identifier',
    description: 'Email or public key',
  })
  @ApiResponse({ status: 200, description: 'Failed attempts retrieved' })
  async getFailedAttempts(@Param('identifier') identifier: string) {
    const count =
      await this.authRateLimitService.getFailedAttemptCount(identifier);
    return {
      identifier,
      failedAttempts: count,
    };
  }

  @Delete('failed-attempts/:identifier')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Clear failed attempts for an identifier' })
  @ApiParam({
    name: 'identifier',
    description: 'Email or public key',
  })
  @ApiResponse({ status: 200, description: 'Failed attempts cleared' })
  async clearFailedAttempts(@Param('identifier') identifier: string) {
    await this.authRateLimitService.clearFailedAttempts(identifier);
    return {
      message: `Failed attempts cleared for ${identifier}`,
      identifier,
    };
  }
}
