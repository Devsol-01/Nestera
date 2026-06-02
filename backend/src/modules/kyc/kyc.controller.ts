import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { InitiateKycDto } from './dto/initiate-kyc.dto';
import { KycWebhookDto } from './dto/kyc-webhook.dto';
import { KycService } from './kyc.service';

@ApiTags('kyc')
@Controller()
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post('user/kyc/initiate')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Initiate third-party KYC verification' })
  @ApiResponse({ status: 201, description: 'KYC initiated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  initiate(@CurrentUser() user: { id: string }, @Body() dto: InitiateKycDto) {
    return this.kycService.initiateVerification(user.id, dto);
  }

  @Post('webhooks/kyc/status')
  @ApiOperation({ summary: 'Handle KYC provider webhook status updates' })
  @ApiBody({ type: KycWebhookDto })
  @ApiResponse({ status: 201, description: 'Webhook processed' })
  handleStatusWebhook(@Body() dto: KycWebhookDto, @Req() req: Request) {
    return this.kycService.handleWebhook(dto, req.body);
  }

  @Get('user/kyc/verifications')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List current user KYC verification records' })
  @ApiResponse({ status: 200, description: 'User KYC verification records' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyVerifications(@CurrentUser() user: { id: string }) {
    return this.kycService.listUserVerifications(user.id);
  }

  @Get('admin/kyc/reports')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Generate compliance report for regulators' })
  @ApiQuery({
    name: 'regulator',
    required: false,
    type: String,
    example: 'fincen',
  })
  @ApiQuery({
    name: 'period',
    required: false,
    type: String,
    example: 'current-month',
  })
  @ApiResponse({ status: 200, description: 'Compliance report' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden — admin role required' })
  getComplianceReport(
    @Query('regulator') regulator: string,
    @Query('period') period: string,
  ) {
    return this.kycService.getComplianceReport(
      regulator || 'default-regulator',
      period || 'current-month',
    );
  }
}
