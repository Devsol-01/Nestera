import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { InitiateKycDto } from './dto/initiate-kyc.dto';
import { KycWebhookDto } from './dto/kyc-webhook.dto';
import {
  UploadKycDocumentDto,
  ReviewKycDocumentDto,
} from './dto/kyc-document.dto';
import { KycService } from './kyc.service';
import { KycDocumentService } from './kyc-document.service';
import { KycDocument } from './entities/kyc-document.entity';

@ApiTags('kyc')
@Controller()
export class KycController {
  constructor(
    private readonly kycService: KycService,
    private readonly kycDocumentService: KycDocumentService,
  ) {}

  @Post('user/kyc/initiate')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Initiate third-party KYC verification' })
  @ApiResponse({ status: 201, description: 'KYC initiated' })
  initiate(@CurrentUser() user: { id: string }, @Body() dto: InitiateKycDto) {
    return this.kycService.initiateVerification(user.id, dto);
  }

  @Post('user/kyc/documents')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.CREATED)
  @Idempotent({ ttlSeconds: 86400 })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['documentType', 'document'],
      properties: {
        documentType: {
          type: 'string',
          enum: [
            'PASSPORT',
            'NATIONAL_ID',
            'DRIVERS_LICENSE',
            'UTILITY_BILL',
            'SELFIE',
          ],
        },
        document: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiOperation({ summary: 'Upload a KYC document with encryption at rest' })
  @UseInterceptors(FileInterceptor('document'))
  async uploadDocument(
    @CurrentUser() user: { id: string },
    @Body() dto: UploadKycDocumentDto,
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: 10 * 1024 * 1024 })],
      }),
    )
    file: any,
  ): Promise<KycDocument> {
    return this.kycDocumentService.uploadDocument(
      user.id,
      dto.documentType,
      file,
    );
  }

  @Get('user/kyc/documents')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List current user KYC documents' })
  getMyDocuments(@CurrentUser() user: { id: string }) {
    return this.kycDocumentService.listUserDocuments(user.id);
  }

  @Post('webhooks/kyc/status')
  @ApiOperation({ summary: 'Handle KYC provider webhook status updates' })
  @ApiResponse({ status: 201, description: 'Webhook processed' })
  handleStatusWebhook(@Body() dto: KycWebhookDto, @Req() req: Request) {
    return this.kycService.handleWebhook(dto, req.body);
  }

  @Get('user/kyc/verifications')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List current user KYC verification records' })
  getMyVerifications(@CurrentUser() user: { id: string }) {
    return this.kycService.listUserVerifications(user.id);
  }

  @Get('admin/kyc/documents/pending')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: list documents pending review' })
  listPendingDocuments() {
    return this.kycDocumentService.listPendingReview();
  }

  @Get('admin/kyc/documents/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: get KYC document details' })
  getDocument(@Param('id') id: string) {
    return this.kycDocumentService.getDocument(id);
  }

  @Patch('admin/kyc/documents/:id/review')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Admin: approve or reject a KYC document' })
  reviewDocument(
    @Param('id') id: string,
    @CurrentUser() admin: { id: string },
    @Body() dto: ReviewKycDocumentDto,
  ) {
    return this.kycDocumentService.reviewDocument(id, admin.id, dto);
  }

  @Get('admin/kyc/reports')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Generate compliance report for regulators' })
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
