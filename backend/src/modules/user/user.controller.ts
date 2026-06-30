import {
  Controller,
  Get,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
  Post,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  ClassSerializerInterceptor,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { StorageService } from '../storage/storage.service';
import { UserService } from './user.service';
import { AvatarUploadService } from './avatar-upload.service';
import { SavingsService } from '../blockchain/savings.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { NetWorthDto } from './dto/net-worth.dto';
import { UserProfileResponseDto } from './dto/user-profile-response.dto';
import { AvatarUploadResponseDto } from './dto/avatar-upload-response.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { CorrelationId } from '../../common/decorators/correlation-id.decorator';

import { FileValidator } from '@nestjs/common';

class KycDocumentValidator extends FileValidator {
  constructor() {
    super({});
  }

  isValid(file: any): boolean {
    const allowedTypes = ['application/pdf', 'image/jpeg'];
    return allowedTypes.includes(file.mimetype);
  }

  buildErrorMessage(): string {
    return 'Invalid file type. Only PDF and JPEG formats are allowed for KYC documents.';
  }
}

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly avatarUploadService: AvatarUploadService,
    private readonly storageService: StorageService,
    private readonly savingsService: SavingsService,
  ) {}

  /**
   * GET /users/profile
   *
   * Full hydrated profile for the authenticated user.
   * Used by the frontend dashboard on boot to render the connect-wallet
   * state, voting capabilities, and user details.
   *
   * - Strictly requires a valid Bearer JWT (JwtAuthGuard on the controller).
   * - ClassSerializerInterceptor applied at method level ensures @Exclude()
   *   on UserProfileResponseDto strips password hashes / nonces before the
   *   JSON response is sent.
   * - `walletAddress` is the linked Stellar public key (null if not yet linked).
   * - `daysActive` is computed in UserService; never stored in the DB.
   */
  @Get('profile')
  @UseInterceptors(ClassSerializerInterceptor)
  @ApiOperation({
    summary: "Get the authenticated user's full profile",
    description:
      'Returns id, email, name, bio, avatarUrl, walletAddress (linked Stellar key), ' +
      'role, kycStatus, createdAt, and computed daysActive. ' +
      'Password hashes and internal fields are always excluded.',
  })
  @ApiResponse({
    status: 200,
    description: 'Profile returned successfully',
    type: UserProfileResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid JWT' })
  @ApiResponse({ status: 404, description: 'User not found' })
  getProfile(
    @CurrentUser() user: { id: string },
  ): Promise<UserProfileResponseDto> {
    return this.userService.getProfile(user.id);
  }

  @Get('me')
  @ApiOperation({ summary: 'Get basic info for the authenticated user' })
  @ApiResponse({ status: 200, description: 'User info returned' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMe(@CurrentUser() user: { id: string }) {
    return this.userService.findById(user.id);
  }

  @Get('me/net-worth')
  @ApiOperation({
    summary: 'Get net worth breakdown for the authenticated user',
    description:
      'Returns wallet balance, savings breakdown (flexible/locked), and percentage allocations.',
  })
  @ApiResponse({
    status: 200,
    description: 'Net worth breakdown',
    type: NetWorthDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getNetWorth(@CurrentUser() user: { id: string }): Promise<NetWorthDto> {
    const userEntity = await this.userService.findById(user.id);

    // If user has no public key, return zero balances
    if (!userEntity.publicKey) {
      return this.createZeroNetWorthResponse();
    }

    // Fetch wallet and savings data in parallel
    const [walletBalance, savingsBalance] = await Promise.all([
      this.savingsService.getWalletBalance(userEntity.publicKey),
      this.savingsService.getUserSavingsBalance(userEntity.publicKey),
    ]);

    const totalSavings = savingsBalance.total;
    const totalNetWorth = walletBalance + totalSavings;

    // Calculate percentages
    const walletPercentage =
      totalNetWorth > 0 ? (walletBalance / totalNetWorth) * 100 : 0;
    const savingsPercentage =
      totalNetWorth > 0 ? (totalSavings / totalNetWorth) * 100 : 0;

    return {
      walletBalance,
      savingsFlexible: savingsBalance.flexible,
      savingsLocked: savingsBalance.locked,
      totalSavings,
      totalNetWorth,
      balanceBreakdown: {
        wallet: {
          amount: walletBalance,
          percentage: walletPercentage,
        },
        savings: {
          amount: totalSavings,
          percentage: savingsPercentage,
          flexibleAmount: savingsBalance.flexible,
          lockedAmount: savingsBalance.locked,
        },
      },
    };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a user by ID (admin / internal use)' })
  @ApiParam({ name: 'id', description: 'User UUID' })
  @ApiResponse({ status: 200, description: 'User record' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }

  @Patch('me')
  @ApiOperation({ summary: 'Update the authenticated user profile' })
  @ApiBody({ type: UpdateUserDto })
  @ApiResponse({ status: 200, description: 'Profile updated' })
  @ApiResponse({ status: 400, description: 'Validation error' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  updateMe(@CurrentUser() user: { id: string }, @Body() dto: UpdateUserDto) {
    return this.userService.update(user.id, dto);
  }

  @Delete('me')
  @ApiOperation({ summary: 'Delete the authenticated user account' })
  @ApiResponse({ status: 200, description: 'Account deleted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  deleteMe(@CurrentUser() user: { id: string }) {
    return this.userService.remove(user.id);
  }

  @Post('avatar')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Upload a profile avatar image',
    description:
      'Accepts JPEG, PNG, or WebP up to 5 MB. Validates content and enqueues background processing (resize, EXIF strip). Returns job status for polling.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      properties: { file: { type: 'string', format: 'binary' } },
    },
  })
  @ApiResponse({
    status: 202,
    description:
      'Avatar accepted for processing; poll status endpoint for result',
    type: AvatarUploadResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid file type, size, or content',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: 5 * 1024 * 1024 },
    }),
  )
  async uploadAvatar(
    @CurrentUser() user: { id: string },
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 })],
        fileIsRequired: true,
      }),
    )
    file: any,
    @CorrelationId() correlationId?: string,
  ): Promise<AvatarUploadResponseDto> {
    return this.avatarUploadService.uploadAvatar(user.id, file, correlationId);
  }

  @Get('avatar/status')
  @ApiOperation({
    summary: 'Get latest avatar upload processing status',
    description:
      'Poll this endpoint after uploading an avatar to check processing progress.',
  })
  @ApiResponse({
    status: 200,
    description: 'Latest avatar upload status',
    type: AvatarUploadResponseDto,
  })
  @ApiResponse({ status: 404, description: 'No avatar upload found' })
  async getAvatarStatus(
    @CurrentUser() user: { id: string },
  ): Promise<AvatarUploadResponseDto | null> {
    return this.avatarUploadService.getLatestUploadStatus(user.id);
  }

  @Get('avatar/status/:uploadId')
  @ApiOperation({ summary: 'Get avatar upload processing status by ID' })
  @ApiParam({ name: 'uploadId', description: 'Avatar upload UUID' })
  @ApiResponse({
    status: 200,
    description: 'Avatar upload status',
    type: AvatarUploadResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Avatar upload not found' })
  async getAvatarStatusById(
    @CurrentUser() user: { id: string },
    @Param('uploadId') uploadId: string,
  ): Promise<AvatarUploadResponseDto> {
    return this.avatarUploadService.getUploadStatus(user.id, uploadId);
  }

  @Post('me/kyc-docs')
  @ApiOperation({
    summary: 'Upload a KYC document',
    description:
      'Accepts PDF or JPEG up to 10 MB. Triggers KYC review process.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      properties: { document: { type: 'string', format: 'binary' } },
    },
  })
  @ApiResponse({ status: 201, description: 'KYC document uploaded' })
  @ApiResponse({ status: 400, description: 'Invalid file type or size' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @UseInterceptors(FileInterceptor('document'))
  async uploadKycDocument(
    @CurrentUser() user: { id: string },
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 1024 * 1024 * 10 }), // 10MB
          new KycDocumentValidator(),
        ],
      }),
    )
    file: any,
  ) {
    const kycDocumentUrl = await this.storageService.saveFile(file);
    return this.userService.updateKycDocument(user.id, kycDocumentUrl);
  }

  private createZeroNetWorthResponse(): NetWorthDto {
    return {
      walletBalance: 0,
      savingsFlexible: 0,
      savingsLocked: 0,
      totalSavings: 0,
      totalNetWorth: 0,
      balanceBreakdown: {
        wallet: {
          amount: 0,
          percentage: 0,
        },
        savings: {
          amount: 0,
          percentage: 0,
          flexibleAmount: 0,
          lockedAmount: 0,
        },
      },
    };
  }
}
