import {
  Controller,
  Get,
  Patch,
  Delete,
  Param,
  Body,
  UseGuards,
  Request,
  Post,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  FileTypeValidator,
  ClassSerializerInterceptor,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { StorageService } from '../storage/storage.service';
import { UserService } from './user.service';
import { SavingsService } from '../blockchain/savings.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { NetWorthDto } from './dto/net-worth.dto';
import { UserProfileResponseDto } from './dto/user-profile-response.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';

import { FileValidator } from '@nestjs/common';

class ImageTypeValidator extends FileValidator {
  constructor() {
    super({});
  }

  isValid(file: Express.Multer.File): boolean {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    return allowedTypes.includes(file.mimetype);
  }

  buildErrorMessage(): string {
    return 'Invalid file type. Only jpeg, png, and webp are allowed.';
  }
}

class KycDocumentValidator extends FileValidator {
  constructor() {
    super({});
  }

  isValid(file: Express.Multer.File): boolean {
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
  getMe(@CurrentUser() user: { id: string }) {
    return this.userService.findById(user.id);
  }

  @Get('me/net-worth')
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
    const walletPercentage = totalNetWorth > 0 ? (walletBalance / totalNetWorth) * 100 : 0;
    const savingsPercentage = totalNetWorth > 0 ? (totalSavings / totalNetWorth) * 100 : 0;

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
  findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }

  @Patch('me')
  updateMe(@CurrentUser() user: { id: string }, @Body() dto: UpdateUserDto) {
    return this.userService.update(user.id, dto);
  }

  @Delete('me')
  deleteMe(@CurrentUser() user: { id: string }) {
    return this.userService.remove(user.id);
  }

  @Post('avatar')
  @UseInterceptors(FileInterceptor('file'))
  async uploadAvatar(
    @CurrentUser() user: { id: string },
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 1024 * 1024 * 5 }), // 5MB
          new ImageTypeValidator(),
        ],
      }),
    )
    file: Express.Multer.File,
  ) {
    const avatarUrl = await this.storageService.saveFile(file);
    return this.userService.updateAvatar(user.id, avatarUrl);
  }

  @Post('me/kyc-docs')
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
    file: Express.Multer.File,
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
