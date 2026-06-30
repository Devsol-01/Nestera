import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  Query,
  UseGuards,
  Request,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { TwoFactorService } from './two-factor.service';
import {
  RegisterDto,
  LoginDto,
  GetNonceDto,
  VerifySignatureDto,
  LinkWalletDto,
} from './dto/auth.dto';
import {
  VerifyTwoFactorDto,
  LoginWithTwoFactorDto,
  AdminDisableTwoFactorDto,
} from './dto/two-factor.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly twoFactorService: TwoFactorService,
  ) {}

  @Post('register')
  @Throttle({ auth: { limit: 5, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Register a new email/password account' })
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @Throttle({ auth: { limit: 5, ttl: 15 * 60 * 1000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login and receive a JWT' })
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Get('nonce')
  @Throttle({ auth: { limit: 5, ttl: 15 * 60 * 1000 } })
  @ApiOperation({ summary: 'Generate a one-time nonce for wallet signature' })
  getNonce(@Query('publicKey') publicKey: string) {
    return this.authService.generateNonce(publicKey);
  }

  @Post('verify-signature')
  @Throttle({ auth: { limit: 5, ttl: 15 * 60 * 1000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify wallet signature and receive a JWT' })
  verifySignature(@Body() dto: VerifySignatureDto) {
    return this.authService.verifySignature(dto);
  }

  /**
   * POST /auth/link-wallet
   *
   * Links a Stellar wallet address to the currently authenticated email account.
   *
   * Pre-conditions (enforced by this endpoint):
   *  - Caller must provide a valid Bearer JWT (JwtAuthGuard)
   *  - publicKey must be a valid Stellar Ed25519 public key
   *  - signature must be a valid Ed25519 signature of `nonce` by the wallet's secret key
   *  - publicKey must not already be linked to ANY account (returns 409 if so)
   */
  @Post('link-wallet')
  @Throttle({ 'wallet-link': { limit: 5, ttl: 60 * 60 * 1000 } })
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Link a Stellar wallet address to the authenticated email account',
    description:
      '1. Call GET /auth/nonce?publicKey=<key> to get a fresh nonce. ' +
      '2. Sign the nonce bytes with the wallet secret key (Ed25519). ' +
      '3. POST { publicKey, nonce, signature } with your Bearer token.',
  })
  @ApiResponse({ status: 200, description: 'Wallet linked successfully' })
  @ApiResponse({ status: 400, description: 'Invalid public key format' })
  @ApiResponse({
    status: 401,
    description: 'Invalid or missing JWT / bad signature',
  })
  @ApiResponse({
    status: 409,
    description: 'Wallet already linked to an account',
  })
  linkWallet(
    @Request() req: { user: { id: string } },
    @Body() dto: LinkWalletDto,
  ) {
    return this.authService.linkWallet(req.user.id, dto);
  }

  // --- Two-Factor Authentication Endpoints ---

  @Post('2fa/enable')
  @Throttle({ otp: { limit: 3, ttl: 15 * 60 * 1000 } })
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Enable 2FA - generates secret and backup codes',
    description:
      'Returns a TOTP secret, otpauth:// URL for QR code generation, and backup codes. ' +
      'Call POST /auth/2fa/verify with a valid token to activate.',
  })
  @ApiResponse({
    status: 201,
    description: 'Secret and backup codes generated',
  })
  @ApiResponse({ status: 400, description: '2FA already enabled' })
  enable2fa(@Request() req: { user: { id: string } }) {
    return this.twoFactorService.enable(req.user.id);
  }

  @Post('2fa/verify')
  @Throttle({ otp: { limit: 3, ttl: 15 * 60 * 1000 } })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verify and activate 2FA with a TOTP token',
    description:
      'After enabling, submit a token from your authenticator app to confirm setup.',
  })
  @ApiResponse({ status: 200, description: '2FA activated' })
  @ApiResponse({ status: 401, description: 'Invalid token' })
  verify2fa(
    @Request() req: { user: { id: string } },
    @Body() dto: VerifyTwoFactorDto,
  ) {
    return this.twoFactorService.verify(req.user.id, dto.token);
  }

  @Post('2fa/validate')
  @Throttle({ auth: { limit: 5, ttl: 15 * 60 * 1000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Complete login with 2FA token',
    description:
      'When login returns requiresTwoFactor: true, call this endpoint with the userId and TOTP token.',
  })
  @ApiResponse({ status: 200, description: 'JWT returned on success' })
  @ApiResponse({ status: 401, description: 'Invalid 2FA token' })
  async validate2fa(
    @Body('userId') userId: string,
    @Body() dto: LoginWithTwoFactorDto,
  ) {
    const valid = await this.twoFactorService.validateLogin(userId, dto.token);
    if (!valid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }
    return this.twoFactorService.completeLogin(userId);
  }

  @Post('2fa/disable')
  @Throttle({ otp: { limit: 3, ttl: 15 * 60 * 1000 } })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Disable 2FA for your account' })
  @ApiResponse({ status: 200, description: '2FA disabled' })
  @ApiResponse({ status: 400, description: '2FA not enabled' })
  disable2fa(@Request() req: { user: { id: string } }) {
    return this.twoFactorService.disable(req.user.id);
  }

  @Post('2fa/admin-disable')
  @Throttle({ otp: { limit: 3, ttl: 15 * 60 * 1000 } })
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Admin: disable 2FA for a locked account',
    description: 'Requires ADMIN role',
  })
  @ApiResponse({ status: 200, description: '2FA disabled for target user' })
  @ApiResponse({ status: 400, description: '2FA not enabled for user' })
  adminDisable2fa(
    @Request() req: { user: { id: string; role: string } },
    @Body() dto: AdminDisableTwoFactorDto,
  ) {
    if (req.user.role !== 'ADMIN') {
      throw new UnauthorizedException('Admin access required');
    }
    return this.twoFactorService.adminDisable(dto.userId);
  }

  @Get('2fa/status')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Check if 2FA is enabled for your account' })
  @ApiResponse({ status: 200, description: '2FA status' })
  get2faStatus(@Request() req: { user: { id: string } }) {
    return this.twoFactorService.getStatus(req.user.id);
  }
}
