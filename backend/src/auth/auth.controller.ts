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
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
  RegisterDto,
  LoginDto,
  GetNonceDto,
  VerifySignatureDto,
  LinkWalletDto,
} from './dto/auth.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new email/password account' })
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login and receive a JWT' })
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Get('nonce')
  @ApiOperation({ summary: 'Generate a one-time nonce for wallet signature' })
  getNonce(@Query('publicKey') publicKey: string) {
    return this.authService.generateNonce(publicKey);
  }

  @Post('verify-signature')
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
  @ApiResponse({ status: 401, description: 'Invalid or missing JWT / bad signature' })
  @ApiResponse({ status: 409, description: 'Wallet already linked to an account' })
  linkWallet(@Request() req: { user: { id: string } }, @Body() dto: LinkWalletDto) {
    return this.authService.linkWallet(req.user.id, dto);
  }
}

