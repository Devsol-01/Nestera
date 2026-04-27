import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  Inject,
  forwardRef,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../modules/user/user.service';
import {
  RegisterDto,
  LoginDto,
  VerifySignatureDto,
  LinkWalletDto,
} from './dto/auth.dto';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import * as bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import * as StellarSdk from '@stellar/stellar-sdk';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuthRateLimitService } from './services/auth-rate-limit.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly NONCE_TTL = 300000; // 5 minutes in milliseconds
  private readonly RATE_LIMIT_WINDOW = 900000; // 15 minutes in milliseconds
  private readonly MAX_NONCE_REQUESTS = 5; // Max requests per window

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly eventEmitter: EventEmitter2,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly authRateLimitService: AuthRateLimitService,
  ) {}

  async register(dto: RegisterDto) {
    const existingUser = await this.userService.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = await this.userService.create({
      ...dto,
      password: hashedPassword,
    });

    // Apply referral code if provided
    if (dto.referralCode) {
      this.eventEmitter.emit('user.signup-with-referral', {
        userId: user.id,
        referralCode: dto.referralCode,
      });
    }

    return {
      user,
      accessToken: this.generateToken(user.id, user.email, user.role),
    };
  }

  async login(dto: LoginDto, ip?: string) {
    const user = await this.validateUser(dto.email, dto.password);
    if (!user) {
      // Record failed attempt
      if (ip) {
        await this.authRateLimitService.recordFailedAttempt(
          dto.email,
          ip,
          'invalid_credentials',
        );
      }
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear failed attempts on successful login
    await this.authRateLimitService.clearFailedAttempts(dto.email);

    // Check if 2FA is enabled
    const fullUser = await this.userService.findByEmail(dto.email);
    if (fullUser?.twoFactorEnabled) {
      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Please provide your 2FA token',
      };
    }

    return {
      accessToken: this.generateToken(
        user.id,
        user.email,
        user.role,
        user.kycStatus,
      ),
    };
  }

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    if (user && user.password && (await bcrypt.compare(pass, user.password))) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  private generateToken(
    userId: string,
    email: string,
    role = 'USER',
    kycStatus = 'NOT_SUBMITTED',
  ) {
    return this.jwtService.sign({ sub: userId, email, role, kycStatus });
  }

  async generateNonce(publicKey: string): Promise<{ nonce: string }> {
    // Validate Stellar public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    // Implement rate limiting per public key
    const rateLimitKey = `nonce:ratelimit:${publicKey}`;
    const requestCount = await this.cacheManager.get<number>(rateLimitKey);

    if (requestCount && requestCount >= this.MAX_NONCE_REQUESTS) {
      this.logger.warn(
        `Rate limit exceeded for public key: ${publicKey.substring(0, 10)}...`,
      );
      throw new UnauthorizedException(
        `Too many nonce requests. Maximum ${this.MAX_NONCE_REQUESTS} requests per 15 minutes allowed.`,
      );
    }

    // Increment rate limit counter
    const newCount = (requestCount || 0) + 1;
    await this.cacheManager.set(rateLimitKey, newCount, this.RATE_LIMIT_WINDOW);

    // Generate nonce with timestamp for additional validation
    const nonce = randomUUID();
    const timestamp = Date.now();
    const nonceData = { nonce, timestamp };

    // Store nonce in cache with TTL
    const cacheKey = `nonce:${publicKey}`;
    await this.cacheManager.set(cacheKey, nonceData, this.NONCE_TTL);

    this.logger.debug(
      `Nonce generated for public key: ${publicKey.substring(0, 10)}... (TTL: ${this.NONCE_TTL}ms)`,
    );

    return { nonce };
  }

  async verifySignature(
    dto: VerifySignatureDto,
    ip?: string,
  ): Promise<{ accessToken: string }> {
    const { publicKey, signature, nonce } = dto;

    // Validate public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    // Retrieve and atomically consume nonce
    const cacheKey = `nonce:${publicKey}`;
    const storedNonceData = await this.cacheManager.get<{
      nonce: string;
      timestamp: number;
    }>(cacheKey);

    if (!storedNonceData) {
      this.logger.warn(
        `Nonce not found or expired for public key: ${publicKey.substring(0, 10)}...`,
      );
      if (ip) {
        await this.authRateLimitService.recordFailedAttempt(
          publicKey,
          ip,
          'nonce_mismatch',
        );
      }
      throw new UnauthorizedException(
        'Nonce not found or expired. Request a new nonce.',
      );
    }

    // Validate nonce timestamp (additional security layer)
    const nonceAge = Date.now() - storedNonceData.timestamp;
    if (nonceAge > this.NONCE_TTL) {
      await this.cacheManager.del(cacheKey);
      this.logger.warn(
        `Expired nonce used for public key: ${publicKey.substring(0, 10)}...`,
      );
      if (ip) {
        await this.authRateLimitService.recordFailedAttempt(
          publicKey,
          ip,
          'nonce_mismatch',
        );
      }
      throw new UnauthorizedException(
        'Nonce has expired. Request a new nonce.',
      );
    }

    // Verify nonce matches
    if (storedNonceData.nonce !== nonce) {
      this.logger.warn(
        `Nonce mismatch for public key: ${publicKey.substring(0, 10)}...`,
      );
      if (ip) {
        await this.authRateLimitService.recordFailedAttempt(
          publicKey,
          ip,
          'nonce_mismatch',
        );
      }
      throw new UnauthorizedException('Nonce mismatch');
    }

    // Verify signature
    const isValidSignature = this.verifyWalletSignature(
      publicKey,
      signature,
      storedNonceData.nonce,
    );

    if (!isValidSignature) {
      this.logger.warn(
        `Invalid signature for public key: ${publicKey.substring(0, 10)}...`,
      );
      if (ip) {
        await this.authRateLimitService.recordFailedAttempt(
          publicKey,
          ip,
          'invalid_signature',
        );
      }
      throw new UnauthorizedException('Invalid signature');
    }

    // Atomically consume the nonce (delete it immediately after successful verification)
    await this.cacheManager.del(cacheKey);
    this.logger.debug(
      `Nonce consumed for public key: ${publicKey.substring(0, 10)}...`,
    );

    // Clear failed attempts on successful verification
    await this.authRateLimitService.clearFailedAttempts(publicKey);

    // Find or create user by public key
    let user = await this.userService.findByPublicKey(publicKey);

    if (!user) {
      // Create new user with public key
      user = await this.userService.create({
        publicKey,
        email: `${publicKey.substring(0, 10)}@stellar.wallet`,
        name: `Stellar Wallet User`,
      });
      this.logger.log(
        `New user created with public key: ${publicKey.substring(0, 10)}...`,
      );
    }

    return {
      accessToken: this.generateToken(user.id, user.email, user.role),
    };
  }

  /**
   * Link a Stellar wallet to an already-authenticated email account.
   *
   * Flow:
   *  1. Caller fetches a nonce via GET /auth/nonce?publicKey=<key>
   *  2. Caller signs the nonce with the wallet's Ed25519 secret key
   *  3. Caller POSTs { publicKey, nonce, signature } + Bearer JWT to this endpoint
   *
   * The method:
   *  - Validates the Stellar key format
   *  - Verifies the Ed25519 signature with proper nonce validation
   *  - Delegates to UserService.linkWallet, which enforces uniqueness at the DB row level
   *
   * @param userId   Extracted from the verified JWT by JwtAuthGuard
   * @param dto      LinkWalletDto from request body
   */
  async linkWallet(
    userId: string,
    dto: LinkWalletDto,
  ): Promise<{ walletAddress: string; message: string }> {
    const { publicKey, nonce, signature } = dto;

    // 1. Validate Stellar public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    // 2. Retrieve and validate stored nonce
    const cacheKey = `nonce:${publicKey}`;
    const storedNonceData = await this.cacheManager.get<{
      nonce: string;
      timestamp: number;
    }>(cacheKey);

    if (!storedNonceData) {
      this.logger.warn(
        `Nonce not found for wallet linking: ${publicKey.substring(0, 10)}...`,
      );
      throw new UnauthorizedException(
        'Nonce not found or expired. Request a new nonce.',
      );
    }

    // Validate nonce timestamp
    const nonceAge = Date.now() - storedNonceData.timestamp;
    if (nonceAge > this.NONCE_TTL) {
      await this.cacheManager.del(cacheKey);
      this.logger.warn(
        `Expired nonce used for wallet linking: ${publicKey.substring(0, 10)}...`,
      );
      throw new UnauthorizedException(
        'Nonce has expired. Request a new nonce.',
      );
    }

    // Verify nonce matches
    if (storedNonceData.nonce !== nonce) {
      this.logger.warn(
        `Nonce mismatch for wallet linking: ${publicKey.substring(0, 10)}...`,
      );
      throw new UnauthorizedException('Nonce mismatch');
    }

    // 3. Verify the Ed25519 signature over the nonce
    //    This proves the caller controls the private key behind publicKey.
    const isValid = this.verifyWalletSignature(
      publicKey,
      signature,
      storedNonceData.nonce,
    );
    if (!isValid) {
      this.logger.warn(
        `Invalid signature for wallet linking: ${publicKey.substring(0, 10)}...`,
      );
      throw new UnauthorizedException(
        'Signature verification failed. Ensure you signed the exact nonce bytes.',
      );
    }

    // Atomically consume the nonce
    await this.cacheManager.del(cacheKey);
    this.logger.debug(
      `Nonce consumed for wallet linking: ${publicKey.substring(0, 10)}...`,
    );

    // 4. Persist the link; UserService throws ConflictException on duplicates
    const updatedUser = await this.userService.linkWalletAddress(
      userId,
      publicKey,
    );

    this.logger.log(
      `Wallet linked successfully for user ${userId}: ${publicKey.substring(0, 10)}...`,
    );

    return {
      walletAddress: updatedUser.walletAddress,
      message: 'Wallet linked successfully',
    };
  }

  private verifyWalletSignature(
    publicKey: string,
    signature: string,
    nonce: string,
  ): boolean {
    try {
      // Convert public key string to Keypair
      const keypair = StellarSdk.Keypair.fromPublicKey(publicKey);

      // Convert signature from hex to Buffer
      const signatureBuffer = Buffer.from(signature, 'hex');

      // Verify the signature against the nonce
      return keypair.verify(Buffer.from(nonce), signatureBuffer);
    } catch (error) {
      return false;
    }
  }
}
