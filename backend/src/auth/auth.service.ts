import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../modules/user/user.service';
import {
  RegisterDto,
  LoginDto,
  VerifySignatureDto,
  LinkWalletDto,
} from './dto/auth.dto';
// import { Cache } from 'cache-manager';
// import { CACHE_MANAGER } from '@nestjs/cache-manager';
import * as bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import * as StellarSdk from '@stellar/stellar-sdk';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    // @Inject(CACHE_MANAGER) private cacheManager: Cache,
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

    return {
      user,
      accessToken: this.generateToken(user.id, user.email, user.role),
    };
  }

  async login(dto: LoginDto) {
    const user = await this.validateUser(dto.email, dto.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return {
      accessToken: this.generateToken(user.id, user.email, user.role),
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

  private generateToken(userId: string, email: string, role = 'USER') {
    return this.jwtService.sign({ sub: userId, email, role });
  }

  async generateNonce(publicKey: string): Promise<{ nonce: string }> {
    // Validate Stellar public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    const nonce = randomUUID();
    // const cacheKey = `nonce:${publicKey}`;
    // await this.cacheManager.set(cacheKey, nonce, 300000); // 300 seconds = 5 minutes

    return { nonce };
  }

  async verifySignature(dto: VerifySignatureDto): Promise<{ accessToken: string }> {
    const { publicKey, signature, nonce } = dto;

    // Validate public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    // Retrieve stored nonce
    // const cacheKey = `nonce:${publicKey}`;
    // const storedNonce = await this.cacheManager.get<string>(cacheKey);
    const storedNonce = nonce; // Temporarily bypass cache for testing

    if (!storedNonce) {
      throw new UnauthorizedException('Nonce not found or expired. Request a new nonce.');
    }

    // Verify signature
    const isValidSignature = this.verifyWalletSignature(publicKey, signature, storedNonce);

    if (!isValidSignature) {
      throw new UnauthorizedException('Invalid signature');
    }

    // Consume the nonce (delete it)
    // await this.cacheManager.del(cacheKey);

    // Find or create user by public key
    let user = await this.userService.findByPublicKey(publicKey);

    if (!user) {
      // Create new user with public key
      user = await this.userService.create({
        publicKey,
        email: `${publicKey.substring(0, 10)}@stellar.wallet`,
        name: `Stellar Wallet User`,
      });
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
   *  - Verifies the Ed25519 signature (same logic as verifySignature)
   *  - Delegates to UserService.linkWallet, which enforces uniqueness at the DB row level
   *
   * @param userId   Extracted from the verified JWT by JwtAuthGuard
   * @param dto      LinkWalletDto from request body
   */
  async linkWallet(
    userId: string,
    dto: LinkWalletDto,
  ): Promise<{ publicKey: string; message: string }> {
    const { publicKey, nonce, signature } = dto;

    // 1. Validate Stellar public key format
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
      throw new BadRequestException('Invalid Stellar public key format');
    }

    // 2. Verify the Ed25519 signature over the nonce
    //    This proves the caller controls the private key behind publicKey.
    const isValid = this.verifyWalletSignature(publicKey, signature, nonce);
    if (!isValid) {
      throw new UnauthorizedException(
        'Signature verification failed. Ensure you signed the exact nonce bytes.',
      );
    }

    // 3. Persist the link; UserService throws ConflictException on duplicates
    const updatedUser = await this.userService.linkWallet(userId, publicKey);

    return {
      publicKey: updatedUser.publicKey!,
      message: 'Wallet linked successfully',
    };
  }

  private verifyWalletSignature(publicKey: string, signature: string, nonce: string): boolean {
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

