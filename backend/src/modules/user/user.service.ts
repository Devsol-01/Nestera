import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { plainToInstance } from 'class-transformer';
import { User } from './entities/user.entity';
import { UpdateUserDto } from './dto/update-user.dto';
import { UpdateSweepSettingsDto } from './dto/update-sweep-settings.dto';
import { SweepSettingsDto } from './dto/sweep-settings.dto';
import { UserProfileResponseDto } from './dto/user-profile-response.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async findById(id: string) {
    const user = await this.userRepository.findOne({
      where: { id },
      select: [
        'id',
        'email',
        'name',
        'bio',
        'publicKey',
        'kycStatus',
        'kycDocumentUrl',
        'createdAt',
        'updatedAt',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async update(id: string, dto: UpdateUserDto) {
    await this.findById(id);

    await this.userRepository.update(id, dto);

    return this.findById(id);
  }

  async findByEmail(email: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });
    return user;
  }

  async findByPublicKey(publicKey: string) {
    const user = await this.userRepository.findOne({
      where: { publicKey },
    });
    return user;
  }

  async create(data: Partial<User>) {
    const newEntity = this.userRepository.create(data);
    const savedUser = await this.userRepository.save(newEntity);

    // Return with only selected fields to match old behavior
    return this.findById(savedUser.id);
  }

  /**
   * Hydrate a full user profile for the frontend dashboard.
   *
   * Fetches: id, email, name, bio, avatarUrl, publicKey (wallet),
   *          role, kycStatus, createdAt.
   * Computes: daysActive = whole days since createdAt.
   * Excludes: password hash, kycRejectionReason, sweepThreshold,
   *           defaultSavingsProductId, and any other internal column.
   *
   * The returned DTO is mapped through class-transformer so that
   * `@Expose`/`@Exclude` decorators on UserProfileResponseDto are
   * respected when ClassSerializerInterceptor serialises the HTTP response.
   */
  async getProfile(userId: string): Promise<UserProfileResponseDto> {
    const raw = await this.userRepository.findOne({
      where: { id: userId },
      select: [
        'id',
        'email',
        'name',
        'bio',
        'avatarUrl',
        'publicKey',   // exposed on the wire as `walletAddress`
        'role',
        'kycStatus',
        'createdAt',
      ],
    });

    if (!raw) {
      throw new NotFoundException('User not found');
    }

    // Compute daysActive: number of full calendar days since account creation
    const msPerDay = 86_400_000;
    const daysActive = Math.floor(
      (Date.now() - new Date(raw.createdAt).getTime()) / msPerDay,
    );

    // Map onto the DTO; plainToInstance applies @Expose/@Exclude decorators
    return plainToInstance(
      UserProfileResponseDto,
      { ...raw, daysActive },
      { excludeExtraneousValues: true }, // strips any property not decorated @Expose()
    );
  }

  /**
   * Cryptographically link a Stellar wallet address to an existing email account.
   *
   * Guards:
   *  - The requesting user must exist.
   *  - The `publicKey` must not already be claimed by **any** account (including the caller's).
   *    Linking the same key twice returns a clear conflict rather than a silent no-op.
   */
  async linkWallet(userId: string, publicKey: string): Promise<User> {
    // Verify caller exists
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Prevent duplicate wallet addresses across the entire users table
    const existingOwner = await this.findByPublicKey(publicKey);
    if (existingOwner) {
      if (existingOwner.id === userId) {
        throw new ConflictException(
          'This wallet address is already linked to your account',
        );
      }
      throw new ConflictException(
        'This wallet address is already linked to another account',
      );
    }

    await this.userRepository.update(userId, { publicKey });

    return this.findById(userId);
  }

  async updateAvatar(userId: string, avatarUrl: string) {
    await this.findById(userId);

    await this.userRepository.update(userId, { avatarUrl });

    return this.findById(userId);
  }

  async updateKycDocument(userId: string, kycDocumentUrl: string) {
    await this.findById(userId);

    await this.userRepository.update(userId, {
      kycDocumentUrl,
      kycStatus: 'PENDING',
    });

    return this.findById(userId);
  }

  async approveKyc(userId: string) {
    await this.findById(userId);

    const updateData: any = {
      kycStatus: 'APPROVED',
    };
    
    await this.userRepository.update(userId, updateData);

    return this.findById(userId);
  }

  async rejectKyc(userId: string, reason: string) {
    await this.findById(userId);

    await this.userRepository.update(userId, {
      kycStatus: 'REJECTED',
      kycRejectionReason: reason,
    });

    return this.findById(userId);
  }

  async remove(id: string) {
    const user = await this.findById(id);

    await this.userRepository.remove(user);

    return { message: 'User deleted successfully' };
  }
}

