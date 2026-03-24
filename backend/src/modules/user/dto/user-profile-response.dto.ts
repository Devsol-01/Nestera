import { ApiProperty } from '@nestjs/swagger';
import { Expose, Exclude } from 'class-transformer';

/**
 * Shape returned by GET /users/profile.
 *
 * Rules enforced by class-transformer (ClassSerializerInterceptor):
 *  - Only properties decorated with @Expose() survive serialisation.
 *  - Sensitive fields (password, nonces, internal KYC details) never appear
 *    in the JSON body because they are never added to this DTO.
 *  - `daysActive` is a computed integer injected by UserService before returning.
 */
@Exclude() // default: strip everything unless explicitly @Expose()'d
export class UserProfileResponseDto {
  @Expose()
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @Expose()
  @ApiProperty({ example: 'alice@example.com' })
  email: string;

  @Expose()
  @ApiProperty({ example: 'Alice', nullable: true })
  name: string | null;

  @Expose()
  @ApiProperty({ example: 'Saving for a rainy day.', nullable: true })
  bio: string | null;

  @Expose()
  @ApiProperty({
    example: 'https://cdn.nestera.io/avatars/abc.jpg',
    nullable: true,
  })
  avatarUrl: string | null;

  /**
   * The linked Stellar wallet address.
   * Exposed as `walletAddress` to match the frontend's naming convention
   * even though the DB column / entity field is `publicKey`.
   */
  @Expose({ name: 'walletAddress' })
  @ApiProperty({
    name: 'walletAddress',
    example: 'GABC1234...',
    nullable: true,
    description: 'Linked Stellar wallet public key (null if no wallet linked)',
  })
  publicKey: string | null;

  @Expose()
  @ApiProperty({ example: 'USER', enum: ['USER', 'ADMIN'] })
  role: 'USER' | 'ADMIN';

  @Expose()
  @ApiProperty({ example: 'NOT_SUBMITTED' })
  kycStatus: string;

  @Expose()
  @ApiProperty({ example: '2025-01-01T00:00:00.000Z' })
  createdAt: Date;

  /**
   * Whole number of days since account creation.
   * Computed by UserService; never stored in the DB.
   */
  @Expose()
  @ApiProperty({
    example: 42,
    description: 'Number of full days the account has been active',
  })
  daysActive: number;
}
