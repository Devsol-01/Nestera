import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AdminUserListItemDto {
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;
  @ApiProperty({ example: 'john.doe@example.com' })
  email: string;
  @ApiPropertyOptional({ example: 'John Doe' })
  name?: string;
  @ApiProperty({ example: 'ADMIN' })
  role: string;
  @ApiProperty({ example: 'APPROVED' })
  kycStatus: string;
  @ApiProperty({ example: true })
  isActive: boolean;
  @ApiProperty({ example: 1500.75 })
  totalSavings: number;
  @ApiProperty({ example: 42 })
  transactionCount: number;
  @ApiPropertyOptional({ example: '2024-06-15T10:30:00.000Z' })
  lastLoginAt?: Date;
  @ApiProperty({ example: '2024-01-15T10:30:00.000Z' })
  createdAt: Date;
}

export class AdminUserDetailDto extends AdminUserListItemDto {
  @ApiPropertyOptional({ example: 'Experienced user in the platform' })
  bio?: string;
  @ApiPropertyOptional({ example: 'https://example.com/avatar.png' })
  avatarUrl?: string;
  @ApiPropertyOptional({ example: '0x1234567890abcdef1234567890abcdef12345678' })
  publicKey?: string;
  @ApiPropertyOptional({ example: '0xabcdef1234567890abcdef1234567890abcdef12' })
  walletAddress?: string;
  @ApiProperty({ example: 'TIER_2' })
  tier: string;
  @ApiProperty({ example: true })
  twoFactorEnabled: boolean;
  @ApiProperty({ example: 5 })
  activeSubscriptions: number;
  @ApiProperty({ example: 2500.5 })
  totalInterestEarned: number;
}

export class UpdateUserRoleDto {
  @ApiProperty({ enum: ['USER', 'ADMIN'], example: 'ADMIN' })
  @IsEnum(['USER', 'ADMIN'])
  @IsNotEmpty()
  role: 'USER' | 'ADMIN';
}

export class UpdateUserStatusDto {
  @ApiProperty({ description: 'true = active, false = deactivated', example: false })
  @IsNotEmpty()
  isActive: boolean;

  @ApiPropertyOptional({ example: 'User violated terms of service' })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class BulkActionDto {
  @ApiProperty({ enum: ['activate', 'deactivate', 'export', 'email'], example: 'deactivate' })
  @IsEnum(['activate', 'deactivate', 'export', 'email'])
  @IsNotEmpty()
  action: 'activate' | 'deactivate' | 'export' | 'email';

  @ApiProperty({ type: [String], example: ['550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001'] })
  @IsString({ each: true })
  @IsNotEmpty()
  userIds: string[];

  @ApiPropertyOptional({ description: 'Required when action=email', example: 'Important Platform Update' })
  @IsString()
  @IsOptional()
  emailSubject?: string;

  @ApiPropertyOptional({ example: 'Dear user, we have some important updates...' })
  @IsString()
  @IsOptional()
  emailBody?: string;
}
