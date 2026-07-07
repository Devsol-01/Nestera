import { IsOptional, IsString, MaxLength } from 'class-validator';
import { ApiPropertyOptional, ApiProperty } from '@nestjs/swagger';

export class UpdateUserDto {
  @ApiPropertyOptional({ description: 'User display name', example: 'John Doe' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @ApiPropertyOptional({ description: 'User biography', example: 'Building my financial future with Nestera' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  bio?: string;
}

export class ApproveKycDto {
  @ApiProperty({ description: 'User ID to approve KYC for', example: '550e8400-e29b-41d4-a716-446655440000' })
  @IsString()
  userId: string;
}

export class RejectKycDto {
  @ApiProperty({ description: 'User ID to reject KYC for', example: '550e8400-e29b-41d4-a716-446655440000' })
  @IsString()
  userId: string;

  @ApiProperty({ description: 'Reason for KYC rejection', example: 'Document verification failed' })
  @IsString()
  reason: string;
}
