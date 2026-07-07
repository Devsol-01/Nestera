import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsOptional, IsString } from 'class-validator';
import { KycVerificationStatus } from '../entities/kyc-verification.entity';

export class KycWebhookDto {
  @ApiProperty({ example: 'prov_123' })
  @IsString()
  providerReference!: string;

  @ApiProperty({ enum: KycVerificationStatus, example: KycVerificationStatus.APPROVED })
  @IsEnum(KycVerificationStatus)
  status!: KycVerificationStatus;

  @ApiProperty({ example: 'Document verified successfully' })
  @IsOptional()
  @IsString()
  reason?: string;
}
