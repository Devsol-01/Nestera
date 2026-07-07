import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsOptional, IsString } from 'class-validator';
import { KycProvider } from '../entities/kyc-verification.entity';

export class InitiateKycDto {
  @ApiProperty({ enum: KycProvider, default: KycProvider.SUMSUB, example: KycProvider.SUMSUB })
  @IsEnum(KycProvider)
  provider!: KycProvider;

  @ApiPropertyOptional({
    description: 'Government ID number (encrypted at rest)',
    example: 'A12345678',
  })
  @IsOptional()
  @IsString()
  idNumber?: string;

  @ApiPropertyOptional({
    description: 'Document type (passport, national_id, etc.)',
    example: 'passport',
  })
  @IsOptional()
  @IsString()
  documentType?: string;
}
