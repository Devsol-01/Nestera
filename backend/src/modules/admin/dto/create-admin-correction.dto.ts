import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  Matches,
} from 'class-validator';
import { CorrectionType } from '../entities/admin-correction-ledger.entity';

export class CreateAdminCorrectionDto {
  @ApiProperty({
    description:
      'ID of the target resource being corrected (transaction id, subscription id, etc.)',
    example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  targetId: string;

  @ApiProperty({
    description: 'Human-readable type of the target resource',
    example: 'transaction',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  targetType: string;

  @ApiProperty({
    enum: CorrectionType,
    description: 'Category of the correction being applied',
    example: CorrectionType.BALANCE_CREDIT,
  })
  @IsEnum(CorrectionType)
  correctionType: CorrectionType;

  @ApiProperty({
    description:
      'Signed correction amount. Positive = credit, negative = debit. ' +
      'Use a decimal string to preserve Stellar arbitrary precision.',
    example: '50.0000000',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  @Matches(/^-?\d+(\.\d+)?$/, {
    message: 'delta must be a numeric string (e.g. "50.00" or "-12.5")',
  })
  delta: string;

  @ApiPropertyOptional({
    description: 'Value of the field before this correction',
    example: '100.0000000',
  })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  previousValue?: string;

  @ApiPropertyOptional({
    description: 'Value of the field after this correction',
    example: '150.0000000',
  })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  newValue?: string;

  @ApiProperty({
    description:
      'Mandatory justification for this correction. Minimum 10 characters.',
    example: 'Customer reported missing interest accrual for March 2026.',
    minLength: 10,
  })
  @IsString()
  @MinLength(10, { message: 'reason must be at least 10 characters' })
  @MaxLength(2000)
  reason: string;

  @ApiPropertyOptional({
    description:
      'Idempotency key / request ID to prevent double-submissions. ' +
      'If omitted the service generates one from the request context.',
    example: 'req-abc123',
  })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  requestId?: string;

  @ApiPropertyOptional({
    description:
      'External workflow or ticket identifier (e.g. Jira key, support ticket).',
    example: 'SUPPORT-4321',
  })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  workflowId?: string;
}
