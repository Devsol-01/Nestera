import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsInt,
  Min,
  Max,
  IsIn,
  IsUUID,
} from 'class-validator';

// ---------------------------------------------------------------------------
// GenerateTestDataDto
// ---------------------------------------------------------------------------

export class GenerateTestDataDto {
  @ApiPropertyOptional({
    description: 'Number of test users to generate (1–50)',
    example: 5,
    default: 5,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(50)
  userCount?: number = 5;

  @ApiPropertyOptional({
    description: 'Number of transactions per user (1–20)',
    example: 5,
    default: 5,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(20)
  transactionsPerUser?: number = 5;

  @ApiPropertyOptional({
    description: 'Number of savings goals per user (1–10)',
    example: 2,
    default: 2,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(10)
  savingsGoalsPerUser?: number = 2;
}

// ---------------------------------------------------------------------------
// SimulateContractEventDto
// ---------------------------------------------------------------------------

export type SandboxEventType = 'Deposit' | 'Withdraw' | 'Yield';
export const SANDBOX_EVENT_TYPES: SandboxEventType[] = [
  'Deposit',
  'Withdraw',
  'Yield',
];

export class SimulateContractEventDto {
  @ApiProperty({
    description: 'Soroban contract event type to simulate',
    enum: SANDBOX_EVENT_TYPES,
    example: 'Deposit',
  })
  @IsString()
  @IsNotEmpty()
  @IsIn(SANDBOX_EVENT_TYPES)
  eventType!: SandboxEventType;

  @ApiProperty({
    description: 'Target user Stellar public key or wallet address',
    example: 'GABC...XYZ',
  })
  @IsString()
  @IsNotEmpty()
  publicKey!: string;

  @ApiProperty({
    description: 'Token amount (as a string to preserve precision)',
    example: '100.00',
  })
  @IsString()
  @IsNotEmpty()
  amount!: string;

  @ApiPropertyOptional({
    description: 'Simulated ledger sequence number',
    example: 1234567,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  ledger?: number;

  @ApiPropertyOptional({
    description: 'Simulated contract ID',
    example: 'CABC...DEF',
  })
  @IsOptional()
  @IsString()
  contractId?: string;
}

// ---------------------------------------------------------------------------
// CreateApiKeyDto
// ---------------------------------------------------------------------------

export class CreateApiKeyDto {
  @ApiProperty({
    description: 'Human-readable name for this sandbox API key',
    example: 'dev-local',
  })
  @IsString()
  @IsNotEmpty()
  name!: string;

  @ApiPropertyOptional({
    description: 'Optional user ID to associate with this key',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsOptional()
  @IsUUID()
  userId?: string;
}

// ---------------------------------------------------------------------------
// ResetSandboxDto
// ---------------------------------------------------------------------------

export class ResetSandboxDto {
  @ApiPropertyOptional({
    description:
      'Confirmation token (must equal "CONFIRM_RESET") to prevent accidental resets',
    example: 'CONFIRM_RESET',
  })
  @IsOptional()
  @IsString()
  confirm?: string;
}
