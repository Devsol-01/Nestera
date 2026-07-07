import {
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Min,
  ValidateIf,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ReplayJobMode } from '../entities/blockchain-replay-job.entity';

export class CreateReplayJobDto {
  @ApiProperty({ enum: ReplayJobMode, example: ReplayJobMode.LEDGER_RANGE })
  @IsEnum(ReplayJobMode)
  mode: ReplayJobMode;

  @ApiPropertyOptional({
    description: 'Start ledger (inclusive) for ledger_range mode',
    example: 100000,
  })
  @ValidateIf((o) => o.mode === ReplayJobMode.LEDGER_RANGE)
  @IsInt()
  @Min(0)
  startLedger?: number;

  @ApiPropertyOptional({
    description: 'End ledger (inclusive) for ledger_range mode',
    example: 200000,
  })
  @ValidateIf((o) => o.mode === ReplayJobMode.LEDGER_RANGE)
  @IsInt()
  @Min(0)
  endLedger?: number;

  @ApiPropertyOptional({ description: 'Event cursor for event_cursor mode', example: 'eyJpZCI6IDEwfQ==' })
  @ValidateIf((o) => o.mode === ReplayJobMode.EVENT_CURSOR)
  @IsString()
  eventCursor?: string;

  @ApiPropertyOptional({
    description: 'Optional end ledger when replaying from cursor',
    example: 200000,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  endLedgerForCursor?: number;
}

export class ReplayJobResponseDto {
  @ApiProperty({ example: 'replay-550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ enum: ReplayJobMode, example: ReplayJobMode.LEDGER_RANGE })
  mode: ReplayJobMode;

  @ApiProperty({ example: 'running' })
  status: string;

  @ApiProperty({ example: 15000 })
  eventsProcessed: number;

  @ApiProperty({ example: 5 })
  eventsFailed: number;

  @ApiProperty({ example: 100 })
  eventsSkipped: number;

  @ApiProperty({ example: 15105 })
  totalEvents: number;

  @ApiPropertyOptional({ example: 'Timeout processing ledger 150050' })
  lastError?: string | null;

  @ApiProperty({ example: 99.3 })
  progressPercent: number;
}
