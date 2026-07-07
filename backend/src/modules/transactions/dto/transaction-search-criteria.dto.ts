import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsArray,
  IsDateString,
  IsEnum,
  IsNumberString,
  IsOptional,
  IsString,
} from 'class-validator';
import {
  LedgerTransactionStatus,
  LedgerTransactionType,
} from '../../blockchain/entities/transaction.entity';
import { Order } from '../../../common/dto/page-options.dto';

export enum TransactionSortBy {
  CREATED_AT = 'createdAt',
  AMOUNT = 'amount',
  TYPE = 'type',
  STATUS = 'status',
}

function toStringArray(value: unknown): string[] | undefined {
  if (!value) return undefined;
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return Array.isArray(value) ? value : undefined;
}

export class TransactionSearchCriteriaDto {
  @ApiPropertyOptional({
    description:
      'Free-text search with relevance scoring across transaction hash, memo, reference IDs, descriptions, tags, and metadata. Exact matches rank highest, followed by prefix matches and partial text matches. Search requests use bounded execution time and a capped result size.',
    example: 'memo-123',
  })
  @IsOptional()
  @IsString()
  readonly search?: string;

  @ApiPropertyOptional({
    description: 'Filter by transaction types (comma-separated)',
    example: 'DEPOSIT,YIELD',
    enum: LedgerTransactionType,
    isArray: true,
  })
  @IsOptional()
  @Transform(({ value }) => toStringArray(value))
  @IsArray()
  @IsEnum(LedgerTransactionType, { each: true })
  readonly type?: LedgerTransactionType[];

  @ApiPropertyOptional({
    description: 'Filter by transaction statuses (comma-separated)',
    example: 'COMPLETED,PENDING',
    enum: LedgerTransactionStatus,
    isArray: true,
  })
  @IsOptional()
  @Transform(({ value }) => toStringArray(value))
  @IsArray()
  @IsEnum(LedgerTransactionStatus, { each: true })
  readonly status?: LedgerTransactionStatus[];

  @ApiPropertyOptional({
    description: 'Filter by start date (ISO 8601 format)',
    example: '2024-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  readonly startDate?: string;

  @ApiPropertyOptional({
    description: 'Filter by end date (ISO 8601 format)',
    example: '2024-12-31T23:59:59.999Z',
  })
  @IsOptional()
  @IsDateString()
  readonly endDate?: string;

  @ApiPropertyOptional({
    description: 'Minimum transaction amount',
    example: '50.00',
  })
  @IsOptional()
  @IsNumberString()
  readonly minAmount?: string;

  @ApiPropertyOptional({
    description: 'Maximum transaction amount',
    example: '5000.00',
  })
  @IsOptional()
  @IsNumberString()
  readonly maxAmount?: string;

  @ApiPropertyOptional({
    description: 'Filter by pool ID',
    example: 'pool-uuid-here',
  })
  @IsOptional()
  @IsString()
  readonly poolId?: string;

  @ApiPropertyOptional({
    description: 'Filter by category',
    example: 'Groceries',
  })
  @IsOptional()
  @IsString()
  readonly category?: string;

  @ApiPropertyOptional({
    description: 'Filter by tags (comma-separated or array)',
    example: 'food,groceries',
    isArray: true,
  })
  @IsOptional()
  @Transform(({ value }) => toStringArray(value))
  @IsArray()
  @IsString({ each: true })
  readonly tags?: string[];

  @ApiPropertyOptional({
    description: 'Field to sort by',
    enum: TransactionSortBy,
    default: TransactionSortBy.CREATED_AT,
  })
  @IsOptional()
  @IsEnum(TransactionSortBy)
  readonly sortBy?: TransactionSortBy = TransactionSortBy.CREATED_AT;

  @ApiPropertyOptional({
    enum: Order,
    default: Order.DESC,
    description: 'Sort order',
  })
  @IsOptional()
  @IsEnum(Order)
  readonly order?: Order = Order.DESC;
}
