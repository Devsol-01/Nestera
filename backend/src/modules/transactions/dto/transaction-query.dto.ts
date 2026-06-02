import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type, Transform } from 'class-transformer';
import {
  IsOptional,
  IsEnum,
  IsDateString,
  IsArray,
  IsString,
} from 'class-validator';
import { PageOptionsDto } from '../../../common/dto/page-options.dto';
import { LedgerTransactionType } from '../../blockchain/entities/transaction.entity';
import { CurrencyCode } from '../../currency/currency.types';

export class TransactionQueryDto extends PageOptionsDto {
  @ApiPropertyOptional({
    description: 'Filter by transaction types (comma-separated)',
    example: 'DEPOSIT,YIELD',
    enum: LedgerTransactionType,
    isArray: true,
  })
  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      return value.split(',').map((v) => v.trim());
    }
    return value;
  })
  @IsArray()
  @IsEnum(LedgerTransactionType, { each: true })
  readonly type?: LedgerTransactionType[];

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
    description: 'Filter by pool ID',
    example: 'pool-uuid-here',
  })
  @IsOptional()
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
  @Transform(({ value }) => {
    if (!value) return undefined;
    if (typeof value === 'string') {
      return value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);
    }
    return Array.isArray(value) ? value : undefined;
  })
  @IsArray()
  @IsString({ each: true })
  readonly tags?: string[];

  @ApiPropertyOptional({
    description: 'Filter by currency code',
    example: 'USDC',
    enum: CurrencyCode,
  })
  @IsOptional()
  @IsEnum(CurrencyCode)
  readonly currencyCode?: CurrencyCode;
}
