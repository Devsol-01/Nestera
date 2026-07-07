import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { TransactionSearchCriteriaDto } from './transaction-search-criteria.dto';

export class CreateSavedSearchDto {
  @ApiProperty({ description: 'Friendly name for the saved search', example: 'My Monthly Deposits' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  readonly name: string;

  @ApiPropertyOptional({ description: 'Optional short description', example: 'All deposits from the last 30 days' })
  @IsOptional()
  @IsString()
  @MaxLength(280)
  readonly description?: string;

  @ApiProperty({
    description: 'Search filters and sorting to persist',
    type: TransactionSearchCriteriaDto,
    example: { type: 'deposit', status: 'completed', fromDate: '2026-06-01', toDate: '2026-06-30' },
  })
  @IsObject()
  @ValidateNested()
  @Type(() => TransactionSearchCriteriaDto)
  readonly query: TransactionSearchCriteriaDto;

  @ApiPropertyOptional({
    description: 'Set this as the default saved search for the user',
    default: false,
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  readonly isDefault?: boolean;
}
