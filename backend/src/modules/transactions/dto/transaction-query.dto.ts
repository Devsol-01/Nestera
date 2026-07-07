import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsBooleanString,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  MIN_PAGE,
  PAGE_VALIDATION_MESSAGES,
  PageOptionsDto,
} from '../../../common/dto/page-options.dto';
import { TransactionSearchCriteriaDto } from './transaction-search-criteria.dto';

export class TransactionQueryDto extends TransactionSearchCriteriaDto {
  @ApiPropertyOptional({ minimum: 1, default: 1, example: 1 })
  @Type(() => Number)
  @IsInt({ message: PAGE_VALIDATION_MESSAGES.pageInt })
  @Min(MIN_PAGE, { message: PAGE_VALIDATION_MESSAGES.pageMin })
  @IsOptional()
  page?: PageOptionsDto['page'] = 1;

  @ApiPropertyOptional({
    minimum: 1,
    maximum: MAX_PAGE_SIZE,
    default: DEFAULT_PAGE_SIZE,
    example: DEFAULT_PAGE_SIZE,
  })
  @Type(() => Number)
  @IsInt({ message: PAGE_VALIDATION_MESSAGES.limitInt })
  @Min(MIN_PAGE, { message: PAGE_VALIDATION_MESSAGES.limitMin })
  @Max(MAX_PAGE_SIZE, { message: PAGE_VALIDATION_MESSAGES.limitMax })
  @IsOptional()
  limit?: PageOptionsDto['limit'] = DEFAULT_PAGE_SIZE;

  @ApiPropertyOptional({
    description:
      "Opaque cursor returned in the previous response's meta.nextCursor. Do not construct manually.",
    example: 'eyJpZCI6IDEwfQ==',
  })
  @IsOptional()
  @IsString({ message: PAGE_VALIDATION_MESSAGES.cursorString })
  cursor?: string;

  @ApiPropertyOptional({
    description: 'Set to "true" to include totalCount metadata',
    default: 'false',
    example: 'true',
  })
  @IsOptional()
  @IsBooleanString({ message: PAGE_VALIDATION_MESSAGES.includeTotalBool })
  includeTotal?: string;

  get pageSize(): number {
    const candidate = this.limit ?? DEFAULT_PAGE_SIZE;
    return Math.min(Math.max(candidate, 1), MAX_PAGE_SIZE);
  }

  get skip(): number {
    return ((this.page ?? 1) - 1) * this.pageSize;
  }

  get shouldIncludeTotal(): boolean {
    return String(this.includeTotal).toLowerCase() === 'true';
  }
}
