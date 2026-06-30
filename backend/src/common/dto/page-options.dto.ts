import { Type } from 'class-transformer';
import {
  IsBooleanString,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export enum Order {
  ASC = 'ASC',
  DESC = 'DESC',
}

export const DEFAULT_PAGE_SIZE = 10;
export const MAX_PAGE_SIZE = 100;
export const MIN_PAGE = 1;

/**
 * Hint-rich, range-aware validation messages for pagination inputs.
 *
 * These messages intentionally include the allowed range so a client can
 * self-correct without consulting external docs (issue #1136). The same
 * constants are reused by every DTO that extends {@link PageOptionsDto}
 * — keep them in sync with {@link DEFAULT_PAGE_SIZE} / {@link MAX_PAGE_SIZE}.
 */
export const PAGE_VALIDATION_MESSAGES = {
  pageInt: `page must be an integer (current value is not a whole number)`,
  pageMin: `page must be a positive integer >= ${MIN_PAGE}; use page=${MIN_PAGE} for the first page.`,
  limitInt: `limit must be an integer (current value is not a whole number)`,
  limitMin: `limit must be a positive integer >= ${MIN_PAGE}; received a non-positive limit.`,
  limitMax: `limit must not exceed the maximum page size of ${MAX_PAGE_SIZE}; use cursor pagination for larger result sets (see meta.nextCursor).`,
  orderEnum: `order must be one of: ${Object.values(Order).join(', ')} (default: ${Order.DESC}).`,
  includeTotalBool: `includeTotal must be the string 'true' or 'false' (URL query strings only).`,
  cursorString: `cursor must be an opaque string value; pass back the exact value returned in meta.nextCursor.`,
} as const;

export class PageOptionsDto {
  @ApiPropertyOptional({ enum: Order, default: Order.ASC })
  @IsEnum(Order, { message: PAGE_VALIDATION_MESSAGES.orderEnum })
  @IsOptional()
  readonly order?: Order = Order.ASC;

  @ApiPropertyOptional({ minimum: 1, default: 1 })
  @Type(() => Number)
  @IsInt({ message: PAGE_VALIDATION_MESSAGES.pageInt })
  @Min(MIN_PAGE, { message: PAGE_VALIDATION_MESSAGES.pageMin })
  @IsOptional()
  readonly page?: number = 1;

  @ApiPropertyOptional({
    minimum: 1,
    maximum: MAX_PAGE_SIZE,
    default: DEFAULT_PAGE_SIZE,
  })
  @Type(() => Number)
  @IsInt({ message: PAGE_VALIDATION_MESSAGES.limitInt })
  @Min(MIN_PAGE, { message: PAGE_VALIDATION_MESSAGES.limitMin })
  @Max(MAX_PAGE_SIZE, { message: PAGE_VALIDATION_MESSAGES.limitMax })
  @IsOptional()
  readonly limit?: number = DEFAULT_PAGE_SIZE;

  @ApiPropertyOptional({
    description:
      "Opaque cursor returned in the previous response's meta.nextCursor. Do not construct manually.",
  })
  @IsOptional()
  @IsString({ message: PAGE_VALIDATION_MESSAGES.cursorString })
  readonly cursor?: string;

  @ApiPropertyOptional({
    description: 'Set to "true" to include totalCount metadata',
    default: 'false',
  })
  @IsOptional()
  @IsBooleanString({ message: PAGE_VALIDATION_MESSAGES.includeTotalBool })
  readonly includeTotal?: string;

  get pageSize(): number {
    const candidate = this.limit ?? DEFAULT_PAGE_SIZE;
    return Math.min(Math.max(candidate, 1), MAX_PAGE_SIZE);
  }

  /** Calculated offset for the database query */
  get skip(): number {
    return ((this.page ?? 1) - 1) * this.pageSize;
  }

  get shouldIncludeTotal(): boolean {
    return String(this.includeTotal).toLowerCase() === 'true';
  }
}
