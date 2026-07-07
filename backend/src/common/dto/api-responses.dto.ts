import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/** Shape emitted by AllExceptionsFilter for HTTP error responses. */
export class ErrorResponseDto {
  @ApiProperty({ example: false })
  success: boolean;

  @ApiProperty({ example: 400 })
  statusCode: number;

  @ApiProperty({ example: '2026-06-01T12:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '/api/v2/savings/products' })
  path: string;

  @ApiProperty({ example: 'Validation failed' })
  message: string;
}

export class UnauthorizedResponseDto extends ErrorResponseDto {
  @ApiProperty({ example: 401 })
  declare statusCode: number;

  @ApiProperty({ example: 'Unauthorized' })
  declare message: string;
}

export class ForbiddenResponseDto extends ErrorResponseDto {
  @ApiProperty({ example: 403 })
  declare statusCode: number;

  @ApiProperty({ example: 'Forbidden resource' })
  declare message: string;
}

export class NotFoundResponseDto extends ErrorResponseDto {
  @ApiProperty({ example: 404 })
  declare statusCode: number;

  @ApiProperty({ example: 'Resource not found' })
  declare message: string;
}

export class ConflictResponseDto extends ErrorResponseDto {
  @ApiProperty({ example: 409 })
  declare statusCode: number;

  @ApiProperty({ example: 'Resource already exists' })
  declare message: string;
}

export class TooManyRequestsResponseDto {
  @ApiProperty({ example: false })
  success: boolean;

  @ApiProperty({ example: 429 })
  statusCode: number;

  @ApiProperty({
    example:
      'Rate limit exceeded for free tier. Maximum 60 requests per 60 seconds.',
  })
  message: string;

  @ApiProperty({
    description:
      'Seconds to wait before retrying (also returned in Retry-After header)',
    example: 60,
  })
  retryAfter: number;

  @ApiProperty({
    description: 'ISO timestamp indicating when the rate limit resets',
    example: '2026-06-29T12:35:00.000Z',
  })
  resetAt: string;

  @ApiProperty({
    description: 'HTTP method and route that triggered the limit',
    example: 'POST /api/v1/auth/login',
  })
  endpoint: string;
}

export class ValidationErrorResponseDto extends ErrorResponseDto {
  @ApiProperty({ example: 422 })
  declare statusCode: number;

  @ApiProperty({
    example:
      'targetAmount must be a positive number; goalName should not be empty',
  })
  declare message: string;
}

/** Generic paginated wrapper. */
export class PaginatedMetaDto {
  @ApiProperty({ example: 1 })
  page: number;

  @ApiProperty({ example: 20 })
  pageSize: number;

  @ApiProperty({ example: 150 })
  itemCount: number;

  @ApiProperty({ example: 8 })
  pageCount: number;

  @ApiProperty({ example: false })
  hasPreviousPage: boolean;

  @ApiProperty({ example: true })
  hasNextPage: boolean;

  @ApiProperty({ example: 'cursor-token-for-next-page', required: false })
  nextCursor?: string | null;
}

export class PaginatedResponseDto<T> {
  @ApiProperty({ isArray: true, description: 'Items on the current page' })
  items: T[];

  @ApiProperty({ type: () => PaginatedMetaDto })
  meta: PaginatedMetaDto;
}

export class SuccessMessageDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 'Operation completed successfully' })
  message: string;

  @ApiPropertyOptional()
  data?: unknown;
}
