import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Standard async response DTO for endpoints that return 202 Accepted.
 * Provides clients with consistent polling guidance and operation tracking.
 */
export class AsyncResponseDto {
  @ApiProperty({
    example: 202,
    description: 'HTTP status code (always 202 for async operations)',
  })
  statusCode: number;

  @ApiProperty({
    example: 'Operation accepted for processing',
    description: 'Human-readable message describing the operation',
  })
  message: string;

  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Unique identifier for tracking this operation',
  })
  operationId: string;

  @ApiProperty({
    example: 5,
    description: 'Recommended seconds to wait before polling the status endpoint',
  })
  retryAfterSeconds: number;

  @ApiProperty({
    example: '/users/data/export/550e8400-e29b-41d4-a716-446655440000/status',
    description: 'Endpoint to poll for operation status updates',
  })
  statusEndpoint: string;

  @ApiPropertyOptional({
    example: 'data-export',
    description: 'Type of operation being performed (optional, for client categorization)',
  })
  operationType?: string;

  @ApiPropertyOptional({
    example: 'pending',
    description: 'Initial status of the operation (optional)',
  })
  status?: string;

  @ApiPropertyOptional({
    type: Object,
    description: 'Additional operation-specific metadata (optional)',
  })
  metadata?: Record<string, unknown>;
}

/**
 * Helper class to construct async responses with proper defaults
 */
export class AsyncResponseBuilder {
  private response: Partial<AsyncResponseDto> = {
    statusCode: 202,
    retryAfterSeconds: 5,
  };

  constructor(operationId: string, statusEndpoint: string) {
    this.response.operationId = operationId;
    this.response.statusEndpoint = statusEndpoint;
  }

  setMessage(message: string): this {
    this.response.message = message;
    return this;
  }

  setRetryAfterSeconds(seconds: number): this {
    this.response.retryAfterSeconds = seconds;
    return this;
  }

  setOperationType(type: string): this {
    this.response.operationType = type;
    return this;
  }

  setStatus(status: string): this {
    this.response.status = status;
    return this;
  }

  setMetadata(metadata: Record<string, unknown>): this {
    this.response.metadata = metadata;
    return this;
  }

  build(): AsyncResponseDto {
    if (!this.response.message) {
      throw new Error('Message is required for async response');
    }
    return this.response as AsyncResponseDto;
  }
}
