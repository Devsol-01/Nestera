import { validate } from 'class-validator';
import { AsyncResponseDto, AsyncResponseBuilder } from './async-response.dto';

describe('AsyncResponseDto', () => {
  it('should have all required fields', () => {
    const dto: AsyncResponseDto = {
      statusCode: 202,
      message: 'Operation accepted',
      operationId: 'op-123',
      retryAfterSeconds: 5,
      statusEndpoint: '/operations/op-123/status',
    };

    expect(dto.statusCode).toBe(202);
    expect(dto.message).toBe('Operation accepted');
    expect(dto.operationId).toBe('op-123');
    expect(dto.retryAfterSeconds).toBe(5);
    expect(dto.statusEndpoint).toBe('/operations/op-123/status');
  });

  it('should accept optional fields', () => {
    const dto: AsyncResponseDto = {
      statusCode: 202,
      message: 'Operation accepted',
      operationId: 'op-123',
      retryAfterSeconds: 5,
      statusEndpoint: '/operations/op-123/status',
      operationType: 'data-export',
      status: 'pending',
      metadata: { format: 'csv' },
    };

    expect(dto.operationType).toBe('data-export');
    expect(dto.status).toBe('pending');
    expect(dto.metadata).toEqual({ format: 'csv' });
  });
});

describe('AsyncResponseBuilder', () => {
  it('should build a valid async response with required fields', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted for processing')
      .build();

    expect(response.statusCode).toBe(202);
    expect(response.message).toBe('Operation accepted for processing');
    expect(response.operationId).toBe('op-123');
    expect(response.retryAfterSeconds).toBe(5);
    expect(response.statusEndpoint).toBe('/operations/op-123/status');
  });

  it('should allow setting custom retry after seconds', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setRetryAfterSeconds(15)
      .build();

    expect(response.retryAfterSeconds).toBe(15);
  });

  it('should allow setting operation type', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setOperationType('analytics-export')
      .build();

    expect(response.operationType).toBe('analytics-export');
  });

  it('should allow setting status', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setStatus('processing')
      .build();

    expect(response.status).toBe('processing');
  });

  it('should allow setting metadata', () => {
    const metadata = { dataType: 'users', format: 'json' };
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setMetadata(metadata)
      .build();

    expect(response.metadata).toEqual(metadata);
  });

  it('should support method chaining', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setRetryAfterSeconds(10)
      .setOperationType('report-generation')
      .setStatus('pending')
      .setMetadata({ reportType: 'tax' })
      .build();

    expect(response.retryAfterSeconds).toBe(10);
    expect(response.operationType).toBe('report-generation');
    expect(response.status).toBe('pending');
    expect(response.metadata).toEqual({ reportType: 'tax' });
  });

  it('should throw error when message is not set', () => {
    const builder = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    );

    expect(() => builder.build()).toThrow('Message is required for async response');
  });

  it('should produce valid AsyncResponseDto structure', () => {
    const response = new AsyncResponseBuilder(
      'op-123',
      '/operations/op-123/status',
    )
      .setMessage('Operation accepted')
      .setRetryAfterSeconds(8)
      .setOperationType('data-export')
      .setStatus('pending')
      .build();

    // Verify the response matches the expected interface
    expect(response).toHaveProperty('statusCode');
    expect(response).toHaveProperty('message');
    expect(response).toHaveProperty('operationId');
    expect(response).toHaveProperty('retryAfterSeconds');
    expect(response).toHaveProperty('statusEndpoint');
    expect(response).toHaveProperty('operationType');
    expect(response).toHaveProperty('status');
  });

  it('should handle UUID-like operation IDs', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const response = new AsyncResponseBuilder(
      uuid,
      `/users/data/export/${uuid}/status`,
    )
      .setMessage('Export queued')
      .build();

    expect(response.operationId).toBe(uuid);
    expect(response.statusEndpoint).toContain(uuid);
  });

  it('should handle numeric operation IDs', () => {
    const response = new AsyncResponseBuilder('12345', '/jobs/12345/status')
      .setMessage('Job queued')
      .build();

    expect(response.operationId).toBe('12345');
    expect(response.statusEndpoint).toBe('/jobs/12345/status');
  });
});
