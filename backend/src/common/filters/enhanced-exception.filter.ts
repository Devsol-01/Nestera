import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  PayloadTooLargeException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import {
  StandardErrorResponseDto,
  ValidationError,
  DebugContext,
} from '../dto/standard-error-response.dto';
import { ErrorCodeRegistry } from '../services/error-code-registry.service';
import { ApplicationException } from '../exceptions/application.exception';
import {
  flattenValidationErrors,
  ClassValidatorErrorLike,
} from '../validators/validation-error.utils';

/**
 * Patterns emitted by RpcClientWrapper that indicate a Soroban/Horizon
 * RPC timeout or full-endpoint-exhaustion event.
 */
const RPC_TIMEOUT_PATTERN = /request timeout after \d+ms/i;
const RPC_EXHAUSTED_PATTERN = /all \w+ rpc endpoints failed/i;
const DB_CONNECTION_PATTERNS = [
  /econnrefused/i,
  /enotfound/i,
  /connection terminated unexpectedly/i,
  /password authentication failed/i,
  /failed to connect/i,
  /connection timeout/i,
  /connect etimedout/i,
];

interface ClassifiedError {
  code: string;
  originalException: unknown;
  validationErrors?: ValidationError[];
}

@Catch()
export class EnhancedExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(EnhancedExceptionFilter.name);

  constructor(private readonly errorRegistry: ErrorCodeRegistry) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // Extract correlation ID from request
    const correlationId = this.getCorrelationId(request);

    // Classify exception and determine error code
    const errorInfo = this.classifyException(exception);

    // Get error metadata from registry
    const metadata = this.errorRegistry.getMetadata(errorInfo.code);

    // Build response
    const errorResponse = this.buildResponse(
      errorInfo,
      metadata,
      request,
      correlationId,
    );

    // Log error
    this.logError(exception, request, correlationId, errorInfo);

    // Send response
    response.status(metadata.httpStatus).json(errorResponse);
  }

  private classifyException(exception: unknown): ClassifiedError {
    // 1. Check RPC errors
    if (this.isRpcError(exception)) {
      const isTimeout = RPC_TIMEOUT_PATTERN.test(exception.message);
      return {
        code: isTimeout ? 'RPC_001' : 'RPC_002',
        originalException: exception,
      };
    }

    // 2. Check database errors
    if (this.isDatabaseError(exception)) {
      const dbCode = this.classifyDatabaseError(exception);
      return {
        code: dbCode,
        originalException: exception,
      };
    }

    // 3. Check validation errors
    if (exception instanceof BadRequestException) {
      const validationErrors = this.extractValidationErrors(exception);
      if (validationErrors.length > 0) {
        return {
          code: 'VAL_001',
          originalException: exception,
          validationErrors,
        };
      }
      return { code: 'SYS_400', originalException: exception };
    }

    // 4. Check custom application errors
    if (exception instanceof ApplicationException) {
      return {
        code: exception.getErrorCode(),
        originalException: exception,
      };
    }

    // 5. Map HTTP exceptions
    if (exception instanceof HttpException) {
      const code = this.mapHttpExceptionToErrorCode(exception);
      return { code, originalException: exception };
    }

    // 6. Default to SYS_500
    return { code: 'SYS_500', originalException: exception };
  }

  private mapHttpExceptionToErrorCode(exception: HttpException): string {
    if (exception instanceof UnauthorizedException) {
      return 'AUTH_001';
    }
    if (exception instanceof ForbiddenException) {
      return 'AUTHZ_001';
    }
    if (exception instanceof NotFoundException) {
      return 'SYS_404';
    }
    if (exception instanceof ConflictException) {
      return 'SYS_409';
    }
    if (exception instanceof InternalServerErrorException) {
      return 'SYS_500';
    }
    if (exception instanceof BadRequestException) {
      return 'SYS_400';
    }
    if (exception instanceof PayloadTooLargeException) {
      return 'SYS_413';
    }

    // Default based on status code
    const status = exception.getStatus();
    if (status >= 400 && status < 500) {
      return `SYS_${status}`;
    }
    return 'SYS_500';
  }

  private isRpcError(exception: unknown): exception is Error {
    if (!(exception instanceof Error)) return false;
    return (
      RPC_TIMEOUT_PATTERN.test(exception.message) ||
      RPC_EXHAUSTED_PATTERN.test(exception.message)
    );
  }

  private isDatabaseError(exception: unknown): exception is Error {
    if (!(exception instanceof Error)) return false;

    const message = exception.message || '';
    const code = (exception as Error & { code?: string }).code || '';

    return (
      DB_CONNECTION_PATTERNS.some((pattern) => pattern.test(message)) ||
      [
        'ECONNREFUSED',
        'ENOTFOUND',
        'ETIMEDOUT',
        '57P01',
        '08001',
        '08006',
        '23505',
        '23503',
      ].includes(code)
    );
  }

  private classifyDatabaseError(exception: Error): string {
    const message = exception.message || '';
    const code = (exception as any).code || '';

    // Connection errors
    if (
      DB_CONNECTION_PATTERNS.some((pattern) => pattern.test(message)) ||
      [
        'ECONNREFUSED',
        'ENOTFOUND',
        'ETIMEDOUT',
        '57P01',
        '08001',
        '08006',
      ].includes(code)
    ) {
      return 'DB_001';
    }

    // Query timeout
    if (exception.name === 'QueryTimeoutError') {
      return 'DB_002';
    }

    // Unique constraint violation (PostgreSQL 23505)
    if (code === '23505') {
      return 'DB_003';
    }

    // Foreign key constraint violation (PostgreSQL 23503)
    if (code === '23503') {
      return 'DB_004';
    }

    // Default database error
    return 'DB_001';
  }

  private extractValidationErrors(
    exception: BadRequestException,
  ): ValidationError[] {
    const response = exception.getResponse();

    if (typeof response !== 'object') {
      return [];
    }

    const message = (response as any).message;

    if (!Array.isArray(message)) {
      return [];
    }

    // Check if it's class-validator format
    if (message.length > 0 && typeof message[0] === 'object') {
        return flattenValidationErrors(message as ClassValidatorErrorLike[]);
    }

    // Check if it's already formatted errors
    if (
      message.length > 0 &&
      typeof message[0] === 'object' &&
      'field' in message[0]
    ) {
      return message as ValidationError[];
    }

    return [];
  }

  private buildResponse(
    errorInfo: ClassifiedError,
    metadata: any,
    request: Request,
    correlationId: string,
  ): StandardErrorResponseDto {
    const errorResponse: StandardErrorResponseDto = {
      success: false,
      statusCode: metadata.httpStatus,
      errorCode: errorInfo.code,
      message: this.getErrorMessage(errorInfo.originalException, metadata),
      timestamp: new Date().toISOString(),
      path: request.url,
      correlationId,
    };

    // Add validation errors if present
    if (errorInfo.validationErrors && errorInfo.validationErrors.length > 0) {
      errorResponse.errors = errorInfo.validationErrors;
    }

    // Add debug context if in development/test
    if (process.env.NODE_ENV !== 'production') {
      errorResponse.debugContext = this.buildDebugContext(
        errorInfo.originalException,
        request,
      );
    }

    return errorResponse;
  }

  private getErrorMessage(exception: unknown, metadata: any): string {
    // Use custom message from exception if available
    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      if (typeof response === 'string') {
        return response;
      }
      if (typeof response === 'object' && response !== null) {
        const msg = (response as any).message;
        if (typeof msg === 'string') {
          return msg;
        }
        if (Array.isArray(msg) && msg.length > 0) {
          if (typeof msg[0] === 'string') {
            return msg.join('; ');
          }
        }
      }
    }

    // Use metadata message
    return metadata.defaultMessage || 'An error occurred';
  }

  private buildDebugContext(
    exception: unknown,
    request: Request,
  ): DebugContext | undefined {
    const debugContext: DebugContext = {
      exception: exception?.constructor?.name || 'UnknownError',
    };

    if (exception instanceof Error) {
      debugContext.stackTrace = exception.stack;
      debugContext.originalMessage = exception.message;
    }

    debugContext.requestDetails = {
      method: request.method,
      headers: request.headers as Record<string, string>,
      query: request.query as Record<string, string>,
    };

    // Include body for non-GET requests
    if (request.method !== 'GET' && request.body) {
      debugContext.requestDetails.body = request.body;
    }

    // Include custom exception context if present
    if (exception instanceof ApplicationException) {
      (debugContext.requestDetails as any).customContext =
        exception.getContext();
    }

    return debugContext;
  }

  private getCorrelationId(request: Request): string {
    return (request as any).correlationId || uuidv4();
  }

  private logError(
    exception: unknown,
    request: Request,
    correlationId: string,
    errorInfo: ClassifiedError,
  ): void {
    const logContext = {
      correlationId,
      errorCode: errorInfo.code,
      path: request.url,
      method: request.method,
      userAgent: request.headers['user-agent'],
    };

    if (exception instanceof Error) {
      this.logger.error(
        `[${correlationId}] ${errorInfo.code} - ${exception.message}`,
        exception.stack,
        logContext,
      );
    } else {
      this.logger.error(
        `[${correlationId}] ${errorInfo.code} - Unknown error`,
        JSON.stringify(exception),
        logContext,
      );
    }
  }
}
