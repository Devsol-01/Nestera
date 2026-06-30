import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ErrorCode } from '../enums/error-code.enum';
import { DomainException } from '../exceptions/domain.exception';
import {
  ClassValidatorErrorLike,
  flattenValidationErrors,
} from '../validators/validation-error.utils';

interface StandardErrorResponse {
  success: false;
  statusCode: number;
  errorCode: ErrorCode;
  message: string;
  details?: Record<string, unknown> | Array<Record<string, unknown>>;
  requestId: string | null;
  timestamp: string;
  path: string;
  docsUrl?: string;
  correlationId?: string;
}

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

const STATUS_TO_ERROR_CODE: Record<number, ErrorCode> = {
  [HttpStatus.BAD_REQUEST]: ErrorCode.BAD_REQUEST,
  [HttpStatus.UNAUTHORIZED]: ErrorCode.UNAUTHORIZED,
  [HttpStatus.FORBIDDEN]: ErrorCode.FORBIDDEN,
  [HttpStatus.NOT_FOUND]: ErrorCode.NOT_FOUND,
  [HttpStatus.CONFLICT]: ErrorCode.CONFLICT,
  [HttpStatus.TOO_MANY_REQUESTS]: ErrorCode.TOO_MANY_REQUESTS,
  [HttpStatus.SERVICE_UNAVAILABLE]: ErrorCode.SERVICE_UNAVAILABLE,
  [HttpStatus.PAYLOAD_TOO_LARGE]: ErrorCode.PAYLOAD_TOO_LARGE,
};

function isRpcFallbackError(exception: unknown): exception is Error {
  if (!(exception instanceof Error)) return false;
  return (
    RPC_TIMEOUT_PATTERN.test(exception.message) ||
    RPC_EXHAUSTED_PATTERN.test(exception.message)
  );
}

function isDatabaseConnectionError(exception: unknown): exception is Error {
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
    ].includes(code)
  );
}

function extractValidationDetails(
  exceptionResponse: Record<string, unknown>,
): Array<Record<string, unknown>> | undefined {
  const msg = exceptionResponse.message;
  if (!Array.isArray(msg)) return undefined;

  if (msg.length > 0 && typeof msg[0] === 'object') {
    return flattenValidationErrors(msg as ClassValidatorErrorLike[]).map(
      (issue) => ({
        field: issue.field,
        constraints: issue.constraints,
        value: issue.value,
      }),
    );
  }

  return msg.map((m: string) => {
    const field = m.split(' ')[0];
    return { field, message: m };
  });
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);
  private readonly isProduction = process.env.NODE_ENV === 'production';

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const requestId =
      ((request as unknown as Record<string, unknown>).correlationId as
        | string
        | undefined) ??
      (request.headers['x-correlation-id'] as string) ??
      null;
    const timestamp = new Date().toISOString();

    // ── Domain exceptions (with stable errorCode) ───────────────────────────
    if (exception instanceof DomainException) {
      const status = exception.getStatus();
      const body: StandardErrorResponse = {
        success: false,
        statusCode: status,
        errorCode: exception.errorCode,
        message: exception.message,
        details: exception.details,
        requestId,
        timestamp,
        path: request.url,
        docsUrl: exception.docsUrl,
      };

      // Add Retry-After header for eventual consistency scenarios
      if (exception.details && typeof exception.details === 'object') {
        const retryAfterSeconds = (exception.details as Record<string, unknown>)
          .retryAfterSeconds as number | undefined;
        if (retryAfterSeconds && !isNaN(retryAfterSeconds)) {
          response.setHeader('Retry-After', Math.ceil(retryAfterSeconds));
        }
      }

      this.logError(request, status, exception);
      return response.status(status).json(body);
    }

    // ── RPC / Blockchain layer errors ───────────────────────────────────────
    if (isRpcFallbackError(exception)) {
      const isTimeout = RPC_TIMEOUT_PATTERN.test(exception.message);
      const httpStatus = isTimeout
        ? HttpStatus.GATEWAY_TIMEOUT
        : HttpStatus.SERVICE_UNAVAILABLE;
      const errorCode = isTimeout
        ? ErrorCode.SOROBAN_RPC_TIMEOUT
        : ErrorCode.SOROBAN_RPC_EXHAUSTED;

      const body: StandardErrorResponse = {
        success: false,
        statusCode: httpStatus,
        errorCode,
        message: isTimeout
          ? 'Soroban RPC request timed out. The network may be under load.'
          : 'All Soroban RPC endpoints are currently unavailable. Please retry later.',
        requestId,
        correlationId:
          (request as Request & { correlationId?: string }).correlationId ??
          undefined,
        timestamp,
        path: request.url,
      };

      this.logger.error(
        `[RPC Fallback] ${request.method} ${request.url} → ${httpStatus}`,
        exception.stack,
        { errorCode, requestId },
      );
      return response.status(httpStatus).json(body);
    }

    // ── Database connectivity errors ────────────────────────────────────────
    if (isDatabaseConnectionError(exception)) {
      const body: StandardErrorResponse = {
        success: false,
        statusCode: HttpStatus.SERVICE_UNAVAILABLE,
        errorCode: ErrorCode.DB_CONNECTION_ERROR,
        message:
          'Database connection is currently unavailable. Please try again shortly.',
        requestId,
        correlationId:
          (request as Request & { correlationId?: string }).correlationId ??
          undefined,
        timestamp,
        path: request.url,
      };

      this.logger.error(
        `[DB Connection] ${request.method} ${request.url} → 503`,
        exception.stack,
      );
      return response.status(HttpStatus.SERVICE_UNAVAILABLE).json(body);
    }

    // ── Standard HTTP exceptions ────────────────────────────────────────────
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    let message: string;
    let details: Array<Record<string, unknown>> | undefined;
    let errorCode: ErrorCode =
      STATUS_TO_ERROR_CODE[status] ?? ErrorCode.INTERNAL_ERROR;

    if (exception instanceof HttpException) {
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse !== null
      ) {
        const resp = exceptionResponse as Record<string, unknown>;

        if (resp.errorCode && typeof resp.errorCode === 'string') {
          errorCode = resp.errorCode as ErrorCode;
        }

        const msg = resp.message;
        if (Array.isArray(msg)) {
          message = 'Validation failed';
          errorCode = ErrorCode.VALIDATION_ERROR;
          details = extractValidationDetails(resp);
        } else {
          message = String(msg ?? 'An error occurred');
        }
      } else {
        message = 'An error occurred';
      }
    } else {
      message = this.isProduction
        ? 'Internal server error'
        : exception instanceof Error
          ? exception.message
          : 'Internal server error';
    }

    const body: StandardErrorResponse = {
      success: false,
      statusCode: status,
      correlationId:
        (request as Request & { correlationId?: string }).correlationId ??
        (request.headers['x-correlation-id'] as string | undefined) ??
        undefined,
      errorCode,
      message,
      details,
      requestId,
      timestamp,
      path: request.url,
    };

    this.logError(request, status, exception);
    response.status(status).json(body);
  }

  private logError(request: Request, status: number, exception: unknown): void {
    const msg =
      exception instanceof Error ? exception.message : String(exception);
    const stack = exception instanceof Error ? exception.stack : undefined;

    if (status >= 500) {
      this.logger.error(
        `HTTP ${status} ${request.method} ${request.url} - ${msg}`,
        stack,
      );
    } else if (status >= 400) {
      this.logger.warn(
        `HTTP ${status} ${request.method} ${request.url} - ${msg}`,
      );
    }
  }
}
