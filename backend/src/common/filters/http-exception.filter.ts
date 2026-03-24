import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/**
 * Patterns emitted by RpcClientWrapper that indicate a Soroban/Horizon
 * RPC timeout or full-endpoint-exhaustion event.
 */
const RPC_TIMEOUT_PATTERN = /request timeout after \d+ms/i;
const RPC_EXHAUSTED_PATTERN = /all \w+ rpc endpoints failed/i;

/** Classify an unknown exception as an RPC-layer error. */
function isRpcFallbackError(exception: unknown): exception is Error {
  if (!(exception instanceof Error)) return false;
  return (
    RPC_TIMEOUT_PATTERN.test(exception.message) ||
    RPC_EXHAUSTED_PATTERN.test(exception.message)
  );
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // ── RPC / Blockchain layer errors ────────────────────────────────────────
    if (isRpcFallbackError(exception)) {
      const isTimeout = RPC_TIMEOUT_PATTERN.test(exception.message);
      const httpStatus = isTimeout
        ? HttpStatus.GATEWAY_TIMEOUT   // 504 – a single endpoint timed out
        : HttpStatus.SERVICE_UNAVAILABLE; // 503 – all fallbacks exhausted

      this.logger.error(
        `[RPC Fallback] ${request.method} ${request.url} → ${httpStatus} | ${exception.message}`,
        exception.stack,
        {
          errorCode: isTimeout ? 'SOROBAN_RPC_TIMEOUT' : 'SOROBAN_RPC_EXHAUSTED',
          path: request.url,
          method: request.method,
          timestamp: new Date().toISOString(),
        },
      );

      return response.status(httpStatus).json({
        success: false,
        statusCode: httpStatus,
        errorCode: isTimeout ? 'SOROBAN_RPC_TIMEOUT' : 'SOROBAN_RPC_EXHAUSTED',
        timestamp: new Date().toISOString(),
        path: request.url,
        message: isTimeout
          ? 'Soroban RPC request timed out. The network may be under load.'
          : 'All Soroban RPC endpoints are currently unavailable. Please retry later.',
      });
    }

    // ── Standard HTTP exceptions ─────────────────────────────────────────────
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    let message: string;
    if (exception instanceof HttpException) {
      const exceptionResponse = exception.getResponse();
      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse !== null
      ) {
        const msg = (exceptionResponse as Record<string, unknown>).message;
        message = Array.isArray(msg)
          ? msg.join('; ')
          : String(msg ?? 'An error occurred');
      } else {
        message = 'An error occurred';
      }
    } else {
      message = status >= 500 ? 'Internal server error' : 'An error occurred';
    }

    const errorResponse = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message:
        typeof message === 'object' && message !== null
          ? (message as { message?: string }).message
          : message,
    };

    if (status >= 500) {
      this.logger.error(
        `HTTP ${status} ${request.method} ${request.url} - ${message}`,
        exception instanceof Error ? exception.stack : '',
      );
    }

    response.status(status).json(errorResponse);
  }
}

