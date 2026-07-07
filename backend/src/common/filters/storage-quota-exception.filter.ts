import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { StorageQuotaExceededException } from '../../modules/storage-quota/storage-quota.types';

/**
 * Maps {@link StorageQuotaExceededException} to an HTTP response.
 *
 * Status code policy:
 *   - 'storage'      → 402 Payment Required (semantically: quota is
 *                       capacity-bound, not request-bound).
 *   - 'concurrency'  → 429 Too Many Requests.
 *   - 'frequency'    → 429 Too Many Requests.
 *
 * The downstream rate-limiter (`TieredThrottlerGuard`) already produces
 * 429s for the upload throttler bucket, so when this filter fires the
 * exception has already escaped that layer and represents a deeper
 * capacity / concurrency check.
 *
 * Kept globally registered in CommonModule; any other HTTP exception
 * falls through to the standard Nest filter chain.
 */
@Catch(StorageQuotaExceededException)
export class StorageQuotaExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(StorageQuotaExceptionFilter.name);

  catch(exception: StorageQuotaExceededException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception.kind === 'storage'
        ? HttpStatus.PAYMENT_REQUIRED
        : HttpStatus.TOO_MANY_REQUESTS;

    const body = {
      success: false,
      statusCode: status,
      errorCode: exception.code,
      quotaKind: exception.kind,
      message: exception.message,
      meta: exception.meta,
      endpoint: `${request?.method ?? '?'} ${request?.originalUrl ?? request?.url ?? '/'}`,
      timestamp: new Date().toISOString(),
    };

    this.logger.warn(
      `[storage-quota] ${exception.kind} ${request?.method ?? '?'} ${request?.originalUrl ?? request?.url ?? '/'} — ${exception.message}`,
    );

    response.status(status).json(body);
  }
}
