import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import {
  flattenValidationErrors,
  ClassValidatorErrorLike,
  ValidationIssue,
} from '../validators/validation-error.utils';

@Catch(BadRequestException)
export class ValidationExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationExceptionFilter.name);

  catch(exception: BadRequestException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const exceptionResponse = exception.getResponse() as
      | string
      | {
          message: string | string[] | ClassValidatorErrorLike[];
          error?: string;
        };

    const statusCode = exception.getStatus();
    const correlationId = (request as any).correlationId;

    let formattedErrors: ValidationIssue[] | string[];
    let message: string;
    let hint: string | undefined;
    let field: string | undefined;

    if (typeof exceptionResponse === 'string') {
      message = exceptionResponse;
      formattedErrors = [exceptionResponse];
    } else if (Array.isArray(exceptionResponse.message)) {
      const msgArray = exceptionResponse.message;

      if (msgArray.length > 0 && typeof msgArray[0] === 'object') {
        const classValidatorErrors = msgArray as ClassValidatorErrorLike[];
        formattedErrors = flattenValidationErrors(classValidatorErrors);
        message = 'Validation failed';
      } else {
        formattedErrors = msgArray as string[];
        message = 'Validation failed';
      }
    } else {
      message =
        typeof exceptionResponse.message === 'string'
          ? exceptionResponse.message
          : 'Bad Request';
      formattedErrors = [message];

      // Surface structured hint/field metadata (e.g., from cursor decoding
      // errors) so clients receive actionable guidance in a single response.
      // See related DTOs in src/common/dto/page-options.dto.ts and the
      // cursor helper in src/common/helpers/cursor-pagination.helper.ts.
      const structured = exceptionResponse as unknown as {
        hint?: unknown;
        field?: unknown;
      };
      hint = typeof structured.hint === 'string' ? structured.hint : undefined;
      field =
        typeof structured.field === 'string' ? structured.field : undefined;
    }

    const body: Record<string, unknown> = {
      success: false,
      statusCode,
      error: 'Validation Error',
      message,
      errors: formattedErrors,
      timestamp: new Date().toISOString(),
      path: request.url,
      correlationId,
    };

    if (hint) body.hint = hint;
    if (field) body.field = field;

    this.logger.debug(
      `Validation error on ${request.method} ${request.url}: ${JSON.stringify(formattedErrors)}`,
    );

    response.status(statusCode).json(body);
  }
}
