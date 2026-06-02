import { applyDecorators, HttpStatus } from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';

/** Standard 401 Unauthorized response */
export const ApiUnauthorized = () =>
  ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Missing or invalid JWT token',
    schema: {
      example: {
        statusCode: 401,
        message: 'Unauthorized',
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/** Standard 403 Forbidden response */
export const ApiForbidden = () =>
  ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
    schema: {
      example: {
        statusCode: 403,
        message: 'Forbidden resource',
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/** Standard 404 Not Found response */
export const ApiNotFound = (resource = 'Resource') =>
  ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: `${resource} not found`,
    schema: {
      example: {
        statusCode: 404,
        message: `${resource} not found`,
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/** Standard 422 / 400 Validation error */
export const ApiBadRequest = (message = 'Validation failed') =>
  ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: message,
    schema: {
      example: {
        statusCode: 400,
        message,
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/** Standard 429 Too Many Requests response */
export const ApiTooManyRequests = () =>
  ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description:
      'Rate limit exceeded. Default limits: 100 req/min (general), 5 req/15 min (auth), 10 req/min (RPC-heavy).',
    schema: {
      example: {
        statusCode: 429,
        message: 'ThrottlerException: Too Many Requests',
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/** Standard 500 Internal Server Error */
export const ApiInternalError = () =>
  ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
    schema: {
      example: {
        statusCode: 500,
        message: 'Internal server error',
        timestamp: '2026-06-01T00:00:00.000Z',
      },
    },
  });

/**
 * Bundle of common error responses for authenticated endpoints:
 * 401, 429, 500
 */
export const ApiAuthResponses = () =>
  applyDecorators(ApiUnauthorized(), ApiTooManyRequests(), ApiInternalError());

/**
 * Bundle for admin-only endpoints: 401, 403, 429, 500
 */
export const ApiAdminResponses = () =>
  applyDecorators(
    ApiUnauthorized(),
    ApiForbidden(),
    ApiTooManyRequests(),
    ApiInternalError(),
  );
