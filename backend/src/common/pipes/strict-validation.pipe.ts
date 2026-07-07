import {
  Injectable,
  BadRequestException,
  ArgumentMetadata,
  PipeTransform,
  Logger,
  Inject,
  Optional,
} from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';
import { getMetadata } from '@nestjs/common';
import type { ValidationError as ClassValidatorError } from 'class-validator';
import { flattenValidationErrors } from '../validators/validation-error.utils';
import { ContractValidationService } from '../services/contract-validation.service';
import { REQUEST } from '@nestjs/core';
import type { Request } from 'express';

/**
 * StrictValidationPipe: Enhanced validation pipe with:
 * - Strict mode enforcement (all fields validated)
 * - Unknown field rejection (whitelist)
 * - Deterministic transformation (string trimming, numeric conversion)
 * - Correlation ID tracking
 * - Backward compatibility field mapping
 * - Comprehensive logging
 */
@Injectable()
export class StrictValidationPipe implements PipeTransform {
  private readonly logger = new Logger(StrictValidationPipe.name);

  constructor(
    @Optional()
    @Inject(REQUEST)
    private request?: Request,
    @Optional()
    private contractValidationService?: ContractValidationService,
  ) {}

  async transform(
    value: unknown,
    metadata: ArgumentMetadata,
  ): Promise<unknown> {
    const { type, metatype } = metadata;

    // Skip validation for non-body parameters or if no metatype
    if (type !== 'body' || !metatype || typeof metatype !== 'function') {
      return value;
    }

    const correlationId = this.getCorrelationId();
    const endpointPath = this.getEndpointPath();
    const skipStrictValidation =
      this.getMetadataFlag(metatype, 'disableStrictValidation') ?? false;
    const backwardCompatibilityMap =
      this.getMetadataFlag(metatype, 'backwardCompatibilityMap') ?? {};

    try {
      // Pre-validation: Apply transformations and backward compatibility
      let transformedValue = this.applyPreValidationTransforms(
        value,
        backwardCompatibilityMap,
      );

      // Transform to class instance
      const transformedObj = plainToClass(metatype, transformedValue, {
        enableImplicitConversion: true,
        excludeExtraneousValues: true,
      });

      // Validate with class-validator (strict mode)
      const validationErrors = await validate(transformedObj, {
        skipMissingProperties: false,
        whitelist: true,
        forbidNonWhitelisted: !skipStrictValidation,
      });

      if (validationErrors.length > 0) {
        const issues = flattenValidationErrors(
          validationErrors as ClassValidatorError[],
        );

        this.logValidationRejection(
          correlationId,
          endpointPath,
          'validation_failed',
          { issues },
        );

        throw new BadRequestException({
          message: 'Validation failed',
          errors: issues,
          correlationId,
        });
      }

      // Post-validation: Apply additional transformations
      const finalValue = this.applyPostValidationTransforms(transformedObj);

      return finalValue;
    } catch (error) {
      // If it's already a BadRequestException, re-throw it
      if (error instanceof BadRequestException) {
        throw error;
      }

      // Log unexpected validation errors
      this.logger.error(
        `Unexpected error during validation for ${endpointPath} (${correlationId}):`,
        error,
      );

      throw new BadRequestException({
        message: 'Validation failed',
        errors: [
          {
            field: 'unknown',
            constraints: { validation: 'An unexpected error occurred during validation' },
          },
        ],
        correlationId,
      });
    }
  }

  /**
   * Pre-validation transformations: Apply backward compatibility mapping
   * and initial data normalization
   */
  private applyPreValidationTransforms(
    value: unknown,
    backwardCompatibilityMap: Record<string, string>,
  ): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return value as Record<string, unknown>;
    }

    const obj = { ...value } as Record<string, unknown>;

    // Apply backward compatibility: Map deprecated field names to new ones
    for (const [deprecatedField, newField] of Object.entries(
      backwardCompatibilityMap,
    )) {
      if (deprecatedField in obj && !(newField in obj)) {
        obj[newField] = obj[deprecatedField];
        delete obj[deprecatedField];
      }
    }

    // Apply deterministic transformations
    for (const key of Object.keys(obj)) {
      const val = obj[key];

      // Trim strings
      if (typeof val === 'string') {
        obj[key] = val.trim();
      }
    }

    return obj;
  }

  /**
   * Post-validation transformations: Final normalization after validation
   */
  private applyPostValidationTransforms(value: unknown): unknown {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return value;
    }

    const obj = value as Record<string, unknown>;

    // Normalize empty strings to undefined for optional fields
    for (const key of Object.keys(obj)) {
      if (obj[key] === '') {
        obj[key] = undefined;
      }
    }

    return obj;
  }

  /**
   * Get correlation ID from request headers or context
   */
  private getCorrelationId(): string {
    if (this.request?.headers) {
      const correlationId =
        (this.request.headers['x-correlation-id'] as string) ||
        (this.request.headers['x-request-id'] as string) ||
        (this.request.headers['correlation-id'] as string);

      if (correlationId) {
        return correlationId;
      }
    }

    // Generate a new one if not present
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get endpoint path from request
   */
  private getEndpointPath(): string {
    if (this.request) {
      return `${this.request.method} ${this.request.path}`;
    }
    return 'unknown_endpoint';
  }

  /**
   * Get metadata flags from DTO class
   */
  private getMetadataFlag(
    metatype: Function,
    flagName: string,
  ): unknown {
    try {
      return getMetadata(flagName, metatype);
    } catch {
      return undefined;
    }
  }

  /**
   * Log validation rejection with correlationId
   */
  private logValidationRejection(
    correlationId: string,
    endpoint: string,
    reason: string,
    details: Record<string, unknown>,
  ): void {
    this.logger.warn(
      JSON.stringify({
        level: 'validation_rejected',
        correlationId,
        endpoint,
        reason,
        timestamp: new Date().toISOString(),
        details,
      }),
    );

    // Also track in ContractValidationService if available
    if (this.contractValidationService) {
      this.contractValidationService.recordValidationFailure(
        correlationId,
        endpoint,
        reason,
        details,
      );
    }
  }
}
