import { SetMetadata } from '@nestjs/common';

/**
 * Decorator to allow backward compatibility for deprecated field names.
 * Allows temporary tolerance of old field names while mapping them to new ones.
 * 
 * Usage:
 * @AllowBackwardCompatibility({
 *   'oldFieldName': 'newFieldName',
 *   'deprecatedField': 'currentField'
 * })
 * async updateUser(@Body() dto: UpdateUserDto) { ... }
 * 
 * When applied to a controller method, requests with 'oldFieldName' will be
 * automatically mapped to 'newFieldName' before validation.
 */
export const AllowBackwardCompatibility = (
  fieldMapping: Record<string, string>,
) => SetMetadata('backwardCompatibilityMap', fieldMapping);
