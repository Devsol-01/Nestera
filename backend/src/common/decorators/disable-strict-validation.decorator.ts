import { SetMetadata } from '@nestjs/common';

/**
 * Decorator to disable strict validation for endpoints that handle
 * special payloads (e.g., file uploads, multipart form data).
 * 
 * Usage:
 * @DisableStrictValidation()
 * @Post('upload')
 * async uploadFile(@Body() dto: FileUploadDto) { ... }
 * 
 * When applied, the endpoint will skip strict validation checks like
 * unknown field rejection, allowing more flexible payload handling.
 */
export const DisableStrictValidation = () =>
  SetMetadata('disableStrictValidation', true);
