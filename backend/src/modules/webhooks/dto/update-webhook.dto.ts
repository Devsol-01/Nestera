import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsUrl,
  IsArray,
  ArrayNotEmpty,
  IsString,
  IsOptional,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UpdateWebhookDto {
  @ApiPropertyOptional({
    description: 'New target URL',
    example: 'https://example.com/webhooks/v2',
  })
  @IsOptional()
  @IsUrl({ require_tld: false })
  url?: string;

  @ApiPropertyOptional({
    description: 'New set of event patterns',
    example: ['savings.*'],
    type: [String],
  })
  @IsOptional()
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  events?: string[];

  @ApiPropertyOptional({
    description: 'New signing secret',
    example: 'new-secret',
  })
  @IsOptional()
  @IsString()
  @MinLength(8)
  @MaxLength(256)
  secret?: string;

  @ApiPropertyOptional({
    description: 'Updated description',
    example: 'Production deposit notifications v2',
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}
