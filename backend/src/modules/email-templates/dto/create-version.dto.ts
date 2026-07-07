import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateVersionDto {
  @ApiPropertyOptional({ example: 2 })
  version?: number;

  @ApiProperty({ example: 'Welcome to Nestera!' })
  subject: string;

  @ApiPropertyOptional({ example: '<h1>Welcome</h1><p>Thank you for joining!</p>' })
  html?: string;

  @ApiPropertyOptional({ example: 'Welcome to Nestera!\nThank you for joining!' })
  text?: string;

  @ApiPropertyOptional({ example: { sendAt: '2026-07-01T10:00:00.000Z' } })
  metadata?: any;

  @ApiPropertyOptional({ example: true })
  active?: boolean;
}
