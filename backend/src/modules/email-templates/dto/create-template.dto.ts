import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateTemplateDto {
  @ApiProperty({ example: 'welcome-email' })
  name: string;

  @ApiPropertyOptional({ example: 'Welcome email sent to new users' })
  description?: string;
}
