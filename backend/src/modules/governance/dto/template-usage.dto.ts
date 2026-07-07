import { ApiProperty } from '@nestjs/swagger';

export class TemplateUsageDto {
  @ApiProperty({ description: 'Template identifier', example: 'rate-change-standard' })
  templateId: string;

  @ApiProperty({ description: 'Template version', example: '1.0.0' })
  templateVersion: string;

  @ApiProperty({ description: 'Template name', example: 'Standard Rate Change' })
  templateName: string;

  @ApiProperty({
    description: 'Number of proposals created using this template',
    example: 25,
  })
  proposalsCreated: number;

  @ApiProperty({ description: 'Number of passed proposals', example: 20 })
  passedProposals: number;

  @ApiProperty({ description: 'Number of failed proposals', example: 5 })
  failedProposals: number;

  @ApiProperty({ description: 'Percentage of successful proposals', example: 80.0 })
  successRate: number;
}
