import { ApiProperty } from '@nestjs/swagger';
import {
  ProposalCategory,
  ProposalType,
} from '../entities/governance-proposal.entity';

export class ProposalTemplateParameterDto {
  @ApiProperty({ description: 'Parameter name', example: 'target' })
  name: string;

  @ApiProperty({ description: 'User-friendly label', example: 'Target Parameter' })
  label: string;

  @ApiProperty({ description: 'Parameter description', example: 'The parameter to modify' })
  description: string;

  @ApiProperty({ description: 'Value type', example: 'string' })
  type: string;

  @ApiProperty({ description: 'Whether the field is required', example: true })
  required: boolean;

  @ApiProperty({
    description: 'Allowed values when using an enum',
    required: false,
    example: ['flexiRate', 'fixedRate'],
  })
  allowedValues?: string[];

  @ApiProperty({
    description: 'Minimum numeric value when applicable',
    required: false,
    example: 0,
  })
  min?: number;

  @ApiProperty({
    description: 'Maximum numeric value when applicable',
    required: false,
    example: 100,
  })
  max?: number;

  @ApiProperty({ description: 'Default value when omitted', required: false, example: 0 })
  default?: unknown;

  @ApiProperty({ description: 'Example value', required: false, example: 'fixedRate' })
  example?: unknown;
}

export class ProposalTemplateDetailDto {
  @ApiProperty({ description: 'Template identifier', example: 'rate-change-standard' })
  id: string;

  @ApiProperty({ description: 'Template version', example: '1.0.0' })
  version: string;

  @ApiProperty({ description: 'Template name', example: 'Standard Rate Change' })
  name: string;

  @ApiProperty({ description: 'Template description', example: 'Template for changing savings product rates' })
  description: string;

  @ApiProperty({ enum: ProposalType, example: ProposalType.RATE_CHANGE })
  type: ProposalType;

  @ApiProperty({ enum: ProposalCategory, example: ProposalCategory.TECHNICAL })
  category: ProposalCategory;

  @ApiProperty({
    type: [ProposalTemplateParameterDto],
    description: 'Parameter schema',
    example: [{
      name: 'target',
      label: 'Target Rate',
      description: 'The rate to set',
      type: 'string',
      required: true,
      allowedValues: ['flexiRate', 'fixedRate'],
    }],
  })
  parameterSchema: ProposalTemplateParameterDto[];
}
