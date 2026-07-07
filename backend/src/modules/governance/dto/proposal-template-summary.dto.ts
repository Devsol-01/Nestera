import { ApiProperty } from '@nestjs/swagger';
import {
  ProposalCategory,
  ProposalType,
} from '../entities/governance-proposal.entity';
export class ProposalTemplateSummaryDto {
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
}
