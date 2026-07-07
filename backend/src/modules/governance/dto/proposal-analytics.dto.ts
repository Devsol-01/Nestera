import { ApiProperty } from '@nestjs/swagger';
import { ProposalCategory } from '../entities/governance-proposal.entity';

export class CategorySuccessRate {
  @ApiProperty({ enum: ProposalCategory, example: ProposalCategory.TECHNICAL })
  category: ProposalCategory;

  @ApiProperty({ description: 'Number of passed proposals', example: 12 })
  passed: number;

  @ApiProperty({ description: 'Number of failed proposals', example: 5 })
  failed: number;

  @ApiProperty({ description: 'Percentage of passed proposals', example: 70.5 })
  successRate: number;
}

export class ProposalAnalyticsDto {
  @ApiProperty({ description: 'Total number of proposals', example: 150 })
  totalProposals: number;

  @ApiProperty({ description: 'Total number of passed proposals', example: 120 })
  passedProposals: number;

  @ApiProperty({ description: 'Percentage of passed proposals', example: 80.0 })
  overallSuccessRate: number;

  @ApiProperty({ description: 'Average voting power per proposal', example: '2500000' })
  averageVotingPower: string;

  @ApiProperty({
    type: [CategorySuccessRate],
    description: 'Category breakdown',
    example: [{ category: ProposalCategory.REVENUE, passed: 12, failed: 5, successRate: 70.5 }],
  })
  categoryBreakdown: CategorySuccessRate[];
}
