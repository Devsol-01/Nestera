import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ProposalCategory,
  ProposalStatus,
} from '../entities/governance-proposal.entity';

export class ProposalTimelineDto {
  @ApiProperty({
    description: 'Proposal start boundary as UNIX block number',
    nullable: true,
    example: 123456,
  })
  startTime: number | null;

  @ApiProperty({
    description: 'Proposal end boundary as UNIX block number',
    nullable: true,
    example: 124000,
  })
  endTime: number | null;
}

export class ProposalListItemDto {
  @ApiProperty({ example: '8a7b3c1d-2e4f-5a6b-7c8d-9e0f1a2b3c4d' })
  id: string;

  @ApiProperty({ example: 42 })
  onChainId: number;

  @ApiProperty({ example: 'Increase Flexi Rate by 10%' })
  title: string;

  @ApiPropertyOptional({ example: 'Proposal to raise the flexible savings rate' })
  description: string | null;

  @ApiProperty({ enum: ProposalCategory, example: ProposalCategory.TREASURY })
  category: ProposalCategory;

  @ApiProperty({ enum: ProposalStatus, example: ProposalStatus.ACTIVE })
  status: ProposalStatus;

  @ApiPropertyOptional({ example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN' })
  proposer: string | null;

  @ApiProperty({
    description: 'Percentage of votes cast FOR (0–100)',
    example: 62.5,
  })
  forPercent: number;

  @ApiProperty({
    description: 'Percentage of votes cast AGAINST (0–100)',
    example: 37.5,
  })
  againstPercent: number;

  @ApiProperty({
    description: 'Percentage of votes cast ABSTAIN (0–100)',
    example: 10.0,
  })
  abstainPercent: number;

  @ApiProperty({ type: () => ProposalTimelineDto, example: { startTime: 123456, endTime: 124000 } })
  timeline: ProposalTimelineDto;
}
