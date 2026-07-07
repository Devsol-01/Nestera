import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ProposalAttachment,
  ProposalStatus,
  ProposalCategory,
  ProposalType,
  ProposalActionPayload,
} from '../entities/governance-proposal.entity';
import { VoteResponseDto } from './vote-response.dto';

export class ProposalResponseDto {
  @ApiProperty({ description: 'Unique identifier', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ description: 'On-chain proposal ID', example: 42 })
  onChainId: number;

  @ApiProperty({ description: 'Proposal title', example: 'Increase Flexi Rate by 10%' })
  title: string;

  @ApiProperty({ description: 'Detailed description', example: 'Proposal to raise the flexible savings rate due to increased market yield' })
  description: string;

  @ApiProperty({ enum: ProposalCategory, example: ProposalCategory.TREASURY })
  category: ProposalCategory;

  @ApiProperty({
    enum: ProposalType,
    nullable: true,
    description: 'Structured proposal type when available',
    example: ProposalType.PARAMETER_CHANGE,
  })
  type: ProposalType | null;

  @ApiPropertyOptional({
    description: 'Template identifier used to create this proposal, if any',
    example: 'rate-change-standard',
  })
  templateId?: string | null;

  @ApiPropertyOptional({
    description: 'Template version used to create this proposal, if any',
    example: '1.0',
  })
  templateVersion?: string | null;

  @ApiPropertyOptional({
    description: 'Template parameters used to generate the action payload',
    type: 'object',
    additionalProperties: true,
    example: { target: 'flexiRate', newValue: 10 },
  })
  templateParameters?: Record<string, unknown> | null;

  @ApiProperty({ nullable: true, description: 'Structured action payload for the proposal', example: { target: 'flexiRate', newValue: 10 } })
  action: ProposalActionPayload | null;

  @ApiProperty({ enum: ProposalStatus, example: ProposalStatus.ACTIVE })
  status: ProposalStatus;

  @ApiProperty({ description: 'Proposer wallet address', nullable: true, example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN' })
  proposer: string | null;

  @ApiProperty({ description: 'Start block number', nullable: true, example: 123456 })
  startBlock: number | null;

  @ApiProperty({ description: 'End block number', nullable: true, example: 124000 })
  endBlock: number | null;

  @ApiProperty({
    type: 'array',
    description: 'Supporting documents and links',
    example: [
      {
        name: 'Economic analysis',
        url: 'https://example.com/analysis.pdf',
        type: 'DOCUMENT',
      },
    ],
  })
  attachments: ProposalAttachment[];

  @ApiProperty({
    description: 'Required voting quorum for this proposal in NST units',
    example: '5000.00000000',
  })
  requiredQuorum: string;

  @ApiProperty({
    description: 'Quorum percentage in basis points',
    example: 5000,
  })
  quorumBps: number;

  @ApiProperty({
    description: 'Minimum voting power required to submit a proposal',
    example: '100.00000000',
  })
  proposalThreshold: string;

  @ApiProperty({
    description: 'Whether the proposal can still be edited by its creator',
    example: true,
  })
  canEdit: boolean;

  @ApiProperty({
    description: 'All votes on this proposal',
    type: [VoteResponseDto],
    example: [
      {
        id: '8a7b3c1d-2e4f-5a6b-7c8d-9e0f1a2b3c4d',
        walletAddress: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHJKLMN',
        direction: 'FOR',
        weight: 5000,
        proposalId: '42',
        createdAt: '2026-03-15T10:30:00.000Z',
      },
    ],
  })
  votes: VoteResponseDto[];

  @ApiProperty({ description: 'Creation timestamp', example: '2026-03-15T10:00:00.000Z' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp', example: '2026-03-29T14:00:00.000Z' })
  updatedAt: Date;
}
