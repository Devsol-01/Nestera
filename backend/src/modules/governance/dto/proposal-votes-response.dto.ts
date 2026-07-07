import { ApiProperty } from '@nestjs/swagger';
import { VoteDirection } from '../entities/vote.entity';

class ProposalVoteTallyDto {
  @ApiProperty({ example: 128 })
  forVotes: number;

  @ApiProperty({ example: 64 })
  againstVotes: number;

  @ApiProperty({ example: 32 })
  abstainVotes: number;

  @ApiProperty({ example: '84250.5' })
  forWeight: string;

  @ApiProperty({ example: '29300' })
  againstWeight: string;

  @ApiProperty({ example: '10500' })
  abstainWeight: string;

  @ApiProperty({ example: '124050.5' })
  totalWeight: string;
}

class RecentVoterDto {
  @ApiProperty({
    example: 'GB7TAYQB6A6E7MCCKRUYJ4JYK2YTHJOTD4A5Q65XAH2EJQ2F6J67P5ST',
  })
  walletAddress: string;

  @ApiProperty({ enum: VoteDirection, enumName: 'VoteDirection', example: VoteDirection.FOR })
  direction: VoteDirection;

  @ApiProperty({ example: '5000' })
  weight: string;

  @ApiProperty({ example: '2026-03-26T13:01:15.518Z' })
  votedAt: string;
}

export class ProposalVotesResponseDto {
  @ApiProperty({ example: 12 })
  proposalOnChainId: number;

  @ApiProperty({
    type: ProposalVoteTallyDto,
    example: { forVotes: 128, againstVotes: 64, abstainVotes: 32, forWeight: '84250.5', againstWeight: '29300', abstainWeight: '10500', totalWeight: '124050.5' },
  })
  tally: ProposalVoteTallyDto;

  @ApiProperty({
    type: [RecentVoterDto],
    example: [{ walletAddress: 'GB7TAYQB6A6E7MCCKRUYJ4JYK2YTHJOTD4A5Q65XAH2EJQ2F6J67P5ST', direction: 'FOR', weight: '5000', votedAt: '2026-03-26T13:01:15.518Z' }],
  })
  recentVoters: RecentVoterDto[];

  @ApiProperty({
    example: 120,
    description: 'Total number of votes for this proposal',
  })
  total: number;

  @ApiProperty({ example: 0, description: 'Current page index (0-based)' })
  page: number;
}
