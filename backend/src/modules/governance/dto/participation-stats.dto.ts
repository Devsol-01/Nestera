import { ApiProperty } from '@nestjs/swagger';

export class ParticipationStatsDto {
  @ApiProperty({ description: 'Total number of unique voters', example: 450 })
  totalUniqueVoters: number;

  @ApiProperty({ description: 'Average number of voters per proposal', example: 35 })
  averageVotersPerProposal: number;

  @ApiProperty({ description: 'Percentage of proposals that reached quorum', example: 78.5 })
  quorumAchievementRate: number;

  @ApiProperty({ description: 'Total votes cast across all proposals', example: 5250 })
  totalVotesCast: number;

  @ApiProperty({ description: 'Current active voters (voted in last 30 days)', example: 120 })
  activeVoters: number;
}
