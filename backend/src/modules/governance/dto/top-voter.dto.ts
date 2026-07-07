import { ApiProperty } from '@nestjs/swagger';

export class TopVoterDto {
  @ApiProperty({ description: 'The wallet address of the voter', example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN' })
  walletAddress: string;

  @ApiProperty({ description: 'Number of unique proposals voted on', example: 15 })
  voteCount: number;

  @ApiProperty({ description: 'Total voting power used across all proposals', example: '1250000' })
  totalWeight: string;

  @ApiProperty({ description: 'Rank of the voter based on activity', example: 1 })
  rank: number;
}
