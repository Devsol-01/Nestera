import { ApiProperty } from '@nestjs/swagger';

export class TrendDataPoint {
  @ApiProperty({ description: 'The time interval (e.g. 2026-03)', example: '2026-03' })
  interval: string;

  @ApiProperty({ description: 'Number of proposals created', example: 5 })
  proposalsCount: number;

  @ApiProperty({ description: 'Number of votes cast', example: 120 })
  votesCount: number;

  @ApiProperty({ description: 'Total voting power used', example: '2500000' })
  totalWeight: string;
}

export class GovernanceTrendDto {
  @ApiProperty({
    type: [TrendDataPoint],
    description: 'Governance trend data',
    example: [{ interval: '2026-03', proposalsCount: 5, votesCount: 120, totalWeight: '2500000' }],
  })
  trends: TrendDataPoint[];
}
