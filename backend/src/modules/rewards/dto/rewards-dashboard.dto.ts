import { ApiProperty } from '@nestjs/swagger';

export class RewardExpiringPointsDto {
  @ApiProperty({ example: 500 })
  amount: number;

  @ApiProperty({ example: '2026-06-30', nullable: true })
  date: string | null;
}

export class RewardRedemptionOptionDto {
  @ApiProperty({ example: 'fee-discount' })
  id: string;

  @ApiProperty({ example: 'Fee Discount' })
  title: string;

  @ApiProperty({ example: 500 })
  pointsCost: number;

  @ApiProperty({
    example: 'Reduce protocol fees on your next savings action.',
  })
  description: string;
}

export class RewardHistoryItemDto {
  @ApiProperty({ example: 'deposit' })
  source: string;

  @ApiProperty({ example: 1200 })
  points: number;

  @ApiProperty({ example: '2026-03-31T09:35:00.000Z' })
  earnedAt: string;

  @ApiProperty({ example: '2026-06-29T09:35:00.000Z' })
  expiresAt: string;

  @ApiProperty({ example: 'Deposit reward for 120 NST.' })
  description: string;
}

export class RewardTierProjectionDto {
  @ApiProperty({ example: 4580 })
  pointsToNextTier: number;

  @ApiProperty({ example: 6200 })
  projectedMonthlyPoints: number;

  @ApiProperty({ example: 23, nullable: true })
  estimatedDaysToNextTier: number | null;

  @ApiProperty({ example: 206.67 })
  dailyAveragePoints: number;
}

export class RewardsDashboardDto {
  @ApiProperty({ example: 15420 })
  totalPoints: number;

  @ApiProperty({ example: 45 })
  currentStreak: number;

  @ApiProperty({ example: 67 })
  longestStreak: number;

  @ApiProperty({
    type: [String],
    example: ['Early Adopter', 'Goal Crusher', 'Consistent Saver'],
  })
  badges: string[];

  @ApiProperty({ example: 'Gold' })
  tier: string;

  @ApiProperty({ example: 20000, nullable: true })
  nextTierPoints: number | null;

  @ApiProperty({ example: 4580 })
  pointsToNextTier: number;

  @ApiProperty({ type: RewardExpiringPointsDto })
  expiringPoints: RewardExpiringPointsDto;

  @ApiProperty({ type: [RewardRedemptionOptionDto] })
  availableRedemptionOptions: RewardRedemptionOptionDto[];

  @ApiProperty({ type: [RewardHistoryItemDto] })
  earningHistory: RewardHistoryItemDto[];

  @ApiProperty({ example: 8, nullable: true })
  leaderboardPosition: number | null;

  @ApiProperty({ example: 127 })
  totalRankedUsers: number;

  @ApiProperty({ type: RewardTierProjectionDto })
  projectedPointsForNextTier: RewardTierProjectionDto;
}
