import { ApiProperty } from '@nestjs/swagger';
import { BadgeCategory, BadgeTier } from '../entities/badge.entity';

export class BadgeDto {
  @ApiProperty({ example: 'badge-550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ example: 'streak_master' })
  code: string;

  @ApiProperty({ example: 'Streak Master' })
  name: string;

  @ApiProperty({ example: 'Awarded for completing a 7-day saving streak' })
  description: string;

  @ApiProperty({ enum: BadgeCategory, example: BadgeCategory.ACHIEVEMENT })
  category: BadgeCategory;

  @ApiProperty({ enum: BadgeTier, example: BadgeTier.GOLD })
  tier: BadgeTier;

  @ApiProperty({ example: 'https://example.com/badges/streak-master.png' })
  icon: string;

  @ApiProperty({ example: '#FFD700' })
  color: string;

  @ApiProperty({ example: 100 })
  points: number;

  @ApiProperty({ example: true })
  active: boolean;

  @ApiPropertyOptional({ example: { requirement: '7_days' } })
  criteria?: Record<string, any>;

  @ApiPropertyOptional({ example: false })
  earned?: boolean;

  @ApiPropertyOptional({ example: '2026-06-29T12:00:00.000Z' })
  earnedAt?: Date;

  @ApiPropertyOptional({ example: { currentStreak: 4 } })
  progress?: Record<string, any>;
}

export class UserBadgeDto {
  @ApiProperty({ example: 'ub-550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ type: BadgeDto, example: { id: 'badge-550e8400-e29b-41d4-a716-446655440000', code: 'streak_master', name: 'Streak Master', description: 'Awarded for completing a 7-day saving streak', category: 'achievement', tier: 'gold', icon: 'https://example.com/badges/streak-master.png', color: '#FFD700', points: 100, active: true } })
  badge: BadgeDto;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z' })
  earnedAt: Date;

  @ApiPropertyOptional({ example: { currentStreak: 4 } })
  progress?: Record<string, any>;

  @ApiProperty({ example: false })
  shared: boolean;

  @ApiPropertyOptional({ example: '2026-06-29T12:30:00.000Z' })
  sharedAt?: Date;

  @ApiPropertyOptional({ example: 'token-550e8400-e29b-41d4-a716-446655440000' })
  shareToken?: string;

  @ApiPropertyOptional({ example: { platform: 'twitter' } })
  metadata?: Record<string, any>;
}

export class BadgeStatsDto {
  @ApiProperty({ example: 50 })
  totalBadges: number;

  @ApiProperty({ example: 12 })
  earnedBadges: number;

  @ApiProperty({ example: 1250 })
  totalPoints: number;

  @ApiProperty({ type: [UserBadgeDto], example: [] })
  recentBadges: UserBadgeDto[];

  @ApiProperty({ example: { achievement: 8, participation: 4 } })
  categoryBreakdown: Record<BadgeCategory, number>;
}
