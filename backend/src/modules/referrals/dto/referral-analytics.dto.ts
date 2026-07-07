import { IsOptional, IsUUID, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ReferralAnalyticsQueryDto {
  @ApiPropertyOptional({
    description: 'Scope analytics to a single campaign',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsOptional()
  @IsUUID()
  campaignId?: string;
}

export class LeaderboardQueryDto {
  @ApiPropertyOptional({
    description: 'Scope leaderboard to a single campaign',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsOptional()
  @IsUUID()
  campaignId?: string;

  @ApiPropertyOptional({
    description: 'Number of top referrers to return',
    default: 10,
    minimum: 1,
    maximum: 100,
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}

export class ConversionFunnelDto {
  @ApiProperty({ description: 'Total referral codes generated', example: 5000 })
  codesGenerated!: number;

  @ApiProperty({ description: 'Referees who signed up using a code', example: 2500 })
  signups!: number;

  @ApiProperty({ description: 'Referrals that qualified (deposit completed)', example: 1200 })
  completed!: number;

  @ApiProperty({ description: 'Referrals that were rewarded', example: 800 })
  rewarded!: number;

  @ApiProperty({ description: 'Referrals flagged as fraudulent', example: 50 })
  fraudulent!: number;

  @ApiProperty({ description: 'Signup rate (signups / codesGenerated) as %', example: 50 })
  signupRate!: number;

  @ApiProperty({
    description: 'Activation rate (completed / signups) as %',
    example: 48,
  })
  activationRate!: number;

  @ApiProperty({ description: 'Reward rate (rewarded / completed) as %', example: 66.7 })
  rewardRate!: number;

  @ApiProperty({
    description: 'Overall conversion (rewarded / codesGenerated) as %',
    example: 16,
  })
  overallConversionRate!: number;
}

export class RevenueAttributionDto {
  @ApiProperty({ description: 'Distinct referred users who signed up', example: 2500 })
  referredUsers!: number;

  @ApiProperty({ description: 'Referred users who made a qualifying deposit', example: 1200 })
  payingReferredUsers!: number;

  @ApiProperty({
    description: 'Total deposit revenue attributed to referred users',
    example: '50000.00',
  })
  attributedRevenue!: string;

  @ApiProperty({ description: 'Total rewards paid out to referrers/referees', example: '5000.00' })
  rewardsPaid!: string;

  @ApiProperty({
    description: 'Net revenue (attributedRevenue - rewardsPaid)',
    example: '45000.00',
  })
  netRevenue!: string;

  @ApiProperty({
    description: 'Return on investment as % ((revenue - cost) / cost)',
    nullable: true,
    example: 800,
  })
  roiPercentage!: number | null;

  @ApiProperty({ description: 'Average attributed revenue per signup', example: '20.00' })
  averageRevenuePerReferral!: string;
}

export class CampaignPerformanceDto {
  @ApiProperty({ nullable: true, example: '550e8400-e29b-41d4-a716-446655440000' })
  campaignId!: string | null;

  @ApiProperty({ example: 'Summer Referral Bonus' })
  campaignName!: string;

  @ApiProperty({ type: () => ConversionFunnelDto, example: { codesGenerated: 1000, signups: 500, completed: 250, rewarded: 150, fraudulent: 10, signupRate: 50, activationRate: 50, rewardRate: 60, overallConversionRate: 15 } })
  funnel!: ConversionFunnelDto;

  @ApiProperty({ type: () => RevenueAttributionDto, example: { referredUsers: 500, payingReferredUsers: 250, attributedRevenue: '25000.00', rewardsPaid: '2500.00', netRevenue: '22500.00', roiPercentage: 800, averageRevenuePerReferral: '50.00' } })
  revenue!: RevenueAttributionDto;
}

export class LeaderboardEntryDto {
  @ApiProperty({ example: 1 })
  rank!: number;

  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440001' })
  userId!: number;

  @ApiProperty({ example: 25 })
  successfulReferrals!: number;

  @ApiProperty({ example: '12500.00' })
  attributedRevenue!: string;

  @ApiProperty({ example: '2500.00' })
  totalRewards!: string;
}

export class ReferralAnalyticsDashboardDto {
  @ApiProperty({ type: () => ConversionFunnelDto, example: { codesGenerated: 5000, signups: 2500, completed: 1200, rewarded: 800, fraudulent: 50, signupRate: 50, activationRate: 48, rewardRate: 66.7, overallConversionRate: 16 } })
  funnel!: ConversionFunnelDto;

  @ApiProperty({ type: () => RevenueAttributionDto, example: { referredUsers: 2500, payingReferredUsers: 1200, attributedRevenue: '50000.00', rewardsPaid: '5000.00', netRevenue: '45000.00', roiPercentage: 800, averageRevenuePerReferral: '20.00' } })
  revenue!: RevenueAttributionDto;

  @ApiProperty({ type: () => [CampaignPerformanceDto], example: [{ campaignId: '550e8400-e29b-41d4-a716-446655440000', campaignName: 'Summer Referral Bonus', funnel: { codesGenerated: 1000, signups: 500, completed: 250, rewarded: 150, fraudulent: 10, signupRate: 50, activationRate: 50, rewardRate: 60, overallConversionRate: 15 }, revenue: { referredUsers: 500, payingReferredUsers: 250, attributedRevenue: '25000.00', rewardsPaid: '2500.00', netRevenue: '22500.00', roiPercentage: 800, averageRevenuePerReferral: '50.00' } }] })
  campaigns!: CampaignPerformanceDto[];

  @ApiProperty({ type: () => [LeaderboardEntryDto], example: [{ rank: 1, userId: '550e8400-e29b-41d4-a716-446655440001', successfulReferrals: 25, attributedRevenue: '12500.00', totalRewards: '2500.00' }] })
  topReferrers!: LeaderboardEntryDto[];

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z' })
  generatedAt!: Date;
}

export class ReferralAnalyticsDashboardDto {
  @ApiProperty({ type: () => ConversionFunnelDto, example: { codesGenerated: 5000, signups: 2500, completed: 1200, rewarded: 800, fraudulent: 50, signupRate: 50, activationRate: 48, rewardRate: 66.7, overallConversionRate: 16 } })
  funnel!: ConversionFunnelDto;

  @ApiProperty({ type: () => RevenueAttributionDto, example: { referredUsers: 2500, payingReferredUsers: 1200, attributedRevenue: '50000.00', rewardsPaid: '5000.00', netRevenue: '45000.00', roiPercentage: 800, averageRevenuePerReferral: '20.00' } })
  revenue!: RevenueAttributionDto;

  @ApiProperty({ type: () => [CampaignPerformanceDto], example: [{ campaignId: '550e8400-e29b-41d4-a716-446655440000', campaignName: 'Summer Referral Bonus', funnel: { codesGenerated: 1000, signups: 500, completed: 250, rewarded: 150, fraudulent: 10, signupRate: 50, activationRate: 50, rewardRate: 60, overallConversionRate: 15 }, revenue: { referredUsers: 500, payingReferredUsers: 250, attributedRevenue: '25000.00', rewardsPaid: '2500.00', netRevenue: '22500.00', roiPercentage: 800, averageRevenuePerReferral: '50.00' } }] })
  campaigns!: CampaignPerformanceDto[];

  @ApiProperty({ type: () => [LeaderboardEntryDto], example: [{ rank: 1, userId: '550e8400-e29b-41d4-a716-446655440001', successfulReferrals: 25, attributedRevenue: '12500.00', totalRewards: '2500.00' }] })
  topReferrers!: LeaderboardEntryDto[];

  @ApiProperty()
  generatedAt!: Date;
}
