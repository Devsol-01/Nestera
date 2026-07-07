import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class TimeSeriesDataPointDto {
  @ApiProperty({ example: '2026-06-29T12:00:00.000Z', type: String, format: 'date-time' })
  timestamp: Date;

  @ApiProperty({ example: 1500, type: Number })
  value: number;

  @ApiPropertyOptional({ example: 1400, type: Number })
  previousValue?: number;

  @ApiPropertyOptional({ example: 100, type: Number })
  change?: number;

  @ApiPropertyOptional({ example: 7.14, type: Number })
  changePercentage?: number;
}

export class ComparisonDto {
  @ApiProperty({ example: 10000, type: Number })
  previousValue: number;

  @ApiProperty({ example: 15000, type: Number })
  currentValue: number;

  @ApiProperty({ example: 5000, type: Number })
  change: number;

  @ApiProperty({ example: 50, type: Number })
  changePercentage: number;

  @ApiProperty({ example: 'up', type: String })
  trend: 'up' | 'down' | 'stable';

  @ApiPropertyOptional({ example: 'Previous 30 days', type: String })
  comparisonPeriod?: string;
}

export class DrillDownDto {
  @ApiProperty({ example: 'savings', type: String })
  category: string;

  @ApiProperty({ example: { USDC: 50000, XLM: 10000 }, type: Object })
  breakdown: Record<string, any>;

  @ApiPropertyOptional({ example: [{ timestamp: '2026-06-29T00:00:00.000Z', value: 1400 }], type: [TimeSeriesDataPointDto] })
  timeSeries?: TimeSeriesDataPointDto[];

  @ApiPropertyOptional({ example: 15000, type: Number })
  total?: number;

  @ApiPropertyOptional({ example: 35.5, type: Number })
  percentage?: number;
}

export class UserGrowthDto {
  @ApiProperty({ example: 11500, type: Number })
  totalUsers: number;

  @ApiProperty({ example: 8900, type: Number })
  activeUsers: number;

  @ApiProperty({ example: 320, type: Number })
  newUsersCount: number;

  @ApiProperty({ example: 2600, type: Number })
  inactiveUsers: number;

  @ApiProperty({ example: 180, type: Number })
  churnedUsers: number;

  @ApiProperty({ example: 77.4, type: Number })
  retentionRate: number;

  @ApiProperty({ example: 1.6, type: Number })
  churnRate: number;

  @ApiProperty({ example: 2.8, type: Number })
  growthRate: number;

  @ApiPropertyOptional({ example: { US: 5000, EU: 3000 }, type: Object })
  usersByRegion?: Record<string, number>;

  @ApiPropertyOptional({ example: { free: 8000, premium: 3500 }, type: Object })
  usersBySegment?: Record<string, number>;

  @ApiPropertyOptional({ example: [{ timestamp: '2026-06-29T00:00:00.000Z', value: 11000 }], type: [TimeSeriesDataPointDto] })
  timeSeries?: TimeSeriesDataPointDto[];

  @ApiPropertyOptional({ example: { previousValue: 10000, currentValue: 11500, change: 1500, changePercentage: 15, trend: 'up', comparisonPeriod: 'Previous 30 days' }, type: () => ComparisonDto })
  comparison?: ComparisonDto;
}

export class TransactionVolumeDto {
  @ApiProperty({ example: 1520, type: Number })
  totalTransactions: number;

  @ApiProperty({ example: 1200, type: Number })
  successfulTransactions: number;

  @ApiProperty({ example: 45, type: Number })
  failedTransactions: number;

  @ApiProperty({ example: 275, type: Number })
  pendingTransactions: number;

  @ApiProperty({ example: 500000, type: Number })
  totalVolume: number;

  @ApiProperty({ example: 328.9, type: Number })
  avgTransactionAmount: number;

  @ApiProperty({ example: 10, type: Number })
  minTransactionAmount: number;

  @ApiProperty({ example: 5000, type: Number })
  maxTransactionAmount: number;

  @ApiProperty({ example: 78.9, type: Number })
  successRate: number;

  @ApiProperty({ example: 3.0, type: Number })
  failureRate: number;

  @ApiProperty({ example: 25000, type: Number })
  avgGasUsed: number;

  @ApiProperty({ example: 38000000, type: Number })
  totalGasSpent: number;

  @ApiPropertyOptional({ example: { deposit: 800, withdrawal: 400, transfer: 320 }, type: Object })
  transactionsByType?: Record<string, number>;

  @ApiPropertyOptional({ example: { USDC: 300000, XLM: 200000 }, type: Object })
  volumeByType?: Record<string, number>;

  @ApiPropertyOptional({ example: [{ timestamp: '2026-06-29T00:00:00.000Z', value: 1400 }], type: [TimeSeriesDataPointDto] })
  timeSeries?: TimeSeriesDataPointDto[];

  @ApiPropertyOptional({ example: { previousValue: 10000, currentValue: 11500, change: 1500, changePercentage: 15, trend: 'up', comparisonPeriod: 'Previous 30 days' }, type: () => ComparisonDto })
  comparison?: ComparisonDto;

  @ApiPropertyOptional({ example: { category: 'savings', breakdown: { USDC: 30000, XLM: 20000 }, total: 50000 }, type: () => DrillDownDto })
  drillDown?: DrillDownDto;
}

export class SavingsMetricsDto {
  @ApiProperty({ example: 3200, type: Number })
  totalAccounts: number;

  @ApiProperty({ example: 2800, type: Number })
  activeAccounts: number;

  @ApiProperty({ example: 150, type: Number })
  newAccounts: number;

  @ApiProperty({ example: 20, type: Number })
  closedAccounts: number;

  @ApiProperty({ example: 2500000, type: Number })
  totalValueLocked: number;

  @ApiProperty({ example: 500000, type: Number })
  inflow: number;

  @ApiProperty({ example: 250000, type: Number })
  outflow: number;

  @ApiProperty({ example: 4.5, type: Number })
  avgApy: number;

  @ApiProperty({ example: 2.0, type: Number })
  minApy: number;

  @ApiProperty({ example: 8.0, type: Number })
  maxApy: number;

  @ApiProperty({ example: 12000, type: Number })
  totalInterestEarned: number;

  @ApiProperty({ example: 4.7, type: Number })
  accountGrowthRate: number;

  @ApiProperty({ example: 12.3, type: Number })
  tvlGrowthRate: number;

  @ApiPropertyOptional({ example: { flexible: 1500, locked: 1700 }, type: Object })
  accountsByProduct?: Record<string, number>;

  @ApiPropertyOptional({ example: { flexible: 1000000, locked: 1500000 }, type: Object })
  tvlByProduct?: Record<string, number>;

  @ApiPropertyOptional({ example: { flexible: 3.5, locked: 5.0 }, type: Object })
  apyByProduct?: Record<string, number>;

  @ApiPropertyOptional({ example: [{ timestamp: '2026-06-29T00:00:00.000Z', value: 2400000 }], type: [TimeSeriesDataPointDto] })
  timeSeries?: TimeSeriesDataPointDto[];

  @ApiPropertyOptional({ example: { previousValue: 2000000, currentValue: 2500000, change: 500000, changePercentage: 25, trend: 'up', comparisonPeriod: 'Previous 30 days' }, type: () => ComparisonDto })
  comparison?: ComparisonDto;

  @ApiPropertyOptional({ example: { category: 'savings', breakdown: { flexible: 1500000, locked: 1000000 }, total: 2500000 }, type: () => DrillDownDto })
  drillDown?: DrillDownDto;
}

export class SystemHealthDto {
  @ApiProperty({ example: 98.5, type: Number })
  healthScore: number;

  @ApiProperty({ example: 99.9, type: Number })
  apiUptime: number;

  @ApiProperty({ example: 99.95, type: Number })
  blockchainUptime: number;

  @ApiProperty({ example: 15420, type: Number })
  totalRequests: number;

  @ApiProperty({ example: 15200, type: Number })
  successfulRequests: number;

  @ApiProperty({ example: 220, type: Number })
  failedRequests: number;

  @ApiProperty({ example: 45, type: Number })
  avgResponseTime: number;

  @ApiProperty({ example: 120, type: Number })
  p95ResponseTime: number;

  @ApiProperty({ example: 250, type: Number })
  p99ResponseTime: number;

  @ApiProperty({ example: 62.5, type: Number })
  memoryUsage: number;

  @ApiProperty({ example: 45.2, type: Number })
  cpuUsage: number;

  @ApiProperty({ example: 78.1, type: Number })
  diskUsage: number;

  @ApiProperty({ example: 94.5, type: Number })
  cacheHitRate: number;

  @ApiPropertyOptional({ example: { database: 'healthy', redis: 'healthy', stellar: 'healthy' }, type: Object })
  serviceStatus?: Record<string, any>;

  @ApiPropertyOptional({ example: [{ severity: 'warning', message: 'High memory usage', timestamp: '2026-06-29T12:00:00.000Z' }], type: Array })
  alerts?: Array<{
    severity: 'critical' | 'warning' | 'info';
    message: string;
    timestamp: Date;
  }>;
}

export class StatisticsOverviewDto {
  @ApiProperty({ type: UserGrowthDto, example: { totalUsers: 11500, activeUsers: 8900, newUsersCount: 320, inactiveUsers: 2600, churnedUsers: 180, retentionRate: 77.4, churnRate: 1.6, growthRate: 2.8, usersByRegion: { US: 5000, EU: 3000 }, usersBySegment: { free: 8000, premium: 3500 } } })
  userGrowth: UserGrowthDto;

  @ApiProperty({ type: TransactionVolumeDto, example: { totalTransactions: 1520, successfulTransactions: 1200, failedTransactions: 45, pendingTransactions: 275, totalVolume: 500000, avgTransactionAmount: 328.9, minTransactionAmount: 10, maxTransactionAmount: 5000, successRate: 78.9, failureRate: 3.0, avgGasUsed: 25000, totalGasSpent: 38000000 } })
  transactionVolume: TransactionVolumeDto;

  @ApiProperty({ type: SavingsMetricsDto, example: { totalAccounts: 3200, activeAccounts: 2800, newAccounts: 150, closedAccounts: 20, totalValueLocked: 2500000, inflow: 500000, outflow: 250000, avgApy: 4.5, minApy: 2.0, maxApy: 8.0, totalInterestEarned: 12000, accountGrowthRate: 4.7, tvlGrowthRate: 12.3 } })
  savingsMetrics: SavingsMetricsDto;

  @ApiProperty({ type: SystemHealthDto, example: { healthScore: 98.5, apiUptime: 99.9, blockchainUptime: 99.95, totalRequests: 15420, successfulRequests: 15200, failedRequests: 220, avgResponseTime: 45, p95ResponseTime: 120, p99ResponseTime: 250, memoryUsage: 62.5, cpuUsage: 45.2, diskUsage: 78.1, cacheHitRate: 94.5 } })
  systemHealth: SystemHealthDto;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z', type: String, format: 'date-time' })
  generatedAt: Date;

  @ApiPropertyOptional({ example: 'Auto-generated report', type: String })
  note?: string;
}

export class StatisticsExportDto {
  @ApiProperty({ example: 'json', type: String })
  format: 'json' | 'csv' | 'xlsx';

  @ApiProperty({ example: 'all', type: String })
  dataType: 'all' | 'users' | 'transactions' | 'savings' | 'health';

  @ApiProperty({ example: 'statistics-export-2026-06-29.json', type: String })
  fileName: string;

  @ApiPropertyOptional({ example: 'Monthly statistics export', type: String })
  description?: string;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z', type: String, format: 'date-time' })
  generatedAt: Date;
}
