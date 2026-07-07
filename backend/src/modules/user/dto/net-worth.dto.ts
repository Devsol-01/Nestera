import { ApiProperty } from '@nestjs/swagger';

export class NetWorthDto {
  @ApiProperty({ description: 'Current wallet balance in XLM', example: 250.75 })
  walletBalance: number;

  @ApiProperty({ description: 'Flexible savings balance in XLM', example: 150.5 })
  savingsFlexible: number;

  @ApiProperty({ description: 'Locked savings balance in XLM', example: 100.25 })
  savingsLocked: number;

  @ApiProperty({ description: 'Total savings balance in XLM', example: 250.75 })
  totalSavings: number;

  @ApiProperty({ description: 'Total net worth (wallet + savings) in XLM', example: 501.5 })
  totalNetWorth: number;

  @ApiProperty({
    description: 'Balance breakdown with percentages',
    example: {
      wallet: { amount: 250.75, percentage: 50 },
      savings: { amount: 250.75, percentage: 50, flexibleAmount: 150.5, lockedAmount: 100.25 },
    },
  })
  balanceBreakdown: {
    wallet: {
      amount: number;
      percentage: number;
    };
    savings: {
      amount: number;
      percentage: number;
      flexibleAmount: number;
      lockedAmount: number;
    };
  };
}
