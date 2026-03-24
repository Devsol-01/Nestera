export class NetWorthDto {
  walletBalance: number;
  savingsFlexible: number;
  savingsLocked: number;
  totalSavings: number;
  totalNetWorth: number;
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
