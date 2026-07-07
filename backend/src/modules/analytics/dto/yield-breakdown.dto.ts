import { ApiProperty } from '@nestjs/swagger';

export class YieldBreakdownDto {
  @ApiProperty({ example: [{ pool: 'USDC-Aave-v3', earned: 125.5 }, { pool: 'XLM-Stellar', earned: 50.0 }], type: Array })
  pools: Array<{
    pool: string;
    earned: number;
  }>;

  @ApiProperty({ example: 175.5 })
  totalInterestEarned: number;
}
