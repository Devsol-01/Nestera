import { ApiProperty } from '@nestjs/swagger';

export class AssetAllocationItemDto {
  @ApiProperty({ example: 'USDC', description: 'Asset identifier / code' })
  assetId: string;

  @ApiProperty({
    example: 1500.0,
    description: 'Total amount held for this asset',
  })
  amount: number;

  @ApiProperty({
    example: 62.5,
    description: 'Percentage of total portfolio (2 decimal places)',
  })
  percentage: number;
}

export class AssetAllocationDto {
  @ApiProperty({ type: [AssetAllocationItemDto], example: [{ assetId: 'USDC', amount: 1500, percentage: 62.5 }] })
  allocations: AssetAllocationItemDto[];

  @ApiProperty({
    example: 2400.0,
    description: 'Absolute total across all assets',
  })
  total: number;
}
