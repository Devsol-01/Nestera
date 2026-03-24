import { ApiProperty } from '@nestjs/swagger';

export class TransactionDto {
  @ApiProperty({
    description: 'ISO 8601 timestamp of when the transaction was recorded',
    example: '2024-01-15T10:30:00Z',
  })
  date: string;

  @ApiProperty({
    description: 'Human-readable amount of the transaction',
    example: '10.5000000',
  })
  amount: string;

  @ApiProperty({
    description: 'Asset/token type involved in the transaction',
    example: 'XLM',
  })
  token: string;

  @ApiProperty({
    description: 'Unique transaction hash on the Stellar network',
    example: 'a1b2c3d4e5f6...',
  })
  hash: string;
}
