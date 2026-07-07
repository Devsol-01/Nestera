import { ApiProperty } from '@nestjs/swagger';
import {
  LedgerTransactionStatus,
  LedgerTransactionType,
} from '../../blockchain/entities/transaction.entity';

export class TransactionResponseDto {
  @ApiProperty({ description: 'Transaction ID', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ description: 'User ID', example: '550e8400-e29b-41d4-a716-446655440001' })
  userId: string;

  @ApiProperty({
    description: 'Transaction type',
    enum: LedgerTransactionType,
    example: LedgerTransactionType.DEPOSIT,
  })
  type: LedgerTransactionType;

  @ApiProperty({
    description: 'Transaction status',
    enum: LedgerTransactionStatus,
    example: LedgerTransactionStatus.COMPLETED,
  })
  status: LedgerTransactionStatus;

  @ApiProperty({ description: 'Transaction amount (raw decimal string)', example: '100000000' })
  amount: string;

  @ApiProperty({
    description: 'Formatted amount with currency symbol and proper decimals',
    example: {
      raw: '100000000',
      numeric: 100,
      formatted: '100.00',
      display: '$100.00',
      symbol: 'USDC',
      decimals: 7,
    },
  })
  amountFormatted: {
    raw: string;
    numeric: number;
    formatted: string;
    display: string;
    symbol: string;
    decimals: number;
  };

  @ApiProperty({ description: 'Public key', nullable: true, example: 'GABC1234ABCDEFGHIJKLMNOPQRSTUVWXYZ1234' })
  publicKey: string | null;

  @ApiProperty({ description: 'Event ID', example: 'evt_550e8400-e29b-41d4-a716-446655440000' })
  eventId: string;

  @ApiProperty({ description: 'Transaction hash', nullable: true, example: 'abc123def456...' })
  transactionHash: string | null;

  @ApiProperty({
    description: 'Stellar Expert explorer links',
    example: {
      transaction: 'https://stellar.expert/explorer/testnet/tx/abc123...',
      search: 'https://stellar.expert/explorer/testnet/search?term=abc123...',
      network: 'https://stellar.expert/explorer/testnet',
    },
    nullable: true,
  })
  explorerLinks?: {
    transaction: string;
    search: string;
    network: string;
  };

  @ApiProperty({ description: 'Ledger sequence', nullable: true, example: '123456789' })
  ledgerSequence: string | null;

  @ApiProperty({ description: 'Pool ID', nullable: true, example: '550e8400-e29b-41d4-a716-446655440002' })
  poolId: string | null;

  @ApiProperty({ description: 'Additional metadata', nullable: true, example: { source: 'stellar', memo: 'deposit' } })
  metadata: Record<string, unknown> | null;

  @ApiProperty({ description: 'Transaction category', nullable: true, example: 'Savings' })
  category?: string | null;

  @ApiProperty({
    description: 'Tags attached to the transaction',
    nullable: true,
    isArray: true,
    example: ['groceries', 'monthly'],
  })
  tags?: string[];

  @ApiProperty({ description: 'Transaction creation date (ISO 8601)', example: '2026-06-29T10:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ description: 'Formatted date for display', example: 'Jun 29, 2026' })
  formattedDate: string;

  @ApiProperty({ description: 'Formatted time for display', example: '10:00 AM' })
  formattedTime: string;
}
