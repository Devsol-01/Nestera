import { ApiProperty } from '@nestjs/swagger';
import { TransactionSearchCriteriaDto } from './transaction-search-criteria.dto';

export class SavedSearchResponseDto {
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440001' })
  userId: string;

  @ApiProperty({ example: 'My Monthly Deposits' })
  name: string;

  @ApiProperty({ example: 'All deposits from the last 30 days', nullable: true })
  description: string | null;

  @ApiProperty({ type: TransactionSearchCriteriaDto, example: { type: 'deposit', status: 'completed', fromDate: '2026-06-01', toDate: '2026-06-30' } })
  query: TransactionSearchCriteriaDto;

  @ApiProperty({ example: true })
  isDefault: boolean;

  @ApiProperty({ example: '2026-06-29T10:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ example: '2026-06-29T12:00:00.000Z' })
  updatedAt: string;
}
