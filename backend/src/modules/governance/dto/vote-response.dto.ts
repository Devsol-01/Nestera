import { ApiProperty } from '@nestjs/swagger';
import { VoteDirection } from '../entities/vote.entity';

export class VoteResponseDto {
  @ApiProperty({ description: 'Unique vote identifier', example: '8a7b3c1d-2e4f-5a6b-7c8d-9e0f1a2b3c4d' })
  id: string;

  @ApiProperty({ description: 'Voter wallet address', example: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN' })
  walletAddress: string;

  @ApiProperty({
    enum: VoteDirection,
    description: 'Vote direction (FOR or AGAINST)',
    example: VoteDirection.FOR,
  })
  direction: VoteDirection;

  @ApiProperty({ description: 'Vote weight (voting power)', example: 5000 })
  weight: number;

  @ApiProperty({ description: 'Associated proposal ID', example: 42 })
  proposalId: string;

  @ApiProperty({ description: 'Vote cast timestamp', example: '2026-03-15T10:30:00.000Z' })
  createdAt: Date;
}
