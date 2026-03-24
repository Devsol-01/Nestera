import { IsString, IsNotEmpty, IsUUID, MinLength, MaxLength, IsOptional, IsUrl } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateDisputeDto {
  @ApiProperty({ example: 'uuid-of-claim' })
  @IsUUID()
  @IsNotEmpty()
  claimId: string;

  @ApiProperty({ example: 'Hospital Admin' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(100)
  disputedBy: string;

  @ApiProperty({ example: 'Claim amount was incorrectly calculated' })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(1000)
  reason: string;
}

export class UpdateDisputeDto {
  @ApiProperty({ example: 'UNDER_REVIEW', enum: ['OPEN', 'UNDER_REVIEW', 'RESOLVED', 'CLOSED'] })
  @IsString()
  @IsOptional()
  status?: string;
}

export class AddDisputeMessageDto {
  @ApiProperty({ example: 'John Doe' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(100)
  author: string;

  @ApiProperty({ example: 'Attached supporting documents' })
  @IsString()
  @IsNotEmpty()
  @MinLength(1)
  @MaxLength(2000)
  message: string;

  @ApiProperty({ example: 'https://example.com/evidence.pdf', required: false })
  @IsOptional()
  @IsUrl()
  evidenceUrl?: string;
}
