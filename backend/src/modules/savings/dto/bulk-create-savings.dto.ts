import { IsArray, IsString, IsNotEmpty, IsNumber, IsPositive, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class BulkSavingsItemDto {
  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsNumber()
  @IsPositive()
  amount: number;

  @IsString()
  @IsNotEmpty()
  savingsType: string; // e.g., 'locked', 'flexible', 'goal'
}

export class BulkCreateSavingsDto {
  @IsString()
  @IsNotEmpty()
  batchId: string;

  @IsArray()
  @ValidateNested({ friendships: true })
  @Type(() => BulkSavingsItemDto)
  items: BulkSavingsItemDto[];
}