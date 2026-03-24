import { IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  bio?: string;
}

export class ApproveKycDto {
  @IsString()
  userId: string;
}

export class RejectKycDto {
  @IsString()
  userId: string;

  @IsString()
  reason: string;
}
