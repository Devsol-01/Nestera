import { IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateVisibilityDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  isLeaderboardVisible: boolean;
}
