import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsEnum,
  IsBoolean,
  IsOptional,
  IsNumber,
  Min,
  Max,
  IsArray,
  IsObject,
} from 'class-validator';

export class CreateFlagDto {
  @ApiProperty({ example: 'new-dashboard-layout' })
  @IsString()
  @IsNotEmpty()
  key: string;

  @ApiProperty({ example: 'New Dashboard Layout' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'Enable the redesigned dashboard' })
  @IsString()
  @IsNotEmpty()
  description: string;

  @ApiProperty({ example: false })
  @IsNotEmpty()
  defaultValue: boolean | string | number;

  @ApiProperty({ enum: ['boolean', 'string', 'number', 'rollout'], example: 'boolean' })
  @IsEnum(['boolean', 'string', 'number', 'rollout'])
  type: 'boolean' | 'string' | 'number' | 'rollout';

  @ApiPropertyOptional({ example: false })
  @IsBoolean()
  @IsOptional()
  enabled?: boolean;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  value?: boolean | string | number;

  @ApiPropertyOptional({ example: 50, minimum: 0, maximum: 100 })
  @IsNumber()
  @Min(0)
  @Max(100)
  @IsOptional()
  rolloutPercentage?: number;

  @ApiPropertyOptional({ example: ['GABCDEF...'] })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  targetUsers?: string[];

  @ApiPropertyOptional({ example: ['public', 'testnet'] })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  targetNetworks?: string[];

  @ApiPropertyOptional({ example: ['beta_tester', 'internal'] })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  targetSegments?: string[];

  @ApiPropertyOptional({ example: false })
  @IsBoolean()
  @IsOptional()
  forceDisabled?: boolean;

  @ApiPropertyOptional({ example: { team: 'frontend', area: 'dashboard' } })
  @IsObject()
  @IsOptional()
  tags?: Record<string, string>;
}
