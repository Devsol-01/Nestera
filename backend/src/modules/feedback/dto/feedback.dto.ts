import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsInt,
  Min,
  Max,
  MinLength,
  MaxLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FeedbackCategory, FeedbackStatus } from '../entities/feedback.entity';

export class CreateFeedbackDto {
  @ApiProperty({ enum: FeedbackCategory, example: FeedbackCategory.BUG_REPORT })
  @IsEnum(FeedbackCategory)
  category: FeedbackCategory;

  @ApiPropertyOptional({ example: 4, minimum: 1, maximum: 5 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(5)
  rating?: number;

  @ApiProperty({ example: 'The savings page fails to load on mobile devices.' })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(2000)
  comment: string;
}

export class UpdateFeedbackStatusDto {
  @ApiProperty({ enum: FeedbackStatus, example: FeedbackStatus.IN_REVIEW })
  @IsEnum(FeedbackStatus)
  status: FeedbackStatus;

  @ApiPropertyOptional({ example: 'Reproduced on iOS Safari 17' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  adminNotes?: string;
}

export class FeedbackQueryDto {
  @ApiPropertyOptional({ enum: FeedbackCategory, example: FeedbackCategory.BUG_REPORT })
  @IsOptional()
  @IsEnum(FeedbackCategory)
  category?: FeedbackCategory;

  @ApiPropertyOptional({ enum: FeedbackStatus, example: FeedbackStatus.OPEN })
  @IsOptional()
  @IsEnum(FeedbackStatus)
  status?: FeedbackStatus;
}
