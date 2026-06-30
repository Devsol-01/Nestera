import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  HttpCode,
  HttpStatus,
  FileValidator,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '../../common/enums/role.enum';
import { StorageService } from '../storage/storage.service';
import { FeedbackService } from './feedback.service';
import {
  StorageQuotaService,
  QuotaReservation,
} from '../storage-quota/storage-quota.service';
import { QuotaUploadKind } from '../storage-quota/entities/storage-quota-ledger.entity';
import { Throttle } from '@nestjs/throttler';
import {
  CreateFeedbackDto,
  UpdateFeedbackStatusDto,
  FeedbackQueryDto,
} from './dto/feedback.dto';
import { FeedbackSubmission } from './entities/feedback.entity';

class ScreenshotValidator extends FileValidator {
  constructor() {
    super({});
  }

  isValid(file: any): boolean {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    return allowed.includes(file.mimetype);
  }

  buildErrorMessage(): string {
    return 'Invalid screenshot. Only JPEG, PNG, and WebP are allowed.';
  }
}

@ApiTags('feedback')
@Controller('feedback')
export class FeedbackController {
  constructor(
    private readonly feedbackService: FeedbackService,
    private readonly storageService: StorageService,
    private readonly quotaService: StorageQuotaService,
  ) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Submit user feedback' })
  @ApiResponse({ status: 201, type: FeedbackSubmission })
  async submit(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateFeedbackDto,
  ): Promise<FeedbackSubmission> {
    return this.feedbackService.submit(user.id, dto);
  }

  @Post('with-screenshot')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ upload: { limit: 10, ttl: 60_000 } })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['category', 'comment', 'screenshot'],
      properties: {
        category: {
          type: 'string',
          enum: ['BUG_REPORT', 'FEATURE_REQUEST', 'GENERAL'],
        },
        rating: { type: 'integer', minimum: 1, maximum: 5 },
        comment: { type: 'string' },
        screenshot: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiOperation({ summary: 'Submit feedback with screenshot attachment' })
  @UseInterceptors(FileInterceptor('screenshot'))
  async submitWithScreenshot(
    @CurrentUser() user: { id: string },
    @Body() dto: CreateFeedbackDto,
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
          new ScreenshotValidator(),
        ],
      }),
    )
    file: any,
  ): Promise<FeedbackSubmission> {
    // Reserve quota before writing the file. Screenshots have no
    // background processing, so commit immediately after the write.
    const reservation: QuotaReservation = await this.quotaService.reserve(
      user.id,
      file.size,
      {
        uploadKind: QuotaUploadKind.FEEDBACK_SCREENSHOT,
        reason: 'feedback-screenshot',
      },
    );

    let screenshotUrl: string;
    try {
      screenshotUrl = await this.storageService.saveFile(file);
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'storage-write-failed',
      });
      throw err;
    }

    try {
      const submission = await this.feedbackService.submit(
        user.id,
        dto,
        screenshotUrl,
        { screenshotReservationId: reservation.reservationId },
      );
      await this.quotaService.commit(reservation.reservationId, {
        finalBytes: file.size,
        reason: 'feedback-screenshot-stored',
      });
      return submission;
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'feedback-record-failed',
      });
      throw err;
    }
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List current user feedback submissions' })
  async getMyFeedback(
    @CurrentUser() user: { id: string },
  ): Promise<FeedbackSubmission[]> {
    return this.feedbackService.findByUser(user.id);
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: list all feedback with optional filters' })
  async adminList(
    @Query() query: FeedbackQueryDto,
  ): Promise<FeedbackSubmission[]> {
    return this.feedbackService.findAll(query);
  }

  @Get('admin/analytics')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: feedback analytics dashboard data' })
  async adminAnalytics() {
    return this.feedbackService.getAnalytics();
  }

  @Get('admin/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: get feedback details' })
  async adminGetOne(@Param('id') id: string): Promise<FeedbackSubmission> {
    return this.feedbackService.findOne(id);
  }

  @Patch('admin/:id/status')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: update feedback status' })
  async adminUpdateStatus(
    @Param('id') id: string,
    @Body() dto: UpdateFeedbackStatusDto,
  ): Promise<FeedbackSubmission> {
    return this.feedbackService.updateStatus(id, dto);
  }
}
