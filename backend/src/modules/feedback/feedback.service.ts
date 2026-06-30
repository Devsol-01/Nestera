import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere } from 'typeorm';
import {
  FeedbackSubmission,
  FeedbackStatus,
  FeedbackCategory,
} from './entities/feedback.entity';
import {
  CreateFeedbackDto,
  UpdateFeedbackStatusDto,
  FeedbackQueryDto,
} from './dto/feedback.dto';

export interface FeedbackAnalytics {
  total: number;
  byCategory: Record<FeedbackCategory, number>;
  byStatus: Record<FeedbackStatus, number>;
  averageRating: number | null;
  ratingDistribution: Record<string, number>;
}

@Injectable()
export class FeedbackService {
  constructor(
    @InjectRepository(FeedbackSubmission)
    private readonly feedbackRepo: Repository<FeedbackSubmission>,
  ) {}

  async submit(
    userId: string,
    dto: CreateFeedbackDto,
    screenshotUrl?: string,
    options?: { screenshotReservationId?: string | null },
  ): Promise<FeedbackSubmission> {
    const feedback = this.feedbackRepo.create({
      userId,
      category: dto.category,
      rating: dto.rating ?? null,
      comment: dto.comment,
      screenshotUrl: screenshotUrl ?? null,
      status: FeedbackStatus.SUBMITTED,
      quotaReservationId: options?.screenshotReservationId ?? null,
    });
    return this.feedbackRepo.save(feedback);
  }

  async findByUser(userId: string): Promise<FeedbackSubmission[]> {
    return this.feedbackRepo.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async findAll(query: FeedbackQueryDto): Promise<FeedbackSubmission[]> {
    const where: FindOptionsWhere<FeedbackSubmission> = {};
    if (query.category) where.category = query.category;
    if (query.status) where.status = query.status;

    return this.feedbackRepo.find({
      where,
      relations: ['user'],
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string): Promise<FeedbackSubmission> {
    const feedback = await this.feedbackRepo.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!feedback) {
      throw new NotFoundException(`Feedback ${id} not found`);
    }
    return feedback;
  }

  async updateStatus(
    id: string,
    dto: UpdateFeedbackStatusDto,
  ): Promise<FeedbackSubmission> {
    const feedback = await this.findOne(id);
    feedback.status = dto.status;
    if (dto.adminNotes !== undefined) {
      feedback.adminNotes = dto.adminNotes;
    }
    if (
      dto.status === FeedbackStatus.RESOLVED ||
      dto.status === FeedbackStatus.CLOSED
    ) {
      feedback.resolvedAt = new Date();
    }
    return this.feedbackRepo.save(feedback);
  }

  async attachScreenshot(
    id: string,
    userId: string,
    screenshotUrl: string,
  ): Promise<FeedbackSubmission> {
    const feedback = await this.findOne(id);
    if (feedback.userId !== userId) {
      throw new ForbiddenException('You can only update your own feedback');
    }
    feedback.screenshotUrl = screenshotUrl;
    return this.feedbackRepo.save(feedback);
  }

  async getAnalytics(): Promise<FeedbackAnalytics> {
    const all = await this.feedbackRepo.find();

    const byCategory = Object.values(FeedbackCategory).reduce(
      (acc, cat) => {
        acc[cat] = all.filter((f) => f.category === cat).length;
        return acc;
      },
      {} as Record<FeedbackCategory, number>,
    );

    const byStatus = Object.values(FeedbackStatus).reduce(
      (acc, status) => {
        acc[status] = all.filter((f) => f.status === status).length;
        return acc;
      },
      {} as Record<FeedbackStatus, number>,
    );

    const rated = all.filter((f) => f.rating != null);
    const averageRating =
      rated.length > 0
        ? rated.reduce((sum, f) => sum + (f.rating ?? 0), 0) / rated.length
        : null;

    const ratingDistribution: Record<string, number> = {};
    for (let i = 1; i <= 5; i++) {
      ratingDistribution[String(i)] = rated.filter(
        (f) => f.rating === i,
      ).length;
    }

    return {
      total: all.length,
      byCategory,
      byStatus,
      averageRating,
      ratingDistribution,
    };
  }
}
