import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import {
  AutoDepositSchedule,
  AutoDepositFrequency,
  AutoDepositStatus,
} from '../entities/auto-deposit-schedule.entity';
import { CreateAutoDepositDto } from '../dto/auto-deposit.dto';
import { SavingsService } from '../savings.service';

const MAX_RETRIES = 5;

@Injectable()
export class AutoDepositService {
  private readonly logger = new Logger(AutoDepositService.name);

  constructor(
    @InjectRepository(AutoDepositSchedule)
    private readonly scheduleRepo: Repository<AutoDepositSchedule>,
    private readonly savingsService: SavingsService,
  ) {}

  async create(
    userId: string,
    dto: CreateAutoDepositDto,
  ): Promise<AutoDepositSchedule> {
    const nextRunAt = this.computeNextRun(dto.frequency);
    const schedule = this.scheduleRepo.create({
      userId,
      productId: dto.productId,
      amount: dto.amount,
      frequency: dto.frequency,
      status: AutoDepositStatus.ACTIVE,
      nextRunAt,
    });
    return this.scheduleRepo.save(schedule);
  }

  async findAllForUser(userId: string): Promise<AutoDepositSchedule[]> {
    return this.scheduleRepo.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async pause(id: string, userId: string): Promise<AutoDepositSchedule> {
    const schedule = await this.findOwned(id, userId);
    if (schedule.status === AutoDepositStatus.CANCELLED) {
      throw new BadRequestException('Cannot pause a cancelled schedule');
    }
    schedule.status = AutoDepositStatus.PAUSED;
    return this.scheduleRepo.save(schedule);
  }

  async cancel(id: string, userId: string): Promise<void> {
    const schedule = await this.findOwned(id, userId);
    schedule.status = AutoDepositStatus.CANCELLED;
    await this.scheduleRepo.save(schedule);
  }

  /** Runs every minute; processes due schedules */
  @Cron(CronExpression.EVERY_MINUTE)
  async processDueSchedules(): Promise<void> {
    const now = new Date();
    const due = await this.scheduleRepo
      .createQueryBuilder('s')
      .where('s.status = :status', { status: AutoDepositStatus.ACTIVE })
      .andWhere('s.nextRunAt <= :now', { now })
      .getMany();

    for (const schedule of due) {
      await this.executeSchedule(schedule);
    }
  }

  private async executeSchedule(schedule: AutoDepositSchedule): Promise<void> {
    try {
      await this.savingsService.subscribe(
        schedule.userId,
        schedule.productId,
        Number(schedule.amount),
        true, // overrideLimits — auto-deposit bypasses per-user subscription cap
      );
      schedule.retryCount = 0;
      schedule.nextRunAt = this.computeNextRun(schedule.frequency);
      await this.scheduleRepo.save(schedule);
      this.logger.log(`Auto-deposit executed for schedule ${schedule.id}`);
    } catch (error) {
      schedule.retryCount += 1;
      if (schedule.retryCount >= MAX_RETRIES) {
        schedule.status = AutoDepositStatus.CANCELLED;
        this.logger.error(
          `Auto-deposit schedule ${schedule.id} cancelled after ${MAX_RETRIES} failures`,
        );
      } else {
        // Exponential backoff: 2^retryCount minutes
        const backoffMs = Math.pow(2, schedule.retryCount) * 60_000;
        schedule.nextRunAt = new Date(Date.now() + backoffMs);
        this.logger.warn(
          `Auto-deposit schedule ${schedule.id} retry ${schedule.retryCount} in ${backoffMs / 1000}s`,
        );
      }
      await this.scheduleRepo.save(schedule);
    }
  }

  private async findOwned(
    id: string,
    userId: string,
  ): Promise<AutoDepositSchedule> {
    const schedule = await this.scheduleRepo.findOne({ where: { id, userId } });
    if (!schedule) {
      throw new NotFoundException(`Auto-deposit schedule ${id} not found`);
    }
    return schedule;
  }

  computeNextRun(frequency: AutoDepositFrequency, from = new Date()): Date {
    const next = new Date(from);
    switch (frequency) {
      case AutoDepositFrequency.DAILY:
        next.setDate(next.getDate() + 1);
        break;
      case AutoDepositFrequency.WEEKLY:
        next.setDate(next.getDate() + 7);
        break;
      case AutoDepositFrequency.BI_WEEKLY:
        next.setDate(next.getDate() + 14);
        break;
      case AutoDepositFrequency.MONTHLY:
        next.setMonth(next.getMonth() + 1);
        break;
    }
    return next;
  }
}
