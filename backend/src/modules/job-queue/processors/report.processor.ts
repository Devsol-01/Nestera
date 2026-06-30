import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QUEUE_NAMES } from '../job-queue.constants';
import { ReportJobData } from '../job-queue.service';
import { ScheduledReportService } from '../../reports/scheduled-report.service';
import { ReportSchedule } from '../../reports/entities/report-schedule.entity';

@Processor(QUEUE_NAMES.REPORTS)
export class ReportProcessor extends WorkerHost {
  private readonly logger = new Logger(ReportProcessor.name);

  constructor(
    private readonly scheduledReportService: ScheduledReportService,
    @InjectRepository(ReportSchedule)
    private readonly scheduleRepository: Repository<ReportSchedule>,
  ) {
    super();
  }

  async process(job: Job<ReportJobData>): Promise<any> {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(
      `${correlationPrefix}Processing report job ${job.id} (attempt ${job.attemptsMade + 1})`,
    );

    const { reportType, userId, scheduleId } = job.data;

    if (scheduleId) {
      const schedule = await this.scheduleRepository.findOne({
        where: { id: scheduleId },
      });
      if (!schedule) {
        throw new Error(`Report schedule ${scheduleId} not found`);
      }

      try {
        const archive =
          await this.scheduledReportService.generateAndArchive(schedule);
        await this.scheduleRepository.update(scheduleId, {
          lastRunAt: new Date(),
          lastError: null,
        });
        return {
          processed: true,
          scheduleId,
          archiveId: archive.id,
          reportType,
          userId,
        };
      } catch (error) {
        const errMsg = (error as Error).message;
        await this.scheduleRepository.update(scheduleId, {
          lastError: errMsg,
        });
        throw error;
      }
    }

    this.logger.log(
      `${correlationPrefix}Ad-hoc report job completed: type=${reportType} user=${userId}`,
    );
    return { processed: true, reportType, userId };
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job<ReportJobData>, error: Error) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.error(
      `${correlationPrefix}Report job ${job.id} failed after ${job.attemptsMade} attempts: ${error.message}`,
    );
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<ReportJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(`${correlationPrefix}Report job ${job.id} completed`);
  }
}
