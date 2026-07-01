import { Process, Processor } from '@nestjs/bull';
import { Injectable } from '@nestjs/common';
import { Job } from 'bullmq';
import {
  DATA_EXPORT_JOB_NAME,
  DATA_EXPORT_QUEUE,
} from './data-export.constants';
import { DataExportService } from './data-export.service';

@Injectable()
@Processor(DATA_EXPORT_QUEUE)
export class DataExportProcessor {
  constructor(private readonly dataExportService: DataExportService) {}

  @Process(DATA_EXPORT_JOB_NAME)
  async handle(job: Job<{ requestId: string }>): Promise<void> {
    await this.dataExportService.processExportJob(
      job.data.requestId,
      String(job.id),
    );
  }
}
