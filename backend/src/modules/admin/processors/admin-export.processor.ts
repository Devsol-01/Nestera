import { Process, Processor } from '@nestjs/bull';
import { Job } from 'bullmq';
import { Injectable } from '@nestjs/common';
import {
  ADMIN_EXPORT_JOB_NAME,
  ADMIN_EXPORT_QUEUE,
} from '../admin-export.constants';
import { AdminExportService } from '../services/admin-export.service';

@Injectable()
@Processor(ADMIN_EXPORT_QUEUE)
export class AdminExportProcessor {
  constructor(private readonly adminExportService: AdminExportService) {}

  @Process(ADMIN_EXPORT_JOB_NAME)
  async handle(job: Job<{ exportJobId: string }>): Promise<void> {
    await this.adminExportService.processExportJob(
      job.data.exportJobId,
      String(job.id),
    );
  }
}
