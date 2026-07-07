import { Global, Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Notification } from '../notifications/entities/notification.entity';
import { QUEUE_NAMES } from './job-queue.constants';
import { NotificationProcessor } from './processors/notification.processor';
import { EmailProcessor } from './processors/email.processor';
import { BlockchainProcessor } from './processors/blockchain.processor';
import { ReportProcessor } from './processors/report.processor';
import { DisputeEvidenceProcessor } from './processors/dispute-evidence.processor';
import { AvatarProcessor } from './processors/avatar.processor';
import { AuditLogExportProcessor } from './processors/audit-log-export.processor';
import { JobQueueService } from './job-queue.service';
import { JobQueueController } from './job-queue.controller';
import { DisputeEvidence } from '../disputes/entities/dispute-evidence.entity';
import { AvatarUpload } from '../user/entities/avatar-upload.entity';
import { User } from '../user/entities/user.entity';
import { ReportSchedule } from '../reports/entities/report-schedule.entity';
import { StorageModule } from '../storage/storage.module';
import { ReportsModule } from '../reports/reports.module';
import { AuditLog } from '../../common/entities/audit-log.entity';

const defaultJobOptions = {
  attempts: 3,
  backoff: { type: 'exponential' as const, delay: 2000 },
  removeOnComplete: { count: 500 },
  removeOnFail: { count: 1000 },
};

@Global()
@Module({
  imports: [
    StorageModule,
    ReportsModule,
    TypeOrmModule.forFeature([
      Notification,
      DisputeEvidence,
      AvatarUpload,
      User,
      ReportSchedule,
    ]),
    TypeOrmModule.forFeature([Notification, AuditLog]),
    TypeOrmModule.forFeature([DisputeEvidence]),
      AuditLog,
    ]),
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const redisUrl = configService.get<string>('redis.url');
        const workerConcurrency = configService.get<number>(
          'eventStream.workerConcurrency',
          5,
        );
        if (redisUrl) {
          const url = new URL(redisUrl);
          return {
            connection: {
              host: url.hostname,
              port: parseInt(url.port, 10) || 6379,
              password: url.password || undefined,
            },
            workerOptions: { concurrency: workerConcurrency },
          };
        }
        return {
          connection: {
            host: 'localhost',
            port: 6379,
          },
          workerOptions: { concurrency: workerConcurrency },
        };
      },
    }),
    BullModule.registerQueue(
      { name: QUEUE_NAMES.NOTIFICATIONS, defaultJobOptions },
      { name: QUEUE_NAMES.EMAIL, defaultJobOptions },
      {
        name: QUEUE_NAMES.BLOCKCHAIN,
        defaultJobOptions: {
          ...defaultJobOptions,
          attempts: 5,
          backoff: { type: 'exponential' as const, delay: 5000 },
        },
      },
      { name: QUEUE_NAMES.REPORTS, defaultJobOptions },
      { name: QUEUE_NAMES.DISPUTE_EVIDENCE, defaultJobOptions },
      { name: QUEUE_NAMES.AVATAR, defaultJobOptions },
      {
        name: QUEUE_NAMES.AUDIT_LOG_EXPORT,
        defaultJobOptions: {
          ...defaultJobOptions,
          attempts: 3,
          backoff: { type: 'exponential' as const, delay: 2000 },
          removeOnComplete: { count: 100 },
          removeOnFail: { count: 500 },
        },
      },
    ),
  ],
  controllers: [JobQueueController],
  providers: [
    JobQueueService,
    NotificationProcessor,
    EmailProcessor,
    BlockchainProcessor,
    ReportProcessor,
    DisputeEvidenceProcessor,
    AvatarProcessor,
    AuditLogExportProcessor,
  ],
  exports: [JobQueueService, BullModule],
})
export class JobQueueModule {}
