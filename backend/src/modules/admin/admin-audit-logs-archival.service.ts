import { Injectable, Logger, Optional } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Cron } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { promisify } from 'util';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream';
import {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import {
  AuditLog,
  AuditAction,
  AuditResourceType,
  SYSTEM_ACTOR,
} from '../../common/entities/audit-log.entity';
import { AuditLogService } from '../../common/services/audit-log.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ShutdownTrackedTask } from '../../common/decorators/shutdown-task.decorator';

const pipelineAsync = promisify(pipeline);

export interface ArchivalConfig {
  retentionDays: number;
  compressionEnabled: boolean;
  coldStorageEnabled: boolean;
  s3Bucket?: string;
  localArchivePath: string;
  batchSize: number;
}

@Injectable()
export class AdminAuditLogsArchivalService {
  private readonly logger = new Logger(AdminAuditLogsArchivalService.name);
  private readonly config: ArchivalConfig;
  private readonly s3?: S3Client;

  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
    private readonly configService: ConfigService,
    private readonly eventEmitter?: EventEmitter2,
    @Optional() private readonly auditLogService?: AuditLogService,
  ) {
    this.config = {
      retentionDays:
        this.configService.get<number>('audit.retentionDays') || 90,
      compressionEnabled:
        this.configService.get<boolean>('audit.compression.enabled') ?? true,
      coldStorageEnabled:
        this.configService.get<boolean>('audit.coldStorage.enabled') ?? true,
      s3Bucket: this.configService.get<string>('audit.coldStorage.s3Bucket'),
      localArchivePath:
        this.configService.get<string>('audit.archivePath') ||
        '/var/archive/audit-logs',
      batchSize:
        this.configService.get<number>('audit.archivalBatchSize') || 10000,
    };

    if (this.config.coldStorageEnabled && this.config.s3Bucket) {
      this.s3 = new S3Client({
        region:
          this.configService.get<string>('audit.coldStorage.region') ||
          'us-east-1',
        credentials: {
          accessKeyId: this.configService.get<string>(
            'audit.coldStorage.awsAccessKeyId',
          )!,
          secretAccessKey: this.configService.get<string>(
            'audit.coldStorage.awsSecretAccessKey',
          )!,
        },
      });
    }

    this.ensureArchiveDirectory();
  }

  /**
   * Daily archival job — runs at 01:00 UTC
   */
  @ShutdownTrackedTask()
  @Cron('0 1 * * *')
  async archiveOldLogs(): Promise<void> {
    const startedAt = Date.now();
    const cutoffDate = this.getArchivalCutoffDate();

    // Capture before-state for audit diff
    const logsBeforeArchival = await this.auditLogRepository.count({
      where: { timestamp: LessThan(cutoffDate) },
    });
    const totalBeforeArchival = await this.auditLogRepository.count();

    try {
      this.logger.log(
        `Starting audit log archival for logs before ${cutoffDate.toISOString()}`,
      );

      const count = await this.archiveLogsBefore(cutoffDate);

      this.logger.log(`Archival completed. Archived ${count} audit logs.`);

      this.eventEmitter?.emit('audit.logs.archived', {
        count,
        cutoffDate,
        timestamp: new Date(),
      });

      // Audit log – successful archival (SYSTEM actor)
      await this.auditLogService?.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.ARCHIVE,
        resourceType: AuditResourceType.JOB,
        description: `Audit log archival completed: ${count} logs archived (cutoff=${cutoffDate.toISOString()}, retentionDays=${this.config.retentionDays}).`,
        previousValue: {
          totalLogsInDb: totalBeforeArchival,
          logsEligibleForArchival: logsBeforeArchival,
          cutoffDate: cutoffDate.toISOString(),
        },
        newValue: {
          archivedCount: count,
          totalLogsAfterArchival: totalBeforeArchival - count,
          completedAt: new Date().toISOString(),
        },
        durationMs: Date.now() - startedAt,
        success: true,
      });
    } catch (error) {
      const msg = (error as Error).message;
      this.logger.error(`Audit log archival failed: ${msg}`);

      this.eventEmitter?.emit('audit.archival.failed', {
        error: msg,
        timestamp: new Date(),
      });

      // Audit log – failed archival
      await this.auditLogService?.log({
        actor: SYSTEM_ACTOR,
        action: AuditAction.ARCHIVE,
        resourceType: AuditResourceType.JOB,
        description: `Audit log archival failed: ${msg}`,
        previousValue: {
          totalLogsInDb: totalBeforeArchival,
          logsEligibleForArchival: logsBeforeArchival,
          cutoffDate: cutoffDate.toISOString(),
        },
        newValue: { error: msg },
        durationMs: Date.now() - startedAt,
        success: false,
        errorMessage: msg,
      });
    }
  }

  /**
   * Archive logs older than the cutoff date
   */
  async archiveLogsBefore(cutoffDate: Date): Promise<number> {
    let totalArchived = 0;

    while (true) {
      const logs = await this.auditLogRepository.find({
        where: {
          timestamp: LessThan(cutoffDate),
        },
        order: { timestamp: 'ASC' },
        take: this.config.batchSize,
      });

      if (logs.length === 0) {
        break;
      }

      const archiveFileName = `audit-logs-${Date.now()}.jsonl`;

      // Write logs to temp file
      const tempPath = path.join(
        this.config.localArchivePath,
        `${archiveFileName}.tmp`,
      );
      await this.writeLogsToFile(logs, tempPath);

      // Compress if enabled
      let finalPath = tempPath;
      if (this.config.compressionEnabled) {
        finalPath = await this.compressFile(tempPath);
        fs.unlinkSync(tempPath);
      }

      // Upload to cold storage
      if (this.config.coldStorageEnabled && this.s3) {
        await this.uploadToS3(finalPath, path.basename(finalPath));
        fs.unlinkSync(finalPath);
      }

      // Delete archived logs from database
      const ids = logs.map((l) => l.id);
      await this.auditLogRepository.delete(ids);

      totalArchived += logs.length;

      this.logger.debug(
        `Archived batch of ${logs.length} logs (total: ${totalArchived})`,
      );
    }

    return totalArchived;
  }

  /**
   * Write logs to JSONL format (one JSON object per line)
   */
  private async writeLogsToFile(
    logs: AuditLog[],
    filePath: string,
  ): Promise<void> {
    const writeStream = createWriteStream(filePath, { encoding: 'utf-8' });

    return new Promise((resolve, reject) => {
      for (const log of logs) {
        const line = JSON.stringify(log) + '\n';
        writeStream.write(line);
      }
      writeStream.end();

      writeStream.on('finish', resolve);
      writeStream.on('error', reject);
    });
  }

  /**
   * Compress a file using gzip
   */
  private async compressFile(inputPath: string): Promise<string> {
    const outputPath = `${inputPath}.gz`;

    await pipelineAsync(
      createReadStream(inputPath),
      zlib.createGzip(),
      createWriteStream(outputPath),
    );

    return outputPath;
  }

  /**
   * Upload file to S3
   */
  private async uploadToS3(filePath: string, fileName: string): Promise<void> {
    if (!this.s3 || !this.config.s3Bucket) {
      throw new Error('S3 not configured');
    }

    const fileStream = createReadStream(filePath);

    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.config.s3Bucket,
        Key: `audit-logs/archive/${fileName}`,
        Body: fileStream,
        ServerSideEncryption: 'AES256',
        StorageClass: 'GLACIER', // Long-term cold storage
      }),
    );

    this.logger.debug(`Uploaded ${fileName} to S3 (GLACIER)`);
  }

  /**
   * Get audit log count for a date range
   */
  async getLogsCountInRange(fromDate: Date, toDate: Date): Promise<number> {
    return this.auditLogRepository.count({
      where: {
        timestamp: LessThan(toDate),
      },
    });
  }

  /**
   * Get archival statistics
   */
  async getArchivalStats(): Promise<{
    totalLogsInDb: number;
    logsOlderThanRetention: number;
    retentionDays: number;
    estimatedStorageGb: number;
  }> {
    const totalLogsInDb = await this.auditLogRepository.count();
    const cutoffDate = this.getArchivalCutoffDate();

    const logsOlderThanRetention = await this.auditLogRepository.count({
      where: {
        timestamp: LessThan(cutoffDate),
      },
    });

    // Rough estimate: ~1KB per log entry
    const estimatedStorageGb = (totalLogsInDb * 1024) / (1024 * 1024 * 1024);

    return {
      totalLogsInDb,
      logsOlderThanRetention,
      retentionDays: this.config.retentionDays,
      estimatedStorageGb: Math.round(estimatedStorageGb * 100) / 100,
    };
  }

  /**
   * Calculate cutoff date based on retention policy
   */
  private getArchivalCutoffDate(): Date {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.config.retentionDays);
    cutoff.setHours(0, 0, 0, 0);
    return cutoff;
  }

  /**
   * Ensure archive directory exists
   */
  private ensureArchiveDirectory(): void {
    if (!fs.existsSync(this.config.localArchivePath)) {
      fs.mkdirSync(this.config.localArchivePath, { recursive: true });
    }
  }
}
