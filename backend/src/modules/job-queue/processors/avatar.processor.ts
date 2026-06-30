import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import sharp from 'sharp';
import { QUEUE_NAMES } from '../job-queue.constants';
import {
  AvatarUpload,
  AvatarProcessingStatus,
} from '../../user/entities/avatar-upload.entity';
import { AvatarJobData } from '../job-queue.service';
import { StorageService } from '../../storage/storage.service';
import { User } from '../../user/entities/user.entity';
import { StorageQuotaService } from '../../storage-quota/storage-quota.service';

const AVATAR_SIZE = 256;
const THUMBNAIL_SIZE = 64;

@Processor(QUEUE_NAMES.AVATAR)
export class AvatarProcessor extends WorkerHost {
  private readonly logger = new Logger(AvatarProcessor.name);

  constructor(
    @InjectRepository(AvatarUpload)
    private readonly avatarUploadRepository: Repository<AvatarUpload>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly storageService: StorageService,
    private readonly quotaService: StorageQuotaService,
  ) {
    super();
  }

  async process(job: Job<AvatarJobData>): Promise<Record<string, unknown>> {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    const { uploadId, userId, storagePath, mimeType } = job.data;

    this.logger.log(
      `${correlationPrefix}Processing avatar job ${job.id} — uploadId=${uploadId} userId=${userId} (attempt ${job.attemptsMade + 1})`,
    );

    await this.avatarUploadRepository.update(uploadId, {
      processingStatus: AvatarProcessingStatus.PROCESSING,
    });

    try {
      const metadata = await this.processImage(storagePath, mimeType);
      const processedUrl = metadata.processedUrl as string;

      await this.userRepository.update(userId, { avatarUrl: processedUrl });

      await this.avatarUploadRepository.update(uploadId, {
        processingStatus: AvatarProcessingStatus.COMPLETED,
        processedUrl,
        processingMetadata: metadata as any,
        processingError: null,
      });

      // Reconcile the quota ledger against actual stored bytes. The avatar
      // pipeline deletes the raw upload and replaces it with processed +
      // thumbnail images, so the final on-disk size is typically smaller
      // than the original reservation.
      await this.reconcileQuota(uploadId);

      this.logger.log(
        `${correlationPrefix}Avatar job ${job.id} completed — uploadId=${uploadId} processedUrl=${processedUrl}`,
      );

      return { uploadId, userId, status: 'completed', metadata };
    } catch (error) {
      const errMsg = (error as Error).message;
      this.logger.error(
        `${correlationPrefix}Avatar job ${job.id} failed — uploadId=${uploadId}: ${errMsg}`,
      );

      await this.avatarUploadRepository.update(uploadId, {
        processingStatus: AvatarProcessingStatus.FAILED,
        processingError: errMsg,
      });

      // Free the reserved quota so the user isn't permanently blocked.
      // If the worker has already moved on to retry attempts, this is
      // called again on the final attempt via onFailed().
      await this.releaseQuota(uploadId, 'avatar-process-failed');

      throw error;
    }
  }

  /**
   * Commit the reservation with the actual byte count of the processed
   * artifacts. Reads the freshly written files where possible so the
   * ledger stays accurate even if images are aggressively re-encoded.
   * Falls back to the original `fileSize` if size recovery fails, so a
   * failed measurement never blocks the reconciliation path.
   */
  private async reconcileQuota(uploadId: string): Promise<void> {
    const upload = await this.avatarUploadRepository.findOne({
      where: { id: uploadId },
    });
    if (!upload || !upload.quotaReservationId) return;

    let measured = 0;
    try {
      const processedUrl = upload.processedUrl ?? '';
      const thumbUrl = (upload.processingMetadata as any)?.thumbnailUrl as
        | string
        | undefined;
      measured =
        this.measureFileLength(processedUrl) + this.measureFileLength(thumbUrl);
    } catch (err) {
      this.logger.warn(
        `Could not measure final avatar bytes for ${uploadId}: ${(err as Error).message}; using estimated size`,
      );
    }

    // Never fall back to the raw upload size: by the time we get here,
    // `processImage` has already deleted the raw upload. Use a
    // conservative 20%-of-raw estimate (capped by raw) as a floor.
    const finalBytes =
      measured > 0
        ? measured
        : Math.min(
            upload.fileSize,
            Math.max(64 * 1024, Math.floor(upload.fileSize * 0.2)),
          );

    try {
      await this.quotaService.commit(upload.quotaReservationId, {
        finalBytes: finalBytes > 0 ? finalBytes : 1,
        reason: 'avatar-processed',
      });
    } catch (err) {
      this.logger.warn(
        `Failed to commit quota for avatar ${uploadId}: ${(err as Error).message}`,
      );
    }
  }

  private measureFileLength(url: string | null | undefined): number {
    if (!url) return 0;
    try {
      const buf = this.storageService.readFileBuffer(url);
      return buf?.length ?? 0;
    } catch {
      return 0;
    }
  }

  private async releaseQuota(uploadId: string, reason: string): Promise<void> {
    const upload = await this.avatarUploadRepository.findOne({
      where: { id: uploadId },
    });
    if (!upload || !upload.quotaReservationId) return;

    try {
      await this.quotaService.release(upload.quotaReservationId, { reason });
    } catch (err) {
      this.logger.warn(
        `Failed to release quota for avatar ${uploadId}: ${(err as Error).message}`,
      );
    }
  }

  private async processImage(
    storagePath: string,
    mimeType: string,
  ): Promise<Record<string, unknown>> {
    let sourceBuffer: Buffer;
    try {
      sourceBuffer = this.storageService.readFileBuffer(storagePath);
    } catch {
      throw new Error(`Source file not found: ${storagePath}`);
    }

    const image = sharp(sourceBuffer);
    const meta = await image.metadata();

    const maxDimension = 4096;
    if (
      (meta.width && meta.width > maxDimension) ||
      (meta.height && meta.height > maxDimension)
    ) {
      throw new Error(
        `Image dimensions exceed maximum allowed size of ${maxDimension}x${maxDimension}`,
      );
    }

    const minDimension = 32;
    if (
      (meta.width && meta.width < minDimension) ||
      (meta.height && meta.height < minDimension)
    ) {
      throw new Error(
        `Image dimensions must be at least ${minDimension}x${minDimension}`,
      );
    }

    const outputFormat = mimeType === 'image/png' ? 'png' : 'webp';
    const outputExt = outputFormat === 'png' ? '.png' : '.webp';

    const processedBuffer = await sharp(sourceBuffer)
      .rotate()
      .resize(AVATAR_SIZE, AVATAR_SIZE, {
        fit: 'cover',
        position: 'centre',
      })
      .toFormat(outputFormat, { quality: 85 })
      .toBuffer();

    const thumbnailBuffer = await sharp(sourceBuffer)
      .rotate()
      .resize(THUMBNAIL_SIZE, THUMBNAIL_SIZE, {
        fit: 'cover',
        position: 'centre',
      })
      .toFormat(outputFormat, { quality: 80 })
      .toBuffer();

    const processedUrl = await this.storageService.saveBuffer(
      processedBuffer,
      `avatars/processed${outputExt}`,
    );
    const thumbnailUrl = await this.storageService.saveBuffer(
      thumbnailBuffer,
      `avatars/thumb${outputExt}`,
    );

    try {
      await this.storageService.deleteFile(storagePath);
    } catch {
      this.logger.warn(`Could not delete original avatar file: ${storagePath}`);
    }

    return {
      processedAt: new Date().toISOString(),
      mimeType,
      originalWidth: meta.width,
      originalHeight: meta.height,
      processedWidth: AVATAR_SIZE,
      processedHeight: AVATAR_SIZE,
      thumbnailSize: THUMBNAIL_SIZE,
      processedUrl,
      thumbnailUrl,
      outputFormat,
      exifStripped: true,
    };
  }

  @OnWorkerEvent('failed')
  async onFailed(job: Job<AvatarJobData>, error: Error) {
    const { uploadId, correlationId } = job.data;
    const correlationPrefix = correlationId ? `[${correlationId}] ` : '';
    const attemptsExhausted = job.attemptsMade >= (job.opts.attempts ?? 3);

    this.logger.error(
      `${correlationPrefix}Avatar job ${job.id} failed (attempt ${job.attemptsMade}/${job.opts.attempts ?? 3}) — uploadId=${uploadId}: ${error.message}`,
    );

    if (attemptsExhausted) {
      await this.avatarUploadRepository.update(uploadId, {
        processingStatus: AvatarProcessingStatus.FAILED,
        processingError: `Exhausted retries: ${error.message}`,
      });
      // Final reconciliation: free the reserved quota so the user can
      // try again after remediation. The process() path also calls this
      // for non-final failures, but on retry-exhaustion we make the
      // release durable.
      await this.releaseQuota(uploadId, 'avatar-attempts-exhausted');
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<AvatarJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(
      `${correlationPrefix}Avatar job ${job.id} worker event: completed — uploadId=${job.data.uploadId}`,
    );
  }
}
