import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  AvatarUpload,
  AvatarProcessingStatus,
} from './entities/avatar-upload.entity';
import { StorageService } from '../storage/storage.service';
import { FileUploadConfigService } from '../storage/file-upload-config.service';
import { JobQueueService } from '../job-queue/job-queue.service';
import { AvatarUploadResponseDto } from './dto/avatar-upload-response.dto';
import {
  StorageQuotaService,
  QuotaReservation,
} from '../storage-quota/storage-quota.service';
import { QuotaUploadKind } from '../storage-quota/entities/storage-quota-ledger.entity';

@Injectable()
export class AvatarUploadService {
  private readonly logger = new Logger(AvatarUploadService.name);

  constructor(
    @InjectRepository(AvatarUpload)
    private readonly avatarUploadRepository: Repository<AvatarUpload>,
    private readonly storageService: StorageService,
    private readonly fileUploadConfig: FileUploadConfigService,
    private readonly jobQueueService: JobQueueService,
    private readonly quotaService: StorageQuotaService,
  ) {}

  async uploadAvatar(
    userId: string,
    file: any,
    correlationId?: string,
  ): Promise<AvatarUploadResponseDto> {
    // 1. Cheap pre-flight: file metadata only, no DB / no storage I/O.
    const validation = await this.fileUploadConfig.validateFile(file, 'avatar');
    if (!validation.valid) {
      throw new BadRequestException(validation.error);
    }

    // 2. Reserve quota BEFORE writing to storage. The atomic SQL inside
    // `reserve()` checks storage size, active-upload count, and hourly
    // frequency in one shot and either accepts or throws.
    const reservation: QuotaReservation = await this.quotaService.reserve(
      userId,
      file.size,
      {
        uploadKind: QuotaUploadKind.AVATAR,
        uploadId: null, // assigned after we know the row id
        reason: 'avatar-upload',
      },
    );

    // 3. Write file. If this fails we MUST release the reservation so the
    // user isn't permanently blocked out by a phantom hold.
    let storagePath: string;
    try {
      storagePath = await this.storageService.saveFile(file, 'avatars/raw');
    } catch (err) {
      await this.safeRelease(reservation.reservationId, 'storage-write-failed');
      throw err;
    }

    // 4. Persist upload row, carrying the reservation token forward so the
    // background processor can call commit()/release() against it.
    const upload = this.avatarUploadRepository.create({
      userId,
      originalFilename: file.originalname,
      storagePath,
      mimeType: file.mimetype,
      fileSize: file.size,
      processingStatus: AvatarProcessingStatus.PENDING,
      jobId: null,
      quotaReservationId: reservation.reservationId,
    });
    const savedUpload = await this.avatarUploadRepository.save(upload);

    const job = await this.jobQueueService.addAvatarProcessingJob(
      {
    // 5. Enqueue background processing. The processor is responsible for
    // calling quotaService.commit() (success) or quotaService.release()
    // (failure) using `savedUpload.quotaReservationId`.
    try {
      const job = await this.jobQueueService.addAvatarProcessingJob({
        uploadId: savedUpload.id,
        userId,
        storagePath,
        mimeType: file.mimetype,
        originalFilename: file.originalname,
      },
      undefined,
      correlationId,
    );
      });

      await this.avatarUploadRepository.update(savedUpload.id, {
        jobId: String(job.id),
      });

      return this.toResponseDto({
        ...savedUpload,
        jobId: String(job.id),
      });
    } catch (err) {
      this.logger.error(
        `Failed to enqueue avatar processing job for upload ${savedUpload.id}: ${(err as Error).message}`,
      );
      // Release the reservation since no processor will run. The file is
      // left on disk for the storage-cleanup sweep to collect.
      await this.safeRelease(reservation.reservationId, 'job-enqueue-failed');
      throw err;
    }
  }

  private async safeRelease(
    reservationId: string,
    reason: string,
  ): Promise<void> {
    try {
      await this.quotaService.release(reservationId, { reason });
    } catch (err) {
      this.logger.warn(
        `Failed to release reservation ${reservationId}: ${(err as Error).message}`,
      );
    }
  }

  async getUploadStatus(
    userId: string,
    uploadId: string,
  ): Promise<AvatarUploadResponseDto> {
    const upload = await this.avatarUploadRepository.findOne({
      where: { id: uploadId, userId },
    });

    if (!upload) {
      throw new NotFoundException('Avatar upload not found');
    }

    return this.toResponseDto(upload);
  }

  async getLatestUploadStatus(
    userId: string,
  ): Promise<AvatarUploadResponseDto | null> {
    const upload = await this.avatarUploadRepository.findOne({
      where: { userId },
      order: { createdAt: 'DESC' },
    });

    if (!upload) {
      return null;
    }

    return this.toResponseDto(upload);
  }

  private toResponseDto(upload: AvatarUpload): AvatarUploadResponseDto {
    return {
      id: upload.id,
      processingStatus: upload.processingStatus,
      jobId: upload.jobId,
      processedUrl: upload.processedUrl,
      processingError: upload.processingError,
      createdAt: upload.createdAt,
    };
  }
}
