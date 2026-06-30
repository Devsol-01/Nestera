import {
  Injectable,
  NotFoundException,
  BadRequestException,
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

@Injectable()
export class AvatarUploadService {
  constructor(
    @InjectRepository(AvatarUpload)
    private readonly avatarUploadRepository: Repository<AvatarUpload>,
    private readonly storageService: StorageService,
    private readonly fileUploadConfig: FileUploadConfigService,
    private readonly jobQueueService: JobQueueService,
  ) {}

  async uploadAvatar(
    userId: string,
    file: any,
    correlationId?: string,
  ): Promise<AvatarUploadResponseDto> {
    const validation = await this.fileUploadConfig.validateFile(file, 'avatar');
    if (!validation.valid) {
      throw new BadRequestException(validation.error);
    }

    const storagePath = await this.storageService.saveFile(file, 'avatars/raw');

    const upload = this.avatarUploadRepository.create({
      userId,
      originalFilename: file.originalname,
      storagePath,
      mimeType: file.mimetype,
      fileSize: file.size,
      processingStatus: AvatarProcessingStatus.PENDING,
      jobId: null,
    });
    const savedUpload = await this.avatarUploadRepository.save(upload);

    const job = await this.jobQueueService.addAvatarProcessingJob(
      {
        uploadId: savedUpload.id,
        userId,
        storagePath,
        mimeType: file.mimetype,
        originalFilename: file.originalname,
      },
      undefined,
      correlationId,
    );

    await this.avatarUploadRepository.update(savedUpload.id, {
      jobId: String(job.id),
    });

    return this.toResponseDto({
      ...savedUpload,
      jobId: String(job.id),
    });
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
