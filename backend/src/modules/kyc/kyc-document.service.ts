import {
  Injectable,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { existsSync, mkdirSync, unlinkSync, writeFileSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';
import {
  KycDocument,
  KycDocumentType,
  KycDocumentStatus,
} from './entities/kyc-document.entity';
import { KycVerification } from './entities/kyc-verification.entity';
import { User } from '../user/entities/user.entity';
import { PiiEncryptionService } from '../../common/services/pii-encryption.service';
import { ReviewKycDocumentDto } from './dto/kyc-document.dto';
import {
  StorageQuotaService,
  QuotaReservation,
} from '../storage-quota/storage-quota.service';
import { QuotaUploadKind } from '../storage-quota/entities/storage-quota-ledger.entity';

const ALLOWED_MIME_TYPES: Record<KycDocumentType, string[]> = {
  [KycDocumentType.PASSPORT]: ['application/pdf', 'image/jpeg', 'image/png'],
  [KycDocumentType.NATIONAL_ID]: ['application/pdf', 'image/jpeg', 'image/png'],
  [KycDocumentType.DRIVERS_LICENSE]: [
    'application/pdf',
    'image/jpeg',
    'image/png',
  ],
  [KycDocumentType.UTILITY_BILL]: [
    'application/pdf',
    'image/jpeg',
    'image/png',
  ],
  [KycDocumentType.SELFIE]: ['image/jpeg', 'image/png', 'image/webp'],
};

const MAX_FILE_SIZE = 10 * 1024 * 1024;

@Injectable()
export class KycDocumentService {
  private readonly logger = new Logger(KycDocumentService.name);
  private readonly storageDir = './uploads/kyc-encrypted';

  constructor(
    @InjectRepository(KycDocument)
    private readonly documentRepo: Repository<KycDocument>,
    @InjectRepository(KycVerification)
    private readonly verificationRepo: Repository<KycVerification>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    private readonly piiEncryption: PiiEncryptionService,
    private readonly quotaService: StorageQuotaService,
  ) {
    this.ensureStorageDir();
  }

  async uploadDocument(
    userId: string,
    documentType: KycDocumentType,
    file: {
      buffer: Buffer;
      originalname: string;
      mimetype: string;
      size: number;
    },
  ): Promise<KycDocument> {
    this.validateFile(documentType, file);

    // Reserve quota before writing the encrypted file. KYC docs have no
    // background processor, so we commit immediately after the file lands
    // on disk; release on any failure along the way.
    const reservation: QuotaReservation = await this.quotaService.reserve(
      userId,
      file.size,
      {
        uploadKind: QuotaUploadKind.KYC_DOCUMENT,
        reason: 'kyc-document',
      },
    );

    const encryptedPayload = this.piiEncryption.encrypt(
      file.buffer.toString('base64'),
    );
    const storageFilename = `${randomUUID()}.enc`;
    const storagePath = join(this.storageDir, storageFilename);
    try {
      writeFileSync(storagePath, encryptedPayload, 'utf8');
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'storage-write-failed',
      });
      throw err;
    }

    const document = this.documentRepo.create({
      userId,
      documentType,
      encryptedStoragePath: storagePath,
      originalFilename: file.originalname,
      mimeType: file.mimetype,
      status: KycDocumentStatus.PENDING_REVIEW,
      quotaReservationId: reservation.reservationId,
    });

    try {
      const saved = await this.documentRepo.save(document);
      await this.userRepo.update(userId, { kycStatus: 'PENDING' });

      // Commit the reservation now that the encrypted file is durably on
      // disk. The encrypted payload is roughly the same size as the input
      // (base64 + encryption overhead), so the original size is a safe
      // accounting approximation.
      await this.quotaService.commit(reservation.reservationId, {
        finalBytes: file.size,
        reason: 'kyc-document-stored',
      });

      this.logger.log(`KYC document uploaded for user ${userId}: ${saved.id}`);
      return saved;
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'document-record-failed',
      });
      // Best-effort cleanup of the orphan encrypted blob.
      try {
        unlinkSync(storagePath);
      } catch {
        // ignore
      }
      throw err;
    }
  }

  async listUserDocuments(userId: string): Promise<KycDocument[]> {
    return this.documentRepo.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async listPendingReview(): Promise<KycDocument[]> {
    return this.documentRepo.find({
      where: { status: KycDocumentStatus.PENDING_REVIEW },
      relations: ['user'],
      order: { createdAt: 'ASC' },
    });
  }

  async getDocument(id: string): Promise<KycDocument> {
    const doc = await this.documentRepo.findOne({
      where: { id },
      relations: ['user', 'verification'],
    });
    if (!doc) {
      throw new NotFoundException(`KYC document ${id} not found`);
    }
    return doc;
  }

  async reviewDocument(
    id: string,
    adminId: string,
    dto: ReviewKycDocumentDto,
  ): Promise<KycDocument> {
    const doc = await this.getDocument(id);

    if (doc.status !== KycDocumentStatus.PENDING_REVIEW) {
      throw new BadRequestException('Document is not pending review');
    }

    if (
      dto.status === KycDocumentStatus.REJECTED &&
      !dto.rejectionReason?.trim()
    ) {
      throw new BadRequestException(
        'Rejection reason is required when rejecting a document',
      );
    }

    doc.status = dto.status;
    doc.reviewedBy = adminId;
    doc.reviewedAt = new Date();
    doc.rejectionReason =
      dto.status === KycDocumentStatus.REJECTED
        ? (dto.rejectionReason ?? null)
        : null;

    const saved = await this.documentRepo.save(doc);

    const isApproved = dto.status === KycDocumentStatus.APPROVED;
    await this.userRepo.update(doc.userId, {
      kycStatus: isApproved ? 'APPROVED' : 'REJECTED',
      kycRejectionReason: isApproved ? undefined : dto.rejectionReason,
      tier: isApproved ? 'VERIFIED' : 'FREE',
    });

    return saved;
  }

  async linkToVerification(
    documentId: string,
    verificationId: string,
    userId: string,
  ): Promise<KycDocument> {
    const doc = await this.getDocument(documentId);
    if (doc.userId !== userId) {
      throw new BadRequestException('Document does not belong to user');
    }

    const verification = await this.verificationRepo.findOne({
      where: { id: verificationId, userId },
    });
    if (!verification) {
      throw new NotFoundException('KYC verification not found');
    }

    doc.verificationId = verificationId;
    return this.documentRepo.save(doc);
  }

  private validateFile(
    documentType: KycDocumentType,
    file: { mimetype: string; size: number },
  ): void {
    const allowed = ALLOWED_MIME_TYPES[documentType];
    if (!allowed.includes(file.mimetype)) {
      throw new BadRequestException(
        `Invalid file type for ${documentType}. Allowed: ${allowed.join(', ')}`,
      );
    }
    if (file.size > MAX_FILE_SIZE) {
      throw new BadRequestException('File exceeds maximum size of 10MB');
    }
  }

  private ensureStorageDir(): void {
    if (!existsSync(this.storageDir)) {
      mkdirSync(this.storageDir, { recursive: true });
    }
  }
}
