import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  Dispute,
  DisputeMessage,
  DisputeStatus,
  DisputeTimeline,
} from './entities/dispute.entity';
import {
  DisputeEvidence,
  EvidenceProcessingStatus,
} from './entities/dispute-evidence.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import {
  CreateDisputeDto,
  UpdateDisputeDto,
  AddDisputeMessageDto,
} from './dto/dispute.dto';
import { UploadEvidenceDto } from './dto/upload-evidence.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType } from '../notifications/entities/notification.entity';
import { AuditLogService } from '../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
} from '../../common/entities/audit-log.entity';
import { StorageService } from '../storage/storage.service';
import { JobQueueService } from '../job-queue/job-queue.service';
import {
  StorageQuotaService,
  QuotaReservation,
} from '../storage-quota/storage-quota.service';
import { QuotaUploadKind } from '../storage-quota/entities/storage-quota-ledger.entity';

const ALLOWED_TRANSITIONS: Record<DisputeStatus, DisputeStatus[]> = {
  [DisputeStatus.OPEN]: [
    DisputeStatus.IN_PROGRESS,
    DisputeStatus.UNDER_REVIEW,
    DisputeStatus.CLOSED,
  ],
  [DisputeStatus.IN_PROGRESS]: [
    DisputeStatus.UNDER_REVIEW,
    DisputeStatus.RESOLVED,
    DisputeStatus.CLOSED,
  ],
  [DisputeStatus.UNDER_REVIEW]: [
    DisputeStatus.RESOLVED,
    DisputeStatus.ESCALATED,
    DisputeStatus.CLOSED,
  ],
  [DisputeStatus.RESOLVED]: [DisputeStatus.CLOSED, DisputeStatus.OPEN],
  [DisputeStatus.CLOSED]: [],
  [DisputeStatus.ESCALATED]: [
    DisputeStatus.UNDER_REVIEW,
    DisputeStatus.RESOLVED,
    DisputeStatus.CLOSED,
  ],
};

@Injectable()
export class DisputesService {
  private assertValidTransition(
    current: DisputeStatus,
    next: DisputeStatus,
    action: string,
  ): void {
    const allowed = ALLOWED_TRANSITIONS[current];
    if (!allowed.includes(next)) {
      throw new BadRequestException(
        `Cannot ${action}: transition from ${current} to ${next} is not allowed`,
      );
    }
  }

  constructor(
    @InjectRepository(Dispute)
    private readonly disputeRepository: Repository<Dispute>,
    @InjectRepository(DisputeMessage)
    private readonly messageRepository: Repository<DisputeMessage>,
    @InjectRepository(MedicalClaim)
    private readonly claimRepository: Repository<MedicalClaim>,
    @InjectRepository(DisputeTimeline)
    private readonly timelineRepository: Repository<DisputeTimeline>,
    @InjectRepository(DisputeEvidence)
    private readonly evidenceRepository: Repository<DisputeEvidence>,
    private readonly notificationsService: NotificationsService,
    private readonly auditLogService: AuditLogService,
    private readonly storageService: StorageService,
    private readonly jobQueueService: JobQueueService,
    private readonly quotaService: StorageQuotaService,
  ) {}

  async createDispute(
    createDisputeDto: CreateDisputeDto,
    correlationId?: string,
    requestId?: string,
  ): Promise<Dispute> {
    const claim = await this.claimRepository.findOneBy({
      id: createDisputeDto.claimId,
    });
    if (!claim) {
      throw new BadRequestException('Invalid claim ID. Claim does not exist.');
    }

    const dispute = this.disputeRepository.create({
      ...createDisputeDto,
      status: DisputeStatus.OPEN,
    });
    const savedDispute = await this.disputeRepository.save(dispute);

    // Add timeline entry
    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: savedDispute.id,
        action: 'CREATED',
        performedBy: savedDispute.disputedBy,
        description: 'Dispute created',
      }),
    );

    await this.auditLogService.log({
      action: AuditAction.CREATE,
      resourceType: AuditResourceType.DISPUTE,
      actor: savedDispute.disputedBy || 'unknown',
      correlationId,
      requestId,
      resourceId: savedDispute.id,
      description: `User submitted dispute for claim ${createDisputeDto.claimId}`,
      newValue: {
        claimId: createDisputeDto.claimId,
        reason: createDisputeDto.reason,
      },
      success: true,
    });

    return savedDispute;
  }

  async findAll(): Promise<Dispute[]> {
    // Stable sort: primary key createdAt DESC, tie-breaker id DESC so that
    // concurrent inserts at the same millisecond never cause duplicate/missing
    // items across paginated pages.
    return await this.disputeRepository.find({
      relations: ['claim', 'messages', 'timeline'],
      order: { createdAt: 'DESC', id: 'DESC' },
    });
  }

  async findOne(id: string): Promise<Dispute> {
    const dispute = await this.disputeRepository.findOne({
      where: { id },
      relations: ['claim', 'messages', 'timeline'],
    });
    if (!dispute) {
      throw new NotFoundException('Dispute not found');
    }
    return dispute;
  }

  async updateDispute(
    id: string,
    updateDisputeDto: UpdateDisputeDto,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    Object.assign(dispute, updateDisputeDto);
    return await this.disputeRepository.save(dispute);
  }

  async addMessage(
    id: string,
    addMessageDto: AddDisputeMessageDto,
  ): Promise<DisputeMessage> {
    const dispute = await this.findOne(id);

    const message = this.messageRepository.create({
      disputeId: dispute.id,
      ...addMessageDto,
    });
    const savedMessage = await this.messageRepository.save(message);

    // Add timeline entry
    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: dispute.id,
        action: 'MESSAGE_ADDED',
        performedBy: addMessageDto.author,
        description: addMessageDto.message,
      }),
    );

    return savedMessage;
  }

  async startInvestigation(
    id: string,
    actor: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    const previousState = { status: dispute.status };

    this.assertValidTransition(
      dispute.status,
      DisputeStatus.UNDER_REVIEW,
      'start investigation',
    );
    dispute.status = DisputeStatus.UNDER_REVIEW;
    dispute.assignedTo = actor;
    dispute.assignedAt = new Date();

    const updatedDispute = await this.disputeRepository.save(dispute);

    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: id,
        action: 'INVESTIGATION_STARTED',
        performedBy: actor,
        description: 'Investigation started',
        previousState,
        newState: { status: dispute.status },
      }),
    );

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.DISPUTE,
      actor,
      correlationId,
      requestId,
      resourceId: id,
      description: `Investigation started on dispute ${id}`,
      previousValue: previousState,
      newValue: { status: DisputeStatus.UNDER_REVIEW, assignedTo: actor },
      success: true,
    });

    return updatedDispute;
  }

  async resolveDispute(
    id: string,
    actor: string,
    resolution: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    const previousState = { status: dispute.status };

    this.assertValidTransition(
      dispute.status,
      DisputeStatus.RESOLVED,
      'resolve dispute',
    );
    dispute.status = DisputeStatus.RESOLVED;
    dispute.resolvedAt = new Date();
    dispute.resolvedBy = actor;
    dispute.resolution = resolution;

    const updatedDispute = await this.disputeRepository.save(dispute);

    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: id,
        action: 'DISPUTE_RESOLVED',
        performedBy: actor,
        description: `Resolved: ${resolution}`,
        previousState,
        newState: { status: dispute.status },
      }),
    );

    await this.auditLogService.log({
      action: AuditAction.RESOLVE,
      resourceType: AuditResourceType.DISPUTE,
      actor,
      correlationId,
      requestId,
      resourceId: id,
      description: `Dispute ${id} resolved: ${resolution}`,
      previousValue: previousState,
      newValue: {
        status: DisputeStatus.RESOLVED,
        resolution,
        resolvedBy: actor,
      },
      success: true,
    });

    return updatedDispute;
  }

  async closeDispute(
    id: string,
    actor: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    const previousState = { status: dispute.status };

    this.assertValidTransition(
      dispute.status,
      DisputeStatus.CLOSED,
      'close dispute',
    );
    dispute.status = DisputeStatus.CLOSED;

    const updatedDispute = await this.disputeRepository.save(dispute);

    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: id,
        action: 'DISPUTE_CLOSED',
        performedBy: actor,
        description: 'Dispute closed',
        previousState,
        newState: { status: dispute.status },
      }),
    );

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.DISPUTE,
      actor,
      correlationId,
      requestId,
      resourceId: id,
      description: `Dispute ${id} closed`,
      previousValue: previousState,
      newValue: { status: DisputeStatus.CLOSED },
      success: true,
    });

    return updatedDispute;
  }

  async escalateDispute(
    id: string,
    actor: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    const previousState = { status: dispute.status };

    this.assertValidTransition(
      dispute.status,
      DisputeStatus.ESCALATED,
      'escalate dispute',
    );
    dispute.status = DisputeStatus.ESCALATED;
    dispute.escalatedTo = actor;
    dispute.escalatedAt = new Date();

    const updatedDispute = await this.disputeRepository.save(dispute);

    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: id,
        action: 'DISPUTE_ESCALATED',
        performedBy: actor,
        description: 'Dispute escalated',
        previousState,
        newState: { status: dispute.status },
      }),
    );

    await this.auditLogService.log({
      action: AuditAction.ESCALATE,
      resourceType: AuditResourceType.DISPUTE,
      actor,
      correlationId,
      requestId,
      resourceId: id,
      description: `Dispute ${id} escalated to ${actor}`,
      previousValue: previousState,
      newValue: { status: DisputeStatus.ESCALATED, escalatedTo: actor },
      success: true,
    });

    return updatedDispute;
  }

  /**
   * Upload evidence file for a dispute and enqueue a background processing job.
   * Returns the saved DisputeEvidence record (status: PENDING) plus the job ID.
   */
  async uploadEvidence(
    disputeId: string,
    file: any,
    dto: UploadEvidenceDto,
    correlationId?: string,
  ): Promise<DisputeEvidence> {
    // Verify dispute exists
    const dispute = await this.findOne(disputeId);

    // Reserve quota BEFORE writing to storage. Attribution goes to the
    // disputer only — `dto.uploadedBy` is a freeform staff label (e.g.
    // "Hospital Admin") and must NOT be used as the quota userId, since
    // it is not a UUID and would collide with other staff uploads for
    // the same dispute on the (userId, tenantId) UNIQUE index.
    const attributedUserId = dispute.disputedBy;
    if (!attributedUserId) {
      throw new BadRequestException(
        'Cannot attribute upload quota: dispute has no attributed disputer',
      );
    }
    await this.quotaService.ensureQuotaRow(attributedUserId, 'verified');

    const reservation: QuotaReservation = await this.quotaService.reserve(
      attributedUserId,
      file.size,
      {
        uploadKind: QuotaUploadKind.DISPUTE_EVIDENCE,
        reason: 'dispute-evidence',
      },
    );

    // Write file. If this fails we MUST release the reservation.
    let storagePath: string;
    try {
      storagePath = await this.storageService.saveFile(file);
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'storage-write-failed',
      });
      throw err;
    }

    // Create evidence record with PENDING status and the reservation token
    // so the dispute-evidence processor can reconcile on completion.
    const evidence = this.evidenceRepository.create({
      disputeId,
      originalFilename: file.originalname,
      storagePath,
      mimeType: file.mimetype,
      fileSize: file.size,
      uploadedBy: dto.uploadedBy,
      processingStatus: EvidenceProcessingStatus.PENDING,
      jobId: null,
      quotaReservationId: reservation.reservationId,
    });
    const savedEvidence = await this.evidenceRepository.save(evidence);

    // Enqueue background processing job
    const job = await this.jobQueueService.addEvidenceProcessingJob(
      {
    let job;
    try {
      job = await this.jobQueueService.addEvidenceProcessingJob({
        evidenceId: savedEvidence.id,
        disputeId,
        storagePath,
        mimeType: file.mimetype,
        originalFilename: file.originalname,
        uploadedBy: dto.uploadedBy,
      },
      undefined,
      correlationId,
    );
      });
    } catch (err) {
      await this.quotaService.release(reservation.reservationId, {
        reason: 'job-enqueue-failed',
      });
      throw err;
    }

    // Store job ID on the evidence record for status polling
    await this.evidenceRepository.update(savedEvidence.id, {
      jobId: String(job.id),
    });
    savedEvidence.jobId = String(job.id);

    // Timeline entry
    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId,
        action: 'EVIDENCE_UPLOADED',
        performedBy: dto.uploadedBy,
        description: `Evidence file uploaded: ${file.originalname}`,
        newState: {
          evidenceId: savedEvidence.id,
          jobId: savedEvidence.jobId,
          processingStatus: EvidenceProcessingStatus.PENDING,
        },
      }),
    );

    return savedEvidence;
  }

  /**
   * Get processing status for a specific evidence record.
   */
  async getEvidenceStatus(
    disputeId: string,
    evidenceId: string,
  ): Promise<DisputeEvidence> {
    const evidence = await this.evidenceRepository.findOne({
      where: { id: evidenceId, disputeId },
    });

    if (!evidence) {
      throw new NotFoundException(
        `Evidence with ID ${evidenceId} not found for dispute ${disputeId}`,
      );
    }

    return evidence;
  }

  /**
   * List all evidence records for a dispute.
   */
  async listEvidence(disputeId: string): Promise<DisputeEvidence[]> {
    await this.findOne(disputeId);
    return this.evidenceRepository.find({
      where: { disputeId },
      order: { createdAt: 'DESC' },
    });
  }

  async reopenDispute(
    id: string,
    actor: string,
    reason: string,
  ): Promise<Dispute> {
    const dispute = await this.findOne(id);
    const previousState = { status: dispute.status };

    this.assertValidTransition(
      dispute.status,
      DisputeStatus.OPEN,
      'reopen dispute',
    );

    dispute.status = DisputeStatus.OPEN;
    (dispute as any).resolvedAt = null;
    (dispute as any).resolvedBy = null;
    (dispute as any).resolution = null;

    const updatedDispute = await this.disputeRepository.save(dispute);

    await this.timelineRepository.save(
      this.timelineRepository.create({
        disputeId: id,
        action: 'DISPUTE_REOPENED',
        performedBy: actor,
        description: `Reopened: ${reason}`,
        previousState,
        newState: { status: dispute.status },
      }),
    );

    return updatedDispute;
  }
}
