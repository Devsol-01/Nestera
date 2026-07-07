import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Dispute } from './dispute.entity';

export enum EvidenceProcessingStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Entity('dispute_evidence')
@Index(['disputeId', 'createdAt'])
export class DisputeEvidence {
  @ApiProperty()
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty()
  @Column('uuid')
  disputeId: string;

  @ManyToOne(() => Dispute, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'disputeId' })
  dispute: Dispute;

  @ApiProperty()
  @Column({ type: 'varchar' })
  originalFilename: string;

  @ApiProperty()
  @Column({ type: 'varchar' })
  storagePath: string;

  @ApiProperty()
  @Column({ type: 'varchar' })
  mimeType: string;

  @ApiProperty()
  @Column({ type: 'int' })
  fileSize: number;

  @ApiProperty()
  @Column({ type: 'varchar' })
  uploadedBy: string;

  @ApiProperty({ enum: EvidenceProcessingStatus })
  @Column({
    type: 'enum',
    enum: EvidenceProcessingStatus,
    default: EvidenceProcessingStatus.PENDING,
  })
  processingStatus: EvidenceProcessingStatus;

  /** BullMQ job ID so callers can poll for status */
  @ApiProperty({ nullable: true })
  @Column({ type: 'varchar', nullable: true })
  jobId: string | null;

  @ApiProperty({ nullable: true })
  @Column({ type: 'text', nullable: true })
  processingError: string | null;

  /** Metadata written back by the processor (e.g. page count, OCR text snippet) */
  @ApiProperty({ nullable: true })
  @Column({ type: 'jsonb', nullable: true })
  processingMetadata: Record<string, any> | null;

  /**
   * Token returned by {@link StorageQuotaService.reserve} when the evidence
   * upload was accepted. The dispute-evidence processor calls `commit()`
   * on success or `release()` on failure so the per-user quota ledger
   * reconciles correctly even when the upload is short-circuited.
   */
  @ApiProperty({ nullable: true })
  @Index()
  @Column({ type: 'varchar', length: 64, nullable: true })
  quotaReservationId: string | null;

  @ApiProperty()
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty()
  @UpdateDateColumn()
  updatedAt: Date;
}
