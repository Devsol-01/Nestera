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
import { User } from '../../user/entities/user.entity';
import { KycVerification } from './kyc-verification.entity';

export enum KycDocumentType {
  PASSPORT = 'PASSPORT',
  NATIONAL_ID = 'NATIONAL_ID',
  DRIVERS_LICENSE = 'DRIVERS_LICENSE',
  UTILITY_BILL = 'UTILITY_BILL',
  SELFIE = 'SELFIE',
}

export enum KycDocumentStatus {
  UPLOADED = 'UPLOADED',
  PENDING_REVIEW = 'PENDING_REVIEW',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
}

@Entity('kyc_documents')
@Index(['userId', 'createdAt'])
export class KycDocument {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column('uuid')
  userId!: string;

  @Column({ type: 'enum', enum: KycDocumentType })
  documentType!: KycDocumentType;

  @Column({ type: 'varchar' })
  encryptedStoragePath!: string;

  @Column({ type: 'varchar' })
  originalFilename!: string;

  @Column({ type: 'varchar' })
  mimeType!: string;

  @Column({
    type: 'enum',
    enum: KycDocumentStatus,
    default: KycDocumentStatus.UPLOADED,
  })
  status!: KycDocumentStatus;

  @Column('uuid', { nullable: true })
  verificationId!: string | null;

  @Column({ type: 'text', nullable: true })
  rejectionReason!: string | null;

  @Column({ type: 'varchar', nullable: true })
  reviewedBy!: string | null;

  @Column({ type: 'timestamp', nullable: true })
  reviewedAt!: Date | null;

  /**
   * Token returned by {@link StorageQuotaService.reserve} when the document
   * was accepted. KYC documents commit immediately after upload, but the
   * token is kept for audit and so future deletion paths can refund quota.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  @Index()
  quotaReservationId!: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;

  @ManyToOne(() => KycVerification, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'verificationId' })
  verification!: KycVerification | null;
}
