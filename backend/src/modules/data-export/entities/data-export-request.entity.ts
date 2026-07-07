import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

export enum ExportStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  READY = 'ready',
  EXPIRED = 'expired',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

@Entity('data_export_requests')
@Index(['userId'])
@Index(['token'], { unique: true })
export class DataExportRequest {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  userId: string;

  @Column({
    type: 'enum',
    enum: ExportStatus,
    default: ExportStatus.PENDING,
  })
  status: ExportStatus;

  @Column({ type: 'varchar', length: 64, unique: true, nullable: true })
  token: string | null;

  @Column({ type: 'varchar', nullable: true })
  filePath: string | null;

  @Column({ type: 'varchar', length: 128, nullable: true })
  queueJobId: string | null;

  @Column({ type: 'text', nullable: true })
  errorMessage: string | null;

  @Column({ type: 'timestamp', nullable: true })
  expiresAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date | null;

  /**
   * SHA-256 hex digest of the raw ZIP artifact computed at finalization.
   * Used to verify the artifact has not been tampered with before serving.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  checksum: string | null;

  /** Size of the artifact in bytes, stored alongside the checksum for audit. */
  @Column({ type: 'bigint', nullable: true })
  fileSize: number | null;
}
