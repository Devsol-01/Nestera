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
import { User } from './user.entity';

export enum AvatarProcessingStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Entity('avatar_uploads')
@Index(['userId', 'createdAt'])
export class AvatarUpload {
  @ApiProperty()
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty()
  @Column('uuid')
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

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

  @ApiProperty({ enum: AvatarProcessingStatus })
  @Column({
    type: 'enum',
    enum: AvatarProcessingStatus,
    default: AvatarProcessingStatus.PENDING,
  })
  processingStatus: AvatarProcessingStatus;

  @ApiProperty({ nullable: true })
  @Column({ type: 'varchar', nullable: true })
  jobId: string | null;

  @ApiProperty({ nullable: true })
  @Column({ type: 'varchar', nullable: true })
  processedUrl: string | null;

  @ApiProperty({ nullable: true })
  @Column({ type: 'text', nullable: true })
  processingError: string | null;

  @ApiProperty({ nullable: true })
  @Column({ type: 'jsonb', nullable: true })
  processingMetadata: Record<string, unknown> | null;

  /**
   * Token returned by {@link StorageQuotaService.reserve} when the upload
   * was accepted. The background processor calls `commit()` on success
   * (with the actual stored byte total after thumbnailing) or `release()`
   * on failure so the per-user quota ledger reconciles correctly even when
   * the upload is short-circuited before completing.
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
