import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  password?: string;

  @Column({ unique: true, nullable: true })
  publicKey?: string;

  @Column({ type: 'text', nullable: true })
  bio: string;

  @Column({ nullable: true })
  avatarUrl: string;

  @Column({ type: 'varchar', default: 'USER' })
  role: 'USER' | 'ADMIN';

  @Column({ type: 'varchar', default: 'NOT_SUBMITTED' })
  kycStatus: 'NOT_SUBMITTED' | 'PENDING' | 'APPROVED' | 'REJECTED';

  @Column({ type: 'varchar', default: 'FREE' })
  tier: 'FREE' | 'VERIFIED' | 'PREMIUM' | 'ENTERPRISE';

  @Column({ nullable: true })
  kycDocumentUrl: string;

  @Column({ type: 'text', nullable: true })
  kycRejectionReason: string;

  @Column({ type: 'boolean', default: false })
  autoSweepEnabled: boolean;

  @Column({ type: 'decimal', precision: 14, scale: 2, nullable: true })
  sweepThreshold: number;

  @Column({ type: 'uuid', nullable: true })
  defaultSavingsProductId: string;

  @Column({ nullable: true, unique: true })
  walletAddress: string;

  @Column({ nullable: true })
  nonce: string;

  @Column({ type: 'boolean', default: false })
  twoFactorEnabled: boolean;

  @Column({ type: 'varchar', nullable: true })
  twoFactorSecret: string | null;

  @Column({ type: 'simple-array', nullable: true })
  twoFactorBackupCodes: string[] | null;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'uuid', nullable: true })
  tenantId: string | null;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
