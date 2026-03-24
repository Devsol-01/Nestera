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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
