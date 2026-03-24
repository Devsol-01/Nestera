import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';

export enum ClaimStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  PROCESSING = 'PROCESSING',
}

@Entity('medical_claims')
export class MedicalClaim {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  patientName: string;

  @Column()
  patientId: string;

  @Column()
  patientDateOfBirth: Date;

  @Column()
  hospitalName: string;

  @Column()
  hospitalId: string;

  @Column('simple-array')
  diagnosisCodes: string[];

  @Column('decimal', { precision: 10, scale: 2 })
  claimAmount: number;

  @Column({ type: 'enum', enum: ClaimStatus, default: ClaimStatus.PENDING })
  status: ClaimStatus;

  @Column({ nullable: true })
  notes: string;

  @Column({ nullable: true })
  blockchainTxHash: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
