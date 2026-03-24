import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn, OneToMany } from 'typeorm';
import { MedicalClaim } from '../../claims/entities/medical-claim.entity';

export enum DisputeStatus {
  OPEN = 'OPEN',
  UNDER_REVIEW = 'UNDER_REVIEW',
  RESOLVED = 'RESOLVED',
  CLOSED = 'CLOSED',
}

@Entity('disputes')
export class Dispute {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  claimId: string;

  @ManyToOne(() => MedicalClaim)
  @JoinColumn({ name: 'claimId' })
  claim: MedicalClaim;

  @Column()
  disputedBy: string;

  @Column('text')
  reason: string;

  @Column({ type: 'enum', enum: DisputeStatus, default: DisputeStatus.OPEN })
  status: DisputeStatus;

  @OneToMany(() => DisputeMessage, message => message.dispute, { cascade: true })
  messages: DisputeMessage[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}

@Entity('dispute_messages')
export class DisputeMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  disputeId: string;

  @ManyToOne(() => Dispute, dispute => dispute.messages)
  @JoinColumn({ name: 'disputeId' })
  dispute: Dispute;

  @Column()
  author: string;

  @Column('text')
  message: string;

  @Column({ nullable: true })
  evidenceUrl: string;

  @CreateDateColumn()
  createdAt: Date;
}
