import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { GovernanceProposal } from './governance-proposal.entity';

export enum VoteDirection {
  AGAINST = 'AGAINST',
  FOR = 'FOR',
}

@Entity('votes')
@Index(['walletAddress', 'proposalId'], { unique: true })
@Index('idx_votes_proposal_id_wallet_address', ['proposalId', 'walletAddress'])
export class Vote {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  walletAddress: string;

  @Column({ type: 'enum', enum: VoteDirection })
  direction: VoteDirection;

  @Column({ type: 'decimal', precision: 18, scale: 8 })
  weight: number;

  @ManyToOne(() => GovernanceProposal, (proposal) => proposal.votes, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'proposalId' })
  proposal: GovernanceProposal;

  @Column()
  proposalId: string;

  @CreateDateColumn()
  createdAt: Date;
}
