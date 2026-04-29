import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Vote } from './vote.entity';

export enum ProposalStatus {
  ACTIVE = 'Active',
  PASSED = 'Passed',
  FAILED = 'Failed',
  CANCELLED = 'Cancelled',
}

export enum ProposalCategory {
  GOVERNANCE = 'Governance',
  TREASURY = 'Treasury',
  TECHNICAL = 'Technical',
  COMMUNITY = 'Community',
}

@Entity('governance_proposals')
@Index('idx_governance_proposals_status', ['status'])
@Index('idx_governance_proposals_status_on_chain_id', ['status', 'onChainId'])
export class GovernanceProposal {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** On-chain proposal ID from the DAO contract */
  @Column({ type: 'int', unique: true })
  onChainId: number;

  @Column()
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({
    type: 'enum',
    enum: ProposalCategory,
    default: ProposalCategory.GOVERNANCE,
  })
  category: ProposalCategory;

  @Column({
    type: 'enum',
    enum: ProposalStatus,
    default: ProposalStatus.ACTIVE,
  })
  status: ProposalStatus;

  @Column({ nullable: true })
  proposer: string;

  @Column({ type: 'bigint', nullable: true })
  startBlock: number;

  @Column({ type: 'bigint', nullable: true })
  endBlock: number;

  @OneToMany(() => Vote, (vote) => vote.proposal)
  votes: Vote[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
