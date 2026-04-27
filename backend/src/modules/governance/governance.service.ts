import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { StellarService } from '../blockchain/stellar.service';
import { SavingsService } from '../blockchain/savings.service';
import { TransactionsService } from '../transactions/transactions.service';
import { UserService } from '../user/user.service';
import { CreateProposalDto } from './dto/create-proposal.dto';
import { EditProposalDto } from './dto/edit-proposal.dto';
import { DelegationResponseDto } from './dto/delegation-response.dto';
import { ProposalListItemDto } from './dto/proposal-list-item.dto';
import { ProposalResponseDto } from './dto/proposal-response.dto';
import { ProposalVotesResponseDto } from './dto/proposal-votes-response.dto';
import {
  GovernanceProposal,
  ProposalActionPayload,
  ProposalCategory,
  ProposalStatus,
  ProposalType,
} from './entities/governance-proposal.entity';
import { Vote, VoteDirection } from './entities/vote.entity';
import { Delegation } from './entities/delegation.entity';
import { VotingPowerResponseDto } from './dto/voting-power-response.dto';
import { TxStatus, TxType } from '../transactions/entities/transaction.entity';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';

/** Timelock duration in milliseconds (24 hours) */
const TIMELOCK_DURATION_MS = 24 * 60 * 60 * 1000;

@Injectable()
export class GovernanceService {
  constructor(
    private readonly userService: UserService,
    private readonly stellarService: StellarService,
    private readonly savingsService: SavingsService,
    private readonly transactionsService: TransactionsService,
    private readonly eventEmitter: EventEmitter2,
    @InjectRepository(GovernanceProposal)
    private readonly proposalRepo: Repository<GovernanceProposal>,
    @InjectRepository(Vote)
    private readonly voteRepo: Repository<Vote>,
    @InjectRepository(LedgerTransaction)
    private readonly transactionRepo: Repository<LedgerTransaction>,
    @InjectRepository(Delegation)
    private readonly delegationRepo: Repository<Delegation>,
  ) {}

  async createProposal(
    userId: string,
    dto: CreateProposalDto,
  ): Promise<ProposalResponseDto> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) {
      throw new BadRequestException(
        'A linked wallet is required before creating governance proposals',
      );
    }

    const votingPower = await this.getVotingPowerAmount(userId);
    const proposalThreshold = this.getProposalThreshold();
    if (votingPower < proposalThreshold) {
      throw new ForbiddenException(
        `Minimum voting power of ${proposalThreshold} NST is required to create a proposal`,
      );
    }

    const normalizedAction = this.validateProposalAction(dto.type, dto.action);
    const currentLedger = await this.getCurrentLedger();
    const startBlock =
      dto.startBlock ?? currentLedger + this.getStartDelayLedgers();
    const endBlock = dto.endBlock ?? startBlock + this.getVotingPeriodLedgers();

    this.validateVotingWindow(startBlock, endBlock, currentLedger);

    const latestProposal = await this.proposalRepo.findOne({
      order: { onChainId: 'DESC' },
    });
    const onChainId = (latestProposal?.onChainId ?? 0) + 1;
    const category = this.mapTypeToCategory(dto.type);
    const title = this.resolveProposalTitle(
      dto.description,
      dto.title,
      onChainId,
    );
    const requiredQuorum = this.calculateRequiredQuorum();

    const proposal = this.proposalRepo.create({
      onChainId,
      title,
      description: dto.description,
      category,
      type: dto.type,
      action: normalizedAction,
      attachments: dto.attachments ?? [],
      proposer: user.publicKey,
      createdByUserId: userId,
      startBlock,
      endBlock,
      status: ProposalStatus.ACTIVE,
      requiredQuorum: requiredQuorum.toFixed(8),
      quorumBps: this.getQuorumBps(),
      proposalThreshold: proposalThreshold.toFixed(8),
    });

    const savedProposal = await this.proposalRepo.save(proposal);

    this.eventEmitter.emit('governance.proposal.created', {
      proposalId: savedProposal.id,
      onChainId: savedProposal.onChainId,
      proposer: savedProposal.proposer,
      title: savedProposal.title,
      type: savedProposal.type,
      requiredQuorum: savedProposal.requiredQuorum,
    });

    return this.toProposalResponse(savedProposal, currentLedger);
  }

  async editProposal(
    userId: string,
    proposalId: string,
    dto: EditProposalDto,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal) {
      throw new NotFoundException(`Proposal ${proposalId} not found`);
    }

    if (!proposal.createdByUserId || proposal.createdByUserId !== userId) {
      throw new ForbiddenException('Only the proposal creator can edit it');
    }

    const currentLedger = await this.getCurrentLedger();
    if (proposal.startBlock !== null && proposal.startBlock <= currentLedger) {
      throw new BadRequestException(
        'Proposal can no longer be edited because voting has already started',
      );
    }

    const existingVoteCount = await this.voteRepo.count({
      where: { proposalId: proposal.id },
    });
    if (existingVoteCount > 0) {
      throw new BadRequestException(
        'Proposal can no longer be edited because voting activity has already been recorded',
      );
    }

    const nextType = dto.type ?? proposal.type;
    if (!nextType) {
      throw new BadRequestException(
        'Proposal type is required before editing this proposal',
      );
    }

    const nextAction = dto.action === undefined ? proposal.action : dto.action;
    if (!nextAction) {
      throw new BadRequestException('Proposal action is required');
    }

    const normalizedAction = this.validateProposalAction(nextType, nextAction);
    const nextStartBlock = dto.startBlock ?? proposal.startBlock ?? null;
    const nextEndBlock = dto.endBlock ?? proposal.endBlock ?? null;

    if (nextStartBlock === null || nextEndBlock === null) {
      throw new BadRequestException(
        'Proposal start and end ledgers must be defined before editing',
      );
    }

    this.validateVotingWindow(nextStartBlock, nextEndBlock, currentLedger);

    proposal.type = nextType;
    proposal.category = this.mapTypeToCategory(nextType);
    proposal.action = normalizedAction;
    proposal.description = dto.description ?? proposal.description;
    proposal.title = this.resolveProposalTitle(
      proposal.description,
      dto.title ?? proposal.title,
      proposal.onChainId,
    );
    proposal.attachments = dto.attachments ?? proposal.attachments ?? [];
    proposal.startBlock = nextStartBlock;
    proposal.endBlock = nextEndBlock;
    proposal.requiredQuorum = this.calculateRequiredQuorum().toFixed(8);
    proposal.quorumBps = this.getQuorumBps();
    proposal.proposalThreshold = this.getProposalThreshold().toFixed(8);

    const savedProposal = await this.proposalRepo.save(proposal);
    return this.toProposalResponse(savedProposal, currentLedger);
  }

  async getProposals(status?: ProposalStatus): Promise<ProposalListItemDto[]> {
    const where = status ? { status } : {};
    const proposals = await this.proposalRepo.find({
      where,
      order: { createdAt: 'DESC' },
    });

    if (proposals.length === 0) {
      return [];
    }

    const proposalIds = proposals.map((p) => p.id);

    // Aggregate vote counts per proposal in a single query
    const tallies: {
      proposalId: string;
      forCount: string;
      againstCount: string;
      abstainCount: string;
    }[] = await this.voteRepo
      .createQueryBuilder('vote')
      .select('vote.proposalId', 'proposalId')
      .addSelect(
        `SUM(CASE WHEN vote.direction = '${VoteDirection.FOR}' THEN 1 ELSE 0 END)`,
        'forCount',
      )
      .addSelect(
        `SUM(CASE WHEN vote.direction = '${VoteDirection.AGAINST}' THEN 1 ELSE 0 END)`,
        'againstCount',
      )
      .addSelect(
        `SUM(CASE WHEN vote.direction = '${VoteDirection.ABSTAIN}' THEN 1 ELSE 0 END)`,
        'abstainCount',
      )
      .where('vote.proposalId IN (:...ids)', { ids: proposalIds })
      .groupBy('vote.proposalId')
      .getRawMany();

    const tallyMap = new Map(tallies.map((t) => [t.proposalId, t]));

    return proposals.map((proposal) => {
      const tally = tallyMap.get(proposal.id);
      const forCount = tally ? Number(tally.forCount) : 0;
      const againstCount = tally ? Number(tally.againstCount) : 0;
      const abstainCount = tally ? Number(tally.abstainCount) : 0;
      const totalCount = forCount + againstCount + abstainCount;

      const forPercent =
        totalCount > 0 ? Math.round((forCount / totalCount) * 10000) / 100 : 0;
      const againstPercent =
        totalCount > 0
          ? Math.round((againstCount / totalCount) * 10000) / 100
          : 0;
      const abstainPercent =
        totalCount > 0
          ? Math.round((abstainCount / totalCount) * 10000) / 100
          : 0;

      return {
        id: proposal.id,
        onChainId: proposal.onChainId,
        title: proposal.title,
        description: proposal.description ?? null,
        category: proposal.category,
        status: proposal.status,
        proposer: proposal.proposer ?? null,
        forPercent,
        againstPercent,
        abstainPercent,
        timeline: {
          startTime: proposal.startBlock ?? null,
          endTime: proposal.endBlock ?? null,
        },
      };
    });
  }

  async getUserDelegation(userId: string): Promise<DelegationResponseDto> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) {
      return { delegate: null };
    }
    const delegate = await this.stellarService.getDelegationForUser(
      user.publicKey,
    );
    return { delegate };
  }

  async getUserVotingPower(userId: string): Promise<VotingPowerResponseDto> {
    const votingPower = await this.getVotingPowerAmount(userId);
    if (votingPower === 0) {
      return { votingPower: '0 NST' };
    }
    const formattedVotingPower = votingPower.toLocaleString(undefined, {
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    });
    return { votingPower: `${formattedVotingPower} NST` };
  }

  async castVote(
    userId: string,
    onChainId: number,
    direction: VoteDirection,
  ): Promise<{ transactionHash: string }> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) {
      throw new BadRequestException('User must have a public key to vote');
    }

    const proposal = await this.proposalRepo.findOneBy({ onChainId });
    if (!proposal) {
      throw new NotFoundException(`Proposal ${onChainId} not found`);
    }

    if (proposal.status !== ProposalStatus.ACTIVE) {
      throw new BadRequestException('Proposal is not active for voting');
    }

    // Check for double voting
    const existingVote = await this.voteRepo.findOneBy({
      walletAddress: user.publicKey,
      proposalId: proposal.id,
    });

    if (existingVote) {
      throw new BadRequestException('User has already voted on this proposal');
    }

    const votingPowerResult = await this.getUserVotingPower(userId);
    const weight = parseFloat(votingPowerResult.votingPower.split(' ')[0]);

    if (weight <= 0) {
      throw new BadRequestException('User has no voting power');
    }

    // In a real scenario, this would involve a Stellar transaction.
    // For now, we simulate the transaction hash and save the vote to DB.
    const mockTxHash = `0x${Math.random().toString(16).slice(2, 10)}${Date.now().toString(16)}`;

    const vote = this.voteRepo.create({
      walletAddress: user.publicKey,
      direction,
      weight,
      proposal,
      proposalId: proposal.id,
    });

    await this.voteRepo.save(vote);

    // Emit event for real-time updates
    this.eventEmitter.emit('governance.vote_cast', {
      proposalId: proposal.id,
      onChainId: proposal.onChainId,
      direction,
      weight,
      walletAddress: user.publicKey,
    });

    return { transactionHash: mockTxHash };
  }

  async delegateVotingPower(
    userId: string,
    delegateAddress: string,
  ): Promise<{ transactionHash: string }> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) {
      throw new BadRequestException('User must have a public key to delegate');
    }

    // Simulate Stellar delegation
    const mockTxHash = `0x${Math.random().toString(16).slice(2, 10)}${Date.now().toString(16)}`;

    // In a real app, we'd update the contract on-chain via StellarService
    // and potentially store it in our DB if needed.

    return { transactionHash: mockTxHash };
  }

  // ── Lifecycle (#541) ───────────────────────────────────────────────────────

  async getProposalStatus(proposalId: string): Promise<{
    status: ProposalStatus;
    timelockEndsAt: Date | null;
    executedAt: Date | null;
  }> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);
    return {
      status: proposal.status,
      timelockEndsAt: proposal.timelockEndsAt ?? null,
      executedAt: proposal.executedAt ?? null,
    };
  }

  async queueProposal(
    proposalId: string,
    userId: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);
    if (proposal.status !== ProposalStatus.PASSED) {
      throw new BadRequestException('Only passed proposals can be queued');
    }
    proposal.status = ProposalStatus.QUEUED;
    proposal.timelockEndsAt = new Date(Date.now() + TIMELOCK_DURATION_MS);
    const saved = await this.proposalRepo.save(proposal);
    this.eventEmitter.emit('governance.proposal.queued', {
      proposalId: saved.id,
    });
    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(saved, currentLedger);
  }

  async executeProposal(
    proposalId: string,
    userId: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);
    if (proposal.status !== ProposalStatus.QUEUED) {
      throw new BadRequestException('Only queued proposals can be executed');
    }
    if (!proposal.timelockEndsAt || new Date() < proposal.timelockEndsAt) {
      throw new BadRequestException('Timelock period has not elapsed yet');
    }
    proposal.status = ProposalStatus.EXECUTED;
    proposal.executedAt = new Date();
    const saved = await this.proposalRepo.save(proposal);
    this.eventEmitter.emit('governance.proposal.executed', {
      proposalId: saved.id,
    });
    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(saved, currentLedger);
  }

  async cancelProposal(
    proposalId: string,
    userId: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);
    if (proposal.createdByUserId !== userId) {
      throw new ForbiddenException('Only the proposal creator can cancel it');
    }
    if (
      proposal.status === ProposalStatus.EXECUTED ||
      proposal.status === ProposalStatus.CANCELLED
    ) {
      throw new BadRequestException(
        `Cannot cancel a proposal with status ${proposal.status}`,
      );
    }
    proposal.status = ProposalStatus.CANCELLED;
    const saved = await this.proposalRepo.save(proposal);
    this.eventEmitter.emit('governance.proposal.cancelled', {
      proposalId: saved.id,
    });
    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(saved, currentLedger);
  }

  // ── Delegation (#542) ──────────────────────────────────────────────────────

  async delegate(
    userId: string,
    delegateAddress: string,
  ): Promise<{ transactionHash: string }> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey)
      throw new BadRequestException('User must have a public key to delegate');
    if (user.publicKey === delegateAddress) {
      throw new BadRequestException('Cannot delegate to yourself');
    }
    // Loop prevention: check if delegateAddress already delegates to user
    const reverseLoop = await this.delegationRepo.findOne({
      where: {
        delegatorAddress: delegateAddress,
        delegateAddress: user.publicKey,
      },
    });
    if (reverseLoop) throw new BadRequestException('Delegation loop detected');

    await this.delegationRepo.upsert(
      { delegatorAddress: user.publicKey, delegateAddress },
      ['delegatorAddress'],
    );
    const txHash = `0x${Math.random().toString(16).slice(2, 10)}${Date.now().toString(16)}`;
    this.eventEmitter.emit('governance.delegation.changed', {
      delegator: user.publicKey,
      delegate: delegateAddress,
    });
    return { transactionHash: txHash };
  }

  async revokeDelegate(userId: string): Promise<void> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey)
      throw new BadRequestException('User must have a public key');
    await this.delegationRepo.delete({ delegatorAddress: user.publicKey });
    this.eventEmitter.emit('governance.delegation.revoked', {
      delegator: user.publicKey,
    });
  }

  async getMyDelegation(
    userId: string,
  ): Promise<{ delegate: string | null; totalDelegatedPower: number }> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) return { delegate: null, totalDelegatedPower: 0 };
    const record = await this.delegationRepo.findOne({
      where: { delegatorAddress: user.publicKey },
    });
    const delegators = await this.delegationRepo.find({
      where: { delegateAddress: user.publicKey },
    });
    const totalDelegatedPower = delegators.length; // simplified; real impl sums NST balances
    return { delegate: record?.delegateAddress ?? null, totalDelegatedPower };
  }

  async getMyDelegators(
    userId: string,
  ): Promise<{ delegators: string[]; totalDelegatedPower: number }> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) return { delegators: [], totalDelegatedPower: 0 };
    const records = await this.delegationRepo.find({
      where: { delegateAddress: user.publicKey },
    });
    return {
      delegators: records.map((r) => r.delegatorAddress),
      totalDelegatedPower: records.length,
    };
  }

  async getProposalVotesByOnChainId(
    onChainId: number,
    page = 0,
  ): Promise<ProposalVotesResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ onChainId });
    if (!proposal) {
      throw new NotFoundException(`Proposal ${onChainId} not found`);
    }

    const [votes, total] = await this.voteRepo.findAndCount({
      where: { proposalId: proposal.id },
      order: { createdAt: 'DESC' },
      take: 20,
      skip: page * 20,
    });

    let forWeight = 0;
    let againstWeight = 0;
    let abstainWeight = 0;
    for (const vote of votes) {
      const voteWeight = Number(vote.weight) || 0;
      if (vote.direction === VoteDirection.FOR) {
        forWeight += voteWeight;
      } else if (vote.direction === VoteDirection.AGAINST) {
        againstWeight += voteWeight;
      } else {
        abstainWeight += voteWeight;
      }
    }

    return {
      proposalOnChainId: onChainId,
      tally: {
        forVotes: votes.filter((vote) => vote.direction === VoteDirection.FOR)
          .length,
        againstVotes: votes.filter(
          (vote) => vote.direction === VoteDirection.AGAINST,
        ).length,
        abstainVotes: votes.filter(
          (vote) => vote.direction === VoteDirection.ABSTAIN,
        ).length,
        forWeight: String(forWeight),
        againstWeight: String(againstWeight),
        abstainWeight: String(abstainWeight),
        totalWeight: String(forWeight + againstWeight + abstainWeight),
      },
      recentVoters: votes.map((vote) => ({
        walletAddress: vote.walletAddress,
        direction: vote.direction,
        weight: String(vote.weight),
        votedAt: vote.createdAt.toISOString(),
      })),
      total,
      page,
    };
  }

  private async getVotingPowerAmount(userId: string): Promise<number> {
    const user = await this.userService.findById(userId);
    if (!user.publicKey) {
      return 0;
    }

    const governanceTokenContractId = process.env.NST_GOVERNANCE_CONTRACT_ID;
    if (!governanceTokenContractId) {
      throw new Error('NST governance token contract ID not configured');
    }

    const balance = await this.savingsService.getUserVaultBalance(
      governanceTokenContractId,
      user.publicKey,
    );

    return Number(balance) / 10_000_000;
  }

  private async getCurrentLedger(): Promise<number> {
    try {
      const latestLedger = await this.stellarService
        .getRpcServer()
        .getLatestLedger();
      const sequence = Number(latestLedger?.sequence);

      if (!Number.isFinite(sequence) || sequence <= 0) {
        throw new Error('Invalid latest ledger sequence');
      }

      return sequence;
    } catch (error) {
      throw new ServiceUnavailableException(
        `Unable to resolve the latest ledger for governance scheduling: ${(error as Error).message}`,
      );
    }
  }

  private validateVotingWindow(
    startBlock: number,
    endBlock: number,
    currentLedger: number,
  ): void {
    if (!Number.isInteger(startBlock) || !Number.isInteger(endBlock)) {
      throw new BadRequestException(
        'Voting window must use whole ledger numbers',
      );
    }

    if (startBlock <= currentLedger) {
      throw new BadRequestException(
        'Voting start ledger must be in the future',
      );
    }

    if (endBlock <= startBlock) {
      throw new BadRequestException(
        'Voting end ledger must be after the start ledger',
      );
    }
  }

  private validateProposalAction(
    type: ProposalType,
    action: Record<string, unknown> | ProposalActionPayload,
  ): ProposalActionPayload {
    if (!action || Array.isArray(action)) {
      throw new BadRequestException('Proposal action must be an object');
    }

    const actionRecord = action as Record<string, unknown>;

    switch (type) {
      case ProposalType.RATE_CHANGE: {
        const target = this.readRequiredString(actionRecord, 'target');
        const allowedTargets = [
          'flexiRate',
          'goalRate',
          'groupRate',
          'lockRate',
        ];

        if (!allowedTargets.includes(target)) {
          throw new BadRequestException(
            `Rate change target must be one of: ${allowedTargets.join(', ')}`,
          );
        }

        const newValue = this.readRequiredPositiveNumber(
          actionRecord,
          'newValue',
        );
        const duration =
          target === 'lockRate'
            ? this.readRequiredPositiveInteger(actionRecord, 'duration')
            : this.readOptionalPositiveInteger(actionRecord, 'duration');

        return {
          target,
          newValue,
          ...(duration !== undefined ? { duration } : {}),
        };
      }

      case ProposalType.PAUSE:
      case ProposalType.UNPAUSE: {
        const reason = this.readOptionalString(actionRecord, 'reason');
        return reason ? { reason } : {};
      }

      case ProposalType.TREASURY_ALLOCATION: {
        const recipient = this.readRequiredString(actionRecord, 'recipient');
        const amount = this.readRequiredPositiveNumber(actionRecord, 'amount');
        const asset = this.readOptionalString(actionRecord, 'asset') ?? 'NST';
        const reason = this.readOptionalString(actionRecord, 'reason');

        return {
          recipient,
          amount,
          asset,
          ...(reason ? { reason } : {}),
        };
      }

      default:
        throw new BadRequestException('Unsupported proposal type');
    }
  }

  private mapTypeToCategory(type: ProposalType): ProposalCategory {
    switch (type) {
      case ProposalType.TREASURY_ALLOCATION:
        return ProposalCategory.TREASURY;
      case ProposalType.RATE_CHANGE:
        return ProposalCategory.TECHNICAL;
      case ProposalType.PAUSE:
      case ProposalType.UNPAUSE:
      default:
        return ProposalCategory.GOVERNANCE;
    }
  }

  private calculateRequiredQuorum(): number {
    return (this.getMaxVotingPower() * this.getQuorumBps()) / 10_000;
  }

  private resolveProposalTitle(
    description: string,
    providedTitle: string | undefined | null,
    onChainId: number,
  ): string {
    const normalizedTitle = providedTitle?.trim();
    if (normalizedTitle) {
      return normalizedTitle.slice(0, 500);
    }

    const firstLine = description.split('\n')[0]?.trim();
    if (firstLine) {
      return firstLine.slice(0, 500);
    }

    return `Proposal #${onChainId}`;
  }

  private toProposalResponse(
    proposal: GovernanceProposal,
    currentLedger: number,
  ): ProposalResponseDto {
    return {
      id: proposal.id,
      onChainId: proposal.onChainId,
      title: proposal.title,
      description: proposal.description,
      category: proposal.category,
      type: proposal.type,
      action: proposal.action,
      status: proposal.status,
      proposer: proposal.proposer ?? null,
      startBlock: proposal.startBlock ?? null,
      endBlock: proposal.endBlock ?? null,
      attachments: proposal.attachments ?? [],
      requiredQuorum: String(proposal.requiredQuorum),
      quorumBps: proposal.quorumBps,
      proposalThreshold: String(proposal.proposalThreshold),
      canEdit:
        proposal.createdByUserId !== null &&
        proposal.createdByUserId !== undefined &&
        proposal.startBlock !== null &&
        proposal.startBlock > currentLedger,
      votes: [],
      createdAt: proposal.createdAt,
      updatedAt: proposal.updatedAt,
    };
  }

  private readNumberEnv(name: string, fallback: number): number {
    const raw = process.env[name];
    const parsed = raw ? Number(raw) : fallback;
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  private getQuorumBps(): number {
    return this.readNumberEnv('GOVERNANCE_QUORUM_BPS', 5000);
  }

  private getProposalThreshold(): number {
    return this.readNumberEnv('GOVERNANCE_PROPOSAL_THRESHOLD', 100);
  }

  private getMaxVotingPower(): number {
    return this.readNumberEnv('GOVERNANCE_MAX_VOTING_POWER', 10_000);
  }

  private getVotingPeriodLedgers(): number {
    return this.readNumberEnv('GOVERNANCE_VOTING_PERIOD_LEDGERS', 17_280);
  }

  private getStartDelayLedgers(): number {
    return this.readNumberEnv('GOVERNANCE_START_DELAY_LEDGERS', 100);
  }

  private readRequiredString(
    value: Record<string, unknown>,
    key: string,
  ): string {
    const candidate = value[key];
    if (typeof candidate !== 'string' || candidate.trim().length === 0) {
      throw new BadRequestException(`Proposal action.${key} is required`);
    }

    return candidate.trim();
  }

  private readOptionalString(
    value: Record<string, unknown>,
    key: string,
  ): string | undefined {
    const candidate = value[key];
    if (candidate === undefined || candidate === null || candidate === '') {
      return undefined;
    }

    if (typeof candidate !== 'string') {
      throw new BadRequestException(`Proposal action.${key} must be a string`);
    }

    return candidate.trim();
  }

  private readRequiredPositiveNumber(
    value: Record<string, unknown>,
    key: string,
  ): number {
    const candidate = Number(value[key]);
    if (!Number.isFinite(candidate) || candidate <= 0) {
      throw new BadRequestException(
        `Proposal action.${key} must be a positive number`,
      );
    }

    return candidate;
  }

  private readRequiredPositiveInteger(
    value: Record<string, unknown>,
    key: string,
  ): number {
    const candidate = Number(value[key]);
    if (!Number.isInteger(candidate) || candidate <= 0) {
      throw new BadRequestException(
        `Proposal action.${key} must be a positive integer`,
      );
    }

    return candidate;
  }

  private readOptionalPositiveInteger(
    value: Record<string, unknown>,
    key: string,
  ): number | undefined {
    if (value[key] === undefined || value[key] === null) {
      return undefined;
    }

    return this.readRequiredPositiveInteger(value, key);
  }
}
