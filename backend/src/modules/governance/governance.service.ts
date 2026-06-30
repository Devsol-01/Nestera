import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  Optional,
  ServiceUnavailableException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { InjectRepository } from '@nestjs/typeorm';
import { QueryFailedError, Repository } from 'typeorm';
import { CacheStrategyService } from '../cache/cache-strategy.service';
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
  getProposalTemplate as getProposalTemplateDefinition,
  listProposalTemplates,
} from './proposal-templates';
import {
  GovernanceProposal,
  ProposalActionPayload,
  ProposalCategory,
  ProposalStatus,
  ProposalType,
} from './entities/governance-proposal.entity';
import { Vote, VoteDirection } from './entities/vote.entity';
import { Delegation } from './entities/delegation.entity';
import { ProposalTransition } from './entities/proposal-transition.entity';
import { ProposalLifecycleService } from './governance-lifecycle.service';
import { VotingPowerResponseDto } from './dto/voting-power-response.dto';
import { TxStatus, TxType } from '../transactions/entities/transaction.entity';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';
import { AuditLogService } from '../../common/services/audit-log.service';
import {
  AuditAction,
  AuditResourceType,
} from '../../common/entities/audit-log.entity';
import { DistributedTracingService } from '../../modules/apm/distributed-tracing.service';
import { TraceSpan } from '../../common/decorators/trace-span.decorator';

/** Timelock duration in milliseconds (24 hours) */
const TIMELOCK_DURATION_MS = 24 * 60 * 60 * 1000;

/** How long the server-side vote dedup cache entry lives (24 hours). */
const VOTE_DEDUP_TTL_MS = 24 * 60 * 60 * 1000;

/** PostgreSQL unique-constraint violation code. */
const PG_UNIQUE_VIOLATION = '23505';

function isUniqueViolation(err: unknown): boolean {
  if (!(err instanceof QueryFailedError)) return false;
  const code =
    (err as unknown as Record<string, string>).code ??
    (err as unknown as { driverError?: { code?: string } }).driverError?.code;
  return code === PG_UNIQUE_VIOLATION;
}

@Injectable()
export class GovernanceService {
  constructor(
    private readonly userService: UserService,
    private readonly stellarService: StellarService,
    private readonly savingsService: SavingsService,
    private readonly transactionsService: TransactionsService,
    private readonly eventEmitter: EventEmitter2,
    private readonly lifecycleService: ProposalLifecycleService,
    private readonly cacheStrategy: CacheStrategyService,
    @InjectRepository(GovernanceProposal)
    private readonly proposalRepo: Repository<GovernanceProposal>,
    @InjectRepository(Vote)
    private readonly voteRepo: Repository<Vote>,
    @InjectRepository(LedgerTransaction)
    private readonly transactionRepo: Repository<LedgerTransaction>,
    @InjectRepository(Delegation)
    private readonly delegationRepo: Repository<Delegation>,
    private readonly auditLogService: AuditLogService,
    @Optional() readonly tracingService?: DistributedTracingService,
  ) {}

  @TraceSpan('governance.createProposal')
  async createProposal(
    userId: string,
    dto: CreateProposalDto,
    correlationId?: string,
    requestId?: string,
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

    const template = dto.templateId
      ? getProposalTemplateDefinition(dto.templateId, dto.templateVersion)
      : null;

    if (dto.templateId && !template) {
      throw new BadRequestException(
        `Unknown proposal template '${dto.templateId}'`,
      );
    }

    if (template && dto.type && dto.type !== template.type) {
      throw new BadRequestException(
        `Template ${template.id} requires proposal type ${template.type}`,
      );
    }

    const type = template?.type ?? dto.type;
    if (!type) {
      throw new BadRequestException(
        'Proposal type is required unless a valid template is selected',
      );
    }

    if (template && dto.action) {
      throw new BadRequestException(
        'Action payload must not be provided when using a proposal template. Use templateParameters instead.',
      );
    }

    const action = template
      ? template.actionFactory(dto.templateParameters ?? {})
      : dto.action;

    if (!action) {
      throw new BadRequestException(
        'Proposal action is required when not using a template',
      );
    }

    const normalizedAction = this.validateProposalAction(type, action);
    const currentLedger = await this.getCurrentLedger();
    const startBlock =
      dto.startBlock ?? currentLedger + this.getStartDelayLedgers();
    const endBlock = dto.endBlock ?? startBlock + this.getVotingPeriodLedgers();

    this.validateVotingWindow(startBlock, endBlock, currentLedger);

    const latestProposal = await this.proposalRepo.findOne({
      order: { onChainId: 'DESC' },
    });
    const onChainId = (latestProposal?.onChainId ?? 0) + 1;
    const category = this.mapTypeToCategory(type);
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
      type,
      templateId: template?.id ?? null,
      templateVersion: template?.version ?? null,
      templateParameters: template ? (dto.templateParameters ?? {}) : null,
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

    await this.auditLogService.log({
      action: AuditAction.CREATE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: savedProposal.id,
      description: `User created proposal "${savedProposal.title}" (type: ${savedProposal.type})`,
      newValue: {
        onChainId: savedProposal.onChainId,
        title: savedProposal.title,
        type: savedProposal.type,
        category: savedProposal.category,
      },
      success: true,
    });

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

  @TraceSpan('governance.editProposal')
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

  @TraceSpan('governance.getProposals')
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

  getProposalTemplates() {
    return listProposalTemplates();
  }

  getProposalTemplateById(templateId: string, version?: string) {
    const template = getProposalTemplateDefinition(templateId, version);
    if (!template) {
      throw new NotFoundException(`Template '${templateId}' not found`);
    }
    return template;
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

  @TraceSpan('governance.castVote')
  async castVote(
    userId: string,
    onChainId: number,
    direction: VoteDirection,
    correlationId?: string,
    requestId?: string,
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

    // Enforce ledger-level voting window boundaries (startBlock..endBlock).
    // Status alone is insufficient: a proposal is created ACTIVE immediately
    // but its window may not have opened yet, or may have already closed.
    await this.lifecycleService.assertValidVotingWindow(proposal);

    // ── Layer 1: server-side dedup key ────────────────────────────────────
    // A cache entry keyed on (walletAddress, proposalId) is set after the
    // first successful vote. Subsequent requests fail here before touching
    // the database, preventing both accidental retries and intentional spam.
    const voteDedupKey = `vote:${user.publicKey}:${proposal.id}`;
    const cachedDuplicate = await this.cacheStrategy.get<true>(voteDedupKey);
    if (cachedDuplicate) {
      throw new ConflictException('You have already voted on this proposal');
    }

    // ── Layer 2: authoritative DB read ────────────────────────────────────
    // Catches votes submitted before the cache entry was set (e.g. on a
    // fresh deployment or after a cache flush).
    const existingVote = await this.voteRepo.findOneBy({
      walletAddress: user.publicKey,
      proposalId: proposal.id,
    });
    if (existingVote) {
      // Backfill the cache so future requests hit layer 1 instead.
      await this.cacheStrategy.set(voteDedupKey, true, VOTE_DEDUP_TTL_MS, [
        'vote',
        `proposal:${proposal.id}`,
      ]);
      throw new ConflictException('You have already voted on this proposal');
    }

    const votingPowerResult = await this.getUserVotingPower(userId);
    const weight = parseFloat(votingPowerResult.votingPower.split(' ')[0]);

    if (weight <= 0) {
      throw new BadRequestException('User has no voting power');
    }

    const mockTxHash = `0x${Math.random().toString(16).slice(2, 10)}${Date.now().toString(16)}`;

    const vote = this.voteRepo.create({
      walletAddress: user.publicKey,
      direction,
      weight,
      proposal,
      proposalId: proposal.id,
    });

    // ── Layer 3: DB unique constraint ─────────────────────────────────────
    // The uq_vote_wallet_proposal UNIQUE constraint on (walletAddress,
    // proposalId) is the last line of defence for concurrent requests that
    // both slipped past layers 1 and 2 before either committed.
    try {
      await this.voteRepo.save(vote);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException(
          'Duplicate vote rejected by the database — you have already voted on this proposal',
        );
      }
      throw error;
    }

    // Populate dedup cache so every subsequent request from this wallet is
    // rejected at layer 1 without a DB round-trip.
    await this.cacheStrategy.set(voteDedupKey, true, VOTE_DEDUP_TTL_MS, [
      'vote',
      `proposal:${proposal.id}`,
    ]);

    this.eventEmitter.emit('governance.vote_cast', {
      proposalId: proposal.id,
      onChainId: proposal.onChainId,
      direction,
      weight,
      walletAddress: user.publicKey,
    });

    await this.auditLogService.log({
      action: AuditAction.VOTE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: String(proposal.onChainId),
      description: `User voted ${direction} on proposal ${proposal.id} (onChainId: ${proposal.onChainId})`,
      newValue: {
        proposalId: proposal.id,
        onChainId: proposal.onChainId,
        direction,
        weight,
      },
      success: true,
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

  @TraceSpan('governance.queueProposal')
  async queueProposal(
    proposalId: string,
    userId: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);

    // State machine check is handled inside transitionTo, but guard here first
    // to give a clearer error before the quorum check.
    if (proposal.status !== ProposalStatus.PASSED) {
      throw new BadRequestException('Only passed proposals can be queued');
    }

    // Re-verify quorum at queue time — the PASSED status may have been set by
    // the indexer without a full weighted-quorum check.
    await this.lifecycleService.verifyQuorumForQueue(proposal);

    const timelockEndsAt = new Date(Date.now() + TIMELOCK_DURATION_MS);
    proposal.timelockEndsAt = timelockEndsAt;

    await this.lifecycleService.transitionTo(proposal, ProposalStatus.QUEUED, {
      triggeredBy: userId,
      reason: `Queued by ${userId}; timelock ends ${timelockEndsAt.toISOString()}`,
    });

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: proposal.id,
      description: `Proposal ${proposal.onChainId} queued for execution (timelock ends ${proposal.timelockEndsAt?.toISOString()})`,
      newValue: {
        status: ProposalStatus.QUEUED,
        timelockEndsAt: proposal.timelockEndsAt,
      },
      success: true,
    });

    this.eventEmitter.emit('governance.proposal.queued', {
      proposalId: proposal.id,
    });

    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(proposal, currentLedger);
  }

  @TraceSpan('governance.executeProposal')
  async executeProposal(
    proposalId: string,
    userId: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);

    if (proposal.status !== ProposalStatus.QUEUED) {
      throw new BadRequestException('Only queued proposals can be executed');
    }

    if (!proposal.timelockEndsAt || new Date() < proposal.timelockEndsAt) {
      throw new BadRequestException(
        `Timelock period has not elapsed yet — unlocks at ${proposal.timelockEndsAt?.toISOString() ?? 'unknown'}`,
      );
    }

    proposal.executedAt = new Date();

    await this.lifecycleService.transitionTo(
      proposal,
      ProposalStatus.EXECUTED,
      {
        triggeredBy: userId,
        reason: `Executed by ${userId} after timelock`,
        metadata: { executedAt: proposal.executedAt.toISOString() },
      },
    );

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: proposal.id,
      description: `Proposal ${proposal.onChainId} executed`,
      newValue: {
        status: ProposalStatus.EXECUTED,
        executedAt: proposal.executedAt,
      },
      success: true,
    });

    this.eventEmitter.emit('governance.proposal.executed', {
      proposalId: proposal.id,
    });

    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(proposal, currentLedger);
  }

  @TraceSpan('governance.cancelProposal')
  async cancelProposal(
    proposalId: string,
    userId: string,
    reason?: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.proposalRepo.findOneBy({ id: proposalId });
    if (!proposal)
      throw new NotFoundException(`Proposal ${proposalId} not found`);

    if (proposal.createdByUserId !== userId) {
      throw new ForbiddenException('Only the proposal creator can cancel it');
    }

    // transitionTo enforces that EXECUTED and CANCELLED are terminal states
    await this.lifecycleService.transitionTo(
      proposal,
      ProposalStatus.CANCELLED,
      {
        triggeredBy: userId,
        reason: reason ?? `Cancelled by creator ${userId}`,
      },
    );

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: proposal.id,
      description: `Proposal ${proposal.onChainId} cancelled${reason ? `: ${reason}` : ''}`,
      newValue: { status: ProposalStatus.CANCELLED, reason },
      success: true,
    });

    this.eventEmitter.emit('governance.proposal.cancelled', {
      proposalId: proposal.id,
    });

    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(proposal, currentLedger);
  }

  // ── Lifecycle helpers ─────────────────────────────────────────────────────

  @TraceSpan('governance.finalizeVoting')
  async finalizeVoting(
    proposalId: string,
    userId: string,
    correlationId?: string,
    requestId?: string,
  ): Promise<ProposalResponseDto> {
    const proposal = await this.lifecycleService.finalizeVoting(
      proposalId,
      userId,
    );

    await this.auditLogService.log({
      action: AuditAction.UPDATE,
      resourceType: AuditResourceType.GOVERNANCE,
      actor: userId,
      correlationId,
      requestId,
      resourceId: proposal.id,
      description: `Voting finalized for proposal ${proposal.onChainId} — status: ${proposal.status}`,
      newValue: { status: proposal.status },
      success: true,
    });

    const currentLedger = await this.getCurrentLedger();
    return this.toProposalResponse(proposal, currentLedger);
  }

  async getTransitionHistory(
    proposalId: string,
  ): Promise<ProposalTransition[]> {
    return this.lifecycleService.getTransitionHistory(proposalId);
  }

  // ── Delegation (#542) ──────────────────────────────────────────────────────

  @TraceSpan('governance.delegate')
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

  @TraceSpan('governance.revokeDelegate')
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
      templateId: proposal.templateId ?? null,
      templateVersion: proposal.templateVersion ?? null,
      templateParameters: proposal.templateParameters ?? null,
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
