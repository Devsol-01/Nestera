import { Body, Controller, Delete, Get, Post, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Idempotent } from '../../common/decorators/idempotent.decorator';
import { DelegationResponseDto } from './dto/delegation-response.dto';
import { VotingPowerResponseDto } from './dto/voting-power-response.dto';
import { DelegateVoteDto } from './dto/delegate-vote.dto';
import { GovernanceService } from './governance.service';

@ApiTags('governance')
@ApiBearerAuth()
@Controller('user')
@UseGuards(JwtAuthGuard)
export class GovernanceController {
  constructor(private readonly governanceService: GovernanceService) {}

  // ── Legacy delegation lookup (kept for backwards compat) ──────────────────

  @Get('delegation')
  @ApiOperation({
    summary: 'Get the authenticated user delegation target',
    description:
      'Reads the Soroban governance contract mapping for the authenticated user and returns the delegated wallet address when present.',
  })
  @ApiResponse({
    status: 200,
    description: 'Delegation lookup result',
    type: DelegationResponseDto,
  })
  getDelegation(
    @CurrentUser() user: { id: string },
  ): Promise<DelegationResponseDto> {
    return this.governanceService.getUserDelegation(user.id);
  }

  @Get('voting-power')
  @ApiOperation({
    summary: 'Get the authenticated user voting power',
    description:
      'Returns the current NST token balance for the authenticated user, representing their voting power in the governance system.',
  })
  @ApiResponse({
    status: 200,
    description: 'Voting power lookup result',
    type: VotingPowerResponseDto,
  })
  getVotingPower(
    @CurrentUser() user: { id: string },
  ): Promise<VotingPowerResponseDto> {
    return this.governanceService.getUserVotingPower(user.id);
  }

  // ── Delegation (#542) ──────────────────────────────────────────────────────

  @Post('governance/delegate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Delegate voting power to a trusted address' })
  @ApiResponse({
    status: 201,
    description: 'Delegation set',
    schema: {
      type: 'object',
      properties: { transactionHash: { type: 'string' } },
    },
  })
  @ApiResponse({ status: 400, description: 'Loop detected or invalid address' })
  delegate(
    @CurrentUser() user: { id: string },
    @Body() dto: DelegateVoteDto,
  ): Promise<{ transactionHash: string }> {
    return this.governanceService.delegate(user.id, dto.delegateAddress);
  }

  @Delete('governance/delegate')
  @Idempotent({ ttlSeconds: 86400 })
  @ApiOperation({ summary: 'Revoke current voting power delegation' })
  @ApiResponse({ status: 200, description: 'Delegation revoked' })
  revokeDelegate(@CurrentUser() user: { id: string }): Promise<void> {
    return this.governanceService.revokeDelegate(user.id);
  }

  @Get('governance/delegation')
  @ApiOperation({
    summary: 'View current delegation and total delegated power',
  })
  @ApiResponse({
    status: 200,
    description: 'Delegation info',
    schema: {
      type: 'object',
      properties: {
        delegate: { type: 'string', nullable: true },
        totalDelegatedPower: { type: 'number' },
      },
    },
  })
  getMyDelegation(
    @CurrentUser() user: { id: string },
  ): Promise<{ delegate: string | null; totalDelegatedPower: number }> {
    return this.governanceService.getMyDelegation(user.id);
  }

  @Get('governance/delegators')
  @ApiOperation({ summary: 'See who has delegated their voting power to you' })
  @ApiResponse({
    status: 200,
    description: 'Delegators list',
    schema: {
      type: 'object',
      properties: {
        delegators: { type: 'array', items: { type: 'string' } },
        totalDelegatedPower: { type: 'number' },
      },
    },
  })
  getMyDelegators(
    @CurrentUser() user: { id: string },
  ): Promise<{ delegators: string[]; totalDelegatedPower: number }> {
    return this.governanceService.getMyDelegators(user.id);
  }
}
