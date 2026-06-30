import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  WithdrawalRequest,
  WithdrawalStatus,
} from '../savings/entities/withdrawal-request.entity';
import { User } from '../user/entities/user.entity';
import { WorkflowService } from './workflow.service';
import { WorkflowActionType } from './entities/admin-workflow.entity';
import { MailService } from '../mail/mail.service';
import { SavingsService } from '../savings/savings.service';

export interface EmergencyWithdrawalPayload {
  withdrawalId: string;
  reason: string;
  initiatedByAdminEmail: string;
}

/**
 * EmergencyWithdrawalWorkflowService
 *
 * Bridges the AdminWorkflow engine and the existing withdrawal processing flow.
 * When a SUPER_ADMIN approves an EMERGENCY_WITHDRAWAL workflow, this service
 * is called to execute the actual withdrawal.
 *
 * Execution is idempotent: the WorkflowService.markExecuted method ensures the
 * workflow is only transitioned to EXECUTED once, even if this endpoint is
 * called multiple times (retry-safe).
 */
@Injectable()
export class EmergencyWithdrawalWorkflowService {
  private readonly logger = new Logger(EmergencyWithdrawalWorkflowService.name);

  constructor(
    @InjectRepository(WithdrawalRequest)
    private readonly withdrawalRepository: Repository<WithdrawalRequest>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly workflowService: WorkflowService,
    private readonly savingsService: SavingsService,
    private readonly mailService: MailService,
  ) {}

  /**
   * Execute an approved EMERGENCY_WITHDRAWAL workflow.
   *
   * 1. Verifies the workflow is APPROVED and of the correct type.
   * 2. Loads and validates the target WithdrawalRequest.
   * 3. Captures before-state snapshot.
   * 4. Transitions the withdrawal to PROCESSING and triggers the processing flow.
   * 5. Marks the workflow as EXECUTED with the after-state snapshot.
   * 6. Sends email notification to the user (fire-and-forget).
   *
   * @throws BadRequestException if the withdrawal is not in a processable state.
   */
  async executeApprovedWorkflow(
    workflowId: string,
    actor: User,
    correlationId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ workflow: any; withdrawal: WithdrawalRequest }> {
    // Step 1: Load and validate the workflow
    const workflow = await this.workflowService.findOneApprovedForExecution(
      workflowId,
      WorkflowActionType.EMERGENCY_WITHDRAWAL,
    );

    const payload = workflow.payload as EmergencyWithdrawalPayload;

    if (!payload.withdrawalId) {
      throw new BadRequestException('Workflow payload is missing withdrawalId');
    }

    // Step 2: Load the withdrawal
    const withdrawal = await this.withdrawalRepository.findOne({
      where: { id: payload.withdrawalId },
      relations: ['subscription', 'subscription.product'],
    });

    if (!withdrawal) {
      throw new NotFoundException(
        `WithdrawalRequest ${payload.withdrawalId} not found`,
      );
    }

    if (withdrawal.status !== WithdrawalStatus.PENDING) {
      throw new BadRequestException(
        `WithdrawalRequest ${payload.withdrawalId} is not in PENDING status (current: ${withdrawal.status})`,
      );
    }

    // Step 3: Capture before-state
    const beforeState = {
      status: withdrawal.status,
      amount: withdrawal.amount,
      netAmount: withdrawal.netAmount,
      penalty: withdrawal.penalty,
      updatedAt: withdrawal.updatedAt,
    };

    try {
      // Step 4: Process the withdrawal
      withdrawal.status = WithdrawalStatus.PROCESSING;
      await this.withdrawalRepository.save(withdrawal);

      await this.savingsService['processWithdrawal'](withdrawal.id);

      // Reload to get fresh state
      const updated = await this.withdrawalRepository.findOne({
        where: { id: withdrawal.id },
        relations: ['subscription', 'subscription.product'],
      });

      const afterState = {
        status: updated?.status ?? WithdrawalStatus.PROCESSING,
        amount: withdrawal.amount,
        netAmount: withdrawal.netAmount,
        penalty: withdrawal.penalty,
        executedByWorkflow: workflowId,
      };

      // Step 5: Mark workflow as executed (idempotency guaranteed by service)
      await this.workflowService.markExecuted(
        workflowId,
        afterState,
        actor,
        correlationId,
        ipAddress,
        userAgent,
      );

      // Step 6: Notify user (fire-and-forget)
      void this.sendApprovalEmail(withdrawal, payload.reason);

      this.logger.log(
        `Emergency withdrawal ${withdrawal.id} executed via workflow ${workflowId} by ${actor.email}`,
      );

      const finalWorkflow = await this.workflowService.findOne(workflowId);
      return { workflow: finalWorkflow, withdrawal: updated ?? withdrawal };
    } catch (error) {
      // Record the failure against the workflow but don't mark it executed
      // so it can be retried or investigated
      await this.workflowService.recordExecutionFailure(
        workflowId,
        error as Error,
        actor,
        correlationId,
      );

      this.logger.error(
        `Emergency withdrawal execution failed for workflow ${workflowId}: ${(error as Error).message}`,
        (error as Error).stack,
      );

      throw error;
    }
  }

  /**
   * Capture the current state of a withdrawal as a pre-execution snapshot.
   * Called when creating an EMERGENCY_WITHDRAWAL workflow so the before-state
   * can be stored alongside the workflow.
   */
  async captureWithdrawalSnapshot(
    withdrawalId: string,
  ): Promise<Record<string, any> | null> {
    const withdrawal = await this.withdrawalRepository.findOne({
      where: { id: withdrawalId },
      relations: ['subscription'],
    });

    if (!withdrawal) return null;

    return {
      id: withdrawal.id,
      userId: withdrawal.userId,
      subscriptionId: withdrawal.subscriptionId,
      amount: withdrawal.amount,
      penalty: withdrawal.penalty,
      netAmount: withdrawal.netAmount,
      status: withdrawal.status,
      createdAt: withdrawal.createdAt,
      updatedAt: withdrawal.updatedAt,
    };
  }

  private async sendApprovalEmail(
    withdrawal: WithdrawalRequest,
    reason: string,
  ): Promise<void> {
    try {
      const user = await this.userRepository.findOne({
        where: { id: withdrawal.userId },
      });

      if (!user) return;

      await this.mailService.sendWithdrawalApprovedEmail(
        user.email,
        user.name || 'User',
        String(withdrawal.amount),
        String(withdrawal.penalty),
        String(withdrawal.netAmount),
      );
    } catch (err) {
      this.logger.warn(
        `Failed to send approval email for withdrawal ${withdrawal.id}: ${(err as Error).message}`,
      );
    }
  }
}
