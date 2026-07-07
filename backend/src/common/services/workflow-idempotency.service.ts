import { Injectable, Inject, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

export interface WorkflowStepRecord {
  completedAt: string;
  result?: unknown;
}

export interface WorkflowState {
  workflowId: string;
  steps: Record<string, WorkflowStepRecord>;
  startedAt: string;
}

const WORKFLOW_KEY_PREFIX = 'workflow-idempotency';
/** Default TTL: 7 days — long enough to cover asynchronous multi-step retry windows. */
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * WorkflowIdempotencyService
 *
 * Provides step-level idempotency for multi-step workflows.  Each workflow
 * is identified by a `workflowId`.  Individual steps within the workflow
 * are identified by a `stepName`.  On retry, callers can skip already-
 * completed steps rather than re-executing them.
 *
 * Usage pattern:
 *
 *   const wf = workflowIdempotencyService;
 *   const wfId = `deposit-${idempotencyKey}`;
 *
 *   if (!(await wf.isStepCompleted(wfId, 'validate'))) {
 *     await validateDeposit(payload);
 *     await wf.markStepCompleted(wfId, 'validate');
 *   }
 *
 *   if (!(await wf.isStepCompleted(wfId, 'reserve'))) {
 *     const reservation = await reserveFunds(payload);
 *     await wf.markStepCompleted(wfId, 'reserve', { reservationId: reservation.id });
 *   }
 *
 *   // ... further steps
 *   await wf.clearWorkflow(wfId); // optional cleanup after success
 *
 * The workflow state is stored in the shared cache (Redis in production,
 * in-memory in tests) under the key `workflow-idempotency:<workflowId>`.
 */
@Injectable()
export class WorkflowIdempotencyService {
  private readonly logger = new Logger(WorkflowIdempotencyService.name);

  constructor(@Inject(CACHE_MANAGER) private readonly cache: Cache) {}

  /**
   * Returns true if the given step has already been completed for the
   * specified workflow.  Callers should skip execution of the step when
   * this returns true.
   */
  async isStepCompleted(
    workflowId: string,
    stepName: string,
  ): Promise<boolean> {
    const state = await this.getWorkflowState(workflowId);
    return state !== null && stepName in state.steps;
  }

  /**
   * Marks a workflow step as completed, optionally persisting a small
   * result payload (e.g. an ID or status) for downstream steps to read.
   *
   * @param workflowId  Unique identifier for the workflow execution.
   * @param stepName    Name of the step being marked complete.
   * @param result      Optional serialisable result to store with the step.
   * @param ttlMs       Time-to-live for the whole workflow record in ms.
   */
  async markStepCompleted(
    workflowId: string,
    stepName: string,
    result?: unknown,
    ttlMs = DEFAULT_TTL_MS,
  ): Promise<void> {
    const state = (await this.getWorkflowState(workflowId)) ?? {
      workflowId,
      steps: {},
      startedAt: new Date().toISOString(),
    };

    state.steps[stepName] = {
      completedAt: new Date().toISOString(),
      result,
    };

    await this.cache.set(this.cacheKey(workflowId), state, ttlMs);
    this.logger.debug(
      `Workflow ${workflowId}: step "${stepName}" marked completed`,
    );
  }

  /**
   * Returns the stored result for a previously completed step, or
   * `undefined` if the step has not been completed or stored no result.
   */
  async getStepResult<T = unknown>(
    workflowId: string,
    stepName: string,
  ): Promise<T | undefined> {
    const state = await this.getWorkflowState(workflowId);
    return state?.steps[stepName]?.result as T | undefined;
  }

  /**
   * Returns the full workflow state, or null if no state is stored for
   * the given workflowId.
   */
  async getWorkflowState(workflowId: string): Promise<WorkflowState | null> {
    return (
      ((await this.cache.get(this.cacheKey(workflowId))) as WorkflowState) ??
      null
    );
  }

  /**
   * Returns the set of step names that have been completed for the given
   * workflow, or an empty array if the workflow has no stored state.
   */
  async getCompletedSteps(workflowId: string): Promise<string[]> {
    const state = await this.getWorkflowState(workflowId);
    return state ? Object.keys(state.steps) : [];
  }

  /**
   * Removes all stored state for a workflow.  Call this after a workflow
   * completes successfully to free cache space; the TTL will clean it up
   * automatically if this is not called.
   */
  async clearWorkflow(workflowId: string): Promise<void> {
    await this.cache.del(this.cacheKey(workflowId));
    this.logger.debug(`Workflow ${workflowId}: state cleared`);
  }

  private cacheKey(workflowId: string): string {
    return `${WORKFLOW_KEY_PREFIX}:${workflowId}`;
  }
}
