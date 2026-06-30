import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WorkflowAuditService } from './workflow-audit.service';
import {
  AuditLog,
  AuditAction,
  AuditResourceType,
} from '../../common/entities/audit-log.entity';
import {
  AdminWorkflow,
  WorkflowStatus,
  WorkflowActionType,
} from './entities/admin-workflow.entity';

const makeWorkflow = (
  overrides: Partial<AdminWorkflow> = {},
): AdminWorkflow => ({
  id: 'wf-001',
  actionType: WorkflowActionType.EMERGENCY_WITHDRAWAL,
  status: WorkflowStatus.APPROVED,
  description: 'Test',
  requiredApproverRole: 'SUPER_ADMIN',
  initiatorId: 'user-001',
  initiatorEmail: 'admin@test.io',
  payload: { withdrawalId: 'wr-001' },
  previousState: null,
  executedState: null,
  idempotencyKey: null,
  approvedById: 'super-001',
  approvedByEmail: 'super@test.io',
  approvedAt: new Date(),
  approverNotes: null,
  rejectedById: null,
  rejectedByEmail: null,
  rejectionReason: null,
  rejectedAt: null,
  canceledById: null,
  canceledByEmail: null,
  cancellationReason: null,
  canceledAt: null,
  executedAt: null,
  expiresAt: new Date(Date.now() + 3600000),
  executionError: null,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

describe('WorkflowAuditService', () => {
  let service: WorkflowAuditService;
  let auditLogRepository: jest.Mocked<Repository<AuditLog>>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WorkflowAuditService,
        {
          provide: getRepositoryToken(AuditLog),
          useValue: {
            create: jest.fn().mockImplementation((dto) => dto),
            save: jest.fn().mockResolvedValue({}),
          },
        },
      ],
    }).compile();

    service = module.get<WorkflowAuditService>(WorkflowAuditService);
    auditLogRepository = module.get(getRepositoryToken(AuditLog));
  });

  afterEach(() => jest.clearAllMocks());

  describe('recordTransition', () => {
    it('saves an audit log entry for APPROVED transition', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });

      await service.recordTransition(wf, {
        correlationId: 'corr-1',
        actor: 'super@test.io',
        actorId: 'super-001',
        fromStatus: WorkflowStatus.PENDING_APPROVAL,
        toStatus: WorkflowStatus.APPROVED,
      });

      expect(auditLogRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: AuditAction.APPROVE,
          resourceType: AuditResourceType.ADMIN,
          resourceId: 'wf-001',
          success: true,
        }),
      );
      expect(auditLogRepository.save).toHaveBeenCalledTimes(1);
    });

    it('saves an audit log entry for REJECTED transition with reason', async () => {
      const wf = makeWorkflow({
        status: WorkflowStatus.REJECTED,
        rejectedByEmail: 'super@test.io',
        rejectionReason: 'Not justified',
        rejectedAt: new Date(),
      });

      await service.recordTransition(wf, {
        correlationId: 'corr-2',
        actor: 'super@test.io',
        actorId: 'super-001',
        fromStatus: WorkflowStatus.PENDING_APPROVAL,
        toStatus: WorkflowStatus.REJECTED,
        reason: 'Not justified',
      });

      expect(auditLogRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: AuditAction.REJECT,
          newValue: expect.objectContaining({
            status: WorkflowStatus.REJECTED,
            rejectedByEmail: 'super@test.io',
            rejectionReason: 'Not justified',
          }),
        }),
      );
    });

    it('saves an audit log entry for TIMED_OUT transition', async () => {
      const wf = makeWorkflow({
        status: WorkflowStatus.TIMED_OUT,
        expiresAt: new Date(Date.now() - 1000),
      });

      await service.recordTransition(wf, {
        correlationId: 'timeout-cron',
        actor: 'system',
        actorId: 'system',
        fromStatus: WorkflowStatus.PENDING_APPROVAL,
        toStatus: WorkflowStatus.TIMED_OUT,
        reason: 'Approval window expired',
      });

      expect(auditLogRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: AuditAction.UPDATE,
          actor: 'system',
        }),
      );
    });

    it('records before/after diff correctly for EXECUTED transition', async () => {
      const wf = makeWorkflow({
        status: WorkflowStatus.EXECUTED,
        executedAt: new Date(),
        executedState: { status: 'PROCESSING', executedByWorkflow: 'wf-001' },
      });

      await service.recordTransition(wf, {
        correlationId: 'corr-3',
        actor: 'super@test.io',
        actorId: 'super-001',
        fromStatus: WorkflowStatus.APPROVED,
        toStatus: WorkflowStatus.EXECUTED,
      });

      const createCall = auditLogRepository.create.mock.calls[0][0] as any;
      expect(createCall.previousValue.status).toBe(WorkflowStatus.APPROVED);
      expect(createCall.newValue.status).toBe(WorkflowStatus.EXECUTED);
      expect(createCall.newValue.executedState).toEqual({
        status: 'PROCESSING',
        executedByWorkflow: 'wf-001',
      });
    });

    it('does not throw if audit log save fails (non-fatal)', async () => {
      auditLogRepository.save.mockRejectedValue(new Error('DB error'));
      const wf = makeWorkflow();

      // Should not throw – audit failure is non-fatal
      await expect(
        service.recordTransition(wf, {
          correlationId: 'corr-4',
          actor: 'super@test.io',
          actorId: 'super-001',
          fromStatus: WorkflowStatus.PENDING_APPROVAL,
          toStatus: WorkflowStatus.APPROVED,
        }),
      ).resolves.not.toThrow();
    });
  });

  describe('recordExecutionFailure', () => {
    it('saves a failure audit log entry', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });
      const error = new Error('Processing failed');

      await service.recordExecutionFailure(
        wf,
        error,
        'corr-5',
        'super@test.io',
      );

      expect(auditLogRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: AuditAction.UPDATE,
          success: false,
          errorMessage: 'Processing failed',
          statusCode: 500,
        }),
      );
    });

    it('does not throw if audit log save fails', async () => {
      auditLogRepository.save.mockRejectedValue(new Error('DB error'));
      const wf = makeWorkflow();

      await expect(
        service.recordExecutionFailure(
          wf,
          new Error('Something broke'),
          'corr-6',
          'super@test.io',
        ),
      ).resolves.not.toThrow();
    });
  });
});
