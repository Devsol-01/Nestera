import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { WorkflowService } from './workflow.service';
import { WorkflowAuditService } from './workflow-audit.service';
import {
  AdminWorkflow,
  WorkflowStatus,
  WorkflowActionType,
} from './entities/admin-workflow.entity';
import {
  CreateWorkflowDto,
  ApproveWorkflowDto,
  RejectWorkflowDto,
  CancelWorkflowDto,
} from './dto/workflow.dto';
import { User } from '../user/entities/user.entity';
import { Role } from '../../common/enums/role.enum';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeUser = (overrides: Partial<User> = {}): User =>
  ({
    id: 'user-001',
    email: 'admin@nestera.io',
    role: Role.ADMIN,
    name: 'Admin User',
    ...overrides,
  }) as User;

const makeSuperAdmin = (overrides: Partial<User> = {}): User =>
  makeUser({
    id: 'super-001',
    email: 'superadmin@nestera.io',
    role: Role.SUPER_ADMIN as unknown as 'USER' | 'ADMIN',
    ...overrides,
  });

const makeWorkflow = (
  overrides: Partial<AdminWorkflow> = {},
): AdminWorkflow => ({
  id: 'wf-001',
  actionType: WorkflowActionType.EMERGENCY_WITHDRAWAL,
  status: WorkflowStatus.PENDING_APPROVAL,
  description: 'Test emergency withdrawal',
  requiredApproverRole: Role.SUPER_ADMIN,
  initiatorId: 'user-001',
  initiatorEmail: 'admin@nestera.io',
  payload: { withdrawalId: 'wr-001', reason: 'test' },
  previousState: null,
  executedState: null,
  idempotencyKey: null,
  approvedById: null,
  approvedByEmail: null,
  approvedAt: null,
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
  expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
  executionError: null,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WorkflowService', () => {
  let service: WorkflowService;
  let workflowRepository: jest.Mocked<Repository<AdminWorkflow>>;
  let auditService: jest.Mocked<WorkflowAuditService>;

  const mockQueryBuilder: any = {
    where: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    orderBy: jest.fn().mockReturnThis(),
    skip: jest.fn().mockReturnThis(),
    take: jest.fn().mockReturnThis(),
    getManyAndCount: jest.fn().mockResolvedValue([[], 0]),
    getMany: jest.fn().mockResolvedValue([]),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WorkflowService,
        {
          provide: getRepositoryToken(AdminWorkflow),
          useValue: {
            create: jest.fn(),
            save: jest.fn(),
            findOne: jest.fn(),
            find: jest.fn(),
            update: jest.fn(),
            createQueryBuilder: jest.fn().mockReturnValue(mockQueryBuilder),
          },
        },
        {
          provide: WorkflowAuditService,
          useValue: {
            recordTransition: jest.fn().mockResolvedValue(undefined),
            recordExecutionFailure: jest.fn().mockResolvedValue(undefined),
          },
        },
      ],
    }).compile();

    service = module.get<WorkflowService>(WorkflowService);
    workflowRepository = module.get(getRepositoryToken(AdminWorkflow));
    auditService = module.get(WorkflowAuditService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // create
  // -------------------------------------------------------------------------

  describe('create', () => {
    it('creates a new PENDING_APPROVAL workflow', async () => {
      const dto: CreateWorkflowDto = {
        actionType: WorkflowActionType.EMERGENCY_WITHDRAWAL,
        description: 'Emergency',
        payload: { withdrawalId: 'wr-001' },
        requiredApproverRole: Role.SUPER_ADMIN,
      };
      const actor = makeUser();
      const created = makeWorkflow();

      workflowRepository.findOne.mockResolvedValue(null); // no idempotency match
      workflowRepository.create.mockReturnValue(created);
      workflowRepository.save.mockResolvedValue(created);

      const result = await service.create(dto, actor, 'corr-1');

      expect(result.status).toBe(WorkflowStatus.PENDING_APPROVAL);
      expect(workflowRepository.save).toHaveBeenCalledTimes(1);
      expect(auditService.recordTransition).toHaveBeenCalledWith(
        created,
        expect.objectContaining({ toStatus: WorkflowStatus.PENDING_APPROVAL }),
      );
    });

    it('returns existing workflow on idempotent create', async () => {
      const dto: CreateWorkflowDto = {
        actionType: WorkflowActionType.EMERGENCY_WITHDRAWAL,
        description: 'Emergency',
        payload: {},
        idempotencyKey: 'idem-key-1',
      };
      const actor = makeUser();
      const existing = makeWorkflow({ idempotencyKey: 'idem-key-1' });

      workflowRepository.findOne.mockResolvedValue(existing);

      const result = await service.create(dto, actor, 'corr-2');

      expect(result).toBe(existing);
      expect(workflowRepository.save).not.toHaveBeenCalled();
      expect(auditService.recordTransition).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // findOne
  // -------------------------------------------------------------------------

  describe('findOne', () => {
    it('returns workflow if found', async () => {
      const wf = makeWorkflow();
      workflowRepository.findOne.mockResolvedValue(wf);
      await expect(service.findOne('wf-001')).resolves.toBe(wf);
    });

    it('throws NotFoundException if not found', async () => {
      workflowRepository.findOne.mockResolvedValue(null);
      await expect(service.findOne('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  // -------------------------------------------------------------------------
  // approve
  // -------------------------------------------------------------------------

  describe('approve', () => {
    it('approves a PENDING_APPROVAL workflow with sufficient role', async () => {
      const wf = makeWorkflow();
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);
      workflowRepository.save.mockResolvedValue({
        ...wf,
        status: WorkflowStatus.APPROVED,
        approvedByEmail: sa.email,
        approvedAt: new Date(),
      });

      const dto: ApproveWorkflowDto = {};
      const result = await service.approve('wf-001', dto, sa, 'corr-3');

      expect(result.status).toBe(WorkflowStatus.APPROVED);
      expect(result.approvedByEmail).toBe(sa.email);
      expect(auditService.recordTransition).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ toStatus: WorkflowStatus.APPROVED }),
      );
    });

    it('throws ForbiddenException if actor role is insufficient', async () => {
      const wf = makeWorkflow({ requiredApproverRole: Role.SUPER_ADMIN });
      const regularAdmin = makeUser(); // only ADMIN
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.approve('wf-001', {}, regularAdmin, 'corr-4'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('throws ForbiddenException on self-approval attempt', async () => {
      const actor = makeSuperAdmin({ id: 'user-001' });
      const wf = makeWorkflow({ initiatorId: 'user-001' }); // same id
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.approve('wf-001', {}, actor, 'corr-5'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('throws BadRequestException if workflow is not PENDING_APPROVAL', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(service.approve('wf-001', {}, sa, 'corr-6')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws BadRequestException if workflow has expired', async () => {
      const wf = makeWorkflow({
        expiresAt: new Date(Date.now() - 1000), // already expired
        status: WorkflowStatus.PENDING_APPROVAL,
      });
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(service.approve('wf-001', {}, sa, 'corr-7')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // -------------------------------------------------------------------------
  // reject
  // -------------------------------------------------------------------------

  describe('reject', () => {
    it('rejects a PENDING_APPROVAL workflow', async () => {
      const wf = makeWorkflow();
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);
      workflowRepository.save.mockResolvedValue({
        ...wf,
        status: WorkflowStatus.REJECTED,
        rejectedByEmail: sa.email,
        rejectionReason: 'Insufficient justification',
      });

      const dto: RejectWorkflowDto = { reason: 'Insufficient justification' };
      const result = await service.reject('wf-001', dto, sa, 'corr-8');

      expect(result.status).toBe(WorkflowStatus.REJECTED);
      expect(result.rejectionReason).toBe('Insufficient justification');
      expect(auditService.recordTransition).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          toStatus: WorkflowStatus.REJECTED,
          reason: 'Insufficient justification',
        }),
      );
    });

    it('throws ForbiddenException if actor role is insufficient to reject', async () => {
      const wf = makeWorkflow({ requiredApproverRole: Role.SUPER_ADMIN });
      const regularAdmin = makeUser();
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.reject('wf-001', { reason: 'nope' }, regularAdmin, 'corr-9'),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  // -------------------------------------------------------------------------
  // cancel
  // -------------------------------------------------------------------------

  describe('cancel', () => {
    it('allows initiator to cancel their own PENDING_APPROVAL workflow', async () => {
      const actor = makeUser({ id: 'user-001' });
      const wf = makeWorkflow({ initiatorId: 'user-001' });
      workflowRepository.findOne.mockResolvedValue(wf);
      workflowRepository.save.mockResolvedValue({
        ...wf,
        status: WorkflowStatus.CANCELED,
        canceledByEmail: actor.email,
        cancellationReason: 'No longer needed',
      });

      const dto: CancelWorkflowDto = { reason: 'No longer needed' };
      const result = await service.cancel('wf-001', dto, actor, 'corr-10');

      expect(result.status).toBe(WorkflowStatus.CANCELED);
    });

    it('allows SUPER_ADMIN to cancel an APPROVED workflow', async () => {
      const sa = makeSuperAdmin();
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });
      workflowRepository.findOne.mockResolvedValue(wf);
      workflowRepository.save.mockResolvedValue({
        ...wf,
        status: WorkflowStatus.CANCELED,
        canceledByEmail: sa.email,
      });

      const result = await service.cancel(
        'wf-001',
        { reason: 'Overriding' },
        sa,
        'corr-11',
      );

      expect(result.status).toBe(WorkflowStatus.CANCELED);
    });

    it('throws ForbiddenException if non-initiator ADMIN tries to cancel', async () => {
      const actor = makeUser({ id: 'user-999' }); // different from initiator
      const wf = makeWorkflow({ initiatorId: 'user-001' });
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.cancel('wf-001', { reason: 'test' }, actor, 'corr-12'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('throws BadRequestException when trying to cancel EXECUTED workflow', async () => {
      const sa = makeSuperAdmin();
      const wf = makeWorkflow({ status: WorkflowStatus.EXECUTED });
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.cancel('wf-001', { reason: 'test' }, sa, 'corr-13'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // -------------------------------------------------------------------------
  // markExecuted (idempotency)
  // -------------------------------------------------------------------------

  describe('markExecuted', () => {
    it('marks an APPROVED workflow as EXECUTED', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);
      workflowRepository.save.mockResolvedValue({
        ...wf,
        status: WorkflowStatus.EXECUTED,
        executedAt: new Date(),
        executedState: { status: 'PROCESSING' },
      });

      const result = await service.markExecuted(
        'wf-001',
        { status: 'PROCESSING' },
        sa,
        'corr-14',
      );

      expect(result.status).toBe(WorkflowStatus.EXECUTED);
      expect(auditService.recordTransition).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ toStatus: WorkflowStatus.EXECUTED }),
      );
    });

    it('is idempotent: returns EXECUTED workflow without re-saving', async () => {
      // First call: already EXECUTED
      const wf = makeWorkflow({ status: WorkflowStatus.EXECUTED });
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);

      const result = await service.markExecuted(
        'wf-001',
        { status: 'PROCESSING' },
        sa,
        'corr-15',
      );

      expect(result).toBe(wf);
      // Must NOT save again or emit another audit event
      expect(workflowRepository.save).not.toHaveBeenCalled();
      expect(auditService.recordTransition).not.toHaveBeenCalled();
    });

    it('throws BadRequestException if workflow is not APPROVED', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.PENDING_APPROVAL });
      const sa = makeSuperAdmin();
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.markExecuted('wf-001', {}, sa, 'corr-16'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // -------------------------------------------------------------------------
  // Timeout (expiry cron)
  // -------------------------------------------------------------------------

  describe('expireTimedOutWorkflows', () => {
    it('transitions expired PENDING_APPROVAL workflows to TIMED_OUT', async () => {
      const expired1 = makeWorkflow({
        id: 'wf-exp-1',
        expiresAt: new Date(Date.now() - 1000),
      });
      const expired2 = makeWorkflow({
        id: 'wf-exp-2',
        expiresAt: new Date(Date.now() - 5000),
      });

      // Override the query builder for this test
      const qb = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([expired1, expired2]),
      };
      workflowRepository.createQueryBuilder.mockReturnValue(qb as any);
      workflowRepository.save.mockImplementation(
        async (wf) => wf as AdminWorkflow,
      );

      await service.expireTimedOutWorkflows();

      expect(workflowRepository.save).toHaveBeenCalledTimes(2);
      expect(auditService.recordTransition).toHaveBeenCalledTimes(2);
      expect(auditService.recordTransition).toHaveBeenCalledWith(
        expect.objectContaining({ status: WorkflowStatus.TIMED_OUT }),
        expect.objectContaining({ toStatus: WorkflowStatus.TIMED_OUT }),
      );
    });

    it('does nothing if no expired workflows exist', async () => {
      const qb = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([]),
      };
      workflowRepository.createQueryBuilder.mockReturnValue(qb as any);

      await service.expireTimedOutWorkflows();

      expect(workflowRepository.save).not.toHaveBeenCalled();
      expect(auditService.recordTransition).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // findOneApprovedForExecution
  // -------------------------------------------------------------------------

  describe('findOneApprovedForExecution', () => {
    it('returns workflow when APPROVED and correct type', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.APPROVED });
      workflowRepository.findOne.mockResolvedValue(wf);

      const result = await service.findOneApprovedForExecution(
        'wf-001',
        WorkflowActionType.EMERGENCY_WITHDRAWAL,
      );
      expect(result).toBe(wf);
    });

    it('throws BadRequestException if wrong action type', async () => {
      const wf = makeWorkflow({
        status: WorkflowStatus.APPROVED,
        actionType: WorkflowActionType.LARGE_REFUND,
      });
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.findOneApprovedForExecution(
          'wf-001',
          WorkflowActionType.EMERGENCY_WITHDRAWAL,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('throws BadRequestException if workflow is not APPROVED', async () => {
      const wf = makeWorkflow({ status: WorkflowStatus.PENDING_APPROVAL });
      workflowRepository.findOne.mockResolvedValue(wf);

      await expect(
        service.findOneApprovedForExecution(
          'wf-001',
          WorkflowActionType.EMERGENCY_WITHDRAWAL,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
