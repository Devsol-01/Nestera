import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { AutoDepositService } from './auto-deposit.service';
import {
  AutoDepositSchedule,
  AutoDepositFrequency,
  AutoDepositStatus,
} from '../entities/auto-deposit-schedule.entity';
import { SavingsService } from '../savings.service';

const mockRepo = () => ({
  create: jest.fn((v) => v),
  save: jest.fn(),
  find: jest.fn(),
  findOne: jest.fn(),
  createQueryBuilder: jest.fn(),
});

const mockSavingsService = () => ({
  subscribe: jest.fn(),
});

describe('AutoDepositService', () => {
  let service: AutoDepositService;
  let repo: ReturnType<typeof mockRepo>;
  let savingsService: ReturnType<typeof mockSavingsService>;

  beforeEach(async () => {
    repo = mockRepo();
    savingsService = mockSavingsService();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AutoDepositService,
        { provide: getRepositoryToken(AutoDepositSchedule), useValue: repo },
        { provide: SavingsService, useValue: savingsService },
      ],
    }).compile();

    service = module.get<AutoDepositService>(AutoDepositService);
  });

  describe('create', () => {
    it('creates a schedule with correct nextRunAt', async () => {
      const dto = {
        productId: 'prod-1',
        amount: 50,
        frequency: AutoDepositFrequency.MONTHLY,
      };
      const saved = { id: 'sched-1', ...dto, status: AutoDepositStatus.ACTIVE };
      repo.save.mockResolvedValue(saved);

      const result = await service.create('user-1', dto);

      expect(repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          productId: 'prod-1',
          amount: 50,
        }),
      );
      expect(result).toEqual(saved);
    });
  });

  describe('pause', () => {
    it('pauses an active schedule', async () => {
      const schedule = {
        id: 's1',
        userId: 'u1',
        status: AutoDepositStatus.ACTIVE,
      };
      repo.findOne.mockResolvedValue(schedule);
      repo.save.mockResolvedValue({
        ...schedule,
        status: AutoDepositStatus.PAUSED,
      });

      const result = await service.pause('s1', 'u1');
      expect(result.status).toBe(AutoDepositStatus.PAUSED);
    });

    it('throws when schedule not found', async () => {
      repo.findOne.mockResolvedValue(null);
      await expect(service.pause('bad-id', 'u1')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('throws when trying to pause a cancelled schedule', async () => {
      repo.findOne.mockResolvedValue({
        id: 's1',
        userId: 'u1',
        status: AutoDepositStatus.CANCELLED,
      });
      await expect(service.pause('s1', 'u1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('cancel', () => {
    it('cancels a schedule', async () => {
      const schedule = {
        id: 's1',
        userId: 'u1',
        status: AutoDepositStatus.ACTIVE,
      };
      repo.findOne.mockResolvedValue(schedule);
      repo.save.mockResolvedValue({
        ...schedule,
        status: AutoDepositStatus.CANCELLED,
      });

      await service.cancel('s1', 'u1');
      expect(repo.save).toHaveBeenCalledWith(
        expect.objectContaining({ status: AutoDepositStatus.CANCELLED }),
      );
    });
  });

  describe('computeNextRun', () => {
    it('adds 1 day for DAILY', () => {
      const from = new Date('2026-01-01T00:00:00Z');
      const next = service.computeNextRun(AutoDepositFrequency.DAILY, from);
      expect(next.getDate()).toBe(2);
    });

    it('adds 7 days for WEEKLY', () => {
      const from = new Date('2026-01-01T00:00:00Z');
      const next = service.computeNextRun(AutoDepositFrequency.WEEKLY, from);
      expect(next.getDate()).toBe(8);
    });

    it('adds 14 days for BI_WEEKLY', () => {
      const from = new Date('2026-01-01T00:00:00Z');
      const next = service.computeNextRun(AutoDepositFrequency.BI_WEEKLY, from);
      expect(next.getDate()).toBe(15);
    });

    it('adds 1 month for MONTHLY', () => {
      const from = new Date('2026-01-15T00:00:00Z');
      const next = service.computeNextRun(AutoDepositFrequency.MONTHLY, from);
      expect(next.getMonth()).toBe(1); // February
    });
  });
});
