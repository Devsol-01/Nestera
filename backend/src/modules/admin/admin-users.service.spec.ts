import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { NotFoundException } from '@nestjs/common';
import { AdminUsersService } from './admin-users.service';
import { AdminUsersQueryDto } from './dto/admin-users-query.dto';
import { User } from '../user/entities/user.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';
import { MailService } from '../mail/mail.service';

const mockUser = (overrides: Partial<User> = {}): User =>
  ({
    id: 'user-1',
    email: 'test@nestera.io',
    name: 'Test User',
    role: 'USER',
    kycStatus: 'APPROVED',
    isActive: true,
    tier: 'FREE',
    twoFactorEnabled: false,
    lastLoginAt: null,
    createdAt: new Date('2025-01-01'),
    ...overrides,
  }) as User;

const makeQb = (results: any[] = [], count = 0) => ({
  andWhere: jest.fn().mockReturnThis(),
  orderBy: jest.fn().mockReturnThis(),
  addOrderBy: jest.fn().mockReturnThis(),
  skip: jest.fn().mockReturnThis(),
  take: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  where: jest.fn().mockReturnThis(),
  update: jest.fn().mockReturnThis(),
  set: jest.fn().mockReturnThis(),
  whereInIds: jest.fn().mockReturnThis(),
  execute: jest.fn().mockResolvedValue({}),
  getMany: jest.fn().mockResolvedValue(results),
  getCount: jest.fn().mockResolvedValue(count),
  getManyAndCount: jest.fn().mockResolvedValue([results, count]),
  getRawOne: jest.fn().mockResolvedValue({ total: '0' }),
});

describe('AdminUsersService', () => {
  let service: AdminUsersService;
  let userRepo: any;
  let subRepo: any;
  let txRepo: any;
  let mail: any;

  beforeEach(async () => {
    const qb = makeQb([mockUser()], 1);
    userRepo = {
      createQueryBuilder: jest.fn().mockReturnValue(qb),
      findOne: jest.fn().mockResolvedValue(mockUser()),
      findByIds: jest.fn().mockResolvedValue([mockUser()]),
      update: jest.fn().mockResolvedValue({}),
    };
    subRepo = {
      createQueryBuilder: jest.fn().mockReturnValue(makeQb()),
      count: jest.fn().mockResolvedValue(2),
    };
    txRepo = { count: jest.fn().mockResolvedValue(5) };
    mail = { sendRawMail: jest.fn().mockResolvedValue(undefined) };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminUsersService,
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(UserSubscription), useValue: subRepo },
        { provide: getRepositoryToken(LedgerTransaction), useValue: txRepo },
        { provide: MailService, useValue: mail },
      ],
    }).compile();

    service = module.get(AdminUsersService);
  });

  describe('listUsers', () => {
    it('returns paginated data with meta', async () => {
      const query = Object.assign(new AdminUsersQueryDto(), {
        page: 1,
        limit: 20,
        includeTotal: 'true',
      });
      const result = await service.listUsers(query);
      expect(result.meta.page).toBe(1);
      expect(result.meta.limit).toBe(20);
      expect(result.meta.totalItemCount).toBe(1);
      expect(result.data).toHaveLength(1);
      expect(result.data[0].email).toBe('test@nestera.io');
    });

    it('includes totalSavings and transactionCount', async () => {
      subRepo.createQueryBuilder.mockReturnValue({
        ...makeQb(),
        getRawOne: jest.fn().mockResolvedValue({ total: '500.00' }),
      });
      txRepo.count.mockResolvedValue(10);
      const result = await service.listUsers({
        page: 1,
        limit: 20,
        skip: 0,
      } as any);
      expect(result.items[0].transactionCount).toBe(10);
    });
  });

  describe('getUserDetails', () => {
    it('returns full detail for existing user', async () => {
      const detail = await service.getUserDetails('user-1');
      expect(detail.id).toBe('user-1');
      expect(detail).toHaveProperty('activeSubscriptions');
      expect(detail).toHaveProperty('totalInterestEarned');
    });

    it('throws NotFoundException for unknown user', async () => {
      userRepo.findOne.mockResolvedValue(null);
      await expect(service.getUserDetails('bad-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('updateRole', () => {
    it('updates and returns new role', async () => {
      const result = await service.updateRole('user-1', 'ADMIN');
      expect(userRepo.update).toHaveBeenCalledWith('user-1', { role: 'ADMIN' });
      expect(result.role).toBe('ADMIN');
    });

    it('throws NotFoundException for unknown user', async () => {
      userRepo.findOne.mockResolvedValue(null);
      await expect(service.updateRole('bad-id', 'ADMIN')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('updateStatus', () => {
    it('deactivates a user', async () => {
      const result = await service.updateStatus('user-1', false);
      expect(userRepo.update).toHaveBeenCalledWith('user-1', {
        isActive: false,
      });
      expect(result.isActive).toBe(false);
    });
  });

  describe('bulkAction', () => {
    it('activates multiple users', async () => {
      const qb = makeQb();
      userRepo.createQueryBuilder.mockReturnValue(qb);
      const result = await service.bulkAction({
        action: 'activate',
        userIds: ['u1', 'u2'],
      });
      expect(result.affected).toBe(2);
      expect(qb.set).toHaveBeenCalledWith({ isActive: true });
    });

    it('sends emails for email action', async () => {
      const result = await service.bulkAction({
        action: 'email',
        userIds: ['user-1'],
        emailSubject: 'Hello',
        emailBody: 'World',
      });
      expect(mail.sendRawMail).toHaveBeenCalledWith(
        'test@nestera.io',
        'Hello',
        'World',
      );
      expect(result.affected).toBe(1);
    });

    it('returns count for export action', async () => {
      const result = await service.bulkAction({
        action: 'export',
        userIds: ['u1', 'u2', 'u3'],
      });
      expect(result.affected).toBe(3);
      expect(result.action).toBe('export');
    });
  });
});
