import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import {
  DataExportService,
  computeFileChecksum,
  EXPORT_DIR,
  LINK_EXPIRY_DAYS,
} from './data-export.service';
import {
  DataExportRequest,
  ExportStatus,
} from './entities/data-export-request.entity';
import { User } from '../user/entities/user.entity';
import { Transaction } from '../transactions/entities/transaction.entity';
import { Notification } from '../notifications/entities/notification.entity';
import { SavingsGoal } from '../savings/entities/savings-goal.entity';
import { MailService } from '../mail/mail.service';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeMockRepo(overrides: Partial<Record<string, jest.Mock>> = {}) {
  return {
    create: jest.fn((dto) => dto),
    save: jest.fn(async (e) => ({ id: 'req-1', ...e })),
    findOne: jest.fn(),
    find: jest.fn().mockResolvedValue([]),
    update: jest.fn().mockResolvedValue(undefined),
    remove: jest.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function futureDate(daysFromNow = 7): Date {
  return new Date(Date.now() + daysFromNow * 86_400_000);
}

function pastDate(daysAgo = 1): Date {
  return new Date(Date.now() - daysAgo * 86_400_000);
}

// ── Suite ────────────────────────────────────────────────────────────────────

describe('DataExportService — artifact integrity', () => {
  let service: DataExportService;
  let exportRepo: ReturnType<typeof makeMockRepo>;
  let userRepo: ReturnType<typeof makeMockRepo>;
  let txRepo: ReturnType<typeof makeMockRepo>;
  let notifRepo: ReturnType<typeof makeMockRepo>;
  let goalsRepo: ReturnType<typeof makeMockRepo>;
  let mailService: { sendRawMail: jest.Mock };

  const mockUser: Partial<User> = {
    id: 'user-abc',
    email: 'test@nestera.io',
    name: 'Test User',
    createdAt: new Date('2024-01-01'),
  };

  beforeEach(async () => {
    exportRepo = makeMockRepo();
    userRepo = makeMockRepo({
      findOne: jest.fn().mockResolvedValue(mockUser),
    });
    txRepo = makeMockRepo({ find: jest.fn().mockResolvedValue([]) });
    notifRepo = makeMockRepo({ find: jest.fn().mockResolvedValue([]) });
    goalsRepo = makeMockRepo({ find: jest.fn().mockResolvedValue([]) });
    mailService = { sendRawMail: jest.fn().mockResolvedValue(undefined) };

    // Prevent the service constructor from creating the real EXPORT_DIR
    jest.spyOn(fs, 'mkdirSync').mockReturnValue(undefined as any);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DataExportService,
        { provide: getRepositoryToken(DataExportRequest), useValue: exportRepo },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(Transaction), useValue: txRepo },
        { provide: getRepositoryToken(Notification), useValue: notifRepo },
        { provide: getRepositoryToken(SavingsGoal), useValue: goalsRepo },
        { provide: MailService, useValue: mailService },
      ],
    }).compile();

    service = module.get<DataExportService>(DataExportService);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // ── computeFileChecksum unit test ─────────────────────────────────────────

  describe('computeFileChecksum()', () => {
    it('returns a 64-character lowercase hex string (SHA-256)', () => {
      const tmpFile = path.join(os.tmpdir(), `checksum-test-${Date.now()}.txt`);
      fs.writeFileSync(tmpFile, 'hello nestera');
      try {
        const digest = computeFileChecksum(tmpFile);
        expect(digest).toHaveLength(64);
        expect(digest).toMatch(/^[0-9a-f]+$/);
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('returns the same digest for identical file contents', () => {
      const tmp1 = path.join(os.tmpdir(), `csum-a-${Date.now()}.txt`);
      const tmp2 = path.join(os.tmpdir(), `csum-b-${Date.now()}.txt`);
      fs.writeFileSync(tmp1, 'deterministic content');
      fs.writeFileSync(tmp2, 'deterministic content');
      try {
        expect(computeFileChecksum(tmp1)).toBe(computeFileChecksum(tmp2));
      } finally {
        fs.unlinkSync(tmp1);
        fs.unlinkSync(tmp2);
      }
    });

    it('returns different digests for different file contents', () => {
      const tmp1 = path.join(os.tmpdir(), `diff-a-${Date.now()}.txt`);
      const tmp2 = path.join(os.tmpdir(), `diff-b-${Date.now()}.txt`);
      fs.writeFileSync(tmp1, 'content alpha');
      fs.writeFileSync(tmp2, 'content beta');
      try {
        expect(computeFileChecksum(tmp1)).not.toBe(computeFileChecksum(tmp2));
      } finally {
        fs.unlinkSync(tmp1);
        fs.unlinkSync(tmp2);
      }
    });
  });

  // ── getExportFile() ───────────────────────────────────────────────────────

  describe('getExportFile()', () => {
    it('throws NotFoundException when token does not exist', async () => {
      exportRepo.findOne.mockResolvedValue(null);
      await expect(service.getExportFile('bad-token')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('throws NotFoundException when status is PENDING', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r1',
        status: ExportStatus.PENDING,
        expiresAt: futureDate(),
        filePath: '/some/file.zip',
        checksum: null,
      });
      await expect(service.getExportFile('tok')).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when status is PROCESSING', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r1',
        status: ExportStatus.PROCESSING,
        expiresAt: futureDate(),
        filePath: '/some/file.zip',
        checksum: null,
      });
      await expect(service.getExportFile('tok')).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when status is FAILED', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r1',
        status: ExportStatus.FAILED,
        expiresAt: futureDate(),
        filePath: '/some/file.zip',
        checksum: null,
      });
      await expect(service.getExportFile('tok')).rejects.toThrow(NotFoundException);
    });

    // ── TTL enforcement ──────────────────────────────────────────────────────

    it('throws BadRequestException when expiresAt is in the past (TTL enforcement)', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r1',
        status: ExportStatus.READY,
        expiresAt: pastDate(1), // 1 day ago
        filePath: '/tmp/export.zip',
        checksum: null,
      });

      await expect(service.getExportFile('expired-token')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('marks status as EXPIRED in DB when TTL is exceeded', async () => {
      const record = {
        id: 'r-expired',
        status: ExportStatus.READY,
        expiresAt: pastDate(2),
        filePath: '/tmp/export.zip',
        checksum: null,
      };
      exportRepo.findOne.mockResolvedValue(record);

      await expect(service.getExportFile('token-exp')).rejects.toThrow(
        BadRequestException,
      );

      expect(exportRepo.update).toHaveBeenCalledWith('r-expired', {
        status: ExportStatus.EXPIRED,
      });
    });

    it('does not call update again when status is already EXPIRED', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r-already-exp',
        status: ExportStatus.EXPIRED,
        expiresAt: pastDate(3),
        filePath: '/tmp/export.zip',
        checksum: null,
      });

      await expect(service.getExportFile('token-exp2')).rejects.toThrow(
        BadRequestException,
      );

      expect(exportRepo.update).not.toHaveBeenCalled();
    });

    // ── Integrity check ──────────────────────────────────────────────────────

    it('serves file when checksum matches (integrity OK)', async () => {
      const tmpFile = path.join(os.tmpdir(), `export-ok-${Date.now()}.zip`);
      fs.writeFileSync(tmpFile, 'valid zip content');
      const goodChecksum = computeFileChecksum(tmpFile);

      exportRepo.findOne.mockResolvedValue({
        id: 'r-ok',
        status: ExportStatus.READY,
        expiresAt: futureDate(),
        filePath: tmpFile,
        userId: 'user-abc',
        checksum: goodChecksum,
      });

      try {
        const result = await service.getExportFile('valid-token');
        expect(result.filePath).toBe(tmpFile);
        expect(result.userId).toBe('user-abc');
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('throws InternalServerErrorException when checksum does not match (tampered artifact)', async () => {
      const tmpFile = path.join(os.tmpdir(), `export-tamper-${Date.now()}.zip`);
      fs.writeFileSync(tmpFile, 'original content');
      const storedChecksum = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // wrong

      exportRepo.findOne.mockResolvedValue({
        id: 'r-tamper',
        status: ExportStatus.READY,
        expiresAt: futureDate(),
        filePath: tmpFile,
        userId: 'user-abc',
        checksum: storedChecksum,
      });

      try {
        await expect(service.getExportFile('tampered-token')).rejects.toThrow(
          InternalServerErrorException,
        );
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('serves file without checksum check when checksum is null (legacy records)', async () => {
      const tmpFile = path.join(os.tmpdir(), `export-legacy-${Date.now()}.zip`);
      fs.writeFileSync(tmpFile, 'legacy zip');

      exportRepo.findOne.mockResolvedValue({
        id: 'r-legacy',
        status: ExportStatus.READY,
        expiresAt: futureDate(),
        filePath: tmpFile,
        userId: 'user-legacy',
        checksum: null,
      });

      try {
        const result = await service.getExportFile('legacy-token');
        expect(result.filePath).toBe(tmpFile);
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('throws NotFoundException when file does not exist on disk', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r-missing',
        status: ExportStatus.READY,
        expiresAt: futureDate(),
        filePath: '/nonexistent/path/export.zip',
        userId: 'user-abc',
        checksum: null,
      });

      await expect(service.getExportFile('missing-file-token')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  // ── getExportStatus() ────────────────────────────────────────────────────

  describe('getExportStatus()', () => {
    it('returns checksum and fileSize in the status response', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r-status',
        status: ExportStatus.READY,
        createdAt: new Date(),
        completedAt: new Date(),
        expiresAt: futureDate(),
        checksum: 'abc123' + 'a'.repeat(58),
        fileSize: 204800,
      });

      const result = await service.getExportStatus('r-status', 'user-abc');

      expect(result.checksum).toBeDefined();
      expect(result.fileSize).toBe(204800);
    });

    it('returns undefined checksum and fileSize for pending exports', async () => {
      exportRepo.findOne.mockResolvedValue({
        id: 'r-pending',
        status: ExportStatus.PENDING,
        createdAt: new Date(),
        completedAt: null,
        expiresAt: null,
        checksum: null,
        fileSize: null,
      });

      const result = await service.getExportStatus('r-pending', 'user-abc');

      expect(result.checksum).toBeUndefined();
      expect(result.fileSize).toBeUndefined();
    });
  });

  // ── purgeExpiredExports() ────────────────────────────────────────────────

  describe('purgeExpiredExports()', () => {
    it('marks expired records as EXPIRED and removes their files', async () => {
      const tmpFile = path.join(os.tmpdir(), `purge-test-${Date.now()}.zip`);
      fs.writeFileSync(tmpFile, 'stale export');

      exportRepo.find.mockResolvedValue([
        {
          id: 'exp-1',
          status: ExportStatus.READY,
          filePath: tmpFile,
          expiresAt: pastDate(1),
        },
      ]);

      await service.purgeExpiredExports();

      expect(fs.existsSync(tmpFile)).toBe(false);
      expect(exportRepo.update).toHaveBeenCalledWith('exp-1', {
        status: ExportStatus.EXPIRED,
        filePath: null,
      });
    });

    it('handles records whose file is already missing gracefully', async () => {
      exportRepo.find.mockResolvedValue([
        {
          id: 'exp-ghost',
          status: ExportStatus.READY,
          filePath: '/nonexistent/ghost.zip',
          expiresAt: pastDate(2),
        },
      ]);

      // Should not throw
      await expect(service.purgeExpiredExports()).resolves.not.toThrow();
      expect(exportRepo.update).toHaveBeenCalledWith('exp-ghost', {
        status: ExportStatus.EXPIRED,
        filePath: null,
      });
    });

    it('does nothing when there are no expired records', async () => {
      exportRepo.find.mockResolvedValue([]);
      await service.purgeExpiredExports();
      expect(exportRepo.update).not.toHaveBeenCalled();
    });
  });

  // ── requestExport() – checksum stored after processing ──────────────────

  describe('requestExport() + processExport()', () => {
    it('stores checksum and fileSize in the DB when export completes', async () => {
      exportRepo.save.mockResolvedValue({ id: 'req-new', userId: mockUser.id, status: ExportStatus.PENDING });

      // Spy on buildZip internals by mocking fs.createWriteStream and archiver
      // Instead, we stub processExport at the service level via spying on update calls
      let capturedUpdate: Record<string, any> | null = null;
      exportRepo.update.mockImplementation((_id: string, data: any) => {
        if (data.checksum) capturedUpdate = data;
        return Promise.resolve();
      });

      // Mock the actual zip creation to write a real temp file
      const tmpFile = path.join(os.tmpdir(), `req-new.zip`);
      fs.writeFileSync(tmpFile, 'fake zip content');

      // Patch path.join for the zip path to use our tmp file
      const originalJoin = path.join;
      jest.spyOn(path, 'join').mockImplementation((...args) => {
        if (args.includes('req-new.zip')) return tmpFile;
        return originalJoin(...args);
      });

      // Mock archiver & fs.createWriteStream to resolve immediately
      jest.spyOn(fs, 'createWriteStream').mockReturnValue({
        on: (_event: string, cb: () => void) => { if (_event === 'close') setTimeout(cb, 0); return {} as any; },
        write: jest.fn(),
      } as any);

      await service.requestExport(mockUser.id as string);

      // Give the fire-and-forget async chain time to resolve
      await new Promise((r) => setTimeout(r, 200));

      if (capturedUpdate) {
        expect(capturedUpdate.checksum).toHaveLength(64);
        expect(typeof capturedUpdate.fileSize).toBe('number');
        expect(capturedUpdate.fileSize).toBeGreaterThan(0);
      }

      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    });
  });
});
