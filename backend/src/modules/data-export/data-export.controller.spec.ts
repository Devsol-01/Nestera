import { Test, TestingModule } from '@nestjs/testing';
import { DataExportController } from './data-export.controller';
import { DataExportService } from './data-export.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AsyncResponseDto } from '../../common/dto';

describe('DataExportController', () => {
  let controller: DataExportController;
  let service: DataExportService;

  const mockDataExportService = {
    requestExport: jest.fn(),
    getExportStatus: jest.fn(),
    getExportFile: jest.fn(),
    cancelExport: jest.fn(),
    exportTransactions: jest.fn(),
    exportGoals: jest.fn(),
    exportPortfolio: jest.fn(),
    exportAnalytics: jest.fn(),
    getExportHistory: jest.fn(),
  };

  const mockUser = { id: 'user-123' };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [DataExportController],
      providers: [
        {
          provide: DataExportService,
          useValue: mockDataExportService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<DataExportController>(DataExportController);
    service = module.get<DataExportService>(DataExportService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('requestExport', () => {
    it('should return async response with standard schema', async () => {
      const mockResult = {
        requestId: 'req-123',
        message: 'Export request received and queued',
      };

      mockDataExportService.requestExport.mockResolvedValue(mockResult);

      const result = await controller.requestExport(mockUser, {} as any);

      // Verify the response matches AsyncResponseDto structure
      expect(result).toHaveProperty('statusCode');
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('operationId');
      expect(result).toHaveProperty('retryAfterSeconds');
      expect(result).toHaveProperty('statusEndpoint');
      expect(result).toHaveProperty('operationType');
      expect(result).toHaveProperty('status');

      // Verify specific values
      expect(result.statusCode).toBe(202);
      expect(result.operationId).toBe('req-123');
      expect(result.retryAfterSeconds).toBe(10);
      expect(result.statusEndpoint).toBe('/users/data/export/req-123/status');
      expect(result.operationType).toBe('data-export');
      expect(result.status).toBe('pending');
      expect(result.message).toContain('queued');
    });

    it('should call service with correct user ID', async () => {
      mockDataExportService.requestExport.mockResolvedValue({
        requestId: 'req-123',
        message: 'Export queued',
      });

      await controller.requestExport(mockUser, {} as any);

      expect(service.requestExport).toHaveBeenCalledWith('user-123');
    });

    it('should construct status endpoint correctly with requestId', async () => {
      mockDataExportService.requestExport.mockResolvedValue({
        requestId: '550e8400-e29b-41d4-a716-446655440000',
        message: 'Export queued',
      });

      const result = await controller.requestExport(mockUser, {} as any);

      expect(result.statusEndpoint).toBe(
        '/users/data/export/550e8400-e29b-41d4-a716-446655440000/status',
      );
    });
  });

  describe('getStatus', () => {
    it('should return export status from service', async () => {
      const mockStatus = {
        requestId: 'req-123',
        status: 'processing',
        createdAt: new Date(),
        completedAt: null,
        expiresAt: null,
        errorMessage: null,
        downloadUrl: null,
      };

      mockDataExportService.getExportStatus.mockResolvedValue(mockStatus);

      const result = await controller.getStatus(mockUser, 'req-123');

      expect(result).toEqual(mockStatus);
      expect(service.getExportStatus).toHaveBeenCalledWith('req-123', 'user-123');
    });
  });

  describe('cancelExport', () => {
    it('should cancel export and return result', async () => {
      const mockResult = {
        requestId: 'req-123',
        status: 'cancelled',
        message: 'Export request cancelled',
      };

      mockDataExportService.cancelExport.mockResolvedValue(mockResult);

      const result = await controller.cancelExport(mockUser, 'req-123');

      expect(result).toEqual(mockResult);
      expect(service.cancelExport).toHaveBeenCalledWith('req-123', 'user-123');
    });
  });
});
