import { Test, TestingModule } from '@nestjs/testing';
import { AdminAnalyticsService } from './admin-analytics.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { Dispute } from '../disputes/entities/dispute.entity';

describe('AdminAnalyticsService', () => {
  let service: AdminAnalyticsService;

  const mockClaimRepository = {
    count: jest.fn(),
    createQueryBuilder: jest.fn(() => ({
      select: jest.fn().mockReturnThis(),
      getRawOne: jest.fn(),
    })),
  };

  const mockDisputeRepository = {
    count: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminAnalyticsService,
        { provide: getRepositoryToken(MedicalClaim), useValue: mockClaimRepository },
        { provide: getRepositoryToken(Dispute), useValue: mockDisputeRepository },
      ],
    }).compile();

    service = module.get<AdminAnalyticsService>(AdminAnalyticsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getOverview', () => {
    it('should return analytics overview', async () => {
      const queryBuilder = {
        select: jest.fn().mockReturnThis(),
        getRawOne: jest.fn().mockResolvedValue({ total: '50000' }),
      };

      mockClaimRepository.count
        .mockResolvedValueOnce(100)
        .mockResolvedValueOnce(20)
        .mockResolvedValueOnce(150);
      mockDisputeRepository.count.mockResolvedValue(10);
      mockClaimRepository.createQueryBuilder.mockReturnValue(queryBuilder);

      const result = await service.getOverview();

      expect(result).toHaveProperty('totalProcessedSweeps', 100);
      expect(result).toHaveProperty('activeDisputes', 10);
      expect(result).toHaveProperty('pendingMedicalClaims', 20);
      expect(result.totalClaimAmount).toBe(50000);
    });
  });
});
