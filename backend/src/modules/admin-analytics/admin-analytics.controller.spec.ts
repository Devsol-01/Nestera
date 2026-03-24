import { Test, TestingModule } from '@nestjs/testing';
import { AdminAnalyticsController } from './admin-analytics.controller';
import { AdminAnalyticsService } from './admin-analytics.service';

describe('AdminAnalyticsController', () => {
  let controller: AdminAnalyticsController;

  const mockAnalyticsService = {
    getOverview: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminAnalyticsController],
      providers: [{ provide: AdminAnalyticsService, useValue: mockAnalyticsService }],
    }).compile();

    controller = module.get<AdminAnalyticsController>(AdminAnalyticsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getOverview', () => {
    it('should return analytics overview', async () => {
      const expected = {
        totalProcessedSweeps: 100,
        activeDisputes: 10,
        pendingMedicalClaims: 20,
        totalUsers: 150,
        totalClaimAmount: 50000,
      };

      mockAnalyticsService.getOverview.mockResolvedValue(expected);

      const result = await controller.getOverview();

      expect(result).toEqual(expected);
      expect(mockAnalyticsService.getOverview).toHaveBeenCalled();
    });
  });
});
