import { Test, TestingModule } from '@nestjs/testing';
import { RewardsController } from './rewards.controller';
import { RewardsService } from './rewards.service';

describe('RewardsController', () => {
  let controller: RewardsController;
  let rewardsService: { getDashboard: jest.Mock };

  beforeEach(async () => {
    rewardsService = {
      getDashboard: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RewardsController],
      providers: [
        {
          provide: RewardsService,
          useValue: rewardsService,
        },
      ],
    }).compile();

    controller = module.get<RewardsController>(RewardsController);
  });

  it('should return the current user dashboard', async () => {
    rewardsService.getDashboard.mockResolvedValue({ totalPoints: 10300 });

    const result = await controller.getDashboard({ id: 'user-1' });

    expect(rewardsService.getDashboard).toHaveBeenCalledWith('user-1');
    expect(result).toEqual({ totalPoints: 10300 });
  });
});
