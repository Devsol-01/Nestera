import { Test, TestingModule } from '@nestjs/testing';
import { TestThrottlingController } from './test-throttling.controller';

describe('TestThrottlingController', () => {
  let controller: TestThrottlingController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestThrottlingController],
    }).compile();

    controller = module.get<TestThrottlingController>(TestThrottlingController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getRateLimitedEndpoint', () => {
    it('should return rate limited message', () => {
      const result = controller.getRateLimitedEndpoint();
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('timestamp');
      expect(result.message).toContain('rate limited');
    });
  });

  describe('getUnlimitedEndpoint', () => {
    it('should return unlimited message', () => {
      const result = controller.getUnlimitedEndpoint();
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('timestamp');
      expect(result.message).toContain('skips rate limiting');
    });
  });

  describe('handleWebhook', () => {
    it('should return webhook message', () => {
      const result = controller.handleWebhook();
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('timestamp');
      expect(result.message).toContain('no rate limiting');
    });
  });

  describe('getBurstEndpoint', () => {
    it('should return burst message', () => {
      const result = controller.getBurstEndpoint();
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('timestamp');
      expect(result.message).toContain('rate limited');
    });
  });
});
