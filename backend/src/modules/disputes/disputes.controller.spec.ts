import { Test, TestingModule } from '@nestjs/testing';
import { DisputesController } from './disputes.controller';
import { DisputesService } from './disputes.service';
import { DisputeStatus } from './entities/dispute.entity';

describe('DisputesController', () => {
  let controller: DisputesController;

  const mockDisputesService = {
    createDispute: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    updateDispute: jest.fn(),
    addMessage: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [DisputesController],
      providers: [{ provide: DisputesService, useValue: mockDisputesService }],
    }).compile();

    controller = module.get<DisputesController>(DisputesController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('createDispute', () => {
    it('should create a dispute', async () => {
      const createDto = {
        claimId: 'claim-123',
        disputedBy: 'Hospital Admin',
        reason: 'Incorrect amount',
      };

      const expected = { id: 'dispute-123', ...createDto, status: DisputeStatus.OPEN };
      mockDisputesService.createDispute.mockResolvedValue(expected);

      const result = await controller.createDispute(createDto);

      expect(result).toEqual(expected);
      expect(mockDisputesService.createDispute).toHaveBeenCalledWith(createDto);
    });
  });

  describe('addMessage', () => {
    it('should add message to dispute', async () => {
      const messageDto = {
        author: 'Admin',
        message: 'Evidence attached',
        evidenceUrl: 'https://example.com/doc.pdf',
      };

      mockDisputesService.addMessage.mockResolvedValue({ id: 'msg-123', ...messageDto });

      const result = await controller.addMessage('dispute-123', messageDto);

      expect(result).toHaveProperty('id');
      expect(mockDisputesService.addMessage).toHaveBeenCalledWith('dispute-123', messageDto);
    });
  });
});
