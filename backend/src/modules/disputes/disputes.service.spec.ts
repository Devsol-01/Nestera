import { Test, TestingModule } from '@nestjs/testing';
import { DisputesService } from './disputes.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Dispute, DisputeMessage, DisputeStatus } from './entities/dispute.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { BadRequestException } from '@nestjs/common';

describe('DisputesService', () => {
  let service: DisputesService;

  const mockDisputeRepository = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOne: jest.fn(),
  };

  const mockMessageRepository = {
    create: jest.fn(),
    save: jest.fn(),
  };

  const mockClaimRepository = {
    findOneBy: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DisputesService,
        { provide: getRepositoryToken(Dispute), useValue: mockDisputeRepository },
        { provide: getRepositoryToken(DisputeMessage), useValue: mockMessageRepository },
        { provide: getRepositoryToken(MedicalClaim), useValue: mockClaimRepository },
      ],
    }).compile();

    service = module.get<DisputesService>(DisputesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createDispute', () => {
    it('should create dispute with valid claim', async () => {
      const createDto = {
        claimId: 'claim-123',
        disputedBy: 'Hospital Admin',
        reason: 'Incorrect calculation',
      };

      mockClaimRepository.findOneBy.mockResolvedValue({ id: 'claim-123' });
      mockDisputeRepository.create.mockReturnValue({ ...createDto, status: DisputeStatus.OPEN });
      mockDisputeRepository.save.mockResolvedValue({ id: 'dispute-123', ...createDto });

      const result = await service.createDispute(createDto);

      expect(mockClaimRepository.findOneBy).toHaveBeenCalledWith({ id: 'claim-123' });
      expect(result).toHaveProperty('id');
    });

    it('should throw error for invalid claim', async () => {
      mockClaimRepository.findOneBy.mockResolvedValue(null);

      await expect(
        service.createDispute({ claimId: 'invalid', disputedBy: 'User', reason: 'Test' }),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
