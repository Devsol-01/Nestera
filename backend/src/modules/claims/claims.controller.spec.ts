import { Test, TestingModule } from '@nestjs/testing';
import { ClaimsController } from './claims.controller';
import { ClaimsService } from './claims.service';
import { ClaimStatus } from './entities/medical-claim.entity';

describe('ClaimsController', () => {
  let controller: ClaimsController;
  let service: ClaimsService;

  const mockClaimsService = {
    createClaim: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ClaimsController],
      providers: [
        {
          provide: ClaimsService,
          useValue: mockClaimsService,
        },
      ],
    }).compile();

    controller = module.get<ClaimsController>(ClaimsController);
    service = module.get<ClaimsService>(ClaimsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('submitClaim', () => {
    it('should submit a claim successfully', async () => {
      const createClaimDto = {
        patientName: 'John Doe',
        patientId: 'PAT-123',
        patientDateOfBirth: '1990-01-15',
        hospitalName: 'City Hospital',
        hospitalId: 'HOSP-ABC123',
        diagnosisCodes: ['A09'],
        claimAmount: 1000,
      };

      const expectedResult = {
        id: '123',
        ...createClaimDto,
        patientDateOfBirth: new Date(createClaimDto.patientDateOfBirth),
        status: ClaimStatus.PENDING,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockClaimsService.createClaim.mockResolvedValue(expectedResult);

      const result = await controller.submitClaim(createClaimDto);

      expect(result).toEqual(expectedResult);
      expect(service.createClaim).toHaveBeenCalledWith(createClaimDto);
    });
  });
});
