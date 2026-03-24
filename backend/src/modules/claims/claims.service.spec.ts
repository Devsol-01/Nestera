import { Test, TestingModule } from '@nestjs/testing';
import { ClaimsService } from './claims.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { MedicalClaim, ClaimStatus } from './entities/medical-claim.entity';
import { Repository } from 'typeorm';
import { HospitalIntegrationService } from '../hospital-integration/hospital-integration.service';

describe('ClaimsService', () => {
  let service: ClaimsService;
  let repository: Repository<MedicalClaim>;
  let hospitalIntegrationService: HospitalIntegrationService;

  const mockRepository = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOneBy: jest.fn(),
  };

  const mockHospitalIntegrationService = {
    fetchClaimData: jest.fn(),
    verifyClaimWithHospital: jest.fn(),
    fetchPatientHistory: jest.fn(),
    getCircuitBreakerStatus: jest.fn(),
    resetCircuitBreaker: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ClaimsService,
        {
          provide: getRepositoryToken(MedicalClaim),
          useValue: mockRepository,
        },
        {
          provide: HospitalIntegrationService,
          useValue: mockHospitalIntegrationService,
        },
      ],
    }).compile();

    service = module.get<ClaimsService>(ClaimsService);
    repository = module.get<Repository<MedicalClaim>>(getRepositoryToken(MedicalClaim));
    hospitalIntegrationService = module.get<HospitalIntegrationService>(HospitalIntegrationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createClaim', () => {
    it('should create a claim with PENDING status', async () => {
      const createClaimDto = {
        patientName: 'John Doe',
        patientId: 'PAT-123',
        patientDateOfBirth: '1990-01-15',
        hospitalName: 'City Hospital',
        hospitalId: 'HOSP-ABC123',
        diagnosisCodes: ['A09'],
        claimAmount: 1000,
      };

      const expectedClaim = {
        id: '123',
        ...createClaimDto,
        patientDateOfBirth: new Date(createClaimDto.patientDateOfBirth),
        status: ClaimStatus.PENDING,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockRepository.create.mockReturnValue(expectedClaim);
      mockRepository.save.mockResolvedValue(expectedClaim);

      const result = await service.createClaim(createClaimDto);

      expect(result.status).toBe(ClaimStatus.PENDING);
      expect(mockRepository.create).toHaveBeenCalled();
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });
});
