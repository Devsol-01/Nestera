import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { MedicalClaim, ClaimStatus } from './entities/medical-claim.entity';
import { CreateClaimDto } from './dto/create-claim.dto';
import { HospitalIntegrationService } from '../hospital-integration/hospital-integration.service';
import { ResourceNotFoundException } from '../../common/exceptions/domain.exception';
import { EventualConsistencyService } from '../../common/services/eventual-consistency.service';

@Injectable()
export class ClaimsService {
  private readonly logger = new Logger(ClaimsService.name);

  constructor(
    @InjectRepository(MedicalClaim)
    private readonly claimsRepository: Repository<MedicalClaim>,
    private readonly hospitalIntegrationService: HospitalIntegrationService,
    private readonly eventEmitter: EventEmitter2,
    private readonly eventualConsistencyService: EventualConsistencyService,
  ) {}

  async createClaim(createClaimDto: CreateClaimDto): Promise<MedicalClaim> {
    const claim = this.claimsRepository.create({
      ...createClaimDto,
      patientDateOfBirth: new Date(createClaimDto.patientDateOfBirth),
      status: ClaimStatus.PENDING,
    });

    return await this.claimsRepository.save(claim);
  }

  async findAll(): Promise<MedicalClaim[]> {
    // Stable sort: primary key createdAt DESC, tie-breaker id DESC so that
    // concurrent inserts at the same millisecond never cause duplicate/missing
    // items across paginated pages.
    return await this.claimsRepository.find({
      order: { createdAt: 'DESC', id: 'DESC' },
    });
  }

  async findOne(id: string): Promise<MedicalClaim | null> {
    return await this.claimsRepository.findOneBy({ id });
  }

  async verifyClaimWithHospital(claimId: string): Promise<MedicalClaim> {
    const claim = await this.findOne(claimId);

    if (!claim) {
      throw new ResourceNotFoundException('Claim', claimId);
    }

    this.logger.log(
      `Verifying claim ${claimId} with hospital ${claim.hospitalId}`,
    );

    try {
      const verification =
        await this.hospitalIntegrationService.verifyClaimWithHospital(
          claim.hospitalId,
          claimId,
        );

      const previousStatus = claim.status;
      claim.status = verification.verified
        ? ClaimStatus.APPROVED
        : ClaimStatus.REJECTED;
      claim.notes = verification.notes || claim.notes;

      const updatedClaim = await this.claimsRepository.save(claim);

      // Emit claim.updated event for notifications
      if (previousStatus !== claim.status) {
        this.eventEmitter.emit('claim.updated', {
          userId: claim.patientId, // Assuming patientId is the userId
          claimId: claim.id,
          status: claim.status,
          claimAmount: claim.claimAmount,
          notes: claim.notes,
          timestamp: new Date(),
        });
      }

      return updatedClaim;
    } catch (error) {
      this.logger.error(`Failed to verify claim ${claimId}:`, error);
      throw error;
    }
  }

  async fetchHospitalClaimData(hospitalId: string, claimId: string) {
    return await this.hospitalIntegrationService.fetchClaimData(
      hospitalId,
      claimId,
    );
  }

  async fetchPatientHistory(hospitalId: string, patientId: string) {
    return await this.hospitalIntegrationService.fetchPatientHistory(
      hospitalId,
      patientId,
    );
  }
}
