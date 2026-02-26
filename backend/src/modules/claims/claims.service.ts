import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { MedicalClaim, ClaimStatus } from './entities/medical-claim.entity';
import { CreateClaimDto } from './dto/create-claim.dto';
import { HospitalIntegrationService } from '../hospital-integration/hospital-integration.service';
import { ClaimUpdatedEvent } from '../notifications/events/claim-updated.event';

@Injectable()
export class ClaimsService {
  private readonly logger = new Logger(ClaimsService.name);

  constructor(
    @InjectRepository(MedicalClaim)
    private readonly claimsRepository: Repository<MedicalClaim>,
    private readonly hospitalIntegrationService: HospitalIntegrationService,
    private readonly eventEmitter: EventEmitter2,
  ) { }

  async createClaim(createClaimDto: CreateClaimDto): Promise<MedicalClaim> {
    const claim = this.claimsRepository.create({
      ...createClaimDto,
      patientDateOfBirth: new Date(createClaimDto.patientDateOfBirth),
      status: ClaimStatus.PENDING,
    });

    return await this.claimsRepository.save(claim);
  }

  async findAll(): Promise<MedicalClaim[]> {
    return await this.claimsRepository.find({ order: { createdAt: 'DESC' } });
  }

  async findOne(id: string): Promise<MedicalClaim | null> {
    return await this.claimsRepository.findOneBy({ id });
  }

  async verifyClaimWithHospital(claimId: string): Promise<MedicalClaim> {
    const claim = await this.findOne(claimId);

    if (!claim) {
      throw new Error('Claim not found');
    }

    this.logger.log(`Verifying claim ${claimId} with hospital ${claim.hospitalId}`);

    try {
      const verification = await this.hospitalIntegrationService.verifyClaimWithHospital(
        claim.hospitalId,
        claimId,
      );

      claim.status = verification.verified ? ClaimStatus.APPROVED : ClaimStatus.REJECTED;
      claim.notes = verification.notes || claim.notes;

      const saved = await this.claimsRepository.save(claim);

      this.eventEmitter.emit(
        'claim.updated',
        new ClaimUpdatedEvent(
          saved.id,
          saved.patientName,
          '',
          saved.hospitalName,
          Number(saved.claimAmount),
          saved.status,
          saved.notes,
        ),
      );

      return saved;
    } catch (error) {
      this.logger.error(`Failed to verify claim ${claimId}:`, error);
      throw error;
    }
  }

  async updateClaimStatus(
    claimId: string,
    status: ClaimStatus,
    patientEmail: string,
    notes?: string,
  ): Promise<MedicalClaim> {
    const claim = await this.findOne(claimId);
    if (!claim) {
      throw new Error('Claim not found');
    }

    claim.status = status;
    if (notes) claim.notes = notes;

    const saved = await this.claimsRepository.save(claim);

    this.eventEmitter.emit(
      'claim.updated',
      new ClaimUpdatedEvent(
        saved.id,
        saved.patientName,
        patientEmail,
        saved.hospitalName,
        Number(saved.claimAmount),
        saved.status,
        saved.notes,
      ),
    );

    return saved;
  }

  async fetchHospitalClaimData(hospitalId: string, claimId: string) {
    return await this.hospitalIntegrationService.fetchClaimData(hospitalId, claimId);
  }

  async fetchPatientHistory(hospitalId: string, patientId: string) {
    return await this.hospitalIntegrationService.fetchPatientHistory(hospitalId, patientId);
  }
}
