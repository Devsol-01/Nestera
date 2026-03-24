import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Dispute, DisputeMessage, DisputeStatus } from './entities/dispute.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { CreateDisputeDto, UpdateDisputeDto, AddDisputeMessageDto } from './dto/dispute.dto';

@Injectable()
export class DisputesService {
  constructor(
    @InjectRepository(Dispute)
    private readonly disputeRepository: Repository<Dispute>,
    @InjectRepository(DisputeMessage)
    private readonly messageRepository: Repository<DisputeMessage>,
    @InjectRepository(MedicalClaim)
    private readonly claimRepository: Repository<MedicalClaim>,
  ) {}

  async createDispute(createDisputeDto: CreateDisputeDto): Promise<Dispute> {
    const claim = await this.claimRepository.findOneBy({ id: createDisputeDto.claimId });
    if (!claim) {
      throw new BadRequestException('Invalid claim ID. Claim does not exist.');
    }

    const dispute = this.disputeRepository.create({
      ...createDisputeDto,
      status: DisputeStatus.OPEN,
    });

    return await this.disputeRepository.save(dispute);
  }

  async findAll(): Promise<Dispute[]> {
    return await this.disputeRepository.find({
      relations: ['claim', 'messages'],
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string): Promise<Dispute> {
    const dispute = await this.disputeRepository.findOne({
      where: { id },
      relations: ['claim', 'messages'],
    });
    if (!dispute) {
      throw new NotFoundException('Dispute not found');
    }
    return dispute;
  }

  async updateDispute(id: string, updateDisputeDto: UpdateDisputeDto): Promise<Dispute> {
    const dispute = await this.findOne(id);
    Object.assign(dispute, updateDisputeDto);
    return await this.disputeRepository.save(dispute);
  }

  async addMessage(id: string, addMessageDto: AddDisputeMessageDto): Promise<DisputeMessage> {
    const dispute = await this.findOne(id);
    
    const message = this.messageRepository.create({
      disputeId: dispute.id,
      ...addMessageDto,
    });

    return await this.messageRepository.save(message);
  }
}
