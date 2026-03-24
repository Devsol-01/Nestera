import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { MedicalClaim, ClaimStatus } from '../claims/entities/medical-claim.entity';
import { Dispute, DisputeStatus } from '../disputes/entities/dispute.entity';
import { AnalyticsOverviewDto } from './dto/analytics-overview.dto';

@Injectable()
export class AdminAnalyticsService {
  constructor(
    @InjectRepository(MedicalClaim)
    private readonly claimRepository: Repository<MedicalClaim>,
    @InjectRepository(Dispute)
    private readonly disputeRepository: Repository<Dispute>,
  ) {}

  async getOverview(): Promise<AnalyticsOverviewDto> {
    const [
      totalProcessedSweeps,
      activeDisputes,
      pendingMedicalClaims,
      totalClaims,
      claimAmountResult,
    ] = await Promise.all([
      this.claimRepository.count({
        where: [{ status: ClaimStatus.APPROVED }, { status: ClaimStatus.REJECTED }],
      }),
      this.disputeRepository.count({
        where: [{ status: DisputeStatus.OPEN }, { status: DisputeStatus.UNDER_REVIEW }],
      }),
      this.claimRepository.count({ where: { status: ClaimStatus.PENDING } }),
      this.claimRepository.count(),
      this.claimRepository
        .createQueryBuilder('claim')
        .select('SUM(claim.claimAmount)', 'total')
        .getRawOne(),
    ]);

    return {
      totalProcessedSweeps,
      activeDisputes,
      pendingMedicalClaims,
      totalUsers: totalClaims,
      totalClaimAmount: parseFloat(claimAmountResult?.total || '0'),
    };
  }
}
