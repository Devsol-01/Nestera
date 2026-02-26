import { ClaimStatus } from '../../claims/entities/medical-claim.entity';

export class ClaimUpdatedEvent {
  constructor(
    public readonly claimId: string,
    public readonly patientName: string,
    public readonly patientEmail: string,
    public readonly hospitalName: string,
    public readonly claimAmount: number,
    public readonly status: ClaimStatus,
    public readonly notes?: string,
  ) {}
}
