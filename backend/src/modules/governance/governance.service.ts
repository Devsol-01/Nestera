import { Injectable } from '@nestjs/common';
import { StellarService } from '../blockchain/stellar.service';
import { UserService } from '../user/user.service';
import { DelegationResponseDto } from './dto/delegation-response.dto';

@Injectable()
export class GovernanceService {
  constructor(
    private readonly userService: UserService,
    private readonly stellarService: StellarService,
  ) {}

  async getUserDelegation(userId: string): Promise<DelegationResponseDto> {
    const user = await this.userService.findById(userId);

    if (!user.publicKey) {
      return { delegate: null };
    }

    const delegate = await this.stellarService.getDelegationForUser(
      user.publicKey,
    );

    return { delegate };
  }
}
