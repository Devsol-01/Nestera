import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { DelegationResponseDto } from './dto/delegation-response.dto';
import { GovernanceService } from './governance.service';

@ApiTags('governance')
@ApiBearerAuth()
@Controller('user')
@UseGuards(JwtAuthGuard)
export class GovernanceController {
  constructor(private readonly governanceService: GovernanceService) {}

  @Get('delegation')
  @ApiOperation({
    summary: 'Get the authenticated user delegation target',
    description:
      'Reads the Soroban governance contract mapping for the authenticated user and returns the delegated wallet address when present.',
  })
  @ApiResponse({
    status: 200,
    description: 'Delegation lookup result',
    type: DelegationResponseDto,
  })
  getDelegation(
    @CurrentUser() user: { id: string },
  ): Promise<DelegationResponseDto> {
    return this.governanceService.getUserDelegation(user.id);
  }
}
