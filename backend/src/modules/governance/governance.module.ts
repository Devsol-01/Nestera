import { Module } from '@nestjs/common';
import { GovernanceController } from './governance.controller';
import { GovernanceService } from './governance.service';
import { UserModule } from '../user/user.module';

@Module({
  imports: [UserModule],
  controllers: [GovernanceController],
  providers: [GovernanceService],
})
export class GovernanceModule {}
