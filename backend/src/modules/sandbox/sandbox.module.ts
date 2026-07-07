import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SandboxController } from './sandbox.controller';
import { SandboxService } from './sandbox.service';
import { TestDataGeneratorService } from './test-data-generator.service';
import { SandboxApiKey } from './entities/sandbox-api-key.entity';
import { SandboxUsageAnalytics } from './entities/sandbox-usage-analytics.entity';
import { User } from '../user/entities/user.entity';
import { UserWallet } from '../user/entities/user-wallet.entity';
import { Transaction } from '../transactions/entities/transaction.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { SavingsGoal } from '../savings/entities/savings-goal.entity';
import { AuthModule } from '../../auth/auth.module';

@Module({
  imports: [
    // Provides JwtStrategy + PassportModule so JwtAuthGuard works correctly
    AuthModule,
    TypeOrmModule.forFeature([
      SandboxApiKey,
      SandboxUsageAnalytics,
      User,
      UserWallet,
      Transaction,
      SavingsProduct,
      SavingsGoal,
    ]),
  ],
  controllers: [SandboxController],
  providers: [SandboxService, TestDataGeneratorService],
  exports: [SandboxService],
})
export class SandboxModule {}
