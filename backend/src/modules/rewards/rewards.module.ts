import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ChallengeAchievement } from '../challenges/entities/challenge-achievement.entity';
import { SavingsGoal } from '../savings/entities/savings-goal.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { Transaction } from '../transactions/entities/transaction.entity';
import { User } from '../user/entities/user.entity';
import { RewardsController } from './rewards.controller';
import { RewardsService } from './rewards.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Transaction,
      UserSubscription,
      SavingsGoal,
      ChallengeAchievement,
    ]),
  ],
  controllers: [RewardsController],
  providers: [RewardsService],
  exports: [RewardsService],
})
export class RewardsModule {}
