import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SavingsController } from './savings.controller';
import { SavingsService } from './savings.service';
import { SavingsProduct } from './entities/savings-product.entity';
import { UserSubscription } from './entities/user-subscription.entity';
import { SavingsGoal } from './entities/savings-goal.entity';
import { User } from '../user/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      SavingsProduct,
      UserSubscription,
      SavingsGoal,
      User,
    ]),
  ],
  controllers: [SavingsController],
  providers: [SavingsService],
  exports: [SavingsService],
})
export class SavingsModule {}
