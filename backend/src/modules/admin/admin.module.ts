import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { SavingsModule } from '../savings/savings.module';
import { AdminController } from './admin.controller';
import { AdminSavingsController } from './admin-savings.controller';

@Module({
  imports: [UserModule, SavingsModule],
  controllers: [AdminController, AdminSavingsController],
})
export class AdminModule {}
