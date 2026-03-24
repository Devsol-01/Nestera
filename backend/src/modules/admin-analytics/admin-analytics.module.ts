import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AdminAnalyticsController } from './admin-analytics.controller';
import { AdminAnalyticsService } from './admin-analytics.service';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { Dispute } from '../disputes/entities/dispute.entity';

@Module({
  imports: [TypeOrmModule.forFeature([MedicalClaim, Dispute])],
  controllers: [AdminAnalyticsController],
  providers: [AdminAnalyticsService],
  exports: [AdminAnalyticsService],
})
export class AdminAnalyticsModule {}
