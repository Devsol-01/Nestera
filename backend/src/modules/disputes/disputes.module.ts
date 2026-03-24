import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DisputesController } from './disputes.controller';
import { DisputesService } from './disputes.service';
import { Dispute, DisputeMessage } from './entities/dispute.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Dispute, DisputeMessage, MedicalClaim])],
  controllers: [DisputesController],
  providers: [DisputesService],
  exports: [DisputesService],
})
export class DisputesModule {}
