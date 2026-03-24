import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ClaimsController } from './claims.controller';
import { ClaimsService } from './claims.service';
import { MedicalClaim } from './entities/medical-claim.entity';
import { HospitalIntegrationModule } from '../hospital-integration/hospital-integration.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([MedicalClaim]),
    HospitalIntegrationModule,
  ],
  controllers: [ClaimsController],
  providers: [ClaimsService],
  exports: [ClaimsService],
})
export class ClaimsModule { }
