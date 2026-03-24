import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { StellarService } from './stellar.service';
import { SavingsService } from './savings.service';
import { BlockchainController } from './blockchain.controller';
import { StellarEventListenerService } from './stellar-event-listener.service';
import { StellarEventListenerController } from './stellar-event-listener.controller';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';

@Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([ProcessedStellarEvent, MedicalClaim]),
  ],
  controllers: [BlockchainController, StellarEventListenerController],
  providers: [StellarService, SavingsService, StellarEventListenerService],
  exports: [StellarService, SavingsService, StellarEventListenerService],
})
export class BlockchainModule { }

