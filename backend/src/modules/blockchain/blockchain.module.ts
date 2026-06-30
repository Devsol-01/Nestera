import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { CacheModule } from '@nestjs/cache-manager';
import { StellarService } from './stellar.service';
import { SavingsService } from './savings.service';
import { OracleService } from './oracle.service';
import { BlockchainController } from './blockchain.controller';
import { StellarEventListenerService } from './stellar-event-listener.service';
import { StellarEventListenerController } from './stellar-event-listener.controller';
import { AdminBlockchainReplayController } from './admin-blockchain-replay.controller';
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { LedgerTransaction } from './entities/transaction.entity';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { IndexerState } from './entities/indexer-state.entity';
import { BlockchainReplayJob } from './entities/blockchain-replay-job.entity';
import { MalformedBlockchainEvent } from './entities/malformed-blockchain-event.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { User } from '../user/entities/user.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';
import { IndexerService } from './indexer.service';
import { IndexerCheckpointService } from './indexer-checkpoint.service';
import { BlockchainReplayService } from './blockchain-replay.service';
import { BalanceSyncService } from './balance-sync.service';
import { BlockchainEventParser } from './blockchain-event-parser.service';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { EventStreamBackpressureService } from './event-stream-backpressure.service';
import { ProtocolMetrics } from '../admin-analytics/entities/protocol-metrics.entity';
import { TransactionsModule } from '../transactions/transactions.module';
import { ContractEventValidatorService } from './contract-event-validator.service';

@Global()
@Module({
  imports: [
    HttpModule,
    JobQueueModule,
    TransactionsModule,
    CacheModule.register({
      ttl: 300,
      max: 100,
    }),
    TypeOrmModule.forFeature([
      ProcessedStellarEvent,
      MedicalClaim,
      LedgerTransaction,
      DeadLetterEvent,
      IndexerState,
      BlockchainReplayJob,
      MalformedBlockchainEvent,
      User,
      UserSubscription,
      SavingsProduct,
      ProtocolMetrics,
    ]),
  ],
  controllers: [
    BlockchainController,
    StellarEventListenerController,
    AdminBlockchainReplayController,
  ],
  providers: [
    StellarService,
    SavingsService,
    OracleService,
    StellarEventListenerService,
    IndexerService,
    IndexerCheckpointService,
    BlockchainReplayService,
    DepositHandler,
    WithdrawHandler,
    YieldHandler,
    BalanceSyncService,
    EventStreamBackpressureService,
    ContractEventValidatorService,
  ],
  exports: [
    StellarService,
    SavingsService,
    OracleService,
    StellarEventListenerService,
    IndexerService,
    IndexerCheckpointService,
    BlockchainReplayService,
    DepositHandler,
    WithdrawHandler,
    YieldHandler,
    BalanceSyncService,
    EventStreamBackpressureService,
    ContractEventValidatorService,
  ],
})
export class BlockchainModule {}
