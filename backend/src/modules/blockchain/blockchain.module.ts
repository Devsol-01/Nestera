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
import { ProcessedStellarEvent } from './entities/processed-event.entity';
import { LedgerTransaction } from './entities/transaction.entity';
import { DeadLetterEvent } from './entities/dead-letter-event.entity';
import { IndexerState } from './entities/indexer-state.entity';
import { MedicalClaim } from '../claims/entities/medical-claim.entity';
import { User } from '../user/entities/user.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { DepositHandler } from './event-handlers/deposit.handler';
import { WithdrawHandler } from './event-handlers/withdraw.handler';
import { YieldHandler } from './event-handlers/yield.handler';
import { IndexerService } from './indexer.service';
import { BalanceSyncService } from './balance-sync.service';
import { ProtocolMetrics } from '../admin-analytics/entities/protocol-metrics.entity';
import { RetryService } from './services/retry.service';
import { BalanceSnapshot } from './entities/balance-snapshot.entity';
import { ReorgHistory } from './entities/reorg-history.entity';

@Global()
@Module({
  imports: [
    HttpModule,
    CacheModule.register({
      ttl: 300, // 5 minutes default TTL
      max: 100, // Maximum number of items in cache
    }),
    TypeOrmModule.forFeature([
      ProcessedStellarEvent,
      MedicalClaim,
      LedgerTransaction,
      DeadLetterEvent,
      IndexerState,
      User,
      UserSubscription,
      SavingsProduct,
      ProtocolMetrics,
      BalanceSnapshot,
      ReorgHistory,
    ]),
  ],
  controllers: [BlockchainController, StellarEventListenerController],
  providers: [
    StellarService,
    SavingsService,
    OracleService,
    StellarEventListenerService,
    IndexerService,
    DepositHandler,
    WithdrawHandler,
    YieldHandler,
    BalanceSyncService,
    RetryService,
  ],
  exports: [
    StellarService,
    SavingsService,
    OracleService,
    StellarEventListenerService,
    IndexerService,
    DepositHandler,
    WithdrawHandler,
    YieldHandler,
    BalanceSyncService,
    RetryService,
  ],
})
export class BlockchainModule {}
