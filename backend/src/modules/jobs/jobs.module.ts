import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { TypeOrmModule } from '@nestjs/typeorm';
import { NotificationProcessor } from './processors/notification.processor';
import { BlockchainProcessor } from './processors/blockchain.processor';
import { ReconciliationProcessor } from './processors/reconciliation.processor';
import { FeeRewardReconciliationService } from './services/fee-reward-reconciliation.service';
import { ReconciliationRecord } from './entities/reconciliation-record.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([ReconciliationRecord]),
    BullModule.registerQueue(
      { name: 'notifications' },
      { name: 'blockchain' },
      { name: 'reconciliation' },
    ),
  ],
  providers: [
    NotificationProcessor,
    BlockchainProcessor,
    ReconciliationProcessor,
    FeeRewardReconciliationService,
  ],
})
export class JobsModule {}
