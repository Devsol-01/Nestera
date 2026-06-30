import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bull';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ScheduleModule } from '@nestjs/schedule';
import { UserModule } from '../user/user.module';
import { SavingsModule } from '../savings/savings.module';
import { MailModule } from '../mail/mail.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { CircuitBreakerModule } from '../../common/circuit-breaker/circuit-breaker.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { AdminController } from './admin.controller';
import { AdminSavingsController } from './admin-savings.controller';
import { AdminWaitlistController } from './admin-waitlist.controller';
import { AdminUsersController } from './admin-users.controller';
import { AdminWithdrawalController } from './admin-withdrawal.controller';
import { AdminWithdrawalService } from './admin-withdrawal.service';
import { AdminWorkflowController } from './admin-workflow.controller';
import { AdminEmergencyWithdrawalWorkflowController } from './admin-emergency-withdrawal-workflow.controller';

import { CircuitBreakerController } from './circuit-breaker.controller';
import { AdminDisputesController } from './admin-disputes.controller';
import { AdminAuditLogsController } from './admin-audit-logs.controller';
import { AdminNotificationsController } from './admin-notifications.controller';
import { AdminTransactionsController } from './admin-transactions.controller';
import { AdminIdempotencyController } from './admin-idempotency.controller';

import { AdminUsersService } from './admin-users.service';
import { AdminSavingsService } from './admin-savings.service';
import { AdminDisputesService } from './admin-disputes.service';
import { AdminAuditLogsService } from './admin-audit-logs.service';
import { AdminNotificationsService } from './admin-notifications.service';
import { AdminNotificationRateLimiterService } from './admin-notification-rate-limiter.service';
import { AdminTransactionsService } from './admin-transactions.service';
import { AdminConfirmationService } from './admin-confirmation.service';
import { WorkflowService } from './workflow.service';
import { WorkflowAuditService } from './workflow-audit.service';
import { EmergencyWithdrawalWorkflowService } from './emergency-withdrawal-workflow.service';
import { AdminTransactionNote } from './entities/admin-transaction-note.entity';
import { AdminConfirmation } from './entities/admin-confirmation.entity';
import { AdminWorkflow } from './entities/admin-workflow.entity';
import { User } from '../user/entities/user.entity';
import { UserSubscription } from '../savings/entities/user-subscription.entity';
import { SavingsProduct } from '../savings/entities/savings-product.entity';
import { LedgerTransaction } from '../blockchain/entities/transaction.entity';
import { WithdrawalRequest } from '../savings/entities/withdrawal-request.entity';
import { AuditLog } from '../../common/entities/audit-log.entity';
import { Transaction } from '../transactions/entities/transaction.entity';
import { Dispute, DisputeTimeline } from '../disputes/entities/dispute.entity';
import { Notification } from '../notifications/entities/notification.entity';
import { JobQueueModule } from '../job-queue/job-queue.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      UserSubscription,
      SavingsProduct,
      LedgerTransaction,
      WithdrawalRequest,
      AuditLog,
      Transaction,
      AdminTransactionNote,
      AdminConfirmation,
      AdminWorkflow,
      Dispute,
      DisputeTimeline,
      Notification,
      AdminExportJob,
    ]),
    BullModule.registerQueue({ name: ADMIN_EXPORT_QUEUE }),
    UserModule,
    SavingsModule,
    MailModule,
    BlockchainModule,
    CircuitBreakerModule,
    NotificationsModule,
    JobQueueModule,
    EventEmitterModule,
    ScheduleModule.forRoot(),
  ],
  controllers: [
    AdminController,
    AdminSavingsController,
    AdminWaitlistController,
    AdminUsersController,
    AdminWithdrawalController,
    AdminWorkflowController,
    AdminEmergencyWithdrawalWorkflowController,
    AdminNotificationsController,
    AdminTransactionsController,
    AdminDisputesController,
    AdminAuditLogsController,
    AdminIdempotencyController,
  ],
  providers: [
    AdminUsersService,
    AdminSavingsService,
    AdminDisputesService,
    AdminAuditLogsService,
    AdminNotificationsService,
    AdminNotificationRateLimiterService,
    AdminTransactionsService,
    AdminWithdrawalService,
    AdminConfirmationService,
    WorkflowService,
    WorkflowAuditService,
    EmergencyWithdrawalWorkflowService,
  ],
  exports: [
    AdminDisputesService,
    AdminAuditLogsService,
    AdminConfirmationService,
    WorkflowService,
  ],
})
export class AdminModule {}
