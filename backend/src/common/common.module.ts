import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PiiEncryptionService } from './services/pii-encryption.service';
import { RateLimitMonitorService } from './services/rate-limit-monitor.service';
import { IdempotencyMonitorService } from './services/idempotency-monitor.service';
import { SecretsConfigService } from './services/secrets-config.service';
import { IdempotencyService } from './services/idempotency.service';
import { IdempotencyCleanupService } from './services/idempotency-cleanup.service';
import { LogSanitizerService } from './services/log-sanitizer.service';
import { CompressionMetricsService } from './services/compression-metrics.service';
import { CompressionMetricsMiddleware } from './middleware/compression.middleware';
import { AuditLogService } from './services/audit-log.service';
import { ContractCompatibilityService } from './services/contract-compatibility.service';
import { ContractValidationService } from './services/contract-validation.service';
import { TenantContextService } from './services/tenant-context.service';
import { TenantContextMiddleware } from './middleware/tenant-context.middleware';
import { CacheModule } from '../modules/cache/cache.module';
import { AuditLog } from './entities/audit-log.entity';
import { Tenant } from './entities/tenant.entity';
import { DataScopeService } from './services/data-scope.service';
import { DistributedLockModule } from './distributed-lock/distributed-lock.module';
import { TestModeModule } from './test-mode/test-mode.module';
import { EventualConsistencyService } from './services/eventual-consistency.service';
import { WorkflowIdempotencyService } from './services/workflow-idempotency.service';

@Global()
@Module({
  imports: [
    CacheModule,
    TypeOrmModule.forFeature([AuditLog, Tenant]),
    TestModeModule,
  ],
  providers: [
    RateLimitMonitorService,
    IdempotencyMonitorService,
    PiiEncryptionService,
    SecretsConfigService,
    IdempotencyService,
    IdempotencyCleanupService,
    LogSanitizerService,
    CompressionMetricsService,
    CompressionMetricsMiddleware,
    AuditLogService,
    ContractCompatibilityService,
    ContractValidationService,
    TenantContextService,
    TenantContextMiddleware,
    DataScopeService,
    EventualConsistencyService,
    WorkflowIdempotencyService,
  ],
  exports: [
    RateLimitMonitorService,
    IdempotencyMonitorService,
    PiiEncryptionService,
    SecretsConfigService,
    IdempotencyService,
    LogSanitizerService,
    CompressionMetricsService,
    AuditLogService,
    ContractCompatibilityService,
    ContractValidationService,
    TenantContextService,
    DataScopeService,
    DistributedLockModule,
    EventualConsistencyService,
    WorkflowIdempotencyService,
  ],
})
export class CommonModule {}
